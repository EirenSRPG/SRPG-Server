// Accounts for the slime RPG: username + password, and a copy of each player's save files so they can
// continue on another device. Used by server.js (all routes are POST /account/...).
//
//   POST /account/register  {username, password}            -> {ok, token, username}
//   POST /account/login     {username, password}            -> {ok, token, username}
//   POST /account/load      {token}                         -> {ok, username, files: {name: {t, d}}}
//   POST /account/save      {token, files, deleted}         -> {ok}      files: {name: {t, d}}  (d = base64)
//   POST /account/logout    {token}                         -> {ok}
//   POST /account/delete    {token, password}               -> {ok}      erases the account and every saved file
//
// Errors are {error: "text"} with a 4xx status.
//
// Storage: one JSON file at DATA_DIR/accounts.json (default ./data). On Render's free tier the disk is wiped on
// every restart/deploy, so set DATA_DIR to a mounted persistent disk (e.g. /var/data) or accounts will vanish.

"use strict";
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { promisify } = require("util");
const scrypt = promisify(crypto.scrypt);

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "accounts.json");

const USER_RE = /^[A-Za-z0-9_]{3,16}$/;
const FILE_RE = /^[A-Za-z0-9_][A-Za-z0-9_.\- ]{0,63}$/;
const MIN_PASSWORD = 8;
const MAX_PASSWORD = 64;
const MAX_BODY = 4 * 1024 * 1024;
const MAX_FILE_B64 = 1400000;          // ~1 MB of file data
const MAX_FILES = 40;
const MAX_TOTAL_B64 = 8 * 1024 * 1024;
const MAX_TOKENS = 5;                  // devices signed in at once; the oldest is signed out
const MAX_FAILS = 8;                   // wrong passwords per 10 minutes (per IP + username)
const FAIL_WINDOW = 10 * 60 * 1000;
const MAX_REGISTER = 10;               // new accounts per hour per IP
const REGISTER_WINDOW = 60 * 60 * 1000;

// ---------- storage ----------

let db = { users: {} };   // lowercase username -> {name, salt, hash, tokens: [sha256], files: {name: {t, d}}, created}
try { db = JSON.parse(fs.readFileSync(DB_FILE, "utf8")); } catch (e) { /* first run */ }
if (!db || typeof db.users !== "object") db = { users: {} };

const tokenIndex = new Map();   // sha256(token) -> lowercase username
for (const [key, user] of Object.entries(db.users)) {
  for (const h of user.tokens || []) tokenIndex.set(h, key);
}

function flush() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const tmp = DB_FILE + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(db));
    fs.renameSync(tmp, DB_FILE);
  } catch (e) {
    console.error("could not write accounts:", e.message);
  }
}

let flushTimer = null;
function persist() {
  if (flushTimer) return;
  flushTimer = setTimeout(() => { flushTimer = null; flush(); }, 500);
}
process.on("SIGTERM", () => { flush(); process.exit(0); });

// ---------- helpers ----------

const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const str = (v) => (typeof v === "string" ? v : "");

async function hashPassword(password, saltHex) {
  return (await scrypt(password, Buffer.from(saltHex, "hex"), 64)).toString("hex");
}

function sameHex(a, b) {
  const x = Buffer.from(a, "hex");
  const y = Buffer.from(b, "hex");
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function issueToken(key) {
  const user = db.users[key];
  const token = crypto.randomBytes(32).toString("hex");
  const h = sha(token);
  user.tokens.push(h);
  tokenIndex.set(h, key);
  while (user.tokens.length > MAX_TOKENS) tokenIndex.delete(user.tokens.shift());
  return token;
}

function userFromToken(token) {
  const key = tokenIndex.get(sha(str(token)));
  return key && db.users[key] ? { key, user: db.users[key] } : null;
}

const buckets = new Map();   // rate limits: key -> {start, count}
function tooMany(key, max, windowMs) {
  const b = buckets.get(key);
  return !!b && Date.now() - b.start < windowMs && b.count >= max;
}
function bump(key, windowMs) {
  const now = Date.now();
  let b = buckets.get(key);
  if (!b || now - b.start >= windowMs) b = { start: now, count: 0 };
  b.count++;
  buckets.set(key, b);
}
setInterval(() => {
  const now = Date.now();
  for (const [k, b] of buckets) if (now - b.start > 60 * 60 * 1000) buckets.delete(k);
}, 10 * 60 * 1000).unref();

function clientIp(req) {
  return str(req.headers["x-forwarded-for"]).split(",")[0].trim() || req.socket.remoteAddress || "?";
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject(new Error("too big")); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); } catch (e) { reject(new Error("bad json")); }
    });
    req.on("error", reject);
  });
}

// ---------- routes ----------

async function register(req, res, msg, json) {
  const ip = clientIp(req);
  if (tooMany("reg:" + ip, MAX_REGISTER, REGISTER_WINDOW)) return json(res, 429, { error: "Too many new accounts from this connection. Try again later." });
  const name = str(msg.username).trim();
  const password = str(msg.password);
  if (!USER_RE.test(name)) return json(res, 400, { error: "Usernames are 3-16 letters, numbers or underscores." });
  if (password.length < MIN_PASSWORD || password.length > MAX_PASSWORD) return json(res, 400, { error: `Passwords are ${MIN_PASSWORD}-${MAX_PASSWORD} characters.` });
  const key = name.toLowerCase();
  if (db.users[key]) return json(res, 409, { error: "That username is already taken." });
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = await hashPassword(password, salt);
  if (db.users[key]) return json(res, 409, { error: "That username is already taken." });   // someone else took it while we hashed
  db.users[key] = { name, salt, hash, tokens: [], files: {}, created: Date.now() };
  bump("reg:" + ip, REGISTER_WINDOW);
  const token = issueToken(key);
  persist();
  console.log(`account created (${Object.keys(db.users).length} accounts)`);
  return json(res, 200, { ok: true, token, username: name });
}

// Checks the password for `key` (always does the same work, so a missing user can't be told apart by timing).
async function passwordOk(key, password) {
  const user = db.users[key];
  const salt = user ? user.salt : "00000000000000000000000000000000";
  const hash = await hashPassword(password, salt);
  return !!user && sameHex(hash, user.hash);
}

async function login(req, res, msg, json) {
  const name = str(msg.username).trim();
  const password = str(msg.password);
  const key = name.toLowerCase();
  const bucket = "login:" + clientIp(req) + "|" + key;
  if (tooMany(bucket, MAX_FAILS, FAIL_WINDOW)) return json(res, 429, { error: "Too many attempts. Try again in a few minutes." });
  if (password.length > MAX_PASSWORD || !(await passwordOk(key, password))) {
    bump(bucket, FAIL_WINDOW);
    return json(res, 401, { error: "Wrong username or password." });
  }
  buckets.delete(bucket);
  const token = issueToken(key);
  persist();
  return json(res, 200, { ok: true, token, username: db.users[key].name });
}

async function deleteAccount(req, res, msg, json) {
  const auth = userFromToken(msg.token);
  if (!auth) return json(res, 401, { error: "Please log in again." });
  const bucket = "login:" + clientIp(req) + "|" + auth.key;
  if (tooMany(bucket, MAX_FAILS, FAIL_WINDOW)) return json(res, 429, { error: "Too many attempts. Try again in a few minutes." });
  if (!(await passwordOk(auth.key, str(msg.password).slice(0, MAX_PASSWORD)))) {
    bump(bucket, FAIL_WINDOW);
    return json(res, 403, { error: "Wrong password." });
  }
  for (const h of auth.user.tokens) tokenIndex.delete(h);
  delete db.users[auth.key];
  persist();
  console.log(`account deleted (${Object.keys(db.users).length} accounts)`);
  return json(res, 200, { ok: true });
}

function loadFiles(res, msg, json) {
  const auth = userFromToken(msg.token);
  if (!auth) return json(res, 401, { error: "Please log in again." });
  return json(res, 200, { ok: true, username: auth.user.name, files: auth.user.files });
}

function saveFiles(res, msg, json) {
  const auth = userFromToken(msg.token);
  if (!auth) return json(res, 401, { error: "Please log in again." });
  const incoming = msg.files && typeof msg.files === "object" ? msg.files : {};
  const deleted = Array.isArray(msg.deleted) ? msg.deleted : [];
  const files = { ...auth.user.files };
  for (const name of deleted) {
    if (typeof name === "string") delete files[name];
  }
  for (const [name, entry] of Object.entries(incoming)) {
    if (!FILE_RE.test(name) || !entry || typeof entry.d !== "string" || entry.d.length > MAX_FILE_B64) {
      return json(res, 400, { error: "Bad save file." });
    }
    files[name] = { t: Math.floor(Number(entry.t)) || 0, d: entry.d };
  }
  const names = Object.keys(files);
  const total = names.reduce((sum, n) => sum + files[n].d.length, 0);
  if (names.length > MAX_FILES || total > MAX_TOTAL_B64) return json(res, 413, { error: "Too much save data for one account." });
  auth.user.files = files;
  persist();
  return json(res, 200, { ok: true });
}

function logout(res, msg, json) {
  const auth = userFromToken(msg.token);
  if (auth) {
    const h = sha(str(msg.token));
    auth.user.tokens = auth.user.tokens.filter((t) => t !== h);
    tokenIndex.delete(h);
    persist();
  }
  return json(res, 200, { ok: true });
}

async function handle(req, res, url, json) {
  if (req.method !== "POST") return json(res, 405, { error: "POST only." });
  let msg;
  try { msg = await readBody(req); } catch (e) { return json(res, 400, { error: "Bad request." }); }
  if (!msg || typeof msg !== "object") return json(res, 400, { error: "Bad request." });
  try {
    switch (url) {
      case "/account/register": return await register(req, res, msg, json);
      case "/account/login": return await login(req, res, msg, json);
      case "/account/delete": return await deleteAccount(req, res, msg, json);
      case "/account/load": return loadFiles(res, msg, json);
      case "/account/save": return saveFiles(res, msg, json);
      case "/account/logout": return logout(res, msg, json);
      default: return json(res, 404, { error: "Not found." });
    }
  } catch (e) {
    console.error(e);
    return json(res, 500, { error: "Server error." });
  }
}

module.exports = { handle };
