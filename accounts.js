// Accounts for the slime RPG: username + password, and a copy of each player's save files so they can
// continue on another device. Used by server.js (all routes are POST /account/...).
//
//   POST /account/register  {username, password}            -> {ok, token, username}
//   POST /account/login     {username, password}            -> {ok, token, username}
//   POST /account/load      {token}                         -> {ok, username, files: {name: {t, d}}}
//   POST /account/save      {token, files, deleted}         -> {ok}      files: {name: {t, d}}  (d = base64)
//   POST /account/logout    {token}                         -> {ok}
//   POST /account/delete    {token, password}               -> {ok}      erases the account and every saved file
//   POST /account/moderators     {token}                    -> {ok, moderators: [names]}          any logged-in account
//   POST /account/list           {token, query}             -> {ok, accounts: [{username, moderator, online, banned, ban, warnings, requested}]}   staff only
//   POST /account/set_moderator  {token, username, moderator} -> {ok}                              admin only
//   POST /account/moderate       {token, username, action, reason, minutes} -> {ok}                staff only
//                                action: "warn" | "unwarn" (removes the newest warning) | "tempban" (minutes) | "ban" (full multiplayer ban, permanent) | "unban"
//   POST /account/request_moderator {token, username}       -> {ok}                                 moderators (asks the admin to promote someone)
//   POST /account/dismiss_request   {token, username}       -> {ok}                                 admin only
//   POST /account/filtered      {token, count}             -> {ok, warned}     the game reports words the chat filter blocked; too many in a short time = 1 automatic warning (no moderator name)
//   POST /account/notices        {token}                    -> {ok, warnings: [{by, reason, at}], mod_requests?: [{username, by, at}]}
//                                warnings are handed out once; mod_requests only for the admin
// The admin is the account named ADMIN_ACCOUNT. "Staff" = the admin + every account with "moderator": true.
// The moderator flag, bans, warnings and promotion requests all live on the account row, so they are saved with it.
//
// Errors are {error: "text"} with a 4xx status.
//
// Storage: a Turso (libSQL) database, one row per account in the "users" table. Set TURSO_DATABASE_URL and
// TURSO_AUTH_TOKEN. Accounts are loaded into memory at startup and changed rows are written back shortly after.
// Nothing is stored on the server's disk, so Render restarts/deploys no longer wipe accounts.

"use strict";
const crypto = require("crypto");
const { promisify } = require("util");
const { createClient } = require("@libsql/client");
const scrypt = promisify(crypto.scrypt);

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
const ADMIN_ACCOUNT = "eiren";         // the only account that may list accounts and hand out the moderator role (lowercase)
const ONLINE_MS = 3 * 60 * 1000;       // an account that talked to the server this recently counts as online
const MAX_LIST = 200;                  // most accounts /account/list returns
const MAX_REGISTER = 10;               // new accounts per hour per IP
const REGISTER_WINDOW = 60 * 60 * 1000;
const MOD_CAN_PERMBAN = true;          // false: only the admin may hand out full (permanent) multiplayer bans
const MAX_TEMP_MINUTES = 30 * 24 * 60; // longest temp ban (longer = a complete ban)
const MAX_REASON = 200;
const MAX_WARNINGS = 20;               // warnings kept per account (oldest dropped)
const FILTER_LIMIT = 5;                // blocked chat words within FILTER_WINDOW that earn one automatic warning
const FILTER_WINDOW = 60 * 1000;
const FILTER_MAX_REPORT = 20;          // most words one report can add (a message is at most 100 characters)
const FILTER_WARNING = "You used too many words that the chat filter blocks. Please keep the chat friendly.";
const MAX_MOD_REQUESTS = 10;           // pending "make X a moderator" requests kept per target

// ---------- storage ----------

const turso = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

let db = { users: {} };         // lowercase username -> {name, salt, hash, tokens: [sha256], files: {name: {t, d}}, created}
const tokenIndex = new Map();   // sha256(token) -> lowercase username
const filterHits = new Map();   // lowercase username -> [{at, count}] blocked words reported recently (memory only)
const lastSeen = new Map();     // lowercase username -> time of their last request (memory only, never saved)
const saved = new Map();        // lowercase username -> the JSON last written to Turso (to find what changed)

let ready = null;
function ensureReady() {
  if (!ready) ready = init().catch((e) => { ready = null; throw e; });   // retried on the next request if it failed
  return ready;
}

async function init() {
  await turso.execute("CREATE TABLE IF NOT EXISTS users (key TEXT PRIMARY KEY, data TEXT NOT NULL)");
  const rs = await turso.execute("SELECT key, data FROM users");
  const users = {};
  saved.clear();
  tokenIndex.clear();
  for (const row of rs.rows) {
    const key = String(row.key);
    const data = String(row.data);
    try {
      users[key] = JSON.parse(data);
      saved.set(key, data);
    } catch (e) {
      console.error("skipping unreadable account row:", key);
    }
  }
  db = { users };
  for (const [key, user] of Object.entries(db.users)) {
    for (const h of user.tokens || []) tokenIndex.set(h, key);
  }
  console.log(`loaded ${Object.keys(db.users).length} accounts`);
}

async function doFlush() {
  const stmts = [];
  const written = [];
  const removed = [];
  for (const [key, user] of Object.entries(db.users)) {
    const data = JSON.stringify(user);
    if (saved.get(key) === data) continue;
    stmts.push({
      sql: "INSERT INTO users (key, data) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET data = excluded.data",
      args: [key, data],
    });
    written.push([key, data]);
  }
  for (const key of saved.keys()) {
    if (db.users[key]) continue;
    stmts.push({ sql: "DELETE FROM users WHERE key = ?", args: [key] });
    removed.push(key);
  }
  if (!stmts.length) return;
  await turso.batch(stmts, "write");
  for (const [key, data] of written) saved.set(key, data);
  for (const key of removed) saved.delete(key);
}

let chain = Promise.resolve();   // flushes run one at a time
function flush() {
  chain = chain.then(doFlush).catch((e) => {
    console.error("could not write accounts:", e.message);
    setTimeout(persist, 5000).unref();   // try again; nothing is lost while the server stays up
  });
  return chain;
}

let flushTimer = null;
function persist() {
  if (flushTimer) return;
  flushTimer = setTimeout(() => { flushTimer = null; flush(); }, 500);
}
process.on("SIGTERM", () => { flush().finally(() => process.exit(0)); });

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
  if (!key || !db.users[key]) return null;
  lastSeen.set(key, Date.now());   // every request from a logged-in game (saves go up every ~20 s) counts as "online"
  return { key, user: db.users[key] };
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

// ---------- roles, bans, warnings ----------

const isAdmin = (key) => key === ADMIN_ACCOUNT;
const isStaff = (key) => isAdmin(key) || (db.users[key] && db.users[key].moderator === true);

// ban = {scope: "multiplayer" | "account", until: ms (0 = permanent), reason, by, at}
// "multiplayer" (temp and full bans; until 0 = permanent) blocks hosting/joining. "account" (unused by the menu) would also block login.
function activeBan(user) {
  const ban = user.ban;
  if (!ban) return null;
  if (ban.until > 0 && ban.until <= Date.now()) {   // a temp ban that ran out
    delete user.ban;
    persist();
    return null;
  }
  return ban;
}

function banText(ban) {
  const when = ban.until > 0 ? "until " + new Date(ban.until).toUTCString() : "permanently";
  return `You are banned ${when}.` + (ban.reason ? " Reason: " + ban.reason : "");
}

let banHook = () => {};
// server.js registers this so a ban also removes the player from the lobby they are in right now: hook(key, reason)
function setBanHook(fn) { banHook = typeof fn === "function" ? fn : () => {}; }

// Hosting or joining needs a logged-in account that isn't banned. Returns {ok, key} or {ok: false, reason}.
async function multiplayerGate(token) {
  try { await ensureReady(); } catch (e) { return { ok: false, reason: "Accounts are unavailable right now. Try again in a moment." }; }
  const auth = userFromToken(token);
  if (!auth) return { ok: false, reason: "Please log in to play multiplayer." };
  const ban = activeBan(auth.user);
  if (ban) return { ok: false, reason: banText(ban) };
  return { ok: true, key: auth.key };
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
  const ban = activeBan(db.users[key]);
  if (ban && ban.scope === "account") return json(res, 403, { error: banText(ban) });
  const token = issueToken(key);
  persist();
  return json(res, 200, { ok: true, token, username: db.users[key].name });
}

async function deleteAccount(req, res, msg, json) {
  const auth = userFromToken(msg.token);
  if (!auth) return json(res, 401, { error: "Please log in again." });
  if (activeBan(auth.user)) return json(res, 403, { error: "A banned account can't be deleted." });
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

// Who has the blue shield. Any logged-in account may ask (every game downloads this so chat can show the shield).
function listModerators(res, msg, json) {
  const auth = userFromToken(msg.token);
  if (!auth) return json(res, 401, { error: "Please log in again." });
  const names = Object.values(db.users).filter((u) => u.moderator === true).map((u) => u.name);
  return json(res, 200, { ok: true, moderators: names });
}

// Staff only (admin + moderators): every account (or the ones whose name contains `query`), online ones first, then A-Z
function listAccounts(res, msg, json) {
  const auth = userFromToken(msg.token);
  if (!auth) return json(res, 401, { error: "Please log in again." });
  if (!isStaff(auth.key)) return json(res, 403, { error: "Not allowed." });
  const query = str(msg.query).trim().toLowerCase().slice(0, 16);
  const now = Date.now();
  const list = [];
  for (const [key, user] of Object.entries(db.users)) {
    if (query && !key.includes(query)) continue;
    const ban = activeBan(user);
    list.push({
      username: user.name,
      moderator: user.moderator === true,
      online: now - (lastSeen.get(key) || 0) < ONLINE_MS,
      banned: !!ban,
      ban: ban ? { scope: ban.scope, until: ban.until, reason: ban.reason, by: ban.by } : null,
      warnings: (user.warnings || []).length,
      requested: (user.modRequests || []).length > 0,
    });
  }
  list.sort((a, b) => (b.online - a.online) || a.username.toLowerCase().localeCompare(b.username.toLowerCase()));
  return json(res, 200, { ok: true, accounts: list.slice(0, MAX_LIST) });
}

// Admin only: give or take away the moderator role
function setModerator(res, msg, json) {
  const auth = userFromToken(msg.token);
  if (!auth) return json(res, 401, { error: "Please log in again." });
  if (auth.key !== ADMIN_ACCOUNT) return json(res, 403, { error: "Not allowed." });
  const key = str(msg.username).trim().toLowerCase();
  const target = db.users[key];
  if (!target) return json(res, 404, { error: "No such account." });
  if (msg.moderator === true) target.moderator = true;
  else delete target.moderator;
  delete target.modRequests;   // answered either way
  persist();
  console.log(`moderator ${msg.moderator === true ? "given to" : "removed from"} ${target.name}`);
  return json(res, 200, { ok: true });
}

// Staff: warn, temp ban, complete ban, or lift a ban
function moderate(res, msg, json) {
  const auth = userFromToken(msg.token);
  if (!auth) return json(res, 401, { error: "Please log in again." });
  if (!isStaff(auth.key)) return json(res, 403, { error: "Not allowed." });
  const key = str(msg.username).trim().toLowerCase();
  const target = db.users[key];
  if (!target) return json(res, 404, { error: "No such account." });
  if (key === auth.key) return json(res, 400, { error: "You can't do that to your own account." });
  if (isAdmin(key)) return json(res, 403, { error: "That account can't be moderated." });
  if (target.moderator === true && !isAdmin(auth.key)) return json(res, 403, { error: "Only the admin can moderate other moderators." });

  const by = db.users[auth.key].name;
  const reason = str(msg.reason).trim().slice(0, MAX_REASON);
  const now = Date.now();
  const action = str(msg.action);

  if (action === "warn") {
    if (!reason) return json(res, 400, { error: "Give a reason for the warning." });
    target.warnings = [...(target.warnings || []), { by, reason, at: now, seen: false }].slice(-MAX_WARNINGS);
  } else if (action === "unwarn") {
    if (!(target.warnings || []).length) return json(res, 409, { error: "That account has no warnings." });
    target.warnings = target.warnings.slice(0, -1);   // removes the newest one (call again for the next)
  } else if (action === "tempban") {
    const minutes = Math.floor(Number(msg.minutes));
    if (!(minutes >= 1)) return json(res, 400, { error: "Give the ban length in minutes." });
    if (minutes > MAX_TEMP_MINUTES) return json(res, 400, { error: "Temp bans are 30 days at most. Use a full ban instead." });
    if (target.ban && target.ban.until === 0) return json(res, 409, { error: "That account is already banned permanently." });
    target.ban = { scope: "multiplayer", until: now + minutes * 60000, reason, by, at: now };
  } else if (action === "ban") {
    if (!MOD_CAN_PERMBAN && !isAdmin(auth.key)) return json(res, 403, { error: "Only the admin can give full bans." });
    target.ban = { scope: "multiplayer", until: 0, reason, by, at: now };   // permanent multiplayer ban; saves and login still work
  } else if (action === "unban") {
    if (!target.ban) return json(res, 409, { error: "That account isn't banned." });
    delete target.ban;
  } else {
    return json(res, 400, { error: "Unknown action." });
  }
  persist();
  console.log(`moderation: ${by} -> ${action} -> ${target.name}${reason ? " (" + reason + ")" : ""}`);
  if (target.ban && (action === "tempban" || action === "ban")) banHook(key, banText(target.ban));   // kick them from their lobby now
  return json(res, 200, { ok: true });
}

// The game reports how many words the chat filter blocked in a message the player sent. Reaching FILTER_LIMIT words inside
// FILTER_WINDOW gives them one warning. It is stored with by: "" so the popup shows only the reason, never who gave it.
function filtered(res, msg, json) {
  const auth = userFromToken(msg.token);
  if (!auth) return json(res, 401, { error: "Please log in again." });
  const count = Math.min(Math.floor(Number(msg.count)) || 0, FILTER_MAX_REPORT);
  if (count < 1) return json(res, 400, { error: "Bad request." });
  const now = Date.now();
  const hits = (filterHits.get(auth.key) || []).filter((h) => now - h.at < FILTER_WINDOW);
  hits.push({ at: now, count });
  let warned = false;
  if (hits.reduce((sum, h) => sum + h.count, 0) >= FILTER_LIMIT) {
    auth.user.warnings = [...(auth.user.warnings || []), { by: "", reason: FILTER_WARNING, at: now, seen: false }].slice(-MAX_WARNINGS);
    filterHits.delete(auth.key);   // start counting from zero again
    warned = true;
    persist();
    console.log(`moderation: chat filter warned ${auth.user.name}`);
  } else {
    filterHits.set(auth.key, hits);
  }
  return json(res, 200, { ok: true, warned });
}

// Moderators can't promote anyone themselves: this leaves a request for the admin ("this person wants to make this person a moderator")
function requestModerator(res, msg, json) {
  const auth = userFromToken(msg.token);
  if (!auth) return json(res, 401, { error: "Please log in again." });
  if (!isStaff(auth.key)) return json(res, 403, { error: "Not allowed." });
  if (isAdmin(auth.key)) return json(res, 400, { error: "You can make moderators directly." });
  if (tooMany("modreq:" + auth.key, 10, 60 * 60 * 1000)) return json(res, 429, { error: "Too many requests. Try again later." });
  const key = str(msg.username).trim().toLowerCase();
  const target = db.users[key];
  if (!target) return json(res, 404, { error: "No such account." });
  if (isAdmin(key) || target.moderator === true) return json(res, 409, { error: "That player is already a moderator." });
  const by = db.users[auth.key].name;
  const requests = target.modRequests || [];
  if (requests.some((r) => r.by === by)) return json(res, 409, { error: "You already asked for this player." });
  target.modRequests = [...requests, { by, at: Date.now() }].slice(-MAX_MOD_REQUESTS);
  bump("modreq:" + auth.key, 60 * 60 * 1000);
  persist();
  console.log(`moderation: ${by} asked for ${target.name} to become a moderator`);
  return json(res, 200, { ok: true });
}

// Admin only: throw a promotion request away without promoting
function dismissRequest(res, msg, json) {
  const auth = userFromToken(msg.token);
  if (!auth) return json(res, 401, { error: "Please log in again." });
  if (!isAdmin(auth.key)) return json(res, 403, { error: "Not allowed." });
  const target = db.users[str(msg.username).trim().toLowerCase()];
  if (!target) return json(res, 404, { error: "No such account." });
  delete target.modRequests;
  persist();
  return json(res, 200, { ok: true });
}

// Polled by every game: new warnings for you (each one is returned once), and for the admin the open promotion requests
function notices(res, msg, json) {
  const auth = userFromToken(msg.token);
  if (!auth) return json(res, 401, { error: "Please log in again." });
  const fresh = (auth.user.warnings || []).filter((w) => !w.seen);
  if (fresh.length) {
    for (const w of fresh) w.seen = true;
    persist();
  }
  const out = { ok: true, warnings: fresh.map((w) => ({ by: w.by, reason: w.reason, at: w.at })) };
  if (isAdmin(auth.key)) {
    out.mod_requests = [];
    for (const user of Object.values(db.users)) {
      if (user.moderator === true || !(user.modRequests || []).length) continue;
      out.mod_requests.push({ username: user.name, by: user.modRequests.map((r) => r.by), at: Math.max(...user.modRequests.map((r) => r.at)) });
    }
    out.mod_requests.sort((a, b) => a.at - b.at);
  }
  return json(res, 200, out);
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
  try { await ensureReady(); } catch (e) {
    console.error("could not load accounts:", e.message);
    return json(res, 503, { error: "Accounts are unavailable right now. Try again in a moment." });
  }
  try {
    switch (url) {
      case "/account/register": return await register(req, res, msg, json);
      case "/account/login": return await login(req, res, msg, json);
      case "/account/delete": return await deleteAccount(req, res, msg, json);
      case "/account/load": return loadFiles(res, msg, json);
      case "/account/save": return saveFiles(res, msg, json);
      case "/account/logout": return logout(res, msg, json);
      case "/account/moderators": return listModerators(res, msg, json);
      case "/account/list": return listAccounts(res, msg, json);
      case "/account/set_moderator": return setModerator(res, msg, json);
      case "/account/moderate": return moderate(res, msg, json);
      case "/account/request_moderator": return requestModerator(res, msg, json);
      case "/account/dismiss_request": return dismissRequest(res, msg, json);
      case "/account/notices": return notices(res, msg, json);
      case "/account/filtered": return filtered(res, msg, json);
      default: return json(res, 404, { error: "Not found." });
    }
  } catch (e) {
    console.error(e);
    return json(res, 500, { error: "Server error." });
  }
}

module.exports = { handle, multiplayerGate, setBanHook };
