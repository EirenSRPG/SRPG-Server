// Relay server for relay_peer.gd.
//
// Text messages (JSON)
//   client -> server: {t:"host", max, code?}   open a room (code = reuse this room code if it is free)
//                     {t:"join", code}          join a room
//                     {t:"refuse", on}          host only: stop / start accepting new guests
//                     {t:"kick", id}            host only: remove a guest
//   server -> client: {t:"hosted", code}        the room exists (code may differ from the one asked for)
//                     {t:"joined", id}          you are in; id is your multiplayer peer id
//                     {t:"peer_joined", id}     host only
//                     {t:"peer_left", id}       host only
//                     {t:"error", reason}       then the socket is closed
//
// General lobby (a hangout run by this server, nobody hosts it; it exists while somebody is inside):
//   client -> server: {t:"hall", token, name}     enter the general lobby (the fullest hall with room, or a new one when all are full)
//                     {t:"hmove", x, y}           my position
//                     {t:"hemote", e}             an emote (0-7)
//                     {t:"hchat", text, account}    say something to the hall (passed on to everybody else)
//                     {t:"hleave"}                leave the hall
//   server -> client: {t:"hall_joined", id, hall, max, players:[{id,name,x,y,c}]}
//                     {t:"hall_peer", id, name, x, y, c} / {t:"hall_peer_left", id} / {t:"hm", id, x, y} / {t:"he", id, e} / {t:"hc", id, name, account, text}
//
// Binary messages are game packets: int32 LE (target when sending / sender when receiving), mode byte, channel byte, payload.
//   guest -> host only (the host's Godot relays guest-to-guest messages)
//   host  -> target > 0: that guest | 0: every guest | < 0: every guest except abs(target)

const http = require("http");
const { WebSocketServer } = require("ws");
const accounts = require("./accounts");   // username/password accounts + cloud saves (POST /account/...)

const PORT = parseInt(process.env.PORT || "8080", 10);
const CODE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";   // no I, O, 0, 1
const CODE_RE = /^[A-Z0-9]{4,6}$/;
const HEADER_SIZE = 6;
const MAX_ROOM_SIZE = 8;
const HALL_MAX = 30;              // players in one general lobby hall
const HALL_W = 640, HALL_H = 384; // the hall's size in pixels (hall.gd uses the same numbers)
const HALL_EMOTES = 8;
const PING_MS = 25000;   // keeps idle connections open behind proxies (Render closes silent ones)

const rooms = new Map();   // code -> {code, host, guests: Map(id -> ws), max, refuse, nextId}

const halls = new Map();   // number -> {number, members: Map(id -> ws), nextId}

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

function json(res, status, obj) {
  res.writeHead(status, { "Content-Type": "application/json", ...CORS });
  res.end(JSON.stringify(obj));
}

// HTTP side: health check, the server's clock, the public lobby list, and the host's public/private switch.
//   GET  /time           -> {unix}: the server's time in seconds since 1970 (UTC). Used by halloween.gd for the Halloween-only content.
//   GET  /rooms          -> [{code, name, players, max}] for rooms that are public, open and not full
//   POST /rooms/public   -> {code, token, on, name}. The first call for a room claims it with `token`
//                           (the host does this as soon as the room exists); after that only the same token can change it.
const server = http.createServer((req, res) => {
  const url = (req.url || "").split("?")[0];
  if (req.method === "OPTIONS") {
    res.writeHead(204, CORS);
    return res.end();
  }
  if (url.startsWith("/account/")) {
    return accounts.handle(req, res, url, json);
  }
  if (req.method === "GET" && url === "/time") {
    // The game asks for the date here (halloween.gd) so the Halloween-only content can't be unlocked by changing the computer's clock.
    res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store", ...CORS });
    return res.end(JSON.stringify({ unix: Date.now() / 1000 }));
  }
  if (req.method === "GET" && url === "/rooms") {
    const list = [];
    for (const room of rooms.values()) {
      if (!room.isPublic || room.refuse || room.guests.size + 1 >= room.max) continue;
      list.push({ code: room.code, name: room.hostName, players: room.guests.size + 1, max: room.max });
    }
    return json(res, 200, list);
  }
  if (req.method === "POST" && url === "/rooms/public") {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 2048) req.destroy();
    });
    req.on("end", () => {
      let msg;
      try { msg = JSON.parse(body); } catch (e) { return json(res, 400, { error: "bad json" }); }
      const code = typeof msg.code === "string" ? msg.code.trim().toUpperCase() : "";
      const token = typeof msg.token === "string" ? msg.token : "";
      const room = rooms.get(code);
      if (!room || token.length < 8 || token.length > 64) return json(res, 404, { error: "no such room" });
      if (room.token === null) room.token = token;
      else if (room.token !== token) return json(res, 403, { error: "not the host" });
      room.isPublic = !!msg.on;
      if (typeof msg.name === "string") room.hostName = msg.name.trim().slice(0, 14) || "Host";
      console.log(`room ${code} is now ${room.isPublic ? "public" : "private"}`);
      return json(res, 200, { ok: true, public: room.isPublic });
    });
    return;
  }
  res.writeHead(200, { "Content-Type": "text/plain", ...CORS });   // health check for the hosting platform
  res.end("ok");
});
const wss = new WebSocketServer({ server, maxPayload: 2 * 1024 * 1024 });

// A multiplayer ban or account ban also removes that player from the lobby they are in right now
accounts.setBanHook((key, reason) => {
  for (const ws of wss.clients) if (ws.accountKey === key) fail(ws, reason);
});

function send(ws, obj) {
  if (ws.readyState === 1) ws.send(JSON.stringify(obj));
}

function fail(ws, reason) {
  send(ws, { t: "error", reason });
  setTimeout(() => ws.close(1000, reason.slice(0, 100)), 50);   // let the error message go out first
}

function newCode() {
  for (let tries = 0; tries < 1000; tries++) {
    let code = "";
    for (let i = 0; i < 4; i++) code += CODE_CHARS[Math.floor(Math.random() * CODE_CHARS.length)];
    if (!rooms.has(code)) return code;
  }
  return null;
}

// Hosting or joining needs a logged-in account that isn't banned from multiplayer (the game sends its login token).
async function gated(ws, msg, action) {
  if (ws.room || ws.hall || ws.gating) return;
  ws.gating = true;
  let gate;
  try {
    gate = await accounts.multiplayerGate(msg.token);
  } catch (e) {
    console.log("multiplayerGate failed:", e && e.message);
    gate = { ok: false, reason: "The lobby server couldn't check your account. Try again." };
  } finally {
    ws.gating = false;   // (without this a failed check left the player waiting for ever)
  }
  if (ws.readyState !== 1) return;
  if (!gate.ok) return fail(ws, gate.reason);
  ws.accountKey = gate.key;
  action(ws, msg);
}

function hostRoom(ws, msg) {
  if (ws.room) return;
  const max = Math.min(Math.max(parseInt(msg.max, 10) || 4, 2), MAX_ROOM_SIZE);
  let code = typeof msg.code === "string" ? msg.code.trim().toUpperCase() : "";
  if (code) {
    if (!CODE_RE.test(code)) return fail(ws, "That room code isn't valid.");
    if (rooms.has(code)) return fail(ws, "That room code is already in use.");
  } else {
    code = newCode();
    if (!code) return fail(ws, "No room codes are free right now.");
  }
  const room = { code, host: ws, guests: new Map(), max, refuse: false, nextId: 2, isPublic: false, token: null, hostName: "Host" };
  rooms.set(code, room);
  ws.room = room;
  ws.role = "host";
  send(ws, { t: "hosted", code });
  console.log(`room ${code} opened (${rooms.size} rooms)`);
}

function joinRoom(ws, msg) {
  if (ws.room) return;
  const code = typeof msg.code === "string" ? msg.code.trim().toUpperCase() : "";
  const room = rooms.get(code);
  if (!room) return fail(ws, "Room not found. Check the room code.");
  if (room.refuse) return fail(ws, "The host isn't accepting new players.");
  if (room.guests.size + 1 >= room.max) return fail(ws, "That room is full.");
  const id = room.nextId++;
  room.guests.set(id, ws);
  ws.room = room;
  ws.role = "guest";
  ws.peerId = id;
  send(ws, { t: "joined", id });
  send(room.host, { t: "peer_joined", id });
}

function toRoman(n) {
  const table = [[1000, "M"], [900, "CM"], [500, "D"], [400, "CD"], [100, "C"], [90, "XC"], [50, "L"], [40, "XL"], [10, "X"], [9, "IX"], [5, "V"], [4, "IV"], [1, "I"]];
  let out = "";
  for (const [value, text] of table) while (n >= value) { out += text; n -= value; }
  return out;
}

function hallSend(hall, obj, except) {
  const text = JSON.stringify(obj);
  for (const member of hall.members.values()) if (member !== except && member.readyState === 1) member.send(text);
}

function hallInfo(ws) {
  return { id: ws.hallId, name: ws.hallName, x: Math.round(ws.hx), y: Math.round(ws.hy), c: ws.hallId % 8 };
}

// The fullest hall that has room, so people gather together; a new hall only when every hall is full. Halls vanish when empty.
function joinHall(ws, msg) {
  if (ws.room || ws.hall) return;
  let hall = null;
  for (const h of halls.values()) {
    if (h.members.size >= HALL_MAX) continue;
    if (!hall || h.members.size > hall.members.size) hall = h;
  }
  if (!hall) {
    let number = 1;
    while (halls.has(number)) number++;   // a closed hall's number is reused
    hall = { number, members: new Map(), nextId: 1 };
    halls.set(number, hall);
    console.log(`Great Hall ${toRoman(number)} opened (${halls.size} halls)`);
  }
  ws.hall = hall;
  ws.hallId = hall.nextId++;
  ws.hallName = (typeof msg.name === "string" ? msg.name.replace(/[^\x20-\x7E]/g, "").trim().slice(0, 14) : "") || "Traveller";
  ws.hx = HALL_W / 2 + (Math.random() - 0.5) * 80;
  ws.hy = HALL_H - 60 + (Math.random() - 0.5) * 20;
  ws.hLast = 0;
  const players = [...hall.members.values()].map(hallInfo);
  hall.members.set(ws.hallId, ws);
  send(ws, { t: "hall_joined", id: ws.hallId, hall: "Great Hall " + toRoman(hall.number), max: HALL_MAX, x: Math.round(ws.hx), y: Math.round(ws.hy), players });
  hallSend(hall, { t: "hall_peer", ...hallInfo(ws) }, ws);
}

function leaveHall(ws) {
  const hall = ws.hall;
  if (!hall) return;
  ws.hall = null;
  hall.members.delete(ws.hallId);
  if (hall.members.size === 0) {
    halls.delete(hall.number);
    console.log(`Great Hall ${toRoman(hall.number)} closed (${halls.size} halls)`);
  } else {
    hallSend(hall, { t: "hall_peer_left", id: ws.hallId });
  }
}

function onHallMessage(ws, msg) {
  const hall = ws.hall;
  const now = Date.now();
  if (msg.t === "hmove") {
    if (now - ws.hLast < 60) return;   // at most ~16 updates a second per player
    ws.hLast = now;
    const x = Number(msg.x), y = Number(msg.y);
    if (!Number.isFinite(x) || !Number.isFinite(y)) return;
    ws.hx = Math.min(Math.max(x, 0), HALL_W);
    ws.hy = Math.min(Math.max(y, 0), HALL_H);
    hallSend(hall, { t: "hm", id: ws.hallId, x: Math.round(ws.hx), y: Math.round(ws.hy) }, ws);
  } else if (msg.t === "hemote") {
    if (now - (ws.hEmoteAt || 0) < 800) return;
    const e = parseInt(msg.e, 10);
    if (!(e >= 0 && e < HALL_EMOTES)) return;
    ws.hEmoteAt = now;
    hallSend(hall, { t: "he", id: ws.hallId, e });
  } else if (msg.t === "hchat") {
    if (now - (ws.hChatAt || 0) < 400) return;   // slow down
    const text = typeof msg.text === "string" ? msg.text.replace(/[\x00-\x1F\x7F]/g, " ").trim().slice(0, 100) : "";
    if (!text) return;
    ws.hChatAt = now;
    const account = typeof msg.account === "string" ? msg.account.replace(/[^A-Za-z0-9_]/g, "").slice(0, 20) : "";
    hallSend(hall, { t: "hc", id: ws.hallId, name: ws.hallName, account, text }, ws);   // (the sender already shows their own line)
  } else if (msg.t === "hleave") {
    leaveHall(ws);
  }
}

function onText(ws, text) {
  let msg;
  try { msg = JSON.parse(text); } catch (e) { return; }
  if (!msg || typeof msg !== "object") return;
  switch (msg.t) {
    case "host": return gated(ws, msg, hostRoom);
    case "join": return gated(ws, msg, joinRoom);
    case "hall": return gated(ws, msg, joinHall);
    case "hmove": case "hemote": case "hchat": case "hleave":
      if (ws.hall) onHallMessage(ws, msg);
      return;
    case "refuse":
      if (ws.role === "host") ws.room.refuse = !!msg.on;
      return;
    case "kick":
      if (ws.role === "host") {
        const target = ws.room.guests.get(parseInt(msg.id, 10));
        if (target) target.close(1000, "You were removed from the lobby.");
      }
      return;
  }
}

function onBinary(ws, data) {
  const room = ws.room;
  if (!room || data.length < HEADER_SIZE) return;
  if (ws.role === "guest") {
    const out = Buffer.from(data);
    out.writeInt32LE(ws.peerId, 0);   // the host sees who sent it
    if (room.host.readyState === 1) room.host.send(out, { binary: true });
    return;
  }
  const target = data.readInt32LE(0);
  const out = Buffer.from(data);
  out.writeInt32LE(1, 0);             // guests always see the host as id 1
  if (target > 0) {
    const guest = room.guests.get(target);
    if (guest && guest.readyState === 1) guest.send(out, { binary: true });
  } else {
    for (const [id, guest] of room.guests) {
      if (target < 0 && id === -target) continue;
      if (guest.readyState === 1) guest.send(out, { binary: true });
    }
  }
}

function onClose(ws) {
  leaveHall(ws);
  const room = ws.room;
  if (!room) return;
  if (ws.role === "host") {
    rooms.delete(room.code);   // the code is free again straight away, so the host can reopen it
    for (const guest of room.guests.values()) guest.close(1000, "The host closed the lobby.");
    console.log(`room ${room.code} closed (${rooms.size} rooms)`);
  } else if (room.guests.get(ws.peerId) === ws) {
    room.guests.delete(ws.peerId);
    send(room.host, { t: "peer_left", id: ws.peerId });
  }
}

wss.on("connection", (ws) => {
  ws.alive = true;
  ws.on("pong", () => { ws.alive = true; });
  ws.on("message", (data, isBinary) => {
    if (isBinary) onBinary(ws, data);
    else onText(ws, data.toString());
  });
  ws.on("close", () => onClose(ws));
  ws.on("error", () => {});
});

// Drop connections that stopped answering (a crashed host frees its room code this way)
setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.alive) { ws.terminate(); continue; }
    ws.alive = false;
    ws.ping();
  }
}, PING_MS);

server.listen(PORT, () => console.log(`relay listening on :${PORT}`));
