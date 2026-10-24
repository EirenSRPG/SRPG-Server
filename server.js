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
const PING_MS = 25000;   // keeps idle connections open behind proxies (Render closes silent ones)

const rooms = new Map();   // code -> {code, host, guests: Map(id -> ws), max, refuse, nextId}

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

function json(res, status, obj) {
  res.writeHead(status, { "Content-Type": "application/json", ...CORS });
  res.end(JSON.stringify(obj));
}

// HTTP side: health check, the public lobby list, and the host's public/private switch.
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
  if (ws.room || ws.gating) return;
  ws.gating = true;
  const gate = await accounts.multiplayerGate(msg.token);
  ws.gating = false;
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

function onText(ws, text) {
  let msg;
  try { msg = JSON.parse(text); } catch (e) { return; }
  if (!msg || typeof msg !== "object") return;
  switch (msg.t) {
    case "host": return gated(ws, msg, hostRoom);
    case "join": return gated(ws, msg, joinRoom);
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
