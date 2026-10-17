// Relay server for relay_peer.gd.
// Star layout: the host is peer id 1, guests get ids 2, 3, ...
// Guests only talk to the host; the host can send to any guest.
//
// Packet format (binary, little-endian), 6-byte header then the payload:
//   int32 peer id (target when a client sends, sender when a client receives)
//   byte  transfer mode
//   byte  channel
// Text messages are JSON control messages (host, join, refuse, kick / hosted, joined, peer_joined, peer_left, error).

const http = require('http');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8080;   // Render (and most hosts) tell us which port to use
const HEADER_SIZE = 6;
const CODE_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ';   // no I or O, so codes are easy to read out loud
const CODE_LENGTH = 4;

const rooms = new Map();   // code -> { host, guests: Map(id -> ws), max, refuse, nextId }

// Plain web page so hosting sites can check the server is alive
const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('Relay server is running.\n');
});

const wss = new WebSocketServer({ server, maxPayload: 1 << 20 });

function sendJson(ws, obj) {
  if (ws && ws.readyState === 1) ws.send(JSON.stringify(obj));
}

function makeFrame(from, mode, channel, payload) {
  const buf = Buffer.alloc(HEADER_SIZE + payload.length);
  buf.writeInt32LE(from, 0);
  buf[4] = mode;
  buf[5] = channel;
  payload.copy(buf, HEADER_SIZE);
  return buf;
}

function makeCode() {
  let code;
  do {
    code = '';
    for (let i = 0; i < CODE_LENGTH; i++) {
      code += CODE_CHARS[Math.floor(Math.random() * CODE_CHARS.length)];
    }
  } while (rooms.has(code));
  return code;
}

function sendBinary(ws, buf) {
  if (ws && ws.readyState === 1) ws.send(buf, { binary: true });
}

wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.role = null;     // 'host' or 'guest'
  ws.room = null;
  ws.peerId = 0;

  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (data, isBinary) => {
    if (isBinary) {
      handleData(ws, Buffer.from(data));
    } else {
      handleControl(ws, data.toString());
    }
  });

  ws.on('close', () => handleClose(ws));
  ws.on('error', () => {});
});

function handleControl(ws, text) {
  let msg;
  try { msg = JSON.parse(text); } catch (e) { return; }
  if (!msg || typeof msg !== 'object') return;

  switch (msg.t) {
    case 'host': {
      if (ws.role) return;
      const code = makeCode();
      const max = Math.min(Math.max(parseInt(msg.max) || 4, 2), 16);
      const room = { code, host: ws, guests: new Map(), max, refuse: false, nextId: 2 };
      rooms.set(code, room);
      ws.role = 'host';
      ws.room = room;
      ws.peerId = 1;
      sendJson(ws, { t: 'hosted', code });
      console.log(`Room ${code} created (max ${max})`);
      break;
    }
    case 'join': {
      if (ws.role) return;
      const code = String(msg.code || '').trim().toUpperCase();
      const room = rooms.get(code);
      if (!room) {
        sendJson(ws, { t: 'error', reason: "That room code doesn't exist. Check it with the host." });
        ws.close();
        return;
      }
      if (room.refuse) {
        sendJson(ws, { t: 'error', reason: "The host isn't accepting new players right now." });
        ws.close();
        return;
      }
      if (room.guests.size + 1 >= room.max) {
        sendJson(ws, { t: 'error', reason: 'That lobby is full.' });
        ws.close();
        return;
      }
      const id = room.nextId++;
      ws.role = 'guest';
      ws.room = room;
      ws.peerId = id;
      room.guests.set(id, ws);
      sendJson(ws, { t: 'joined', id });
      sendJson(room.host, { t: 'peer_joined', id });
      console.log(`Room ${room.code}: guest ${id} joined`);
      break;
    }
    case 'refuse': {
      if (ws.role === 'host') ws.room.refuse = !!msg.on;
      break;
    }
    case 'kick': {
      if (ws.role !== 'host') return;
      const guest = ws.room.guests.get(parseInt(msg.id));
      if (guest) guest.close();
      break;
    }
  }
}

function handleData(ws, buf) {
  if (!ws.room || buf.length < HEADER_SIZE) return;
  const room = ws.room;
  const target = buf.readInt32LE(0);
  const mode = buf[4];
  const channel = buf[5];
  const payload = buf.subarray(HEADER_SIZE);

  if (ws.role === 'guest') {
    // Guests only ever talk to the host (the host's Godot relays guest-to-guest)
    sendBinary(room.host, makeFrame(ws.peerId, mode, channel, payload));
    return;
  }

  // Host: 0 = everyone, positive = that guest, negative = everyone except that guest
  const frame = makeFrame(1, mode, channel, payload);
  if (target > 0) {
    sendBinary(room.guests.get(target), frame);
  } else {
    for (const [id, guest] of room.guests) {
      if (target === 0 || id !== -target) sendBinary(guest, frame);
    }
  }
}

function handleClose(ws) {
  const room = ws.room;
  if (!room) return;
  if (ws.role === 'host') {
    // The lobby ends when the host leaves
    for (const guest of room.guests.values()) guest.close();
    rooms.delete(room.code);
    console.log(`Room ${room.code} closed`);
  } else if (ws.role === 'guest') {
    room.guests.delete(ws.peerId);
    sendJson(room.host, { t: 'peer_left', id: ws.peerId });
    console.log(`Room ${room.code}: guest ${ws.peerId} left`);
  }
}

// Ping everyone every 30 seconds: keeps connections open through proxies and drops dead ones
setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.isAlive) {
      ws.terminate();
      continue;
    }
    ws.isAlive = false;
    ws.ping();
  }
}, 30000);

server.listen(PORT, () => {
  console.log(`Relay server listening on port ${PORT}`);
});
