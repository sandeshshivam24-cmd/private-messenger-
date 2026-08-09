import express from 'express';
import cors from 'cors';
import http from 'http';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import crypto from 'crypto';
import { Server } from 'socket.io';
import {
  ensureStore,
  saveStore,
  safeUser,
  findUser,
  getPairKey,
  createUserId,
  createMessageId,
  fmtLastSeen,
  initialsFromName
} from './store.js';

dotenv.config();

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || 'http://localhost:5173';

const app = express();
app.use(cors({ origin: CLIENT_ORIGIN, credentials: true }));
app.use(express.json({ limit: '20mb' }));

let store = await ensureStore();
const socketsByUserId = new Map();

const httpServer = http.createServer(app);
const io = new Server(httpServer, {
  cors: { origin: CLIENT_ORIGIN, credentials: true },
  // Default is 1MB, which is too small for base64 photo/document payloads.
  maxHttpBufferSize: 20 * 1024 * 1024
});

const signToken = (user) => jwt.sign(
  { sub: user.id, username: user.username, role: user.role, sessionId: user.sessionId },
  JWT_SECRET,
  { expiresIn: '12h' }
);

const authRequired = (req, res, next) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = store.users.find((u) => u.id === payload.sub);
    if (!user || !user.enabled) return res.status(401).json({ error: 'Invalid account' });
    if (user.sessionId !== payload.sessionId) return res.status(401).json({ error: 'Session expired' });
    req.user = user;
    req.payload = payload;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

const adminOnly = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
};

const publicUser = (u) => ({
  ...safeUser(u),
  lastSeenLabel: u.showLastSeen ? fmtLastSeen(u.lastSeen) : 'Hidden'
});

const unreadCountsFor = (userId) => {
  const counts = {};
  for (const msg of store.messages) {
    if (msg.toId === userId && !msg.seenAt) {
      counts[msg.fromId] = (counts[msg.fromId] || 0) + 1;
    }
  }
  return counts;
};

const serializeContacts = (currentUserId) => {
  const unread = unreadCountsFor(currentUserId);
  return store.users
    .filter((u) => u.id !== currentUserId)
    .map((u) => ({
      ...publicUser(u),
      unreadCount: unread[u.id] || 0
    }))
    .sort((a, b) => {
      if ((b.unreadCount || 0) !== (a.unreadCount || 0)) {
        return (b.unreadCount || 0) - (a.unreadCount || 0);
      }
      return a.displayName.localeCompare(b.displayName);
    });
};

const validateSession = (user, sessionId) => user.sessionId === sessionId && user.enabled;

const markUserOnline = (userId, socketId = null) => {
  const user = store.users.find((u) => u.id === userId);
  if (!user) return;
  user.online = true;
  user.lastSeen = new Date().toISOString();
  if (socketId) socketsByUserId.set(userId, socketId);
  saveStore(store);
};

const markUserOffline = (userId) => {
  const user = store.users.find((u) => u.id === userId);
  if (!user) return;
  user.online = false;
  user.lastSeen = new Date().toISOString();
  socketsByUserId.delete(userId);
  saveStore(store);
};

const getConversation = (a, b) => {
  const pair = getPairKey(a, b);
  const convo = store.messages
    .filter((m) => m.pairKey === pair)
    .sort((x, y) => new Date(x.createdAt) - new Date(y.createdAt));

  // Purge messages that have already been seen by the receiver.
  const kept = [];
  let changed = false;

  for (const msg of convo) {
    if (msg.toId === a && msg.seenAt) {
      changed = true;
      continue;
    }
    if (msg.toId === b && msg.seenAt) {
      changed = true;
      continue;
    }
    kept.push(msg);
  }

  if (changed) {
    store.messages = store.messages.filter((m) => {
      if (m.pairKey !== pair) return true;
      if (m.toId === a && m.seenAt) return false;
      if (m.toId === b && m.seenAt) return false;
      return true;
    });
    saveStore(store);
  }

  return kept;
};

app.get('/api/health', (_, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  const user = findUser(store, 'username', String(username || '').trim());
  if (!user || !user.enabled) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(String(password || ''), user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  user.sessionId = crypto.randomUUID();
  user.online = true;
  user.lastSeen = new Date().toISOString();
  saveStore(store);

  const token = signToken(user);

  const oldSocketId = socketsByUserId.get(user.id);
  if (oldSocketId && io.sockets.sockets.get(oldSocketId)) {
    io.to(oldSocketId).emit('force-logout', { reason: 'Logged in from another device' });
    io.sockets.sockets.get(oldSocketId).disconnect(true);
  }

  res.json({
    token,
    user: safeUser(user),
    contacts: serializeContacts(user.id)
  });
});

app.get('/api/me', authRequired, (req, res) => {
  res.json({ user: safeUser(req.user), contacts: serializeContacts(req.user.id) });
});

app.post('/api/logout', authRequired, (req, res) => {
  markUserOffline(req.user.id);
  req.user.sessionId = null;
  saveStore(store);
  res.json({ ok: true });
});

app.post('/api/keys', authRequired, (req, res) => {
  const { publicKey } = req.body || {};
  if (!publicKey || typeof publicKey !== 'object') return res.status(400).json({ error: 'publicKey (JWK object) required' });
  req.user.publicKey = publicKey;
  saveStore(store);

  // Broadcast updated public key to all online users so key derivation works instantly
  io.emit('presence:update', { userId: req.user.id, online: req.user.online, lastSeen: req.user.lastSeen, publicKey });
  store.users.forEach((u) => {
    const sid = socketsByUserId.get(u.id);
    if (sid && io.sockets.sockets.get(sid)) {
      io.to(sid).emit('contacts:list', { contacts: serializeContacts(u.id) });
    }
  });

  res.json({ ok: true });
});

app.get('/api/contacts', authRequired, (req, res) => {
  res.json({ contacts: serializeContacts(req.user.id) });
});

app.get('/api/conversations/:otherId', authRequired, (req, res) => {
  const other = store.users.find((u) => u.id === req.params.otherId);
  if (!other) return res.status(404).json({ error: 'User not found' });

  const convo = getConversation(req.user.id, other.id);
  res.json({
    other: publicUser(other),
    messages: convo.filter((m) => !m.hiddenFor?.includes(req.user.id))
  });
});

app.get('/api/admin/users', authRequired, adminOnly, (req, res) => {
  res.json({ users: store.users.map(safeUser) });
});

app.post('/api/admin/users', authRequired, adminOnly, async (req, res) => {
  const { username, password, displayName, showLastSeen = true } = req.body || {};
  const uname = String(username || '').trim();
  if (!uname || !password || !displayName) return res.status(400).json({ error: 'Missing fields' });
  if (findUser(store, 'username', uname)) return res.status(400).json({ error: 'Username already exists' });

  const newUser = {
    id: createUserId(store),
    username: uname,
    displayName: String(displayName).trim(),
    passwordHash: await bcrypt.hash(String(password), 10),
    role: 'user',
    enabled: true,
    online: false,
    lastSeen: null,
    sessionId: null,
    initials: initialsFromName(displayName),
    showLastSeen: Boolean(showLastSeen),
    publicKey: null
  };
  store.users.push(newUser);
  saveStore(store);
  res.json({ user: safeUser(newUser) });
});

app.patch('/api/admin/users/:id', authRequired, adminOnly, async (req, res) => {
  const user = store.users.find((u) => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const { displayName, password, enabled, showLastSeen } = req.body || {};
  if (displayName !== undefined) {
    user.displayName = String(displayName).trim();
    user.initials = initialsFromName(displayName);
  }
  if (password) user.passwordHash = await bcrypt.hash(String(password), 10);
  if (enabled !== undefined) user.enabled = Boolean(enabled);
  if (showLastSeen !== undefined) user.showLastSeen = Boolean(showLastSeen);

  if (!user.enabled) {
    user.sessionId = null;
    const socketId = socketsByUserId.get(user.id);
    if (socketId && io.sockets.sockets.get(socketId)) {
      io.to(socketId).emit('force-logout', { reason: 'Account disabled' });
      io.sockets.sockets.get(socketId).disconnect(true);
    }
  }

  saveStore(store);
  res.json({ user: safeUser(user) });
});

app.delete('/api/admin/users/:id', authRequired, adminOnly, (req, res) => {
  const idx = store.users.findIndex((u) => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  const user = store.users[idx];
  user.enabled = false;
  user.sessionId = null;
  const socketId = socketsByUserId.get(user.id);
  if (socketId && io.sockets.sockets.get(socketId)) {
    io.to(socketId).emit('force-logout', { reason: 'Account deleted' });
    io.sockets.sockets.get(socketId).disconnect(true);
  }
  store.users.splice(idx, 1);
  store.messages = store.messages.filter((m) => m.fromId !== req.params.id && m.toId !== req.params.id);
  saveStore(store);
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/disable', authRequired, adminOnly, (req, res) => {
  const user = store.users.find((u) => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.enabled = false;
  user.sessionId = null;
  const socketId = socketsByUserId.get(user.id);
  if (socketId && io.sockets.sockets.get(socketId)) {
    io.to(socketId).emit('force-logout', { reason: 'Account disabled' });
    io.sockets.sockets.get(socketId).disconnect(true);
  }
  saveStore(store);
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/enable', authRequired, adminOnly, (req, res) => {
  const user = store.users.find((u) => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.enabled = true;
  saveStore(store);
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/reset-password', authRequired, adminOnly, async (req, res) => {
  const user = store.users.find((u) => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const password = String(req.body?.password || '').trim();
  if (!password) return res.status(400).json({ error: 'Password required' });
  user.passwordHash = await bcrypt.hash(password, 10);
  saveStore(store);
  res.json({ ok: true });
});

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    if (!token) return next(new Error('No token'));
    const payload = jwt.verify(token, JWT_SECRET);
    const user = store.users.find((u) => u.id === payload.sub);
    if (!user || !validateSession(user, payload.sessionId)) return next(new Error('Unauthorized'));
    socket.user = user;
    socket.payload = payload;
    next();
  } catch {
    next(new Error('Unauthorized'));
  }
});

io.on('connection', (socket) => {
  const user = socket.user;
  markUserOnline(user.id, socket.id);
  io.emit('presence:update', { userId: user.id, online: true, lastSeen: user.lastSeen, publicKey: user.publicKey });

  socket.emit('contacts:list', { contacts: serializeContacts(user.id) });

  socket.on('contacts:request', () => {
    socket.emit('contacts:list', { contacts: serializeContacts(user.id) });
  });

  socket.on('message:send', (payload = {}, ack = () => {}) => {
    const toId = payload.toId;
    const other = store.users.find((u) => u.id === toId);
    if (!other) return ack({ ok: false, error: 'User not found' });

    const msg = {
      id: createMessageId(store),
      pairKey: getPairKey(user.id, toId),
      fromId: user.id,
      toId,
      type: payload.type || 'text',
      encryptedPayload: payload.encryptedPayload,
      iv: payload.iv,
      fileName: payload.fileName || null,
      mimeType: payload.mimeType || null,
      createdAt: new Date().toISOString(),
      seenAt: null,
      hiddenFor: []
    };

    store.messages.push(msg);
    saveStore(store);

    const recipientSocketId = socketsByUserId.get(toId);
    if (recipientSocketId && io.sockets.sockets.get(recipientSocketId)) {
      io.to(recipientSocketId).emit('message:deliver', msg);
      io.to(socket.id).emit('message:delivered', { messageId: msg.id, online: true });
      ack({ ok: true, delivered: true, messageId: msg.id });
    } else {
      io.to(socket.id).emit('message:delivered', { messageId: msg.id, online: false });
      ack({ ok: true, delivered: false, messageId: msg.id });
    }
  });

  socket.on('message:seen', ({ otherId, messageIds = [] } = {}) => {
    if (!otherId) return;

    for (const msg of store.messages) {
      const isMatch = msg.fromId === otherId && msg.toId === user.id;
      const isListed = Array.isArray(messageIds) && messageIds.includes(msg.id);
      if (isMatch && !msg.seenAt) {
        msg.seenAt = new Date().toISOString();
      }
      if (isMatch && isListed && !msg.seenAt) {
        msg.seenAt = new Date().toISOString();
      }
    }
    saveStore(store);

    const otherSocketId = socketsByUserId.get(otherId);
    if (otherSocketId && io.sockets.sockets.get(otherSocketId)) {
      io.to(otherSocketId).emit('message:status', {
        withUserId: user.id,
        seen: true,
        seenMessageIds: Array.isArray(messageIds) ? messageIds : []
      });
    }
  });

  socket.on('message:edit', ({ messageId, toId, encryptedPayload, iv } = {}, ack = () => {}) => {
    if (!messageId || !toId || !encryptedPayload || !iv) return ack({ ok: false, error: 'Missing fields' });

    const stored = store.messages.find((m) => m.id === messageId);
    if (stored) {
      if (stored.fromId !== user.id) return ack({ ok: false, error: 'Not your message' });
      stored.encryptedPayload = encryptedPayload;
      stored.iv = iv;
      stored.edited = true;
      saveStore(store);
    }

    const targetSocketId = socketsByUserId.get(toId);
    if (targetSocketId && io.sockets.sockets.get(targetSocketId)) {
      io.to(targetSocketId).emit('message:edited', {
        messageId,
        fromId: user.id,
        encryptedPayload,
        iv
      });
    }
    ack({ ok: true });
  });

  socket.on('message:delete', ({ messageId, toId, scope } = {}, ack = () => {}) => {
    if (!messageId) return ack({ ok: false, error: 'Missing messageId' });

    if (scope === 'everyone') {
      const stored = store.messages.find((m) => m.id === messageId);
      if (stored && stored.fromId !== user.id) return ack({ ok: false, error: 'Not your message' });
      store.messages = store.messages.filter((m) => m.id !== messageId);
      saveStore(store);

      const targetSocketId = toId && socketsByUserId.get(toId);
      if (targetSocketId && io.sockets.sockets.get(targetSocketId)) {
        io.to(targetSocketId).emit('message:deleted', { messageId, fromId: user.id, scope: 'everyone' });
      }
    } else {
      // Delete-for-me: only hide from this user; the other party keeps their copy.
      const stored = store.messages.find((m) => m.id === messageId);
      if (stored) {
        stored.hiddenFor = Array.from(new Set([...(stored.hiddenFor || []), user.id]));
        saveStore(store);
      }
    }
    ack({ ok: true });
  });

  socket.on('typing', ({ toId, isTyping }) => {
    const targetSocketId = socketsByUserId.get(toId);
    if (targetSocketId) io.to(targetSocketId).emit('typing', { fromId: user.id, isTyping: Boolean(isTyping) });
  });

  socket.on('call:initiate', ({ toId, callId }) => {
    const targetSocketId = socketsByUserId.get(toId);
    if (!targetSocketId) return socket.emit('call:rejected', { callId, reason: 'User offline' });
    io.to(targetSocketId).emit('call:incoming', {
      callId,
      fromId: user.id,
      fromName: user.displayName
    });
  });

  socket.on('call:accept', ({ callId, toId }) => {
    const targetSocketId = socketsByUserId.get(toId);
    if (targetSocketId) io.to(targetSocketId).emit('call:accepted', { callId, byId: user.id });
  });

  socket.on('call:reject', ({ callId, toId }) => {
    const targetSocketId = socketsByUserId.get(toId);
    if (targetSocketId) io.to(targetSocketId).emit('call:rejected', { callId, byId: user.id });
  });

  socket.on('call:signal', ({ toId, data }) => {
    const targetSocketId = socketsByUserId.get(toId);
    if (targetSocketId) io.to(targetSocketId).emit('call:signal', { fromId: user.id, data });
  });

  socket.on('call:end', ({ toId, callId }) => {
    const targetSocketId = socketsByUserId.get(toId);
    if (targetSocketId) io.to(targetSocketId).emit('call:ended', { callId, byId: user.id });
  });

  socket.on('logout', () => {
    markUserOffline(user.id);
    socket.disconnect(true);
  });

  socket.on('disconnect', () => {
    markUserOffline(user.id);
    io.emit('presence:update', { userId: user.id, online: false, lastSeen: user.lastSeen });
  });
});

httpServer.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
