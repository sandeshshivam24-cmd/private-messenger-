import bcrypt from 'bcryptjs';
import fs from 'fs';
import path from 'path';

export const rootDir = process.cwd();
export const dataFile = path.join(rootDir, 'data.json');

export const loadStore = () => {
  if (!fs.existsSync(dataFile)) return null;
  try {
    const raw = fs.readFileSync(dataFile, 'utf-8');
    if (!raw || !raw.trim()) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
};

export const saveStore = (store) => {
  fs.writeFileSync(dataFile, JSON.stringify(store, null, 2), 'utf-8');
};

export const seedStore = async () => {
  const now = new Date().toISOString();
  const users = [
    {
      id: 'u_admin',
      username: 'admin',
      displayName: 'Admin',
      passwordHash: await bcrypt.hash('admin123', 10),
      role: 'admin',
      enabled: true,
      online: false,
      lastSeen: null,
      sessionId: null,
      initials: 'AD',
      showLastSeen: true,
      publicKey: null
    },
    {
      id: 'u_rahul',
      username: 'rahul01',
      displayName: 'Rahul',
      passwordHash: await bcrypt.hash('pass123!', 10),
      role: 'user',
      enabled: true,
      online: false,
      lastSeen: now,
      sessionId: null,
      initials: 'RA',
      showLastSeen: true,
      publicKey: null
    },
    {
      id: 'u_aman',
      username: 'aman01',
      displayName: 'Aman',
      passwordHash: await bcrypt.hash('pass123!', 10),
      role: 'user',
      enabled: true,
      online: false,
      lastSeen: now,
      sessionId: null,
      initials: 'AM',
      showLastSeen: true,
      publicKey: null
    },
    {
      id: 'u_neha',
      username: 'neha01',
      displayName: 'Neha',
      passwordHash: await bcrypt.hash('pass123!', 10),
      role: 'user',
      enabled: true,
      online: false,
      lastSeen: now,
      sessionId: null,
      initials: 'NE',
      showLastSeen: true,
      publicKey: null
    },
    {
      id: 'u_vivek',
      username: 'vivek01',
      displayName: 'Vivek',
      passwordHash: await bcrypt.hash('pass123!', 10),
      role: 'user',
      enabled: true,
      online: false,
      lastSeen: now,
      sessionId: null,
      initials: 'VI',
      showLastSeen: true,
      publicKey: null
    },
    {
      id: 'u_kajal',
      username: 'kajal01',
      displayName: 'Kajal',
      passwordHash: await bcrypt.hash('pass123!', 10),
      role: 'user',
      enabled: true,
      online: false,
      lastSeen: now,
      sessionId: null,
      initials: 'KA',
      showLastSeen: true,
      publicKey: null
    }
  ];
  const store = { users, messages: [], nextUserId: 7, nextMessageId: 1 };
  saveStore(store);
  return store;
};

export const ensureStore = async () => {
  const existing = loadStore();
  if (existing) return existing;
  return seedStore();
};

export const safeUser = (u) => ({
  id: u.id,
  username: u.username,
  displayName: u.displayName,
  role: u.role,
  enabled: u.enabled,
  online: u.online,
  lastSeen: u.lastSeen,
  initials: u.initials,
  showLastSeen: u.showLastSeen,
  publicKey: u.publicKey || null
});

export const findUser = (store, key, value) => store.users.find((u) => u[key] === value);

export const getPairKey = (a, b) => [a, b].sort().join('__');

export const createUserId = (store) => `u_${String(store.nextUserId++).padStart(3, '0')}`;

export const createMessageId = (store) => `m_${String(store.nextMessageId++).padStart(5, '0')}`;

export const fmtLastSeen = (iso) => {
  if (!iso) return 'Never';
  const date = new Date(iso);
  return date.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
};

export const initialsFromName = (name) => {
  const parts = String(name || '')
    .trim()
    .split(/\s+/)
    .filter(Boolean);
  const a = parts[0]?.[0] || 'U';
  const b = parts[1]?.[0] || parts[0]?.[1] || 'X';
  return (a + b).toUpperCase();
};
