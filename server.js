const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json({ limit: '5mb' }));


// will be lost on every redeploy — same as the SQLite db file.
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
app.use('/uploads', express.static(UPLOAD_DIR));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const safe = Date.now() + '-' + file.originalname.replace(/[^a-z0-9.\-_]/gi, '_');
    cb(null, safe);
  }
});
const upload = multer({ storage, limits: { fileSize: 2 * 1024 * 1024 * 1024 } }); // 2GB cap

// ===== ENV VARS (set these in Railway — never hardcode) =====
const {
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI,
  JWT_SECRET,
  OWNER_DISCORD_ID,
  PORT = 3000
} = process.env;

// ===== DB (attach a Railway volume so this persists across deploys) =====
const db = new Database('data.db');
db.exec(`
  CREATE TABLE IF NOT EXISTS programs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    version TEXT,
    cover_url TEXT,
    video_url TEXT,
    download_url TEXT NOT NULL,
    download_count INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS users (
    discord_id TEXT PRIMARY KEY,
    username TEXT,
    avatar TEXT,
    first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
    last_seen TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS support_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_discord_id TEXT NOT NULL,
    username TEXT,
    avatar TEXT,
    status TEXT DEFAULT 'open',
    claimed_by TEXT,
    owner_seen_at TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS support_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    sender TEXT NOT NULL,
    sender_name TEXT,
    message TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

// ===== Discord OAuth =====
app.get('/auth/discord', (req, res) => {
  const url = `https://discord.com/api/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT_URI)}&response_type=code&scope=identify`;
  res.redirect(url);
});

app.get('/auth/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).send('Missing code');

  try {
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: DISCORD_REDIRECT_URI
      })
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) return res.status(400).send('OAuth failed');

    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const user = await userRes.json();

    const avatarUrl = user.avatar
      ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=256`
      : `https://cdn.discordapp.com/embed/avatars/${Number(user.discriminator || 0) % 5}.png`;

    db.prepare(`
      INSERT INTO users (discord_id, username, avatar, last_seen) VALUES (?, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(discord_id) DO UPDATE SET username=excluded.username, avatar=excluded.avatar, last_seen=CURRENT_TIMESTAMP
    `).run(user.id, user.username, avatarUrl);

    const appToken = jwt.sign(
      { id: user.id, username: user.username, avatar: avatarUrl, isOwner: user.id === OWNER_DISCORD_ID },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.redirect(`northlauncher://auth?token=${appToken}`);
  } catch (err) {
    console.error(err);
    res.status(500).send('Auth error');
  }
});

// ===== Auth middleware =====
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  const raw = auth ? auth.replace('Bearer ', '') : req.query.token;
  if (!raw) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(raw, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}
function requireOwner(req, res, next) {
  if (!req.user?.isOwner) return res.status(403).json({ error: 'Owner only' });
  next();
}

app.get('/me', requireAuth, (req, res) => res.json(req.user));

// ===== Programs API =====
app.post('/programs/upload', requireAuth, requireOwner, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file received' });
  const publicUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
  res.json({ url: publicUrl, filename: req.file.originalname });
});

app.get('/programs', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM programs ORDER BY created_at DESC').all();
  res.json(rows);
});

app.post('/programs', requireAuth, requireOwner, (req, res) => {
  const { title, description, version, cover_url, video_url, download_url } = req.body;
  if (!title || !download_url) return res.status(400).json({ error: 'title and download_url required' });
  const stmt = db.prepare(`INSERT INTO programs (title, description, version, cover_url, video_url, download_url) VALUES (?,?,?,?,?,?)`);
  const info = stmt.run(title, description, version, cover_url, video_url, download_url);
  res.json({ id: info.lastInsertRowid });
});

app.put('/programs/:id', requireAuth, requireOwner, (req, res) => {
  const { title, description, version, cover_url, video_url, download_url } = req.body;
  db.prepare(`UPDATE programs SET title=?, description=?, version=?, cover_url=?, video_url=?, download_url=? WHERE id=?`)
    .run(title, description, version, cover_url, video_url, download_url, req.params.id);
  res.json({ ok: true });
});

app.delete('/programs/:id', requireAuth, requireOwner, (req, res) => {
  db.prepare('DELETE FROM programs WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// Called by the launcher right before it starts downloading a program's exe
app.post('/programs/:id/download', requireAuth, (req, res) => {
  db.prepare('UPDATE programs SET download_count = download_count + 1 WHERE id=?').run(req.params.id);
  const row = db.prepare('SELECT download_url, download_count FROM programs WHERE id=?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not found' });
  res.json(row);
});

// ===== Support chat: live SSE streams =====
// sessionSubscribers: sessionId -> Set<res>   (the one user in that chat, watching their own thread)
// ownerSubscribers: Set<res>                  (the owner-only dashboard, watching every thread at once)
const sessionSubscribers = new Map();
const ownerSubscribers = new Set();

function sseHeaders(res) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no'
  });
  res.write('\n');
}
function sseSend(res, event, data) {
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}
function broadcastToSession(sessionId, event, data) {
  const set = sessionSubscribers.get(Number(sessionId));
  if (set) for (const r of set) sseSend(r, event, data);
}
function broadcastToOwners(event, data) {
  for (const r of ownerSubscribers) sseSend(r, event, data);
}
// Keeps SSE connections alive through proxies (Railway included) that would
// otherwise time out an idle HTTP connection after ~30-60s of silence.
setInterval(() => {
  for (const set of sessionSubscribers.values()) for (const r of set) r.write(': ping\n\n');
  for (const r of ownerSubscribers) r.write(': ping\n\n');
}, 25000);

// ===== User side: start/resume a support session =====
app.post('/support/session', requireAuth, (req, res) => {
  let session = db.prepare(`
    SELECT * FROM support_sessions WHERE user_discord_id=? AND status != 'closed' ORDER BY created_at DESC LIMIT 1
  `).get(req.user.id);

  let isNew = false;
  if (!session) {
    const info = db.prepare(`INSERT INTO support_sessions (user_discord_id, username, avatar) VALUES (?,?,?)`)
      .run(req.user.id, req.user.username, req.user.avatar);
    session = db.prepare('SELECT * FROM support_sessions WHERE id=?').get(info.lastInsertRowid);
    isNew = true;

    // Automatic first reply so the person isn't staring at an empty chat —
    // fires once, right when the session is created.
    const autoMsg = db.prepare(`
      INSERT INTO support_messages (session_id, sender, sender_name, message) VALUES (?, 'owner', 'Support', ?)
    `).run(session.id, "Thanks for reaching out — the team will respond to you shortly.");
    session = db.prepare('SELECT * FROM support_sessions WHERE id=?').get(session.id);
    broadcastToOwners('new-session', session);
  }

  const messages = db.prepare('SELECT * FROM support_messages WHERE session_id=? ORDER BY created_at ASC').all(session.id);
  res.json({ session, messages, isNew });
});

// ===== Send a message — works for the session's own user, or the owner replying =====
app.post('/support/message', requireAuth, (req, res) => {
  const { sessionId, message } = req.body;
  if (!sessionId || !message || !message.trim()) return res.status(400).json({ error: 'sessionId and message required' });

  const session = db.prepare('SELECT * FROM support_sessions WHERE id=?').get(sessionId);
  if (!session) return res.status(404).json({ error: 'session not found' });

  const isOwner = !!req.user.isOwner;
  const isSessionUser = String(session.user_discord_id) === String(req.user.id);
  if (!isOwner && !isSessionUser) return res.status(403).json({ error: 'not your session' });

  const sender = isOwner ? 'owner' : 'user';
  const senderName = isOwner ? (req.user.username || 'North') : (req.user.username || session.username);
  const info = db.prepare(`INSERT INTO support_messages (session_id, sender, sender_name, message) VALUES (?,?,?,?)`)
    .run(sessionId, sender, senderName, message.trim());
  db.prepare(`UPDATE support_sessions SET updated_at=CURRENT_TIMESTAMP WHERE id=?`).run(sessionId);

  const fullMessage = db.prepare('SELECT * FROM support_messages WHERE id=?').get(info.lastInsertRowid);
  broadcastToSession(sessionId, 'message', fullMessage);
  broadcastToOwners('message', { ...fullMessage, session_user: session.username, session_avatar: session.avatar });
  res.json(fullMessage);
});

// ===== Live stream for a single chat thread (the user's own side) =====
app.get('/support/stream/:sessionId', requireAuth, (req, res) => {
  const sessionId = Number(req.params.sessionId);
  const session = db.prepare('SELECT * FROM support_sessions WHERE id=?').get(sessionId);
  if (!session) return res.status(404).end();
  const isOwner = !!req.user.isOwner;
  const isSessionUser = String(session.user_discord_id) === String(req.user.id);
  if (!isOwner && !isSessionUser) return res.status(403).end();

  sseHeaders(res);
  if (!sessionSubscribers.has(sessionId)) sessionSubscribers.set(sessionId, new Set());
  sessionSubscribers.get(sessionId).add(res);
  req.on('close', () => { sessionSubscribers.get(sessionId)?.delete(res); });
});

// ===== Owner dashboard: inbox, claim, live global stream =====
app.get('/support/owner/sessions', requireAuth, requireOwner, (req, res) => {
  const rows = db.prepare(`
    SELECT s.*,
      (SELECT message FROM support_messages m WHERE m.session_id = s.id ORDER BY m.created_at DESC LIMIT 1) as last_message,
      (SELECT COUNT(*) FROM support_messages m WHERE m.session_id = s.id AND m.sender='user' AND m.created_at > COALESCE(s.owner_seen_at, '1970-01-01')) as unread
    FROM support_sessions s
    ORDER BY s.updated_at DESC
  `).all();
  res.json(rows);
});

app.get('/support/owner/sessions/:id/messages', requireAuth, requireOwner, (req, res) => {
  const messages = db.prepare('SELECT * FROM support_messages WHERE session_id=? ORDER BY created_at ASC').all(req.params.id);
  db.prepare('UPDATE support_sessions SET owner_seen_at=CURRENT_TIMESTAMP WHERE id=?').run(req.params.id);
  res.json(messages);
});

app.post('/support/owner/sessions/:id/claim', requireAuth, requireOwner, (req, res) => {
  db.prepare(`UPDATE support_sessions SET status='claimed', claimed_by=? WHERE id=?`).run(req.user.username || 'North', req.params.id);
  const session = db.prepare('SELECT * FROM support_sessions WHERE id=?').get(req.params.id);
  broadcastToSession(req.params.id, 'claimed', session);
  broadcastToOwners('claimed', session);
  res.json(session);
});

app.post('/support/owner/sessions/:id/close', requireAuth, requireOwner, (req, res) => {
  db.prepare(`UPDATE support_sessions SET status='closed' WHERE id=?`).run(req.params.id);
  const session = db.prepare('SELECT * FROM support_sessions WHERE id=?').get(req.params.id);
  broadcastToSession(req.params.id, 'closed', session);
  broadcastToOwners('closed', session);
  res.json(session);
});

app.get('/support/owner/stream', requireAuth, requireOwner, (req, res) => {
  sseHeaders(res);
  ownerSubscribers.add(res);
  req.on('close', () => ownerSubscribers.delete(res));
});


app.get('/dashboard/stats', requireAuth, requireOwner, (req, res) => {
  const totalDownloads = db.prepare('SELECT COALESCE(SUM(download_count),0) as n FROM programs').get().n;
  const totalUsers = db.prepare('SELECT COUNT(*) as n FROM users').get().n;
  const totalPrograms = db.prepare('SELECT COUNT(*) as n FROM programs').get().n;
  res.json({ totalDownloads, totalUsers, totalPrograms });
});

app.get('/', (req, res) => res.send('North Launcher backend running.'));

app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
