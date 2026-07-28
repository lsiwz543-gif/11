const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
app.set('trust proxy', 1); // Railway sits behind a proxy; without this req.protocol reports 'http'
app.use(cors());
app.use(express.json({ limit: '5mb' }));

// ===== File uploads (program .exe files) =====
// If a Railway Volume is attached, Railway sets RAILWAY_VOLUME_MOUNT_PATH automatically —
// we store uploads + the DB there so they survive redeploys/restarts.
// WITHOUT A VOLUME ATTACHED IN RAILWAY, THIS FALLS BACK TO EPHEMERAL STORAGE AND
// EVERY UPLOADED FILE (AND THE DB) IS WIPED ON THE NEXT DEPLOY. Attach one in
// Railway → Service → Settings → Volumes, mount path can be anything (e.g. /data).
const DATA_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH || __dirname;
if (!process.env.RAILWAY_VOLUME_MOUNT_PATH) {
  console.warn('⚠️  No Railway Volume detected (RAILWAY_VOLUME_MOUNT_PATH not set). Uploaded files and the database will be lost on the next deploy/restart until you attach one.');
}
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
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

// ===== DB (lives on the same volume-aware path as uploads) =====
const db = new Database(path.join(DATA_DIR, 'data.db'));
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
  CREATE TABLE IF NOT EXISTS banners (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    image_url TEXT NOT NULL,
    link_url TEXT,
    sort_order INTEGER DEFAULT 0,
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
  if (!auth) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(auth.replace('Bearer ', ''), JWT_SECRET);
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

// ===== Home banners (animated carousel) =====
app.get('/banners', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM banners ORDER BY sort_order ASC, created_at ASC').all();
  res.json(rows);
});

app.post('/banners', requireAuth, requireOwner, (req, res) => {
  const { image_url, link_url, sort_order } = req.body;
  if (!image_url) return res.status(400).json({ error: 'image_url required' });
  const info = db.prepare('INSERT INTO banners (image_url, link_url, sort_order) VALUES (?,?,?)')
    .run(image_url, link_url || '', sort_order || 0);
  res.json({ id: info.lastInsertRowid });
});

app.delete('/banners/:id', requireAuth, requireOwner, (req, res) => {
  db.prepare('DELETE FROM banners WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// ===== Dashboard stats (owner only) =====
app.get('/dashboard/stats', requireAuth, requireOwner, (req, res) => {
  const totalDownloads = db.prepare('SELECT COALESCE(SUM(download_count),0) as n FROM programs').get().n;
  const totalUsers = db.prepare('SELECT COUNT(*) as n FROM users').get().n;
  const totalPrograms = db.prepare('SELECT COUNT(*) as n FROM programs').get().n;
  res.json({ totalDownloads, totalUsers, totalPrograms });
});

app.get('/', (req, res) => res.send('North Launcher backend running.'));

app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
