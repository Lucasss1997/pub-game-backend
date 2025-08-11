// server.js — backend with CORS allow-list + auth + dashboard + games
// ENV on Render:
//   DATABASE_URL=postgres://...        (from Railway/Render Postgres)
//   JWT_SECRET=your_long_random_secret

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();

// ---------- CORS (allow your frontend & local dev) ----------
const ALLOWED_ORIGINS = [
  'https://pub-game-frontend.onrender.com', // your live frontend
  'http://localhost:3000',
];

app.use(
  cors({
    origin: (origin, cb) => {
      // Allow same-origin / curl / mobile apps (no origin header)
      if (!origin) return cb(null, true);
      if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      return cb(null, false);
    },
    credentials: false, // we use Authorization: Bearer (no cookies)
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);
app.options('*', cors()); // preflight

// ---------- Parsers ----------
app.use(express.json());

// ---------- Config / DB ----------
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ---------- Schema bootstrap (idempotent) ----------
async function ensureSchema() {
  // users
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id uuid PRIMARY KEY,
      email text UNIQUE NOT NULL,
      password_hash text NOT NULL,
      pub_name text,
      pub_id integer
    );
  `);

  // pubs
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pubs (
      id serial PRIMARY KEY,
      name text NOT NULL,
      city text,
      address text,
      active boolean DEFAULT true,
      created_at timestamptz DEFAULT now(),
      expires_at timestamptz,
      stripe_customer_id text
    );
  `);

  // games (generic, per your existing schema)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS games (
      name text PRIMARY KEY,
      updated_at timestamptz DEFAULT now()
    );
  `);
  await pool.query(`ALTER TABLE games ADD COLUMN IF NOT EXISTS safe_code text`);
  await pool.query(`ALTER TABLE games ADD COLUMN IF NOT EXISTS winning_box integer`);
  // If your games table now has pub_id with a DEFAULT, inserts below will use that default.
  await pool.query(`ALTER TABLE games ADD COLUMN IF NOT EXISTS pub_id integer`);

  // seed Crack the Safe (respects DEFAULT pub_id if present)
  const safe = await pool.query(`SELECT safe_code FROM games WHERE name='crack-the-safe'`);
  if (safe.rowCount === 0) {
    const code = Math.floor(100 + Math.random() * 900).toString();
    await pool.query(
      `INSERT INTO games (name, safe_code) VALUES ('crack-the-safe', $1)
       ON CONFLICT (name) DO NOTHING`,
      [code]
    );
  }

  // seed What's in the Box
  const box = await pool.query(`SELECT winning_box FROM games WHERE name='whats-in-the-box'`);
  if (box.rowCount === 0) {
    const winning = Math.floor(Math.random() * 20) + 1; // 1..20
    await pool.query(
      `INSERT INTO games (name, winning_box) VALUES ('whats-in-the-box', $1)
       ON CONFLICT (name) DO NOTHING`,
      [winning]
    );
  }
}

// ---------- Root / health / ping ----------
app.get('/', (_req, res) => {
  res.json({
    ok: true,
    service: 'pub-game-backend',
    health: '/healthz',
    ping: '/api/ping',
    login: 'POST /api/login',
    register: 'POST /api/register',
    me: 'GET /api/me',
    dashboard: 'GET /api/dashboard (auth)',
    games: {
      crack_the_safe_guess: 'POST /api/games/crack-the-safe/guess { guess }',
      whats_in_the_box_open: 'POST /api/games/whats-in-the-box/open { boxId }',
    },
  });
});

app.get('/api/ping', (_req, res) => res.json({ message: 'pong' }));

app.get('/healthz', async (_req, res) => {
  try {
    const { rows } = await pool.query('SELECT NOW() now');
    res.json({ ok: true, now: rows[0].now });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});

// ---------- Auth helper ----------
function requireAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
  if (!token) return res.status(401).json({ error: 'Missing or invalid token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ---------- Auth ----------
app.post('/api/register', async (req, res) => {
  const { email, password, pubName } = req.body || {};
  if (!email || !password || !pubName) return res.status(400).json({ error: 'Missing email, password, or pub name' });

  try {
    const password_hash = await bcrypt.hash(password, 10);
    const id = crypto.randomUUID();
    await pool.query(
      'INSERT INTO users (id, email, password_hash, pub_name) VALUES ($1,$2,$3,$4)',
      [id, email, password_hash, pubName]
    );
    res.status(201).json({ userId: id });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });

  try {
    const r = await pool.query('SELECT * FROM users WHERE email=$1 LIMIT 1', [email]);
    const user = r.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid email or password' });

    const token = jwt.sign(
      { userId: user.id, pubName: user.pub_name || null },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({ token });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ userId: req.user.userId, pubName: req.user.pubName || null });
});

// ---------- Dashboard ----------
app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    const u = await pool.query('SELECT pub_id FROM users WHERE id=$1 LIMIT 1', [req.user.userId]);
    if (!u.rowCount || !u.rows[0].pub_id) return res.json({ pubs: [] });
    const pubs = await pool.query('SELECT * FROM pubs WHERE id=$1', [u.rows[0].pub_id]);
    res.json({ pubs: pubs.rows });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- Games (public endpoints) ----------

// Crack the Safe: 3-digit code; returns higher/lower/correct; rolls to a new code on win
app.post('/api/games/crack-the-safe/guess', async (req, res) => {
  try {
    const guess = String(req.body?.guess || '').trim();
    if (!/^\d{3}$/.test(guess)) return res.status(400).json({ error: 'Guess must be 3 digits' });

    const r = await pool.query(`SELECT safe_code FROM games WHERE name='crack-the-safe' LIMIT 1`);
    if (!r.rowCount) return res.status(400).json({ error: 'Game not initialised' });
    const code = r.rows[0].safe_code;

    if (guess === code) {
      const next = Math.floor(100 + Math.random() * 900).toString();
      await pool.query(`UPDATE games SET safe_code=$1, updated_at=NOW() WHERE name='crack-the-safe'`, [next]);
      return res.json({ result: 'correct' });
    }
    res.json({ result: Number(guess) > Number(code) ? 'lower' : 'higher' });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

// What's in the Box: 1..20; returns win/miss; rolls to a new winning box on win
app.post('/api/games/whats-in-the-box/open', async (req, res) => {
  try {
    const boxId = Number(req.body?.boxId);
    if (!Number.isInteger(boxId) || boxId < 1 || boxId > 20) {
      return res.status(400).json({ error: 'boxId must be 1..20' });
    }

    const r = await pool.query(`SELECT winning_box FROM games WHERE name='whats-in-the-box' LIMIT 1`);
    if (!r.rowCount) return res.status(400).json({ error: 'Game not initialised' });
    const winning = r.rows[0].winning_box;

    if (boxId === winning) {
      const next = Math.floor(Math.random() * 20) + 1;
      await pool.query(`UPDATE games SET winning_box=$1, updated_at=NOW() WHERE name='whats-in-the-box'`, [next]);
      return res.json({ result: 'win' });
    }
    res.json({ result: 'miss' });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- 404 JSON ----------
app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

// ---------- Start ----------
app.listen(PORT, async () => {
  try {
    await ensureSchema();
  } catch (e) {
    console.error('Startup schema error (continuing to serve):', e);
  }
  console.log(`Server running on port ${PORT}`);
});