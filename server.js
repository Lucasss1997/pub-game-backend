// server.js — backend with persistent game state + PUBLIC game endpoints
// Keeps: /, /healthz, /api/register, /api/login, /api/me, /api/dashboard
// Adds (PUBLIC): 
//    POST /api/games/crack-the-safe/guess   { guess: "123" } -> { result: "higher"|"lower"|"correct" }
//    POST /api/games/crack-the-safe/reset   -> { ok:true }          // (optional; lock later)
//    POST /api/games/whats-in-the-box/open  { boxId: 1..20 } -> { result: "win"|"miss" }
//    POST /api/games/whats-in-the-box/reset -> { ok:true }          // (optional; lock later)
//
// ENV on Render:
//   DATABASE_URL=postgres://...
//   JWT_SECRET=your_long_random_secret

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ---------- boot-time schema (adds columns if missing) ----------
async function ensureSchema() {
  // Users
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
      email text UNIQUE NOT NULL,
      password_hash text NOT NULL,
      pub_name text,
      pub_id integer
    );
  `);

  // Pubs
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

  // Games base table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS games (
      name text PRIMARY KEY,
      updated_at timestamptz DEFAULT now()
    );
  `);

  // Ensure columns exist (idempotent)
  await pool.query(`ALTER TABLE games ADD COLUMN IF NOT EXISTS safe_code text`);
  await pool.query(`ALTER TABLE games ADD COLUMN IF NOT EXISTS winning_box integer`);

  // Seed Crack the Safe if absent
  const safe = await pool.query(`SELECT safe_code FROM games WHERE name='crack-the-safe'`);
  if (safe.rowCount === 0) {
    const code = Math.floor(100 + Math.random() * 900).toString();
    await pool.query(
      `INSERT INTO games(name, safe_code) VALUES('crack-the-safe', $1)`,
      [code]
    );
  }

  // Seed What’s in the Box if absent
  const box = await pool.query(`SELECT winning_box FROM games WHERE name='whats-in-the-box'`);
  if (box.rowCount === 0) {
    const winning = Math.floor(Math.random() * 20) + 1; // 1..20
    await pool.query(
      `INSERT INTO games(name, winning_box) VALUES('whats-in-the-box', $1)`,
      [winning]
    );
  }
}

// ---------- health & root ----------
app.get('/', (_req, res) => {
  res.json({
    ok: true,
    service: 'pub-game-backend',
    health: '/healthz',
    login: 'POST /api/login',
    register: 'POST /api/register',
    me: 'GET /api/me',
    dashboard: 'GET /api/dashboard (auth)',
    games: {
      crack_the_safe_guess: 'POST /api/games/crack-the-safe/guess { guess }',
      whats_in_the_box_open: 'POST /api/games/whats-in-the-box/open { boxId }'
    }
  });
});

app.get('/healthz', async (_req, res) => {
  try {
    const { rows } = await pool.query('SELECT NOW() now');
    res.json({ ok: true, now: rows[0].now });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});

// ---------- helpers ----------
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing or invalid token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ---------- auth ----------
app.post('/api/register', async (req, res) => {
  const { email, password, pubName } = req.body || {};
  if (!email || !password || !pubName) return res.status(400).json({ error: 'Missing email, password, or pub name' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query(
      'INSERT INTO users (email, password_hash, pub_name) VALUES ($1,$2,$3) RETURNING id',
      [email, hash, pubName]
    );
    res.status(201).json({ userId: r.rows[0].id });
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

    const token = jwt.sign({ userId: user.id, pubName: user.pub_name || null }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token });
  } catch (e) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ userId: req.user.userId, pubName: req.user.pubName || null });
});

// ---------- dashboard ----------
app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    const u = await pool.query('SELECT pub_id FROM users WHERE id=$1 LIMIT 1', [req.user.userId]);
    if (!u.rowCount || !u.rows[0].pub_id) return res.json({ pubs: [] });
    const pubId = u.rows[0].pub_id;
    const pubs = await pool.query('SELECT * FROM pubs WHERE id=$1', [pubId]);
    res.json({ pubs: pubs.rows });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ====================== GAMES (PUBLIC) ======================

// Crack the Safe: guess -> higher/lower/correct (persistent code)
app.post('/api/games/crack-the-safe/guess', async (req, res) => {
  try {
    const guess = String((req.body || {}).guess || '').trim();
    if (!/^\d{3}$/.test(guess)) return res.status(400).json({ error: 'Guess must be a 3-digit code' });

    const r = await pool.query(`SELECT safe_code FROM games WHERE name='crack-the-safe' LIMIT 1`);
    if (!r.rowCount) return res.status(400).json({ error: 'Game not initialised' });
    const code = r.rows[0].safe_code;

    if (guess === code) {
      const next = Math.floor(100 + Math.random() * 900).toString();
      await pool.query(`UPDATE games SET safe_code=$1, updated_at=NOW() WHERE name='crack-the-safe'`, [next]);
      return res.json({ result: 'correct' });
    }
    const hint = Number(guess) > Number(code) ? 'lower' : 'higher';
    res.json({ result: hint });
  } catch (e) {
    console.error('safe guess error', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Optional reset (lock later with auth/role)
app.post('/api/games/crack-the-safe/reset', async (_req, res) => {
  try {
    const next = Math.floor(100 + Math.random() * 900).toString();
    await pool.query(
      `INSERT INTO games(name, safe_code) VALUES('crack-the-safe',$1)
       ON CONFLICT (name) DO UPDATE SET safe_code=EXCLUDED.safe_code, updated_at=NOW()`,
      [next]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// What's in the Box: open -> win/miss (persistent winning box)
app.post('/api/games/whats-in-the-box/open', async (req, res) => {
  try {
    const boxId = Number((req.body || {}).boxId);
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
  } catch (e) {
    console.error('box open error', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Optional reset (lock later with auth/role)
app.post('/api/games/whats-in-the-box/reset', async (_req, res) => {
  try {
    const next = Math.floor(Math.random() * 20) + 1;
    await pool.query(
      `INSERT INTO games(name, winning_box) VALUES('whats-in-the-box',$1)
       ON CONFLICT (name) DO UPDATE SET winning_box=EXCLUDED.winning_box, updated_at=NOW()`,
      [next]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- 404 fallback ----------
app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

// ---------- start ----------
app.listen(PORT, async () => {
  await ensureSchema();
  console.log(`Server running on port ${PORT}`);
});