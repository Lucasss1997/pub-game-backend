// server.js — live version with persistent game state
// Endpoints kept: /, /healthz, /api/register, /api/login, /api/me, /api/dashboard
// New game endpoints (PUBLIC for QR access):
//   POST /api/games/crack-the-safe/guess   { guess: "123" } -> { result: "higher"|"lower"|"correct" }
//   POST /api/games/crack-the-safe/reset   (optional admin later)
//   POST /api/games/whats-in-the-box/open  { boxId: 7 }      -> { result: "win"|"miss" }
//   POST /api/games/whats-in-the-box/reset (optional admin later)
//
// ENV on Render:
//   DATABASE_URL=postgres://...
//   JWT_SECRET=long_random_string

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

// --- DB (Render/Railway compatible) ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// --- Boot-time: ensure tables + seed games once ---
async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
      email text UNIQUE NOT NULL,
      password_hash text NOT NULL,
      pub_name text,
      pub_id integer
    );
  `);

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

  // Single-row config for each game
  await pool.query(`
    CREATE TABLE IF NOT EXISTS games (
      name text PRIMARY KEY,
      safe_code text,
      winning_box integer,
      updated_at timestamptz DEFAULT now()
    );
  `);

  // Seed Crack the Safe (if absent)
  const safeRow = await pool.query(`SELECT name FROM games WHERE name = 'crack-the-safe'`);
  if (safeRow.rowCount === 0) {
    const code = Math.floor(100 + Math.random() * 900).toString();
    await pool.query(
      `INSERT INTO games(name, safe_code) VALUES ($1, $2)`,
      ['crack-the-safe', code]
    );
  }

  // Seed What’s in the Box (if absent)
  const boxRow = await pool.query(`SELECT name FROM games WHERE name = 'whats-in-the-box'`);
  if (boxRow.rowCount === 0) {
    const winning = Math.floor(Math.random() * 20) + 1; // 1..20
    await pool.query(
      `INSERT INTO games(name, winning_box) VALUES ($1, $2)`,
      ['whats-in-the-box', winning]
    );
  }
}

// --- Health & Root ---
app.get('/', (req, res) => {
  res.json({
    ok: true,
    service: 'pub-game-backend',
    health: '/healthz',
    login: 'POST /api/login',
    register: 'POST /api/register',
    me: 'GET /api/me',
    dashboard: 'GET /api/dashboard (auth)',
    games: {
      crack_the_safe_guess: 'POST /api/games/crack-the-safe/guess {guess}',
      box_open: 'POST /api/games/whats-in-the-box/open {boxId}',
    }
  });
});

app.get('/healthz', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT NOW() as now');
    res.json({ ok: true, now: rows[0].now });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});

// --- Helpers ---
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing or invalid token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// --- Auth ---
app.post('/api/register', async (req, res) => {
  const { email, password, pubName } = req.body || {};
  if (!email || !password || !pubName) {
    return res.status(400).json({ error: 'Missing email, password, or pub name' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, pub_name) VALUES ($1, $2, $3) RETURNING id',
      [email, hashedPassword, pubName]
    );
    res.status(201).json({ userId: result.rows[0].id });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Missing email or password' });
  }
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1 LIMIT 1', [email]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid email or password' });

    const token = jwt.sign(
      { userId: user.id, pubName: user.pub_name || null },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ userId: req.user.userId, pubName: req.user.pubName || null });
});

// --- Dashboard (expects users.pub_id + pubs table) ---
app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    const { rows: userRows } = await pool.query('SELECT pub_id FROM users WHERE id = $1 LIMIT 1', [req.user.userId]);
    if (!userRows.length || !userRows[0].pub_id) {
      return res.json({ pubs: [] });
    }
    const pubId = userRows[0].pub_id;
    const { rows: pubs } = await pool.query('SELECT * FROM pubs WHERE id = $1', [pubId]);
    res.json({ pubs });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ========================= GAMES (PUBLIC) =========================

// Crack the Safe: guess
app.post('/api/games/crack-the-safe/guess', async (req, res) => {
  try {
    const guess = String((req.body || {}).guess || '').trim();
    if (!/^\d{3}$/.test(guess)) {
      return res.status(400).json({ error: 'Guess must be a 3-digit code' });
    }

    const row = await pool.query(`SELECT safe_code FROM games WHERE name = 'crack-the-safe' LIMIT 1`);
    if (!row.rowCount) return res.status(400).json({ error: 'Game not initialised' });
    const code = row.rows[0].safe_code;

    if (guess === code) {
      // winner -> rotate to a new code
      const newCode = Math.floor(100 + Math.random() * 900).toString();
      await pool.query(
        `UPDATE games SET safe_code = $1, updated_at = NOW() WHERE name = 'crack-the-safe'`,
        [newCode]
      );
      return res.json({ result: 'correct' });
    }

    // give a hint without revealing the code
    const hint = Number(guess) > Number(code) ? 'lower' : 'higher';
    return res.json({ result: hint });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// (Optional) reset endpoint — protect later with auth/role
app.post('/api/games/crack-the-safe/reset', async (_req, res) => {
  try {
    const newCode = Math.floor(100 + Math.random() * 900).toString();
    await pool.query(
      `INSERT INTO games(name, safe_code) VALUES('crack-the-safe', $1)
       ON CONFLICT (name) DO UPDATE SET safe_code = EXCLUDED.safe_code, updated_at = NOW()`,
      [newCode]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// What’s in the Box: open
app.post('/api/games/whats-in-the-box/open', async (req, res) => {
  try {
    const boxId = Number((req.body || {}).boxId);
    if (!Number.isInteger(boxId) || boxId < 1 || boxId > 20) {
      return res.status(400).json({ error: 'boxId must be an integer 1..20' });
    }

    const row = await pool.query(`SELECT winning_box FROM games WHERE name = 'whats-in-the-box' LIMIT 1`);
    if (!row.rowCount) return res.status(400).json({ error: 'Game not initialised' });
    const winning = row.rows[0].winning_box;

    if (boxId === winning) {
      // winner -> rotate to a new winning box
      const next = Math.floor(Math.random() * 20) + 1;
      await pool.query(
        `UPDATE games SET winning_box = $1, updated_at = NOW() WHERE name = 'whats-in-the-box'`,
        [next]
      );
      return res.json({ result: 'win' });
    }
    return res.json({ result: 'miss' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// (Optional) reset endpoint
app.post('/api/games/whats-in-the-box/reset', async (_req, res) => {
  try {
    const next = Math.floor(Math.random() * 20) + 1;
    await pool.query(
      `INSERT INTO games(name, winning_box) VALUES('whats-in-the-box', $1)
       ON CONFLICT (name) DO UPDATE SET winning_box = EXCLUDED.winning_box, updated_at = NOW()`,
      [next]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// --- 404 JSON fallback (keep LAST) ---
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// --- Start ---
app.listen(PORT, async () => {
  await ensureSchema();
  console.log(`Server running on port ${PORT}`);
});