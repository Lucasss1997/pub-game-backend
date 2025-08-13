// server.js
// Complete backend for Pub Game

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const cookieParser = require('cookie-parser');
const WebSocket = require('ws');
require('dotenv').config();

const app = express();

// CORS: allow your frontend origin; credentials for cookie token
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || '*';
app.use(cors({ origin: ALLOW_ORIGIN === '*' ? true : ALLOW_ORIGIN, credentials: true }));
app.use(express.json());
app.use(cookieParser());

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me';

// --- Postgres pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === 'disable' ? false : { rejectUnauthorized: false },
});

// ---------- Helpers ----------
function signToken(claims) {
  return jwt.sign(claims, JWT_SECRET, { expiresIn: '1d' });
}

function requireAuth(req, res, next) {
  const bearer = req.headers.authorization;
  const headerToken = bearer && bearer.startsWith('Bearer ') ? bearer.slice(7) : null;
  const cookieToken = req.cookies?.token;
  const token = headerToken || cookieToken;
  if (!token) return res.status(401).json({ ok: false, error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ ok: false, error: 'Invalid token' });
  }
}

function parsePoundsToCents(input) {
  if (input === null || input === undefined) return 0;
  if (typeof input === 'number' && Number.isFinite(input)) {
    return Math.round(input * 100);
  }
  let s = String(input).trim();
  s = s.replace(/[£\s,]/g, '').replace(/p$/i, '');
  if (s === '' || s === '.') return 0;
  if (!/^\d+(\.\d{0,2})?$/.test(s)) {
    const err = new Error('Invalid money format');
    err.status = 400;
    throw err;
  }
  return Math.round(parseFloat(s) * 100);
}

// ---------- Health / Index ----------
app.get('/healthz', (req, res) => res.json({ ok: true, service: 'pub-game-backend' }));
app.get('/', (req, res) => {
  res.type('application/json').send(JSON.stringify({
    ok: true,
    service: 'pub-game-backend',
    health: '/healthz',
    login: 'POST /api/login',
    register: 'POST /api/register',
    me: 'GET /api/me (auth)',
    dashboard: 'GET /api/dashboard (auth)',
    admin: {
      products_get: 'GET /api/admin/products (auth)',
      products_post: 'POST /api/admin/products (auth)',
      jackpot_get: 'GET /api/admin/jackpot (auth)',
      jackpot_post: 'POST /api/admin/jackpot (auth)',
      debug: 'GET /api/admin/debug (auth)',
    },
  }));
});

// ---------- Auth ----------
app.post('/api/register', async (req, res) => {
  const { email, password, pubId, pubName } = req.body || {};
  if (!email || !password) return res.status(400).json({ ok: false, error: 'Missing fields' });
  try {
    const hash = await bcrypt.hash(password, 10);
    // Create user; optionally link to pub
    const result = await pool.query(
      `INSERT INTO users (email, password_hash, pub_id, pub_name)
       VALUES ($1,$2,$3,$4)
       RETURNING id, email, pub_id`,
      [email, hash, pubId || null, pubName || null]
    );
    const user = result.rows[0];
    const token = signToken({ id: user.id, pub_id: user.pub_id || null, email: user.email });
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax', secure: true });
    res.json({ ok: true, token });
  } catch (e) {
    console.error('[POST /api/register]', e);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ ok: false, error: 'Missing fields' });
  try {
    const rs = await pool.query('SELECT id, email, password_hash, pub_id FROM users WHERE email=$1', [email]);
    if (!rs.rows.length) return res.status(401).json({ ok: false, error: 'Invalid credentials' });
    const user = rs.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ ok: false, error: 'Invalid credentials' });
    const token = signToken({ id: user.id, pub_id: user.pub_id || null, email: user.email });
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax', secure: true });
    res.json({ ok: true, token });
  } catch (e) {
    console.error('[POST /api/login]', e);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ ok: true, user: req.user });
});

// ---------- Dashboard (improved & safe) ----------
app.get('/api/dashboard', requireAuth, async (req, res) => {
  const pubId = req.user?.pub_id;
  if (!pubId) {
    return res.status(409).json({
      ok: false,
      code: 'NO_PUB_ID',
      error: 'Account is not linked to a pub. Ask an admin to set pub_id for this user.'
    });
  }

  try {
    const [pubRs, prodRs, statRs] = await Promise.all([
      pool.query('SELECT id, name, city, address, expires_on FROM pubs WHERE id=$1', [pubId]),
      pool.query('SELECT game_key, name, price_cents, active FROM pub_game_products WHERE pub_id=$1 ORDER BY game_key', [pubId]),
      pool.query('SELECT COALESCE(jackpot_cents,0) AS jackpot_cents, COALESCE(players_this_week,0) AS players_this_week, COALESCE(prizes_won,0) AS prizes_won FROM pub_stats WHERE pub_id=$1', [pubId]),
    ]);

    if (!pubRs.rows.length) {
      return res.status(404).json({ ok: false, code: 'PUB_NOT_FOUND', error: `No pub found with id ${pubId}` });
    }

    res.json({
      ok: true,
      pub: pubRs.rows[0],
      products: prodRs.rows || [],
      stats: statRs.rows[0] || { jackpot_cents: 0, players_this_week: 0, prizes_won: 0 },
    });
  } catch (e) {
    console.error('[GET /api/dashboard] error', e);
    res.status(500).json({ ok: false, code: 'SERVER_ERROR', error: 'Server error' });
  }
});

// ---------- Admin: products ----------
app.get('/api/admin/products', requireAuth, async (req, res) => {
  try {
    const pubId = req.user?.pub_id;
    if (!pubId) return res.status(409).json({ ok: false, error: 'NO_PUB_ID' });
    const { rows } = await pool.query(
      'SELECT game_key, name, price_cents, active FROM pub_game_products WHERE pub_id=$1 ORDER BY game_key',
      [pubId]
    );
    res.json({ ok: true, products: rows || [] });
  } catch (e) {
    console.error('[GET /api/admin/products]', e);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.post('/api/admin/products', requireAuth, async (req, res) => {
  try {
    const pubId = req.user?.pub_id;
    if (!pubId) return res.status(409).json({ ok: false, error: 'NO_PUB_ID' });

    const rows = Array.isArray(req.body?.products) ? req.body.products : [];
    for (const p of rows) {
      const priceCents = parsePoundsToCents(p?.price);
      await pool.query(
        `INSERT INTO pub_game_products(pub_id, game_key, name, price_cents, active)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (pub_id, game_key) DO UPDATE
         SET name = EXCLUDED.name, price_cents = EXCLUDED.price_cents, active = EXCLUDED.active`,
        [pubId, p.game_key, p.name || '', priceCents, !!p.active]
      );
    }
    res.json({ ok: true });
  } catch (e) {
    console.error('[POST /api/admin/products]', e);
    res.status(e.status || 500).json({ ok: false, error: e.message || 'Server error' });
  }
});

// ---------- Admin: jackpot ----------
app.get('/api/admin/jackpot', requireAuth, async (req, res) => {
  try {
    const pubId = req.user?.pub_id;
    if (!pubId) return res.status(409).json({ ok: false, error: 'NO_PUB_ID' });

    const { rows } = await pool.query(
      'SELECT COALESCE(jackpot_cents,0) AS jackpot_cents FROM pub_settings WHERE pub_id=$1',
      [pubId]
    );
    res.json({ ok: true, jackpot_cents: rows[0]?.jackpot_cents ?? 0 });
  } catch (e) {
    console.error('[GET /api/admin/jackpot]', e);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.post('/api/admin/jackpot', requireAuth, async (req, res) => {
  try {
    const pubId = req.user?.pub_id;
    if (!pubId) return res.status(409).json({ ok: false, error: 'NO_PUB_ID' });

    const cents = parsePoundsToCents(req.body?.jackpot);
    await pool.query(
      `INSERT INTO pub_settings (pub_id, jackpot_cents)
       VALUES ($1, $2)
       ON CONFLICT (pub_id) DO UPDATE SET jackpot_cents = EXCLUDED.jackpot_cents`,
      [pubId, cents]
    );
    res.json({ ok: true, jackpot_cents: cents });
  } catch (e) {
    console.error('[POST /api/admin/jackpot]', e);
    res.status(e.status || 500).json({ ok: false, error: e.message || 'Server error' });
  }
});

// ---------- Admin: debug ----------
app.get('/api/admin/debug', requireAuth, async (req, res) => {
  try {
    const pubId = req.user?.pub_id;
    const pub = await pool.query('SELECT id FROM pubs WHERE id=$1', [pubId]);
    const prods = await pool.query('SELECT COUNT(*)::int AS n FROM pub_game_products WHERE pub_id=$1', [pubId]);
    const jackpot = await pool.query('SELECT COALESCE(jackpot_cents,0) AS jackpot_cents FROM pub_settings WHERE pub_id=$1', [pubId]);
    res.json({
      ok: true,
      user: req.user,
      pubExists: !!pub.rows.length,
      products: prods.rows[0]?.n ?? 0,
      jackpot_cents: jackpot.rows[0]?.jackpot_cents ?? 0
    });
  } catch (e) {
    console.error('[GET /api/admin/debug]', e);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ---------- (Optional) Game endpoints (stubs OK) ----------
app.post('/api/games/crack_the_safe', async (req, res) => {
  // Expect { guess: "123" } and respond with result
  const { guess } = req.body || {};
  if (!/^\d{3}$/.test(String(guess || ''))) {
    return res.status(400).json({ ok: false, error: 'Guess must be three digits' });
  }
  // Demo logic: pretend correct is 459 (replace with your real store)
  const correct = process.env.SAFE_CODE || '459';
  const result = guess === correct ? 'correct' : 'incorrect';
  return res.json({ ok: true, result });
});

// ---------- Start HTTP & WebSocket ----------
const server = app.listen(PORT, () => console.log(`Pub Game backend on :${PORT}`));
const wss = new WebSocket.Server({ server });
wss.on('connection', (ws) => {
  ws.on('message', (msg) => {
    console.log('WS recv:', String(msg));
    ws.send(String(msg));
  });
});