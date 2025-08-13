// server.js
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const cookieParser = require('cookie-parser');
const WebSocket = require('ws');
require('dotenv').config();

const app = express();

// ---- CONFIG ----
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'PLEASE_SET_JWT_SECRET';
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'https://pub-game-frontend.onrender.com';

// If behind a proxy (Render), this helps secure cookies work reliably
app.set('trust proxy', 1);

// CORS must explicitly allow your frontend and send credentials
app.use(cors({
  origin: FRONTEND_ORIGIN,
  credentials: true,
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));

app.use(express.json());
app.use(cookieParser());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ---------- Helpers ----------
function setAuthCookie(res, token) {
  res.cookie('token', token, {
    httpOnly: true,
    secure: true,         // required with SameSite=None
    sameSite: 'none',     // allow cross-site (frontend <> backend)
    path: '/',
    maxAge: 1000 * 60 * 60 * 24 * 7 // 7 days
  });
}

function clearAuthCookie(res) {
  res.clearCookie('token', {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    path: '/'
  });
}

function requireAuth(req, res, next) {
  const bearer = req.headers.authorization || '';
  const token = req.cookies.token || bearer.replace(/^Bearer\s+/,'');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
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

// ---------- Health & Info ----------
app.get('/healthz', (req, res) => res.json({ ok: true }));
app.get('/', (req, res) => res.json({
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
    jackpot_post: 'POST /api/admin/jackpot (auth)'
  }
}));

// ---------- Auth ----------
app.post('/api/register', async (req, res) => {
  const { email, password, pubName } = req.body || {};
  if (!email || !password || !pubName) {
    return res.status(400).json({ error: 'Missing fields' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    // Ensure your users table has pub_id. If not, adjust accordingly.
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, pub_name) VALUES ($1,$2,$3) RETURNING id, pub_id, pub_name',
      [email, hashedPassword, pubName]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (!result.rows.length) return res.status(401).json({ error: 'Invalid credentials' });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    // Ensure pub_id exists for this user; many of your queries depend on it
    const payload = { id: user.id, pub_id: user.pub_id };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });

    setAuthCookie(res, token);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/logout', (req, res) => {
  clearAuthCookie(res);
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, async (req, res) => {
  res.json({ user: req.user });
});

// ---------- Dashboard ----------
app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    const pubId = req.user.pub_id;
    if (!pubId) return res.status(400).json({ error: 'No pub_id on user' });

    const [{ rows: pubRows }, { rows: prodRows }, { rows: statRows }] =
      await Promise.all([
        pool.query('SELECT name, city, address, expires_on FROM pubs WHERE id=$1', [pubId]),
        pool.query('SELECT game_key, name, price_cents, active FROM pub_game_products WHERE pub_id=$1', [pubId]),
        pool.query('SELECT COALESCE(jackpot_cents,0) AS jackpot_cents, players_this_week, prizes_won FROM pub_stats WHERE pub_id=$1', [pubId]),
      ]);

    res.json({
      pub: pubRows[0] || null,
      products: prodRows || [],
      stats: statRows[0] || { jackpot_cents: 0, players_this_week: 0, prizes_won: 0 },
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- Admin: Products ----------
app.get('/api/admin/products', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, game_key, name, price_cents, active FROM pub_game_products WHERE pub_id=$1 ORDER BY game_key',
      [req.user.pub_id]
    );
    res.json({ products: rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/products', requireAuth, async (req, res) => {
  try {
    const rows = Array.isArray(req.body?.products) ? req.body.products : [];
    for (const p of rows) {
      const priceCents = parsePoundsToCents(p?.price);
      await pool.query(
        `INSERT INTO pub_game_products(pub_id, game_key, name, price_cents, active)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (pub_id, game_key) DO UPDATE
         SET name = EXCLUDED.name, price_cents = EXCLUDED.price_cents, active = EXCLUDED.active`,
        [req.user.pub_id, p.game_key, p.name || '', priceCents, !!p.active]
      );
    }
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(e.status || 500).json({ error: e.message || 'Server error' });
  }
});

// ---------- Admin: Jackpot ----------
app.get('/api/admin/jackpot', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT jackpot_cents FROM pub_settings WHERE pub_id=$1',
      [req.user.pub_id]
    );
    const cents = rows[0]?.jackpot_cents ?? 0;
    res.json({ jackpot_cents: cents });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/jackpot', requireAuth, async (req, res) => {
  try {
    const cents = parsePoundsToCents(req.body?.jackpot);
    await pool.query(
      `INSERT INTO pub_settings (pub_id, jackpot_cents)
       VALUES ($1, $2)
       ON CONFLICT (pub_id) DO UPDATE SET jackpot_cents = EXCLUDED.jackpot_cents`,
      [req.user.pub_id, cents]
    );
    res.json({ ok: true, jackpot_cents: cents });
  } catch (e) {
    console.error(e);
    res.status(e.status || 500).json({ error: e.message || 'Server error' });
  }
});

// ---------- WebSocket ----------
const server = app.listen(PORT, () => console.log(`Server running on ${PORT}`));
const wss = new WebSocket.Server({ server });
wss.on('connection', (ws) => {
  ws.on('message', (msg) => {
    console.log(`WS: ${msg}`);
    ws.send(`Echo: ${msg}`);
  });
});