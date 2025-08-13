const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const cookieParser = require('cookie-parser');
const WebSocket = require('ws');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ----------------- helpers -----------------
function requireAuth(req, res, next) {
  const bearer = req.headers.authorization || '';
  const token = req.cookies.token || (bearer.startsWith('Bearer ') ? bearer.slice(7) : '');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
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
    const e = new Error('Invalid money format');
    e.status = 400;
    throw e;
  }
  return Math.round(parseFloat(s) * 100);
}

// ----------------- auth -----------------
app.post('/api/register', async (req, res) => {
  const { email, password, pubName } = req.body || {};
  if (!email || !password || !pubName) return res.status(400).json({ error: 'Missing fields' });
  try {
    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (email, password_hash, pub_name)
       VALUES ($1,$2,$3) RETURNING id, pub_id, pub_name`,
      [email, hashed, pubName]
    );
    res.json(result.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
  try {
    const q = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (!q.rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const user = q.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, pub_id: user.pub_id }, JWT_SECRET, { expiresIn: '1d' });
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax', secure: true });
    res.json({ token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

// ----------------- dashboard -----------------
app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    const pubId = req.user.pub_id;

    const [{ rows: pubRows }, { rows: prodRows }, { rows: statRows }] =
      await Promise.all([
        pool.query('SELECT name, city, address, expires_on FROM pubs WHERE id=$1', [pubId]),
        pool.query('SELECT game_key, name, price_cents, active FROM pub_game_products WHERE pub_id=$1 ORDER BY game_key', [pubId]),
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

// ----------------- admin: products -----------------
app.get('/api/admin/products', requireAuth, async (req, res) => {
  try {
    const pubId = req.user.pub_id;
    const { rows } = await pool.query(
      'SELECT game_key, name, price_cents, active FROM pub_game_products WHERE pub_id=$1 ORDER BY game_key',
      [pubId]
    );
    res.json({ products: rows || [] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/products', requireAuth, async (req, res) => {
  try {
    const pubId = req.user.pub_id;
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
    console.error(e);
    res.status(e.status || 500).json({ error: e.message || 'Server error' });
  }
});

// ----------------- admin: jackpot -----------------
app.get('/api/admin/jackpot', requireAuth, async (req, res) => {
  try {
    const pubId = req.user.pub_id;
    const { rows } = await pool.query(
      'SELECT COALESCE(jackpot_cents,0) AS jackpot_cents FROM pub_settings WHERE pub_id=$1',
      [pubId]
    );
    res.json(rows[0] || { jackpot_cents: 0 });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/jackpot', requireAuth, async (req, res) => {
  try {
    const pubId = req.user.pub_id;
    const cents = parsePoundsToCents(req.body?.jackpot);
    await pool.query(
      `INSERT INTO pub_settings (pub_id, jackpot_cents)
       VALUES ($1, $2)
       ON CONFLICT (pub_id) DO UPDATE SET jackpot_cents = EXCLUDED.jackpot_cents`,
      [pubId, cents]
    );
    res.json({ ok: true, jackpot_cents: cents });
  } catch (e) {
    console.error(e);
    res.status(e.status || 500).json({ error: e.message || 'Server error' });
  }
});

// ----------------- utilities -----------------
app.get('/api/admin/debug', requireAuth, async (req, res) => {
  try {
    const pubId = req.user.pub_id;
    const [{ rows: products }, { rows: settings }] = await Promise.all([
      pool.query('SELECT * FROM pub_game_products WHERE pub_id=$1', [pubId]),
      pool.query('SELECT * FROM pub_settings WHERE pub_id=$1', [pubId]),
    ]);
    res.json({ user: req.user, pubId, products: products.length, jackpot_cents: settings[0]?.jackpot_cents ?? null });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ----------------- mailer (optional, used later) -----------------
const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: Number(process.env.SMTP_PORT || 587),
  secure: false,
  auth: process.env.SMTP_USER && process.env.SMTP_PASS ? {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  } : undefined,
});

// ----------------- websocket -----------------
const server = app.listen(PORT, () => console.log(`Server running on ${PORT}`));
const wss = new WebSocket.Server({ server });
wss.on('connection', (ws) => {
  ws.on('message', (msg) => ws.send(`Echo: ${msg}`));
});