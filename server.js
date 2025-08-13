// server.js
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();

/**
 * CORS — must allow cookies (credentials) from your frontend origin.
 * Set FRONTEND_ORIGIN in your backend env to your app’s URL, e.g.
 * https://pub-game-frontend.onrender.com
 */
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || '*';
app.use(
  cors({
    origin: FRONTEND_ORIGIN === '*' ? true : FRONTEND_ORIGIN,
    credentials: true,
  })
);

app.use(express.json());
app.use(cookieParser());

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change';
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

/* ------------------------ helpers ------------------------ */

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '1d' });
}

/** Accept either cookie token or Authorization: Bearer <token> */
function requireAuth(req, res, next) {
  let token = null;

  // Cookie first
  if (req.cookies && req.cookies.token) token = req.cookies.token;

  // Bearer fallback
  const auth = req.headers.authorization || '';
  if (!token && auth.startsWith('Bearer ')) token = auth.slice(7);

  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

/** parse "£1.23", "1.23", "123p", 1.23 -> cents */
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

/* ------------------------ auth ------------------------ */

app.post('/api/register', async (req, res) => {
  const { email, password, pubName } = req.body || {};
  if (!email || !password || !pubName) {
    return res.status(400).json({ error: 'Missing fields' });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (email, password_hash, pub_name)
       VALUES ($1,$2,$3) RETURNING id, pub_id, pub_name`,
      [email, hash, pubName]
    );
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

  try {
    const r = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (!r.rows.length) return res.status(401).json({ error: 'Invalid credentials' });

    const u = r.rows[0];
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = signToken({ id: u.id, pub_id: u.pub_id });

    // Important: cookies must be SameSite=None; Secure for cross-site on iOS/Safari
    res.cookie('token', token, {
      httpOnly: true,
      sameSite: 'none',
      secure: true,
      maxAge: 24 * 60 * 60 * 1000,
    });

    res.json({ token }); // also return token so frontend can store as fallback
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token', { httpOnly: true, sameSite: 'none', secure: true });
  res.json({ ok: true });
});

/* ------------------------ dashboard ------------------------ */

app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    const [{ rows: pubRows }, { rows: prodRows }] = await Promise.all([
      pool.query('SELECT name, city, address, expires_on FROM pubs WHERE id=$1', [req.user.pub_id]),
      pool.query(
        'SELECT game_key, name, price_cents, active FROM pub_game_products WHERE pub_id=$1',
        [req.user.pub_id]
      ),
    ]);

    res.json({
      pub: pubRows[0] || null,
      products: prodRows || [],
      stats: { jackpot_cents: 0, players_this_week: 0, prizes_won: 0 }, // keep simple
    });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

/* ------------------------ admin ------------------------ */

app.post('/api/admin/jackpot', requireAuth, async (req, res) => {
  try {
    const { game_key, jackpot } = req.body || {};
    const cents = parsePoundsToCents(jackpot);

    await pool.query(
      `INSERT INTO game_jackpots (pub_id, game_key, jackpot_cents)
       VALUES ($1,$2,$3)
       ON CONFLICT (pub_id, game_key)
       DO UPDATE SET jackpot_cents = EXCLUDED.jackpot_cents`,
      [req.user.pub_id, game_key, cents]
    );

    res.json({ ok: true, jackpot_cents: cents });
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message || 'Server error' });
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
         SET name=EXCLUDED.name, price_cents=EXCLUDED.price_cents, active=EXCLUDED.active`,
        [req.user.pub_id, p.game_key, p.name || '', priceCents, !!p.active]
      );
    }
    res.json({ ok: true });
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message || 'Server error' });
  }
});

/* ------------------------ start ------------------------ */

app.get('/healthz', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`API listening on ${PORT}`);
});