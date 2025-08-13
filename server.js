// server/index.js
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();

const FRONTENDS = (process.env.CORS_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);
// Allow credentials (cookies) + your Render frontend(s)
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true); // curl/postman
      if (FRONTENDS.length === 0 || FRONTENDS.includes(origin)) return cb(null, true);
      return cb(new Error('CORS blocked from ' + origin), false);
    },
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// -------- helpers --------
function requireAuth(req, _res, next) {
  const bearer = req.headers.authorization?.split(' ')[1];
  const token = bearer || req.cookies.token;
  if (!token) return _res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    _res.status(401).json({ error: 'Invalid token' });
  }
}

function parsePoundsToCents(input) {
  if (input === null || input === undefined) return 0;
  if (typeof input === 'number' && Number.isFinite(input)) return Math.round(input * 100);
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

// -------- auth --------
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

  try {
    const q = await pool.query('SELECT id, email, password_hash, pub_id FROM users WHERE email=$1', [email]);
    if (!q.rows.length) return res.status(401).json({ error: 'Invalid credentials' });

    const user = q.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, pub_id: user.pub_id }, JWT_SECRET, { expiresIn: '1d' });

    // IMPORTANT: cross‑site cookie needs SameSite=None; Secure
    res.cookie('token', token, {
      httpOnly: true,
      sameSite: 'None',
      secure: true,
      maxAge: 24 * 3600 * 1000,
    });

    res.json({ token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token', { sameSite: 'None', secure: true });
  res.json({ ok: true });
});

// quick dev helper you used
app.post('/api/dev/ensure-user', async (req, res) => {
  const { email, password, pubName = 'Demo Pub' } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

  try {
    let user = await pool.query('SELECT id FROM users WHERE email=$1', [email]);
    if (!user.rows.length) {
      const pub = await pool.query(
        'INSERT INTO pubs (name, city, address) VALUES ($1,$2,$3) RETURNING id',
        [pubName, 'City', '1 High St']
      );
      const pubId = pub.rows[0].id;
      const hash = await bcrypt.hash(password, 10);
      user = await pool.query(
        'INSERT INTO users (email, password_hash, pub_id) VALUES ($1,$2,$3) RETURNING id',
        [email, hash, pubId]
      );
      // Ensure products rows exist
      await pool.query(
        `INSERT INTO pub_game_products (pub_id, game_key, name, price_cents, active)
         VALUES ($1,'crack_safe','£1 Standard Entry',100,true)
         ON CONFLICT (pub_id, game_key) DO NOTHING`,
        [pubId]
      );
      await pool.query(
        `INSERT INTO pub_game_products (pub_id, game_key, name, price_cents, active)
         VALUES ($1,'whats_in_the_box','£1 Standard Entry',100,true)
         ON CONFLICT (pub_id, game_key) DO NOTHING`,
        [pubId]
      );
    }
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// dashboard
app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    const [{ rows: pub }, { rows: prods }] = await Promise.all([
      pool.query('SELECT name, city, address, expires_on FROM pubs WHERE id=$1', [req.user.pub_id]),
      pool.query('SELECT game_key, name, price_cents, active FROM pub_game_products WHERE pub_id=$1', [
        req.user.pub_id,
      ]),
    ]);
    res.json({ pub: pub[0] || null, products: prods || [] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// admin: save products
app.post('/api/admin/products', requireAuth, async (req, res) => {
  try {
    const list = Array.isArray(req.body?.products) ? req.body.products : [];
    for (const p of list) {
      const price = parsePoundsToCents(p?.price);
      await pool.query(
        `INSERT INTO pub_game_products (pub_id, game_key, name, price_cents, active)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (pub_id, game_key)
         DO UPDATE SET name=EXCLUDED.name, price_cents=EXCLUDED.price_cents, active=EXCLUDED.active`,
        [req.user.pub_id, p.game_key, p.name || '', price, !!p.active]
      );
    }
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(e.status || 500).json({ error: e.message || 'Server error' });
  }
});

// health
app.get('/healthz', (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log('API on', PORT));