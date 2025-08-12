// server.js — drop‑in with Admin (products + jackpot) + auth + dashboard
// ENV needed on Render:
//   DATABASE_URL=postgres://...
//   JWT_SECRET=your_long_random_secret
// Optional:
//   PORT=10000 (Render sets this automatically)

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
app.use(cors({ origin: true, credentials: true }));

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

// --- DB ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Create tables if missing (idempotent)
async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      pub_name TEXT,
      pub_id INTEGER,               -- optional link to pubs
      created_at timestamptz DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pubs (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      city TEXT,
      address TEXT,
      active BOOLEAN DEFAULT true,
      expires_at timestamptz,
      stripe_customer_id TEXT,
      created_at timestamptz DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pub_game_products (
      id SERIAL PRIMARY KEY,
      pub_id INTEGER NOT NULL,
      game_key TEXT NOT NULL,
      name TEXT NOT NULL,
      price_cents INTEGER NOT NULL DEFAULT 0,
      active BOOLEAN NOT NULL DEFAULT true,
      sort_order INTEGER DEFAULT 0,
      created_at timestamptz DEFAULT now(),
      UNIQUE (pub_id, game_key)
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS jackpots (
      pub_id INTEGER PRIMARY KEY,
      jackpot_cents INTEGER NOT NULL DEFAULT 0,
      updated_at timestamptz DEFAULT now()
    );
  `);
}
ensureSchema().catch((e) => {
  console.error('Schema init error:', e);
  process.exit(1);
});

// Parse JSON AFTER any raw-body webhooks (we have none here)
app.use(express.json());

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
    admin: {
      products_get: 'GET /api/admin/products (auth)',
      products_post: 'POST /api/admin/products (auth)',
      jackpot_get: 'GET /api/admin/jackpot (auth)',
      jackpot_post: 'POST /api/admin/jackpot (auth)',
      debug: 'GET /api/admin/debug (auth)',
    },
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
  const parts = authHeader.split(' ');
  const token = parts.length === 2 ? parts[1] : null;
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
    console.error('Register error:', err);
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
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/me', requireAuth, async (req, res) => {
  res.json({ userId: req.user.userId, pubName: req.user.pubName || null });
});

// --- Dashboard (expects users.pub_id + pubs table) ---
app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    const uid = req.user.userId;

    const { rows: userRows } = await pool.query('SELECT pub_id FROM users WHERE id = $1 LIMIT 1', [uid]);
    if (!userRows.length || !userRows[0].pub_id) {
      return res.json({ pubs: [] });
    }

    const pubId = userRows[0].pub_id;
    const { rows: pubs } = await pool.query('SELECT * FROM pubs WHERE id = $1', [pubId]);
    res.json({ pubs });
  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ----------------------- ADMIN ROUTES -----------------------

// Utils
function poundsToCents(x) {
  const n = Number(x);
  if (!isFinite(n)) return 0;
  return Math.round(n * 100);
}
function centsToPounds(c) {
  const n = Number(c || 0);
  return Number((n / 100).toFixed(2));
}

// GET products for this pub
app.get('/api/admin/products', requireAuth, async (req, res) => {
  try {
    const { rows: ur } = await pool.query('SELECT pub_id FROM users WHERE id = $1 LIMIT 1', [req.user.userId]);
    const pubId = ur[0]?.pub_id;
    if (!pubId) return res.status(400).json({ error: 'No pub linked to this user' });

    // Ensure defaults exist
    const defaults = [
      { game_key: 'crack_safe', name: 'Crack the Safe Ticket', price_cents: 200, active: true, sort_order: 1 },
      { game_key: 'whats_in_box', name: 'What’s in the Box Ticket', price_cents: 200, active: true, sort_order: 2 },
    ];
    for (const d of defaults) {
      await pool.query(
        `INSERT INTO pub_game_products (pub_id, game_key, name, price_cents, active, sort_order)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (pub_id, game_key)
         DO NOTHING`,
        [pubId, d.game_key, d.name, d.price_cents, d.active, d.sort_order]
      );
    }

    const { rows } = await pool.query(
      `SELECT id, pub_id, game_key, name, price_cents, active, sort_order
         FROM pub_game_products
        WHERE pub_id = $1
        ORDER BY sort_order, id`,
      [pubId]
    );

    res.json({
      pubId,
      products: rows.map(r => ({
        id: r.id,
        game_key: r.game_key,
        name: r.name,
        price: centsToPounds(r.price_cents),
        active: !!r.active,
        sort_order: r.sort_order ?? 0,
      })),
    });
  } catch (e) {
    console.error('Admin products GET error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST upsert products
app.post('/api/admin/products', requireAuth, async (req, res) => {
  try {
    const { rows: ur } = await pool.query('SELECT pub_id FROM users WHERE id = $1 LIMIT 1', [req.user.userId]);
    const pubId = ur[0]?.pub_id;
    if (!pubId) return res.status(400).json({ error: 'No pub linked to this user' });

    const items = Array.isArray(req.body?.products) ? req.body.products : [];
    if (!items.length) return res.status(400).json({ error: 'No products provided' });

    for (const it of items) {
      const gameKey = String(it.game_key || '').trim();
      const name = String(it.name || '').trim() || 'Ticket';
      const priceCents = poundsToCents(it.price);
      const active = !!it.active;
      const sortOrder = Number(it.sort_order ?? 0);

      await pool.query(
        `INSERT INTO pub_game_products (pub_id, game_key, name, price_cents, active, sort_order)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (pub_id, game_key)
         DO UPDATE SET name=excluded.name, price_cents=excluded.price_cents,
                       active=excluded.active, sort_order=excluded.sort_order`,
        [pubId, gameKey, name, priceCents, active, sortOrder]
      );
    }

    res.json({ ok: true });
  } catch (e) {
    console.error('Admin products POST error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET jackpot for pub
app.get('/api/admin/jackpot', requireAuth, async (req, res) => {
  try {
    const { rows: ur } = await pool.query('SELECT pub_id FROM users WHERE id = $1 LIMIT 1', [req.user.userId]);
    const pubId = ur[0]?.pub_id;
    if (!pubId) return res.status(400).json({ error: 'No pub linked to this user' });

    const { rows } = await pool.query('SELECT jackpot_cents FROM jackpots WHERE pub_id = $1 LIMIT 1', [pubId]);
    const cents = rows[0]?.jackpot_cents || 0;
    res.json({ pubId, jackpot: centsToPounds(cents) });
  } catch (e) {
    console.error('Admin jackpot GET error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST set jackpot (pounds)
app.post('/api/admin/jackpot', requireAuth, async (req, res) => {
  try {
    const { rows: ur } = await pool.query('SELECT pub_id FROM users WHERE id = $1 LIMIT 1', [req.user.userId]);
    const pubId = ur[0]?.pub_id;
    if (!pubId) return res.status(400).json({ error: 'No pub linked to this user' });

    const cents = poundsToCents(req.body?.jackpot);
    await pool.query(
      `INSERT INTO jackpots (pub_id, jackpot_cents, updated_at)
       VALUES ($1,$2, now())
       ON CONFLICT (pub_id)
       DO UPDATE SET jackpot_cents = excluded.jackpot_cents, updated_at = now()`,
      [pubId, cents]
    );

    res.json({ ok: true, jackpot: centsToPounds(cents) });
  } catch (e) {
    console.error('Admin jackpot POST error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Debug info to help diagnose from the app
app.get('/api/admin/debug', requireAuth, async (req, res) => {
  try {
    const uid = req.user.userId;
    const u = await pool.query('SELECT id, email, pub_id FROM users WHERE id = $1', [uid]);
    const pubId = u.rows[0]?.pub_id || null;
    const prod = pubId
      ? await pool.query('SELECT count(*) FROM pub_game_products WHERE pub_id = $1', [pubId])
      : { rows: [{ count: 0 }] };
    const jack = pubId
      ? await pool.query('SELECT jackpot_cents FROM jackpots WHERE pub_id = $1', [pubId])
      : { rows: [] };
    res.json({
      user: u.rows[0] || null,
      pubId,
      products: Number(prod.rows[0].count || 0),
      jackpot_cents: jack.rows[0]?.jackpot_cents ?? null,
    });
  } catch (e) {
    console.error('Admin debug error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// --- 404 JSON fallback (keep LAST) ---
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// --- Start ---
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});