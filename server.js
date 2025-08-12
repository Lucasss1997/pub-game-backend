// server.js — Pub Game backend (drop‑in)
// - Health & friendly root
// - Auth: register/login/me (JWT)
// - Dashboard: fetch pub for logged-in user
// - Admin: products (ticket prices/active), jackpot, debug
//
// ENV (Render/Railway):
//   DATABASE_URL=postgres://...           (required)
//   JWT_SECRET=your_long_random_secret    (required)
//   PORT=10000 (Render sets this automatically)

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
      products_put: 'PUT /api/admin/products (auth)',
      jackpot_get: 'GET /api/admin/jackpot (auth)',
      jackpot_put: 'PUT /api/admin/jackpot (auth)',
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

async function getUserPubId(userId) {
  const { rows } = await pool.query('SELECT pub_id FROM users WHERE id = $1 LIMIT 1', [userId]);
  return rows[0]?.pub_id || null;
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

// =====================================================================
// ADMIN ROUTES — Products (ticket pricing) & Jackpot
// Tables expected:
//   pubs(id, name, ..., jackpot_cents int NULL)
//   users(id, email, password_hash, pub_id uuid/int, ...)
//   pub_game_products(id serial, pub_id, game_key text, name text,
//                     price_cents int, active bool, sort_order int,
//                     UNIQUE(pub_id, game_key))
// =====================================================================

// Ensure jackpot column exists (idempotent)
async function ensureJackpotColumn() {
  await pool.query('ALTER TABLE pubs ADD COLUMN IF NOT EXISTS jackpot_cents integer');
}

// GET /api/admin/debug — small snapshot for diagnostics
app.get('/api/admin/debug', requireAuth, async (req, res) => {
  try {
    const uid = req.user.userId;
    const { rows: u } = await pool.query('SELECT id, email, pub_id FROM users WHERE id = $1', [uid]);
    const pubId = u[0]?.pub_id || null;
    let productsCount = 0;
    let jackpot = null;

    if (pubId) {
      const { rows: pr } = await pool.query('SELECT COUNT(*)::int AS c FROM pub_game_products WHERE pub_id = $1', [pubId]);
      productsCount = pr[0]?.c || 0;
      await ensureJackpotColumn();
      const { rows: jr } = await pool.query('SELECT jackpot_cents FROM pubs WHERE id = $1', [pubId]);
      jackpot = jr[0]?.jackpot_cents ?? null;
    }

    res.json({
      user: u[0] || null,
      pubId,
      products: productsCount,
      jackpot_cents: jackpot,
    });
  } catch (e) {
    console.error('Admin debug error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET products (robust, never 500 to UI)
app.get('/api/admin/products', requireAuth, async (req, res) => {
  try {
    const pubId = await getUserPubId(req.user.userId);
    if (!pubId) return res.status(400).json({ error: 'No pub linked to this user' });

    // Seed two defaults, but don't fail if this errors
    try {
      const defaults = [
        { game_key: 'crack_safe',   name: 'Crack the Safe Ticket',    price_cents: 200, active: true, sort_order: 1 },
        { game_key: 'whats_in_box', name: 'What’s in the Box Ticket', price_cents: 200, active: true, sort_order: 2 },
      ];
      for (const d of defaults) {
        await pool.query(
          `INSERT INTO pub_game_products (pub_id, game_key, name, price_cents, active, sort_order)
           VALUES ($1,$2,$3,$4,$5,$6)
           ON CONFLICT (pub_id, game_key) DO NOTHING`,
          [pubId, d.game_key, d.name, d.price_cents, d.active, d.sort_order]
        );
      }
    } catch (seedErr) {
      console.error('Seed defaults error (non-fatal):', seedErr);
    }

    const { rows } = await pool.query(
      `SELECT id, pub_id, game_key, name,
              COALESCE(price_cents, 0) AS price_cents,
              COALESCE(active, true)   AS active,
              COALESCE(sort_order, 0)  AS sort_order
         FROM pub_game_products
        WHERE pub_id = $1
        ORDER BY sort_order, id`,
      [pubId]
    );

    const products = rows.map(r => ({
      id: r.id,
      game_key: r.game_key,
      name: r.name || 'Ticket',
      price: Number((Number(r.price_cents || 0) / 100).toFixed(2)), // cents -> pounds
      active: !!r.active,
      sort_order: Number(r.sort_order || 0),
    }));

    res.json({ pubId, products });
  } catch (e) {
    console.error('Admin products GET hard error:', e);
    // Do not block UI
    res.status(200).json({ pubId: null, products: [] });
  }
});

// PUT products (create/update one product)
// Body shape:
// { game_key: 'crack_safe', name: 'Crack...', price: 2.5, active: true, sort_order: 1 }
app.put('/api/admin/products', requireAuth, async (req, res) => {
  try {
    const pubId = await getUserPubId(req.user.userId);
    if (!pubId) return res.status(400).json({ error: 'No pub linked to this user' });

    const { game_key, name, price, active, sort_order } = req.body || {};
    if (!game_key) return res.status(400).json({ error: 'Missing game_key' });

    const price_cents = Math.round(Number(price || 0) * 100);
    const isActive = active === undefined ? true : !!active;
    const order = Number.isFinite(Number(sort_order)) ? Number(sort_order) : 0;
    const productName = name || (game_key === 'crack_safe'
      ? 'Crack the Safe Ticket'
      : game_key === 'whats_in_box'
      ? 'What’s in the Box Ticket'
      : 'Ticket');

    // Ensure unique by (pub_id, game_key)
    await pool.query(
      `INSERT INTO pub_game_products (pub_id, game_key, name, price_cents, active, sort_order)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT (pub_id, game_key)
       DO UPDATE SET name = EXCLUDED.name,
                     price_cents = EXCLUDED.price_cents,
                     active = EXCLUDED.active,
                     sort_order = EXCLUDED.sort_order`,
      [pubId, game_key, productName, price_cents, isActive, order]
    );

    // Return the refreshed list
    const { rows } = await pool.query(
      `SELECT id, pub_id, game_key, name,
              COALESCE(price_cents, 0) AS price_cents,
              COALESCE(active, true)   AS active,
              COALESCE(sort_order, 0)  AS sort_order
         FROM pub_game_products
        WHERE pub_id = $1
        ORDER BY sort_order, id`,
      [pubId]
    );

    const products = rows.map(r => ({
      id: r.id,
      game_key: r.game_key,
      name: r.name || 'Ticket',
      price: Number((Number(r.price_cents || 0) / 100).toFixed(2)),
      active: !!r.active,
      sort_order: Number(r.sort_order || 0),
    }));

    res.json({ pubId, products });
  } catch (e) {
    console.error('Admin products PUT error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET jackpot
app.get('/api/admin/jackpot', requireAuth, async (req, res) => {
  try {
    const pubId = await getUserPubId(req.user.userId);
    if (!pubId) return res.status(400).json({ error: 'No pub linked to this user' });
    await ensureJackpotColumn();
    const { rows } = await pool.query('SELECT jackpot_cents FROM pubs WHERE id = $1', [pubId]);
    const cents = rows[0]?.jackpot_cents ?? 0;
    res.json({ pubId, jackpot: Number((Number(cents) / 100).toFixed(2)) });
  } catch (e) {
    console.error('Jackpot GET error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// PUT jackpot { jackpot: number in pounds }
app.put('/api/admin/jackpot', requireAuth, async (req, res) => {
  try {
    const pubId = await getUserPubId(req.user.userId);
    if (!pubId) return res.status(400).json({ error: 'No pub linked to this user' });
    await ensureJackpotColumn();
    const pounds = Number(req.body?.jackpot || 0);
    const cents = Math.max(0, Math.round(pounds * 100));
    await pool.query('UPDATE pubs SET jackpot_cents = $1 WHERE id = $2', [cents, pubId]);
    res.json({ ok: true, pubId, jackpot: pounds });
  } catch (e) {
    console.error('Jackpot PUT error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// --- 404 JSON fallback (keep LAST) ---
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// --- Start ---
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});