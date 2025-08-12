// server.js — Pub Game backend (full drop-in)
// ENV: DATABASE_URL, JWT_SECRET

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

// ---------- Helpers ----------
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.split(' ')[1] || null;
  if (!token) return res.status(401).json({ error: 'Missing or invalid token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Convert pounds string/number -> integer cents
function toCents(val) {
  if (val === '' || val == null) return null;
  const s = String(val).replace(/[^0-9.]/g, '');
  if (!/^\d+(\.\d{1,2})?$/.test(s)) return null;
  return Math.round(parseFloat(s) * 100);
}
const toPounds = (cents) =>
  typeof cents === 'number' ? (cents / 100).toFixed(2) : '0.00';

async function ensureSchema() {
  // products for each pub/game
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pub_game_products (
      id SERIAL PRIMARY KEY,
      pub_id INTEGER NOT NULL,
      game_key TEXT NOT NULL,
      name TEXT NOT NULL,
      price_cents INTEGER NOT NULL DEFAULT 100,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      sort_order INTEGER NOT NULL DEFAULT 1,
      created_at timestamptz DEFAULT now(),
      UNIQUE(pub_id, game_key)
    );
  `);
  // jackpot per pub
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pub_settings (
      pub_id INTEGER PRIMARY KEY,
      jackpot_cents INTEGER
    );
  `);
  // optional: games table (only if you want to persist safe code)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS games (
      id SERIAL PRIMARY KEY,
      pub_id INTEGER,
      game_key TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'live',
      secret_code TEXT,
      created_at timestamptz DEFAULT now()
    );
  `);
}
ensureSchema().catch((e) => console.error('ensureSchema error', e));

// ---------- Root & health ----------
app.get('/', (req, res) => {
  res.json({
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
    public: {
      pricing: 'GET /api/public/pricing?game=crack_the_safe',
      meta: 'GET /api/public/game-meta?game_key=crack_safe',
    },
    games: {
      crack_guess: 'POST /api/games/crack-safe/guess',
      crack_guess_alias: 'POST /api/games/crack_the_safe/guess',
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

// ---------- Auth ----------
app.post('/api/register', async (req, res) => {
  const { email, password, pubName } = req.body || {};
  if (!email || !password || !pubName) {
    return res.status(400).json({ error: 'Missing email, password, or pub name' });
  }
  try {
    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, pub_name) VALUES ($1, $2, $3) RETURNING id',
      [email, hashed, pubName]
    );
    res.status(201).json({ userId: result.rows[0].id });
  } catch (err) {
    console.error('Register error:', err);
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1 LIMIT 1', [email]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid email or password' });

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

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ userId: req.user.userId, pubName: req.user.pubName || null });
});

// ---------- Dashboard ----------
app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    const uid = req.user.userId;
    const { rows: urows } = await pool.query('SELECT pub_id FROM users WHERE id = $1 LIMIT 1', [uid]);
    if (!urows.length || !urows[0].pub_id) return res.json({ pubs: [] });
    const pubId = urows[0].pub_id;
    const { rows: pubs } = await pool.query('SELECT * FROM pubs WHERE id = $1', [pubId]);
    res.json({ pubs });
  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Helper to get authed user's pub_id
async function getAuthedPubId(userId) {
  const { rows } = await pool.query('SELECT pub_id FROM users WHERE id = $1 LIMIT 1', [userId]);
  return rows[0]?.pub_id || null;
}

// ---------- Admin: products ----------
app.get('/api/admin/products', requireAuth, async (req, res) => {
  try {
    const pubId = await getAuthedPubId(req.user.userId);
    if (!pubId) return res.json([]);

    // Seed defaults (safe if already exist)
    const seeds = [
      { game_key: 'crack_safe', name: '£1 Standard Entry', price_cents: 100, active: true, sort_order: 1 },
      { game_key: 'whats_in_the_box', name: '£1 Standard Entry', price_cents: 100, active: true, sort_order: 2 },
    ];
    for (const s of seeds) {
      await pool.query(
        `INSERT INTO pub_game_products (pub_id, game_key, name, price_cents, active, sort_order)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (pub_id, game_key) DO NOTHING`,
        [pubId, s.game_key, s.name, s.price_cents, s.active, s.sort_order]
      );
    }

    const { rows } = await pool.query(
      `SELECT id, pub_id, game_key, name, price_cents, active, sort_order
         FROM pub_game_products
        WHERE pub_id = $1
        ORDER BY sort_order, id`,
      [pubId]
    );

    res.json(rows);
  } catch (e) {
    console.error('Admin products GET error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/products', requireAuth, async (req, res) => {
  try {
    const pubId = await getAuthedPubId(req.user.userId);
    if (!pubId) return res.status(400).json({ error: 'No pub linked to this user' });

    const { game_key, name, price_cents, active, sort_order } = req.body || {};
    if (!game_key) return res.status(400).json({ error: 'Missing game_key' });

    const cents = Math.max(0, Math.round(Number(price_cents || 0)));
    const nm = String(name || 'Ticket').slice(0, 120);
    const so = Number.isFinite(Number(sort_order)) ? Number(sort_order) : (game_key === 'crack_safe' ? 1 : 2);

    await pool.query(
      `INSERT INTO pub_game_products (pub_id, game_key, name, price_cents, active, sort_order)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT (pub_id, game_key)
       DO UPDATE SET name=EXCLUDED.name, price_cents=EXCLUDED.price_cents,
                     active=EXCLUDED.active, sort_order=EXCLUDED.sort_order`,
      [pubId, game_key, nm, cents, !!active, so]
    );

    const { rows } = await pool.query(
      `SELECT id, pub_id, game_key, name, price_cents, active, sort_order
         FROM pub_game_products
        WHERE pub_id = $1 AND game_key = $2 LIMIT 1`,
      [pubId, game_key]
    );

    res.json({ product: rows[0] || null });
  } catch (e) {
    console.error('Admin products POST error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- Admin: jackpot ----------
app.get('/api/admin/jackpot', requireAuth, async (req, res) => {
  try {
    const pubId = await getAuthedPubId(req.user.userId);
    if (!pubId) return res.json({ jackpot_cents: 0 });

    const { rows } = await pool.query('SELECT jackpot_cents FROM pub_settings WHERE pub_id = $1', [pubId]);
    res.json({ jackpot_cents: rows[0]?.jackpot_cents ?? 0 });
  } catch (e) {
    console.error('Jackpot GET error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/jackpot', requireAuth, async (req, res) => {
  try {
    const pubId = await getAuthedPubId(req.user.userId);
    if (!pubId) return res.status(400).json({ error: 'No pub linked to this user' });

    const cents = Math.max(0, Math.round(Number(req.body?.jackpot_cents || 0)));
    await pool.query(
      `INSERT INTO pub_settings (pub_id, jackpot_cents) VALUES ($1,$2)
       ON CONFLICT (pub_id) DO UPDATE SET jackpot_cents=EXCLUDED.jackpot_cents`,
      [pubId, cents]
    );
    res.json({ ok: true, jackpot_cents: cents });
  } catch (e) {
    console.error('Jackpot POST error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- Admin: debug ----------
app.get('/api/admin/debug', requireAuth, async (req, res) => {
  try {
    const pubId = await getAuthedPubId(req.user.userId);
    const pcount = pubId
      ? await pool.query('SELECT COUNT(*)::int AS c FROM pub_game_products WHERE pub_id = $1', [pubId])
      : { rows: [{ c: 0 }] };
    const j = pubId
      ? await pool.query('SELECT jackpot_cents FROM pub_settings WHERE pub_id = $1', [pubId])
      : { rows: [{ jackpot_cents: null }] };
    res.json({ pubId, products: pcount.rows[0].c, jackpot_cents: j.rows[0].jackpot_cents });
  } catch (e) {
    console.error('Admin debug error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- Public: pricing/meta ----------
app.get('/api/public/pricing', async (req, res) => {
  try {
    const game = (req.query.game || '').toString();
    if (!game) return res.status(400).json({ error: 'Missing game param' });

    // Simple default to first pub (or adapt to ?pubId=)
    const { rows: pub } = await pool.query('SELECT id FROM pubs ORDER BY id LIMIT 1');
    const pubId = pub[0]?.id;
    if (!pubId) return res.json({ price_cents: 0, jackpot_cents: 0 });

    const { rows: prows } = await pool.query(
      'SELECT price_cents FROM pub_game_products WHERE pub_id = $1 AND game_key IN ($2, $3) LIMIT 1',
      [pubId, game, game.replace(/-/g, '_')]
    );
    const { rows: jrows } = await pool.query(
      'SELECT jackpot_cents FROM pub_settings WHERE pub_id = $1',
      [pubId]
    );

    res.json({
      price_cents: prows[0]?.price_cents ?? 0,
      jackpot_cents: jrows[0]?.jackpot_cents ?? 0,
    });
  } catch (e) {
    console.error('public/pricing error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/public/game-meta', async (req, res) => {
  try {
    const key = (req.query.game_key || '').toString();
    if (!key) return res.status(400).json({ error: 'Missing game_key' });

    const { rows: pub } = await pool.query('SELECT id FROM pubs ORDER BY id LIMIT 1');
    const pubId = pub[0]?.id;
    if (!pubId) return res.json({ price_cents: 0, jackpot_cents: 0 });

    const { rows: prows } = await pool.query(
      'SELECT price_cents FROM pub_game_products WHERE pub_id = $1 AND game_key = $2 LIMIT 1',
      [pubId, key]
    );
    const { rows: jrows } = await pool.query(
      'SELECT jackpot_cents FROM pub_settings WHERE pub_id = $1',
      [pubId]
    );
    res.json({
      price_cents: prows[0]?.price_cents ?? 0,
      jackpot_cents: jrows[0]?.jackpot_cents ?? 0,
    });
  } catch (e) {
    console.error('public/game-meta error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- Game: Crack the Safe ----------
let inMemorySecretCode = '123'; // fallback if no DB record

async function getActiveSafeCode(pubId) {
  // If you want to persist per pub, read the most recent live code from games table
  try {
    const params = [];
    let where = `game_key = 'crack_safe' AND status = 'live'`;
    if (pubId) {
      params.push(pubId);
      where += ` AND pub_id = $${params.length}`;
    }
    const { rows } = await pool.query(
      `SELECT secret_code FROM games WHERE ${where} ORDER BY id DESC LIMIT 1`,
      params
    );
    const code = rows[0]?.secret_code;
    return (code && /^\d{3}$/.test(code)) ? code : null;
  } catch {
    return null;
  }
}

// POST /api/games/crack-safe/guess
app.post('/api/games/crack-safe/guess', async (req, res) => {
  try {
    const guess = (req.body?.guess || '').toString();
    if (!/^\d{3}$/.test(guess)) {
      return res.status(400).json({ error: 'Guess must be a 3-digit string' });
    }

    // Use first pub for now (or pass ?pubId= in your QR and look it up)
    const { rows: pub } = await pool.query('SELECT id FROM pubs ORDER BY id LIMIT 1');
    const pubId = pub[0]?.id || null;

    const code = (await getActiveSafeCode(pubId)) || inMemorySecretCode;
    const result = guess === code ? 'correct' : 'wrong';
    return res.json({ result });
  } catch (e) {
    console.error('crack-safe/guess error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Alias: snake_case path
app.post('/api/games/crack_the_safe/guess', (req, res, next) =>
  app._router.handle({ ...req, url: '/api/games/crack-safe/guess' }, res, next)
);

// ---------- 404 JSON fallback ----------
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});