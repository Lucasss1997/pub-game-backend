// server.js — Pub Game backend with SSE live updates
// ENV: DATABASE_URL, JWT_SECRET (required)

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

/* ---------------- SSE wiring ---------------- */
const sseClients = new Map(); // Map<pubId:number, Set<res>>
function sseAddClient(pubId, res) {
  const set = sseClients.get(pubId) || new Set();
  set.add(res);
  sseClients.set(pubId, set);
}
function sseRemoveClient(pubId, res) {
  const set = sseClients.get(pubId);
  if (!set) return;
  set.delete(res);
  if (!set.size) sseClients.delete(pubId);
}
function sseBroadcast(pubId, event, payload) {
  const set = sseClients.get(pubId);
  if (!set) return;
  const data = `event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const res of set) {
    try { res.write(data); } catch (_) {}
  }
}

/* ------------- helpers ------------- */
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

/* ------------- routes: root/health ------------- */
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
    live: 'GET /api/live/stream?pubId=<id>',
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

/* ------------- auth ------------- */
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

/* ------------- dashboard ------------- */
app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    const uid = req.user.userId;
    const { rows: userRows } = await pool.query('SELECT pub_id FROM users WHERE id = $1 LIMIT 1', [uid]);
    if (!userRows.length || !userRows[0].pub_id) return res.json({ pubs: [] });
    const pubId = userRows[0].pub_id;
    const { rows: pubs } = await pool.query('SELECT * FROM pubs WHERE id = $1', [pubId]);
    res.json({ pubs });
  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ------------- admin tables ensure ------------- */
async function ensureAdminTables() {
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
  await pool.query(`ALTER TABLE pubs ADD COLUMN IF NOT EXISTS jackpot_cents integer;`);
}
ensureAdminTables().catch((e) => console.error('ensureAdminTables', e));

/* ------------- admin: debug ------------- */
app.get('/api/admin/debug', requireAuth, async (req, res) => {
  try {
    const uid = req.user.userId;
    const { rows: u } = await pool.query('SELECT id, email, pub_id FROM users WHERE id = $1', [uid]);
    const pubId = u[0]?.pub_id || null;
    const pr = pubId
      ? await pool.query('SELECT COUNT(*)::int AS c FROM pub_game_products WHERE pub_id = $1', [pubId])
      : { rows: [{ c: 0 }] };
    const jr = pubId
      ? await pool.query('SELECT jackpot_cents FROM pubs WHERE id = $1', [pubId])
      : { rows: [{ jackpot_cents: null }] };
    res.json({ user: u[0] || null, pubId, products: pr.rows[0].c, jackpot_cents: jr.rows[0].jackpot_cents });
  } catch (e) {
    console.error('Admin debug error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ------------- admin: products ------------- */
app.get('/api/admin/products', requireAuth, async (req, res) => {
  try {
    const pubId = await getUserPubId(req.user.userId);
    if (!pubId) return res.status(400).json({ error: 'No pub linked to this user' });

    // seed defaults (non-fatal)
    try {
      const defs = [
        { game_key: 'crack_safe', name: 'Crack the Safe Ticket', price_cents: 200, active: true, sort_order: 1 },
        { game_key: 'whats_in_the_box', name: 'What’s in the Box Ticket', price_cents: 200, active: true, sort_order: 2 },
      ];
      for (const d of defs) {
        await pool.query(
          `INSERT INTO pub_game_products (pub_id, game_key, name, price_cents, active, sort_order)
           VALUES ($1,$2,$3,$4,$5,$6)
           ON CONFLICT (pub_id, game_key) DO NOTHING`,
          [pubId, d.game_key, d.name, d.price_cents, d.active, d.sort_order]
        );
      }
    } catch (e) { /* ignore */ }

    const { rows } = await pool.query(
      `SELECT id, pub_id, game_key, name,
              COALESCE(price_cents,0) AS price_cents,
              COALESCE(active,true) AS active,
              COALESCE(sort_order,0) AS sort_order
         FROM pub_game_products
        WHERE pub_id = $1
        ORDER BY sort_order, id`,
      [pubId]
    );

    res.json({ products: rows });
  } catch (e) {
    console.error('Admin products GET error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/products', requireAuth, async (req, res) => {
  try {
    const pubId = await getUserPubId(req.user.userId);
    if (!pubId) return res.status(400).json({ error: 'No pub linked to this user' });

    const { game_key, name, price_cents, active, sort_order } = req.body || {};
    if (!game_key) return res.status(400).json({ error: 'Missing game_key' });

    const cents = Math.max(0, Math.round(Number(price_cents || 0)));
    const nm = String(name || 'Ticket').slice(0, 120);
    const so = Number.isFinite(Number(sort_order)) ? Number(sort_order) : 0;

    await pool.query(
      `INSERT INTO pub_game_products (pub_id, game_key, name, price_cents, active, sort_order)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT (pub_id, game_key)
       DO UPDATE SET name=EXCLUDED.name, price_cents=EXCLUDED.price_cents,
                     active=EXCLUDED.active, sort_order=EXCLUDED.sort_order`,
      [pubId, game_key, nm, cents, !!active, so]
    );

    // broadcast live update
    sseBroadcast(pubId, 'products.updated', { game_key, name: nm, price_cents: cents, active: !!active, sort_order: so });

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

/* ------------- admin: jackpot ------------- */
app.get('/api/admin/jackpot', requireAuth, async (req, res) => {
  try {
    const pubId = await getUserPubId(req.user.userId);
    if (!pubId) return res.status(400).json({ error: 'No pub linked to this user' });
    const { rows } = await pool.query('SELECT jackpot_cents FROM pubs WHERE id = $1', [pubId]);
    res.json({ jackpot_cents: rows[0]?.jackpot_cents ?? 0 });
  } catch (e) {
    console.error('Jackpot GET error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/jackpot', requireAuth, async (req, res) => {
  try {
    const pubId = await getUserPubId(req.user.userId);
    if (!pubId) return res.status(400).json({ error: 'No pub linked to this user' });

    const cents = Math.max(0, Math.round(Number(req.body?.jackpot_cents || 0)));
    await pool.query('UPDATE pubs SET jackpot_cents = $1 WHERE id = $2', [cents, pubId]);

    // broadcast live update
    sseBroadcast(pubId, 'jackpot.updated', { jackpot_cents: cents });

    res.json({ ok: true, jackpot_cents: cents });
  } catch (e) {
    console.error('Jackpot POST error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ------------- SSE live stream ------------- */
// Public: allow no auth — games just pass ?pubId=#
app.get('/api/live/stream', (req, res) => {
  const pubId = Number(req.query.pubId);
  if (!Number.isFinite(pubId)) {
    return res.status(400).json({ error: 'Missing or invalid pubId' });
  }
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no', // for some proxies
  });
  res.write(`event: hello\ndata: {"ok":true}\n\n`);

  sseAddClient(pubId, res);
  req.on('close', () => sseRemoveClient(pubId, res));
});

/* ------------- 404 fallback ------------- */
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

/* ------------- start ------------- */
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});