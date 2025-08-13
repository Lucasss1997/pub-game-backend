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
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Ensure jackpot table exists
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pub_game_jackpots (
      pub_id   INTEGER NOT NULL,
      game_key TEXT    NOT NULL,
      jackpot_cents INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (pub_id, game_key)
    );
  `);
})().catch(console.error);

// helpers
function requireAuth(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}
const parseMoney = (val) => {
  if (val === null || val === undefined) return 0;
  if (typeof val === 'number') return Math.round(val);
  const s = String(val).trim().replace(/[£,\s]/g, '');
  if (!s) return 0;
  if (!/^\d+(\.\d{0,2})?$/.test(s)) throw Object.assign(new Error('Bad money format'), { status: 400 });
  return Math.round(parseFloat(s) * 100);
};

// auth
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
  try {
    const q = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (!q.rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const u = q.rows[0];
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: u.id, pub_id: u.pub_id }, JWT_SECRET, { expiresIn: '1d' });
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax', secure: true });
    res.json({ token });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

// admin config (products+jackpots)
app.get('/api/admin/config', requireAuth, async (req, res) => {
  try {
    const pubId = req.user.pub_id;

    const [prod, jps] = await Promise.all([
      pool.query(
        `SELECT game_key, name, price_cents, active
           FROM pub_game_products
          WHERE pub_id=$1
          ORDER BY game_key`,
        [pubId]
      ),
      pool.query(
        `SELECT game_key, jackpot_cents
           FROM pub_game_jackpots
          WHERE pub_id=$1`,
        [pubId]
      ),
    ]);

    const productsByGame = {};
    for (const r of prod.rows) {
      // choose the first row per game_key as the editable one
      if (!productsByGame[r.game_key]) {
        productsByGame[r.game_key] = {
          game_key: r.game_key,
          name: r.name,
          price_cents: r.price_cents,
          active: r.active,
        };
      }
    }

    const jackpotsByGame = {};
    for (const r of jps.rows) jackpotsByGame[r.game_key] = r.jackpot_cents;

    res.json({
      productsByGame,
      productsCount: prod.rowCount,
      jackpotsByGame,
    });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// save product (one or many)
app.post('/api/admin/products', requireAuth, async (req, res) => {
  try {
    const pubId = req.user.pub_id;
    const rows = Array.isArray(req.body?.products) ? req.body.products : [];
    for (const p of rows) {
      const price = Number.isFinite(p.price_cents) ? p.price_cents : parseMoney(p.price);
      await pool.query(
        `INSERT INTO pub_game_products (pub_id, game_key, name, price_cents, active)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (pub_id, game_key) DO UPDATE
           SET name=EXCLUDED.name, price_cents=EXCLUDED.price_cents, active=EXCLUDED.active`,
        [pubId, p.game_key, p.name || "", price, !!p.active]
      );
    }
    res.json({ ok: true });
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message || 'Server error' });
  }
});

// per-game jackpot
app.post('/api/admin/jackpot', requireAuth, async (req, res) => {
  try {
    const pubId = req.user.pub_id;
    const gameKey = (req.body?.game_key || "").trim();
    if (!gameKey) return res.status(400).json({ error: "Missing game_key" });
    const cents = Number.isFinite(req.body?.jackpot) ? req.body.jackpot : parseMoney(req.body?.jackpot);

    await pool.query(
      `INSERT INTO pub_game_jackpots (pub_id, game_key, jackpot_cents)
       VALUES ($1,$2,$3)
       ON CONFLICT (pub_id, game_key) DO UPDATE
         SET jackpot_cents = EXCLUDED.jackpot_cents`,
      [pubId, gameKey, cents]
    );
    res.json({ ok: true, game_key: gameKey, jackpot_cents: cents });
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message || 'Server error' });
  }
});

// (unchanged) dashboard – left as-is or adapt later
app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    const [{ rows: prodRows }] = await Promise.all([
      pool.query('SELECT game_key, name, price_cents, active FROM pub_game_products WHERE pub_id=$1', [req.user.pub_id]),
    ]);
    res.json({ products: prodRows || [] });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

// websockets (unchanged simple echo)
const server = app.listen(PORT, () => console.log(`Server running on ${PORT}`));
const wss = new WebSocket.Server({ server });
wss.on('connection', (ws) => {
  ws.on('message', (msg) => ws.send(`Echo: ${msg}`));
});