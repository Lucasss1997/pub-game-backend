// server.js — per-game jackpot, public meta endpoints, ticket posting, WS broadcasts

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
const JWT_SECRET = process.env.JWT_SECRET || 'change_me';

// ---------- DB ----------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// ---------- Helpers ----------
function requireAuth(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function parsePoundsToCents(input) {
  if (input === null || input === undefined) return 0;
  if (typeof input === 'number' && Number.isFinite(input)) return Math.round(input * 100);
  let s = String(input).trim().replace(/[£\s,]/g, '').replace(/p$/i, '');
  if (s === '' || s === '.') return 0;
  if (!/^\d+(\.\d{0,2})?$/.test(s)) {
    const err = new Error('Invalid money format'); err.status = 400; throw err;
  }
  return Math.round(parseFloat(s) * 100);
}

// ---------- Auth ----------
app.post('/api/register', async (req, res) => {
  const { email, password, pubName } = req.body || {};
  if (!email || !password || !pubName) return res.status(400).json({ error: 'Missing fields' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      `INSERT INTO users(email, password_hash, pub_name)
       VALUES ($1,$2,$3) RETURNING id, pub_id`,
      [email, hash, pubName]
    );
    const user = rows[0];
    const token = jwt.sign({ id: user.id, pub_id: user.pub_id }, JWT_SECRET, { expiresIn: '1d' });
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax', secure: true });
    res.json({ token });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const u = rows[0];
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: u.id, pub_id: u.pub_id }, JWT_SECRET, { expiresIn: '1d' });
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax', secure: true });
    res.json({ token });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/logout', (req, res) => { res.clearCookie('token'); res.json({ ok: true }); });

// ---------- Admin (existing) ----------
app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    const [pub, products, stats] = await Promise.all([
      pool.query('SELECT name, city, address, expires_on FROM pubs WHERE id=$1', [req.user.pub_id]),
      pool.query('SELECT game_key, name, price_cents, active FROM pub_game_products WHERE pub_id=$1 ORDER BY game_key', [req.user.pub_id]),
      pool.query('SELECT COALESCE(SUM(jackpot_cents),0) as jackpot_cents FROM pub_game_jackpots WHERE pub_id=$1', [req.user.pub_id]),
    ]);
    res.json({
      pub: pub.rows[0] || null,
      products: products.rows || [],
      stats: { jackpot_cents: stats.rows[0]?.jackpot_cents || 0 }
    });
  } catch {
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
         SET name=EXCLUDED.name, price_cents=EXCLUDED.price_cents, active=EXCLUDED.active`,
        [req.user.pub_id, p.game_key, p.name || '', priceCents, !!p.active]
      );
      // ensure jackpot row exists for that game
      await pool.query(
        `INSERT INTO pub_game_jackpots(pub_id, game_key, jackpot_cents)
         VALUES ($1,$2, COALESCE((SELECT jackpot_cents FROM pub_game_jackpots WHERE pub_id=$1 AND game_key=$2),0))
         ON CONFLICT (pub_id, game_key) DO NOTHING`,
        [req.user.pub_id, p.game_key]
      );
    }
    res.json({ ok: true });
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message || 'Server error' });
  }
});

// ---------- NEW: public game meta & ticket endpoints ----------
app.get('/api/game/:pubId/:gameKey/meta', async (req, res) => {
  const pubId = Number(req.params.pubId);
  const gameKey = String(req.params.gameKey);
  if (!pubId || !gameKey) return res.status(400).json({ error: 'Bad request' });

  try {
    const { rows } = await pool.query(
      `SELECT p.game_key, p.name, p.price_cents, p.active,
              COALESCE(j.jackpot_cents,0) AS jackpot_cents
         FROM pub_game_products p
    LEFT JOIN pub_game_jackpots j
           ON j.pub_id = p.pub_id AND j.game_key = p.game_key
        WHERE p.pub_id=$1 AND p.game_key=$2`,
      [pubId, gameKey]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/game/:pubId/:gameKey/ticket', async (req, res) => {
  const pubId = Number(req.params.pubId);
  const gameKey = String(req.params.gameKey);
  let amount = Number(req.body?.amount || 0); // in cents
  if (!pubId || !gameKey || !Number.isFinite(amount) || amount < 0) {
    return res.status(400).json({ error: 'Bad request' });
  }

  try {
    // Optional: record sale
    await pool.query(
      `INSERT INTO game_sales(pub_id, game_key, amount_cents)
       VALUES ($1,$2,$3)`,
      [pubId, gameKey, amount]
    );

    // Update jackpot (here: add full ticket price; change logic if needed)
    const { rows } = await pool.query(
      `INSERT INTO pub_game_jackpots(pub_id, game_key, jackpot_cents)
       VALUES ($1,$2,$3)
       ON CONFLICT (pub_id, game_key)
       DO UPDATE SET jackpot_cents = pub_game_jackpots.jackpot_cents + EXCLUDED.jackpot_cents
       RETURNING jackpot_cents`,
      [pubId, gameKey, amount]
    );

    const jackpot_cents = rows[0].jackpot_cents;
    broadcast(`jackpot:${pubId}:${gameKey}`, {
      type: 'jackpot',
      pubId, gameKey, jackpot_cents
    });

    res.json({ ok: true, jackpot_cents });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- Server & WS ----------
const server = app.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`);
});

const wss = new WebSocket.Server({ server });

/** simple topic pub/sub registry */
const clients = new Map(); // ws -> Set(topics)

function broadcast(topic, payload) {
  const str = JSON.stringify(payload);
  for (const [ws, topics] of clients.entries()) {
    if (topics.has(topic)) {
      try { ws.send(str); } catch {}
    }
  }
}

wss.on('connection', (ws) => {
  clients.set(ws, new Set());
  ws.on('message', (raw) => {
    try {
      const msg = JSON.parse(raw.toString());
      if (msg.type === 'subscribe' && typeof msg.topic === 'string') {
        clients.get(ws).add(msg.topic);
      }
    } catch {}
  });
  ws.on('close', () => { clients.delete(ws); });
});