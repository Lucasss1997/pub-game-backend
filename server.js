// server.js
// Express backend with per-game jackpots, products, and play flow.
// Auth supports either Bearer token (Authorization header) or cookie.
// Optional email summary when a game ends (Nodemailer).

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookie = require('cookie-parser');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const { Pool } = require('pg');

const app = express();
app.use(express.json());
app.use(cookie());

app.use(
  cors({
    origin: (process.env.CORS_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean) || true,
    credentials: true,
  })
);

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('render.com') ? { rejectUnauthorized: false } : false,
});

// ---- DB bootstrap (idempotent)
async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pub_users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      pub_id TEXT NOT NULL DEFAULT 'pub-1'   -- simple multi-tenant key
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pub_products (
      id SERIAL PRIMARY KEY,
      pub_id TEXT NOT NULL,
      game_key TEXT NOT NULL,            -- 'safe' | 'box'
      name TEXT NOT NULL,
      price_pounds NUMERIC(10,2) NOT NULL DEFAULT 1.00,
      active BOOLEAN NOT NULL DEFAULT TRUE
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pub_jackpots (
      id SERIAL PRIMARY KEY,
      pub_id TEXT NOT NULL,
      game_key TEXT NOT NULL,
      jackpot_cents INTEGER NOT NULL DEFAULT 0,
      UNIQUE (pub_id, game_key)
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pub_plays (
      id SERIAL PRIMARY KEY,
      pub_id TEXT NOT NULL,
      game_key TEXT NOT NULL,
      user_id INTEGER,
      ticket_price_cents INTEGER NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);

  // seed a user if none
  const r = await pool.query(`SELECT COUNT(*)::int AS n FROM pub_users`);
  if (r.rows[0].n === 0) {
    await pool.query(
      `INSERT INTO pub_users (email, password, pub_id) VALUES ($1,$2,$3)`,
      [process.env.SEED_EMAIL || 'new@pub.com', process.env.SEED_PASS || 'password123', 'pub-1']
    );
  }
}
init().catch(console.error);

// ---- auth helpers
function issueToken(user) {
  return jwt.sign({ id: user.id, email: user.email, pub_id: user.pub_id }, JWT_SECRET, { expiresIn: '10d' });
}

function getTokenFromReq(req) {
  const h = req.headers.authorization || '';
  if (h.startsWith('Bearer ')) return h.slice(7).trim();
  if (req.cookies?.token) return req.cookies.token;
  if (req.query?.t) return req.query.t;
  return null;
}

async function requireAuth(req, res, next) {
  const token = getTokenFromReq(req);
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

// ---- login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing credentials' });
  const r = await pool.query(`SELECT * FROM pub_users WHERE email=$1`, [email]);
  const user = r.rows[0];
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  const token = issueToken(user);
  // also set cookie for convenience
  res.cookie('token', token, { httpOnly: true, sameSite: 'lax', secure: !!process.env.COOKIE_SECURE });
  res.json({ token });
});

// ---- admin config (products + jackpots for both games)
app.get('/api/admin/config', requireAuth, async (req, res) => {
  const pub = req.user.pub_id;
  const products = await pool.query(
    `SELECT game_key, name, price_pounds, active FROM pub_products WHERE pub_id=$1 ORDER BY game_key, id`,
    [pub]
  );
  const jackpots = await pool.query(
    `SELECT game_key, jackpot_cents FROM pub_jackpots WHERE pub_id=$1`,
    [pub]
  );
  res.json({
    pub_id: pub,
    products: products.rows,
    jackpots: jackpots.rows.reduce((acc, r) => {
      acc[r.game_key] = (r.jackpot_cents || 0) / 100;
      return acc;
    }, {}),
  });
});

// ---- save/update a product (per game)
app.post('/api/admin/product', requireAuth, async (req, res) => {
  const pub = req.user.pub_id;
  const { game_key, name, price_pounds, active } = req.body || {};
  if (!game_key || !name) return res.status(400).json({ error: 'Missing game_key or name' });
  const price = Number(price_pounds ?? 1).toFixed(2);

  await pool.query(
    `INSERT INTO pub_products (pub_id, game_key, name, price_pounds, active)
     VALUES ($1,$2,$3,$4,$5)`,
    [pub, game_key, name, price, active ?? true]
  );
  res.json({ ok: true });
});

// ---- set jackpot (per game)
app.post('/api/admin/jackpot', requireAuth, async (req, res) => {
  const pub = req.user.pub_id;
  const { game_key, jackpot } = req.body || {};
  if (!game_key) return res.status(400).json({ error: 'Missing game_key' });
  const cents = Math.round(Number(jackpot || 0) * 100);

  await pool.query(
    `INSERT INTO pub_jackpots (pub_id, game_key, jackpot_cents)
     VALUES ($1,$2,$3)
     ON CONFLICT (pub_id, game_key) DO UPDATE SET jackpot_cents=EXCLUDED.jackpot_cents`,
    [pub, game_key, cents]
  );
  res.json({ ok: true, jackpot: cents / 100 });
});

// ---- dashboard (very simple)
app.get('/api/dashboard', requireAuth, async (req, res) => {
  const pub = req.user.pub_id;
  const plays = await pool.query(
    `SELECT game_key, COUNT(*)::int AS plays
     FROM pub_plays WHERE pub_id=$1
     GROUP BY game_key`,
    [pub]
  );
  res.json({ pub_id: pub, plays: plays.rows });
});

// ---- start a game: records a play and increments that game's jackpot
//    ticket_price_pounds is stored and added to jackpot (adjust % if needed)
app.post('/api/game/start', requireAuth, async (req, res) => {
  const pub = req.user.pub_id;
  const { game_key, ticket_price_pounds } = req.body || {};
  if (!game_key) return res.status(400).json({ error: 'Missing game_key' });

  const price = Math.max(0, Number(ticket_price_pounds || 0));
  const cents = Math.round(price * 100);

  // record play
  await pool.query(
    `INSERT INTO pub_plays (pub_id, game_key, user_id, ticket_price_cents)
     VALUES ($1,$2,$3,$4)`,
    [pub, game_key, req.user.id || null, cents]
  );

  // increment jackpot (100% of ticket goes to jackpot; tweak rule if needed)
  await pool.query(
    `INSERT INTO pub_jackpots (pub_id, game_key, jackpot_cents)
     VALUES ($1,$2,$3)
     ON CONFLICT (pub_id, game_key) DO UPDATE
       SET jackpot_cents = pub_jackpots.jackpot_cents + EXCLUDED.jackpot_cents`,
    [pub, game_key, cents]
  );

  const j = await pool.query(
    `SELECT jackpot_cents FROM pub_jackpots WHERE pub_id=$1 AND game_key=$2`,
    [pub, game_key]
  );

  res.json({ ok: true, jackpot: (j.rows[0]?.jackpot_cents || 0) / 100 });
});

// ---- end a game: optional winner and optional email breakdown
app.post('/api/game/end', requireAuth, async (req, res) => {
  const pub = req.user.pub_id;
  const { game_key, winner_id = null, email_breakdown = false } = req.body || {};
  if (!game_key) return res.status(400).json({ error: 'Missing game_key' });

  // Get stats for this game
  const plays = await pool.query(
    `SELECT COUNT(*)::int AS tickets,
            COALESCE(SUM(ticket_price_cents),0)::int AS takings_cents
     FROM pub_plays WHERE pub_id=$1 AND game_key=$2
       AND created_at > NOW() - INTERVAL '24 hours'`, // basic "since last day"
    [pub, game_key]
  );
  const jackpotRow = await pool.query(
    `SELECT jackpot_cents FROM pub_jackpots WHERE pub_id=$1 AND game_key=$2`,
    [pub, game_key]
  );

  const tickets = plays.rows[0]?.tickets || 0;
  const takings_cents = plays.rows[0]?.takings_cents || 0;
  const jackpot_cents = jackpotRow.rows[0]?.jackpot_cents || 0;

  // If there's a winner, reset jackpot to 0; otherwise keep rolling over
  if (winner_id) {
    await pool.query(
      `UPDATE pub_jackpots SET jackpot_cents=0 WHERE pub_id=$1 AND game_key=$2`,
      [pub, game_key]
    );
  }

  // Optional email breakdown
  if (email_breakdown && process.env.MAIL_HOST) {
    try {
      const transporter = nodemailer.createTransport({
        host: process.env.MAIL_HOST,
        port: Number(process.env.MAIL_PORT || 587),
        secure: !!process.env.MAIL_SECURE, // true for 465
        auth: process.env.MAIL_USER
          ? { user: process.env.MAIL_USER, pass: process.env.MAIL_PASS }
          : undefined,
      });

      const to = process.env.MAIL_TO || req.user.email;
      const subject = `Game summary: ${game_key}`;
      const text = [
        `Pub: ${pub}`,
        `Game: ${game_key}`,
        `Tickets sold: ${tickets}`,
        `Takings: £${(takings_cents / 100).toFixed(2)}`,
        `Jackpot ${winner_id ? 'paid and reset to £0.00' : `now £${(jackpot_cents / 100).toFixed(2)}`}`,
      ].join('\n');

      await transporter.sendMail({
        from: process.env.MAIL_FROM || 'noreply@pubgame.local',
        to, subject, text,
      });
    } catch (e) {
      console.error('Email send failed:', e.message);
    }
  }

  res.json({
    ok: true,
    tickets,
    takings: takings_cents / 100,
    jackpot: winner_id ? 0 : jackpot_cents / 100,
    winner_id: winner_id || null,
  });
});

// health
app.get('/healthz', (_req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Backend listening on ${PORT}`));