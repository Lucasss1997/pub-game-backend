// server.js (FULL with email summaries)
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

/* ---------- email transport (optional) ---------- */
let mailer = null;
if (process.env.SMTP_HOST) {
  mailer = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: false,
    auth: process.env.SMTP_USER ? {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    } : undefined
  });
}
const EMAIL_FROM = process.env.EMAIL_FROM || 'no-reply@pubgame.local';
const EMAIL_TO = (process.env.EMAIL_TO || '').split(',').map(s => s.trim()).filter(Boolean);

/* -------------------- helpers -------------------- */
function requireAuth(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { id, pub_id }
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}
function parsePoundsToCents(input) {
  if (input === null || input === undefined) return 0;
  if (typeof input === 'number' && Number.isFinite(input)) return Math.round(input * 100);
  let s = String(input).trim().replace(/[£\s,]/g, '').replace(/p$/i, '');
  if (s === '' || s === '.') return 0;
  if (!/^\d+(\.\d{0,2})?$/.test(s)) { const e = new Error('Invalid money format'); e.status = 400; throw e; }
  return Math.round(parseFloat(s) * 100);
}
const centsToPounds = (c) => (Math.round(c || 0) / 100).toFixed(2);

async function sendSummaryEmail({ pubId, gameKey, session, poolAfter, outcome }) {
  if (!mailer || EMAIL_TO.length === 0) return; // email disabled
  const subject = `Pub Game – ${gameKey.replace(/_/g,' ')} ${outcome === 'win' ? 'WIN' : 'ROLLOVER'}`;
  const html = `
    <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif">
      <h2>Game Summary: ${gameKey}</h2>
      <table cellpadding="6" style="border-collapse:collapse">
        <tr><td><strong>Pub ID</strong></td><td>${pubId}</td></tr>
        <tr><td><strong>Session ID</strong></td><td>${session.id}</td></tr>
        <tr><td><strong>Status</strong></td><td>${outcome.toUpperCase()}</td></tr>
        <tr><td><strong>Started</strong></td><td>${session.started_at}</td></tr>
        <tr><td><strong>Ended</strong></td><td>${new Date().toISOString()}</td></tr>
        <tr><td><strong>Ticket price</strong></td><td>£${centsToPounds(session.ticket_price_cents)}</td></tr>
        <tr><td><strong>Tickets sold</strong></td><td>${session.entries_count}</td></tr>
        <tr><td><strong>Jackpot at start</strong></td><td>£${centsToPounds(session.jackpot_start_cents)}</td></tr>
        <tr><td><strong>Jackpot at end</strong></td><td>£${centsToPounds(poolAfter)}</td></tr>
      </table>
    </div>
  `;
  await mailer.sendMail({
    from: EMAIL_FROM,
    to: EMAIL_TO,
    subject,
    html
  });
}

/* -------------------- auth -------------------- */
app.post('/api/register', async (req, res) => {
  const { email, password, pubName } = req.body || {};
  if (!email || !password || !pubName) return res.status(400).json({ error: 'Missing fields' });
  try {
    const hashed = await bcrypt.hash(password, 10);
    const pub = await pool.query(`INSERT INTO pubs(name) VALUES ($1) RETURNING id`, [pubName]);
    const pubId = pub.rows[0].id;
    const u = await pool.query(
      `INSERT INTO users(email, password_hash, pub_id)
       VALUES ($1,$2,$3) RETURNING id, email, pub_id`, [email, hashed, pubId]
    );
    await pool.query(
      `INSERT INTO pub_game_pools (pub_id, game_key, jackpot_cents)
       SELECT DISTINCT $1, p.game_key, 0
       FROM pub_game_products p
       WHERE p.pub_id = $1
       ON CONFLICT (pub_id, game_key) DO NOTHING`,
      [pubId]
    );
    res.json(u.rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
  try {
    const r = await pool.query(`SELECT * FROM users WHERE email=$1`, [email]);
    if (!r.rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const user = r.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, pub_id: user.pub_id }, JWT_SECRET, { expiresIn: '2d' });
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax', secure: true });
    res.json({ token });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/logout', (req, res) => { res.clearCookie('token'); res.json({ ok: true }); });

/* -------------------- dashboard -------------------- */
app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    const pubId = req.user.pub_id;
    const [prod, pools] = await Promise.all([
      pool.query(`SELECT game_key, name, price_cents, active FROM pub_game_products WHERE pub_id=$1 ORDER BY game_key`, [pubId]),
      pool.query(`SELECT game_key, jackpot_cents FROM pub_game_pools WHERE pub_id=$1 ORDER BY game_key`, [pubId])
    ]);
    res.json({ products: prod.rows || [], pools: pools.rows || [] });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* -------------------- admin: products -------------------- */
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
         SET name=EXCLUDED.name, price_cents=EXCLUDED.price_cents, active=EXCLUDED.active`,
        [pubId, p.game_key, p.name || '', priceCents, !!p.active]
      );
      await pool.query(
        `INSERT INTO pub_game_pools(pub_id, game_key, jackpot_cents)
         VALUES ($1,$2,0)
         ON CONFLICT (pub_id, game_key) DO NOTHING`,
        [pubId, p.game_key]
      );
    }
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(e.status || 500).json({ error: e.message || 'Server error' }); }
});

/* -------------------- admin: per-game pools -------------------- */
app.get('/api/admin/pools', requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT game_key, jackpot_cents FROM pub_game_pools WHERE pub_id=$1 ORDER BY game_key`, [req.user.pub_id]
    );
    res.json(r.rows || []);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/admin/pools', requireAuth, async (req, res) => {
  try {
    const pubId = req.user.pub_id;
    const rows = Array.isArray(req.body?.pools) ? req.body.pools : [];
    for (const row of rows) {
      const cents = parsePoundsToCents(row?.jackpot);
      await pool.query(
        `INSERT INTO pub_game_pools(pub_id, game_key, jackpot_cents)
         VALUES ($1,$2,$3)
         ON CONFLICT (pub_id, game_key) DO UPDATE
         SET jackpot_cents = EXCLUDED.jackpot_cents`,
        [pubId, row.game_key, cents]
      );
    }
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(e.status || 500).json({ error: e.message || 'Server error' }); }
});

/* -------------------- game lifecycle -------------------- */
app.post('/api/games/:gameKey/start', requireAuth, async (req, res) => {
  try {
    const pubId = req.user.pub_id, gameKey = req.params.gameKey;
    const [prod, poolRow] = await Promise.all([
      pool.query(`SELECT price_cents FROM pub_game_products WHERE pub_id=$1 AND game_key=$2`, [pubId, gameKey]),
      pool.query(`SELECT jackpot_cents FROM pub_game_pools WHERE pub_id=$1 AND game_key=$2`, [pubId, gameKey])
    ]);
    const priceCents = prod.rows[0]?.price_cents || 0;
    const jackpotCents = poolRow.rows[0]?.jackpot_cents || 0;
    const started = await pool.query(
      `INSERT INTO pub_games(pub_id, game_key, ticket_price_cents, jackpot_start_cents, entries_count)
       VALUES ($1,$2,$3,$4,0) RETURNING *`,
      [pubId, gameKey, priceCents, jackpotCents]
    );
    res.json({ ok: true, game: started.rows[0] });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/games/:gameKey/entry', requireAuth, async (req, res) => {
  try {
    const pubId = req.user.pub_id, gameKey = req.params.gameKey;
    const prod = await pool.query(`SELECT price_cents FROM pub_game_products WHERE pub_id=$1 AND game_key=$2`, [pubId, gameKey]);
    const inc = prod.rows[0]?.price_cents || 0;

    await pool.query(
      `UPDATE pub_game_pools SET jackpot_cents = jackpot_cents + $3
         WHERE pub_id=$1 AND game_key=$2`,
      [pubId, gameKey, inc]
    );
    await pool.query(
      `UPDATE pub_games
          SET entries_count = entries_count + 1
        WHERE pub_id=$1 AND game_key=$2 AND status='live'`,
      [pubId, gameKey]
    );

    res.json({ ok: true, added_cents: inc });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/games/:gameKey/win', requireAuth, async (req, res) => {
  try {
    const pubId = req.user.pub_id, gameKey = req.params.gameKey;
    // grab the live session first
    const s = await pool.query(
      `SELECT * FROM pub_games WHERE pub_id=$1 AND game_key=$2 AND status='live' ORDER BY started_at DESC LIMIT 1`,
      [pubId, gameKey]
    );
    const session = s.rows[0];

    // reset pool to 0 and close session
    await pool.query(
      `UPDATE pub_game_pools SET jackpot_cents = 0 WHERE pub_id=$1 AND game_key=$2`,
      [pubId, gameKey]
    );
    await pool.query(
      `UPDATE pub_games
          SET status='ended', ended_at=now(), jackpot_end_cents=0
        WHERE id=$1`, [session?.id || 0]
    );

    if (session) await sendSummaryEmail({ pubId, gameKey, session, poolAfter: 0, outcome: 'win' });

    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/games/:gameKey/rollover', requireAuth, async (req, res) => {
  try {
    const pubId = req.user.pub_id, gameKey = req.params.gameKey;
    // current pool
    const pr = await pool.query(
      `SELECT jackpot_cents FROM pub_game_pools WHERE pub_id=$1 AND game_key=$2`,
      [pubId, gameKey]
    );
    const poolCents = pr.rows[0]?.jackpot_cents || 0;

    // live session
    const s = await pool.query(
      `SELECT * FROM pub_games WHERE pub_id=$1 AND game_key=$2 AND status='live' ORDER BY started_at DESC LIMIT 1`,
      [pubId, gameKey]
    );
    const session = s.rows[0];

    // close session but do not touch the pool
    await pool.query(
      `UPDATE pub_games
          SET status='ended', ended_at=now(), jackpot_end_cents=$2
        WHERE id=$1`, [session?.id || 0, poolCents]
    );

    if (session) await sendSummaryEmail({ pubId, gameKey, session, poolAfter: poolCents, outcome: 'rollover' });

    res.json({ ok: true, rollover_cents: poolCents });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* -------------------- public game info -------------------- */
app.get('/api/games/:gameKey/info', async (req, res) => {
  try {
    const pub = req.query.pubId, gameKey = req.params.gameKey;
    if (!pub) return res.status(400).json({ error: 'Missing pubId' });
    const [prod, poolRow] = await Promise.all([
      pool.query(`SELECT price_cents FROM pub_game_products WHERE pub_id=$1 AND game_key=$2`, [pub, gameKey]),
      pool.query(`SELECT jackpot_cents FROM pub_game_pools WHERE pub_id=$1 AND game_key=$2`, [pub, gameKey])
    ]);
    res.json({
      ticket_price: centsToPounds(prod.rows[0]?.price_cents || 0),
      jackpot: centsToPounds(poolRow.rows[0]?.jackpot_cents || 0)
    });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* -------------------- ws -------------------- */
const server = app.listen(PORT, () => console.log(`Server running on ${PORT}`));
const wss = new WebSocket.Server({ server });
wss.on('connection', (ws) => { ws.on('message', (msg) => ws.send(`Echo: ${msg}`)); });