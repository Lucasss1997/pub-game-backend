// server.js — Pub Game backend (per-game jackpots + staff entries + email summaries)
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
  ssl: process.env.DATABASE_URL?.includes('localhost')
    ? false
    : { rejectUnauthorized: false }
});

/* ===================== Email (optional) ===================== */
let mailerReady = false;
let transporter = null;

(async () => {
  try {
    if (process.env.EMAIL_SERVICE) {
      transporter = nodemailer.createTransport({
        service: process.env.EMAIL_SERVICE, // e.g. 'gmail'
        auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
      });
    } else if (process.env.EMAIL_HOST) {
      transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: Number(process.env.EMAIL_PORT || 587),
        secure: process.env.EMAIL_SECURE === 'true',
        auth: process.env.EMAIL_USER ? { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS } : undefined
      });
    }
    if (transporter) {
      await transporter.verify();
      mailerReady = true;
      console.log('Mailer ready.');
    } else {
      console.log('Mailer not configured; skipping email sends.');
    }
  } catch (e) {
    console.warn('Mailer disabled (verify failed):', e.message);
  }
})();

function pounds(cents) {
  return (Math.round(cents || 0) / 100).toFixed(2);
}

async function sendSummaryEmail({ pubId, gameKey, outcome }) {
  if (!mailerReady) return;

  // pull pub name + last ended/live session
  const [{ rows: urows }, { rows: srows }, { rows: prows }, { rows: pools }] = await Promise.all([
    pool.query(`SELECT pub_name FROM users WHERE pub_id=$1 LIMIT 1`, [pubId]),
    pool.query(`
      SELECT *
        FROM pub_games
       WHERE pub_id=$1 AND game_key=$2
       ORDER BY started_at DESC
       LIMIT 1
    `, [pubId, gameKey]),
    pool.query(`SELECT price_cents FROM pub_game_products WHERE pub_id=$1 AND game_key=$2`, [pubId, gameKey]),
    pool.query(`SELECT jackpot_cents FROM pub_game_pools WHERE pub_id=$1 AND game_key=$2`, [pubId, gameKey])
  ]);

  const pubName = urows[0]?.pub_name || 'Pub';
  const session = srows[0] || null;
  const ticket_price_cents = prows[0]?.price_cents || 0;
  const poolAfter = pools[0]?.jackpot_cents || 0;

  const toList = (process.env.EMAIL_TO || '')
    .split(',').map(s => s.trim()).filter(Boolean);
  if (!toList.length && process.env.EMAIL_USER) toList.push(process.env.EMAIL_USER);
  if (!toList.length) return;

  const title = (gameKey || '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
  const subject = `Pub Game • ${pubName} • ${title} • ${outcome.toUpperCase()}`;
  const html = `
    <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:560px;margin:0 auto">
      <h2 style="margin:0 0 8px 0">${pubName} — ${title}</h2>
      <table cellpadding="8" cellspacing="0" style="border:1px solid #eee;border-radius:8px;width:100%">
        <tr><td><strong>Status</strong></td><td align="right">${outcome.toUpperCase()}</td></tr>
        <tr><td><strong>Tickets sold (session)</strong></td><td align="right">${session?.entries_count ?? 0}</td></tr>
        <tr><td><strong>Ticket price</strong></td><td align="right">£${pounds(ticket_price_cents)}</td></tr>
        <tr><td><strong>Jackpot start</strong></td><td align="right">£${pounds(session?.jackpot_start_cents ?? 0)}</td></tr>
        <tr><td><strong>Jackpot end</strong></td><td align="right">£${pounds(poolAfter)}</td></tr>
        <tr><td><strong>Session ID</strong></td><td align="right">${session?.id ?? '-'}</td></tr>
        <tr><td><strong>Started</strong></td><td align="right">${session?.started_at ?? '-'}</td></tr>
        <tr><td><strong>Ended</strong></td><td align="right">${new Date().toISOString()}</td></tr>
      </table>
    </div>
  `;

  await transporter.sendMail({
    from: process.env.EMAIL_FROM || process.env.EMAIL_USER || 'no-reply@pubgame.local',
    to: toList,
    subject,
    html
  });
}

/* ===================== Helpers ===================== */
function requireAuth(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, JWT_SECRET); // { id, pub_id }
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
  if (!/^\d+(\.\d{0,2})?$/.test(s)) {
    const err = new Error('Invalid money format'); err.status = 400; throw err;
  }
  return Math.round(parseFloat(s) * 100);
}

async function getTicketPriceCents(pubId, gameKey) {
  const r = await pool.query(
    `SELECT price_cents FROM pub_game_products WHERE pub_id=$1 AND game_key=$2`,
    [pubId, gameKey]
  );
  return r.rows[0]?.price_cents || 0;
}

async function startSessionIfMissing(pubId, gameKey) {
  // Is there a live session?
  const live = await pool.query(
    `SELECT * FROM pub_games WHERE pub_id=$1 AND game_key=$2 AND status='live'
      ORDER BY started_at DESC LIMIT 1`,
    [pubId, gameKey]
  );
  if (live.rows.length) return live.rows[0];

  // Ensure pool exists, get jackpot start
  await pool.query(
    `INSERT INTO pub_game_pools(pub_id, game_key, jackpot_cents)
     VALUES ($1,$2,0)
     ON CONFLICT (pub_id, game_key) DO NOTHING`,
    [pubId, gameKey]
  );
  const poolRow = await pool.query(
    `SELECT jackpot_cents FROM pub_game_pools WHERE pub_id=$1 AND game_key=$2`,
    [pubId, gameKey]
  );
  const jackpot = poolRow.rows[0]?.jackpot_cents || 0;
  const price = await getTicketPriceCents(pubId, gameKey);

  const ins = await pool.query(
    `INSERT INTO pub_games(pub_id, game_key, status, ticket_price_cents, jackpot_start_cents, entries_count)
     VALUES ($1,$2,'live',$3,$4,0)
     RETURNING *`,
    [pubId, gameKey, price, jackpot]
  );
  return ins.rows[0];
}

async function endSession(pubId, gameKey, outcome /* 'win' | 'rollover' */) {
  // Get current values first
  const [poolRow, sessionRow] = await Promise.all([
    pool.query(
      `SELECT jackpot_cents FROM pub_game_pools WHERE pub_id=$1 AND game_key=$2`,
      [pubId, gameKey]
    ),
    pool.query(
      `SELECT * FROM pub_games WHERE pub_id=$1 AND game_key=$2 AND status='live'
         ORDER BY started_at DESC LIMIT 1`,
      [pubId, gameKey]
    )
  ]);

  const poolCents = poolRow.rows[0]?.jackpot_cents || 0;
  const session = sessionRow.rows[0] || null;

  if (outcome === 'win') {
    // reset pool
    await pool.query(
      `UPDATE pub_game_pools SET jackpot_cents=0 WHERE pub_id=$1 AND game_key=$2`,
      [pubId, gameKey]
    );
  }
  // close session
  if (session) {
    await pool.query(
      `UPDATE pub_games
          SET status='ended', ended_at=now(), jackpot_end_cents=$2
        WHERE id=$1`,
      [session.id, outcome === 'win' ? 0 : poolCents]
    );
  }

  // summary email (optional)
  try {
    await sendSummaryEmail({
      pubId,
      gameKey,
      outcome
    });
  } catch (e) {
    console.warn('sendSummaryEmail failed:', e.message);
  }
}

/* ===================== Health / Root ===================== */
app.get('/', (req, res) => {
  res.json({
    ok: true,
    service: 'pub-game-backend',
    health: '/healthz',
    login: 'POST /api/login',
    dashboard: 'GET /api/dashboard (auth)',
    game_info: 'GET /api/games/:gameKey/info?pubId=ID',
    staff_entry: 'POST /api/staff/entry (auth)'
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

/* ===================== Auth ===================== */
app.post('/api/register', async (req, res) => {
  const { email, password, pubName } = req.body || {};
  if (!email || !password || !pubName) return res.status(400).json({ error: 'Missing fields' });
  try {
    const hashed = await bcrypt.hash(password, 10);
    const u = await pool.query(
      `INSERT INTO users (email, password_hash, pub_name)
       VALUES ($1,$2,$3)
       RETURNING id, email, pub_id, pub_name`,
      [email, hashed, pubName]
    );
    res.json(u.rows[0]);
  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
  try {
    const r = await pool.query('SELECT * FROM users WHERE email=$1 LIMIT 1', [email]);
    if (!r.rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const user = r.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, pub_id: user.pub_id }, JWT_SECRET, { expiresIn: '2d' });
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax', secure: true });
    res.json({ token });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/logout', (req, res) => { res.clearCookie('token'); res.json({ ok: true }); });

/* ===================== Dashboard ===================== */
app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    const pubId = req.user.pub_id;
    const [prod, pools] = await Promise.all([
      pool.query(`SELECT game_key, name, price_cents, active FROM pub_game_products WHERE pub_id=$1 ORDER BY game_key`, [pubId]),
      pool.query(`SELECT game_key, jackpot_cents FROM pub_game_pools   WHERE pub_id=$1 ORDER BY game_key`, [pubId])
    ]);
    res.json({ products: prod.rows || [], pools: pools.rows || [] });
  } catch (e) {
    console.error('Dashboard error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ===================== Admin: products & pools ===================== */
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
  } catch (e) {
    console.error('Admin products error:', e);
    res.status(e.status || 500).json({ error: e.message || 'Server error' });
  }
});

app.get('/api/admin/pools', requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT game_key, jackpot_cents FROM pub_game_pools WHERE pub_id=$1 ORDER BY game_key`,
      [req.user.pub_id]
    );
    res.json(r.rows || []);
  } catch (e) {
    console.error('Admin pools error:', e);
    res.status(500).json({ error: 'Server error' });
  }
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
  } catch (e) {
    console.error('Admin pools post error:', e);
    res.status(e.status || 500).json({ error: e.message || 'Server error' });
  }
});

/* ===================== Public game info ===================== */
app.get('/api/games/:gameKey/info', async (req, res) => {
  try {
    const pub = req.query.pubId;
    const gameKey = req.params.gameKey;
    if (!pub) return res.status(400).json({ error: 'Missing pubId' });

    const [prod, poolRow] = await Promise.all([
      pool.query(`SELECT price_cents FROM pub_game_products WHERE pub_id=$1 AND game_key=$2`, [pub, gameKey]),
      pool.query(`SELECT jackpot_cents FROM pub_game_pools   WHERE pub_id=$1 AND game_key=$2`, [pub, gameKey])
    ]);
    res.json({
      ticket_price: pounds(prod.rows[0]?.price_cents || 0),
      jackpot:      pounds(poolRow.rows[0]?.jackpot_cents || 0)
    });
  } catch (e) {
    console.error('Game info error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ===================== Staff manual entry ===================== */
/**
 * POST /api/staff/entry  (auth)
 * body: { game_key, quantity?, mobile?, note? }
 * - ensures a live session exists (auto-start if needed)
 * - increments jackpot by price * quantity
 * - increments session entries_count by quantity
 * - logs the entry in pub_game_entries (source='staff')
 */
app.post('/api/staff/entry', requireAuth, async (req, res) => {
  const pubId   = req.user.pub_id;
  const gameKey = (req.body?.game_key || '').trim();
  const qty     = Math.max(1, Number(req.body?.quantity || 1) | 0);
  const mobile  = (req.body?.mobile || '').trim() || null;
  const note    = (req.body?.note || '').trim() || null;

  if (!gameKey) return res.status(400).json({ error: 'Missing game_key' });

  try {
    // Ensure we have a live session
    const session = await startSessionIfMissing(pubId, gameKey);

    // Ticket price
    const priceCents = await getTicketPriceCents(pubId, gameKey);
    const increment = priceCents * qty;

    // Bump jackpot (ensure pool row exists)
    await pool.query(
      `INSERT INTO pub_game_pools(pub_id, game_key, jackpot_cents)
       VALUES ($1,$2,0)
       ON CONFLICT (pub_id, game_key) DO NOTHING`,
      [pubId, gameKey]
    );
    const up = await pool.query(
      `UPDATE pub_game_pools
          SET jackpot_cents = jackpot_cents + $3
        WHERE pub_id=$1 AND game_key=$2
        RETURNING jackpot_cents`,
      [pubId, gameKey, increment]
    );

    // Bump session entries
    await pool.query(
      `UPDATE pub_games
          SET entries_count = entries_count + $2
        WHERE id=$1`,
      [session.id, qty]
    );

    // Log entry
    await pool.query(
      `INSERT INTO pub_game_entries(pub_id, game_key, session_id, mobile, source, quantity, note)
       VALUES ($1,$2,$3,$4,'staff',$5,$6)`,
      [pubId, gameKey, session.id, mobile, qty, note]
    );

    res.json({
      ok: true,
      session_id: session.id,
      jackpot_cents: up.rows[0]?.jackpot_cents || 0,
      ticket_price_cents: priceCents,
      quantity: qty
    });
  } catch (e) {
    console.error('staff/entry error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ===================== Game lifecycle (optional endpoints) ===================== */
// Mark a game as WIN (pays out; pool resets to 0)
app.post('/api/games/:gameKey/win', requireAuth, async (req, res) => {
  try {
    await endSession(req.user.pub_id, req.params.gameKey, 'win');
    res.json({ ok: true });
  } catch (e) {
    console.error('win error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Mark a game as ROLLOVER (keeps pool; ends session)
app.post('/api/games/:gameKey/rollover', requireAuth, async (req, res) => {
  try {
    await endSession(req.user.pub_id, req.params.gameKey, 'rollover');
    res.json({ ok: true });
  } catch (e) {
    console.error('rollover error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ===================== 404 & Start ===================== */
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

/* ===================== WebSocket (demo) ===================== */
const wss = new WebSocket.Server({ server });
wss.on('connection', (ws) => {
  ws.on('message', (msg) => ws.send(`Echo: ${msg}`));
});