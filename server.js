// server.js
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

// ---- DB ----
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('localhost')
    ? false
    : { rejectUnauthorized: false }
});

// ---- Auth helper ----
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

function parsePoundsToCents(input) {
  if (input === null || input === undefined) return 0;
  if (typeof input === 'number' && Number.isFinite(input)) return Math.round(input * 100);
  let s = String(input).trim().replace(/[£\s,]/g, '').replace(/p$/i, '');
  if (s === '' || s === '.') return 0;
  if (!/^\d+(\.\d{0,2})?$/.test(s)) {
    const err = new Error('Invalid money format');
    err.status = 400;
    throw err;
  }
  return Math.round(parseFloat(s) * 100);
}

// ---- Nodemailer (safe, optional) ----
let mailerReady = false;
let transporter = null;

(async () => {
  try {
    if (process.env.EMAIL_SERVICE) {
      transporter = nodemailer.createTransport({
        service: process.env.EMAIL_SERVICE, // e.g. 'gmail'
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS
        }
      });
    } else if (process.env.EMAIL_HOST) {
      transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: Number(process.env.EMAIL_PORT || 587),
        secure: process.env.EMAIL_SECURE === 'true',
        auth: process.env.EMAIL_USER
          ? { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
          : undefined
      });
    }
    if (transporter) {
      await transporter.verify();
      mailerReady = true;
      console.log('Mailer ready.');
    } else {
      console.log('Mailer not configured (EMAIL_* envs missing). Skipping email sends.');
    }
  } catch (e) {
    console.warn('Mailer disabled (verify failed):', e.message);
  }
})();

async function sendGameBreakdownEmail({ to, pubName, gameKey, ticketsSold, ticketPriceCents, jackpotCents, winner, winningCode }) {
  if (!mailerReady) return; // no-op if not configured

  const pretty = v => (v / 100).toFixed(2);
  const gameTitle = (gameKey || '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());

  const subject = `Game Breakdown • ${pubName || 'Pub'} • ${gameTitle}`;
  const html = `
    <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:520px;margin:0 auto">
      <h2 style="margin:0 0 8px 0">${pubName || 'Pub'} — ${gameTitle}</h2>
      <p style="margin:0 0 12px 0;color:#333">Here’s the breakdown for the last game.</p>
      <table width="100%" cellspacing="0" cellpadding="8" style="border:1px solid #eee;border-radius:8px">
        <tr><td><strong>Tickets sold</strong></td><td align="right">${ticketsSold}</td></tr>
        <tr><td><strong>Ticket price</strong></td><td align="right">£${pretty(ticketPriceCents)}</td></tr>
        <tr><td><strong>Current jackpot</strong></td><td align="right">£${pretty(jackpotCents)}</td></tr>
        <tr><td><strong>Winner?</strong></td><td align="right">${winner ? 'Yes' : 'No'}</td></tr>
        ${winningCode ? `<tr><td><strong>Winning code</strong></td><td align="right">${winningCode}</td></tr>` : ''}
      </table>
      <p style="margin:12px 0 0 0;color:#555;font-size:12px">You can turn these emails off anytime by removing EMAIL_* envs.</p>
    </div>
  `;

  await transporter.sendMail({
    from: `"Pub Game" <${process.env.EMAIL_FROM || process.env.EMAIL_USER || 'no-reply@pubgame.local'}>`,
    to,
    subject,
    html
  });
}

// ---------- Auth Routes ----------
app.post('/api/register', async (req, res) => {
  const { email, password, pubName } = req.body || {};
  if (!email || !password || !pubName) {
    return res.status(400).json({ error: 'Missing fields' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const r = await pool.query(
      `INSERT INTO users (email, password_hash, pub_name) VALUES ($1,$2,$3)
       RETURNING id, pub_name, pub_id`,
      [email, hashedPassword, pubName]
    );
    res.json(r.rows[0]);
  } catch (e) {
    console.error(e);
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

    const token = jwt.sign({ id: user.id, pub_id: user.pub_id }, JWT_SECRET, { expiresIn: '1d' });
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax', secure: true });
    res.json({ token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

// ---------- Dashboard ----------
app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    const [{ rows: pubRows }, { rows: prodRows }, { rows: statRows }] = await Promise.all([
      pool.query('SELECT name, city, address, expires_on FROM pubs WHERE id=$1', [req.user.pub_id]),
      pool.query('SELECT game_key, name, price_cents, active FROM pub_game_products WHERE pub_id=$1', [req.user.pub_id]),
      pool.query('SELECT COALESCE(jackpot_cents,0) AS jackpot_cents, players_this_week, prizes_won FROM pub_stats WHERE pub_id=$1', [req.user.pub_id])
    ]);
    res.json({
      pub: pubRows[0] || null,
      products: prodRows || [],
      stats: statRows[0] || { jackpot_cents: 0, players_this_week: 0, prizes_won: 0 }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- Admin: Save Jackpot (overall; keep if you still use it) ----------
app.post('/api/admin/jackpot', requireAuth, async (req, res) => {
  try {
    const cents = parsePoundsToCents(req.body?.jackpot);
    await pool.query(
      `INSERT INTO pub_settings (pub_id, jackpot_cents)
       VALUES ($1,$2)
       ON CONFLICT (pub_id) DO UPDATE SET jackpot_cents=EXCLUDED.jackpot_cents`,
      [req.user.pub_id, cents]
    );
    res.json({ ok: true, jackpot_cents: cents });
  } catch (e) {
    console.error(e);
    res.status(e.status || 500).json({ error: e.message || 'Server error' });
  }
});

// ---------- Admin: Save Products ----------
app.post('/api/admin/products', requireAuth, async (req, res) => {
  try {
    const rows = Array.isArray(req.body?.products) ? req.body.products : [];
    for (const p of rows) {
      const priceCents = parsePoundsToCents(p?.price);
      await pool.query(
        `INSERT INTO pub_game_products (pub_id, game_key, name, price_cents, active)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (pub_id, game_key) DO UPDATE
         SET name=EXCLUDED.name, price_cents=EXCLUDED.price_cents, active=EXCLUDED.active`,
        [req.user.pub_id, p.game_key, p.name || '', priceCents, !!p.active]
      );
    }
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(e.status || 500).json({ error: e.message || 'Server error' });
  }
});

// ---------- Game Complete -> Send Breakdown Email ----------
/**
 * Frontend calls this when a game ends.
 * Body example:
 * {
 *   "tickets_sold": 27,
 *   "ticket_price_cents": 200,
 *   "jackpot_cents": 5400,
 *   "winner": false,
 *   "winning_code": null,
 *   "email_to": "manager@pub.com"    // optional; falls back to user email
 * }
 */
app.post('/api/games/:gameKey/complete', requireAuth, async (req, res) => {
  try {
    const gameKey = req.params.gameKey; // e.g. 'crack_the_safe'
    const {
      tickets_sold = 0,
      ticket_price_cents = 0,
      jackpot_cents = 0,
      winner = false,
      winning_code = null,
      email_to
    } = req.body || {};

    // get pub + user email fallback
    const u = await pool.query('SELECT email, pub_name FROM users WHERE id=$1 LIMIT 1', [req.user.id]);
    const to = email_to || u.rows[0]?.email;
    const pubName = u.rows[0]?.pub_name || 'Pub';

    // fire-and-forget (await so we can catch errors; if mailer off it no-ops)
    await sendGameBreakdownEmail({
      to,
      pubName,
      gameKey,
      ticketsSold: Number(tickets_sold) || 0,
      ticketPriceCents: Number(ticket_price_cents) || 0,
      jackpotCents: Number(jackpot_cents) || 0,
      winner: !!winner,
      winningCode: winning_code || undefined
    });

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- WebSocket (unchanged demo) ----------
const server = app.listen(PORT, () => console.log(`Server running on ${PORT}`));
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
  ws.on('message', (msg) => {
    console.log(`WS: ${msg}`);
    ws.send(`Echo: ${msg}`);
  });
});