// Full server.js – auth, dashboard, Stripe, raffle (products/entry/draw)
// Works on Render/Railway

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const Stripe = require('stripe');
require('dotenv').config();

const app = express();
app.use(cors({ origin: true, credentials: true }));

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// --- DB ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// --- Root / Health ---
app.get('/', (req, res) => {
  res.json({
    ok: true,
    service: 'pub-game-backend',
    health: '/healthz',
    login: 'POST /api/login',
    register: 'POST /api/register',
    me: 'GET /api/me',
    dashboard: 'GET /api/dashboard (auth)',
    raffle: {
      products: 'GET /api/raffle/products?pubId=1&gameKey=crack_the_safe',
      enter: 'POST /api/raffle/enter',
      entries: 'GET /api/raffle/entries?pubId=1&gameKey=crack_the_safe (auth)',
      draw: 'POST /api/raffle/draw (auth)',
      consume: 'POST /api/raffle/consume (auth)',
    },
    stripe_webhook: 'POST /api/billing/webhook',
  });
});

app.get('/healthz', async (_req, res) => {
  try {
    const { rows } = await pool.query('SELECT NOW() as now');
    res.json({ ok: true, now: rows[0].now });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});

// --- Stripe Webhook BEFORE json parser (raw body) ---
app.post('/api/billing/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    if (event.type === 'checkout.session.completed') {
      const s = event.data.object;
      const entryId = s.metadata?.entryId;

      // Mark raffle entry as paid (if this Checkout was created by raffle/enter)
      if (entryId) {
        await pool.query(
          `UPDATE raffle_entries
             SET status='paid', paid_at=NOW(), stripe_pi=$1
           WHERE id=$2`,
          [s.payment_intent, entryId]
        );
      }

      // Keep any existing billing logic you had here (e.g., pubs.expires_at update)
    }

    res.json({ received: true });
  } catch (e) {
    console.error('Webhook handling error:', e);
    res.status(500).json({ ok: false });
  }
});

// --- JSON parser AFTER webhook ---
app.use(express.json());

// --- Auth helpers ---
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

// --- Auth endpoints ---
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
  if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });
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

// --- Dashboard (expects users.pub_id and pubs table) ---
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

/* =========================
   RAFFLE / ENTRY ENDPOINTS
   ========================= */

// GET /api/raffle/products?pubId=1&gameKey=crack_the_safe
app.get('/api/raffle/products', async (req, res) => {
  try {
    const pubId = Number(req.query.pubId);
    const gameKey = String(req.query.gameKey || '');
    if (!pubId || !gameKey) return res.status(400).json({ error: 'Missing pubId/gameKey' });

    const { rows } = await pool.query(
      `SELECT id, name, price_cents
         FROM pub_game_products
        WHERE pub_id=$1 AND game_key=$2 AND active IS NOT FALSE
        ORDER BY sort_order, created_at`,
      [pubId, gameKey]
    );
    res.json({ products: rows });
  } catch (e) {
    console.error('products error', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/raffle/enter  { pubId, gameKey, productId, mobile }
app.post('/api/raffle/enter', async (req, res) => {
  try {
    const { pubId, gameKey, productId, mobile } = req.body || {};
    if (!pubId || !gameKey || !productId || !mobile) {
      return res.status(400).json({ error: 'Missing fields' });
    }

    // Load product/amount
    const p = await pool.query(
      `SELECT id, price_cents FROM pub_game_products
        WHERE id=$1 AND pub_id=$2 AND game_key=$3 LIMIT 1`,
      [productId, pubId, gameKey]
    );
    const prod = p.rows[0];
    if (!prod) return res.status(400).json({ error: 'Invalid product' });

    // Create pending entry
    const ins = await pool.query(
      `INSERT INTO raffle_entries
        (pub_id, game_key, mobile_e164, amount_pennies, currency, status, product_id)
       VALUES ($1,$2,$3,$4,'gbp','pending',$5)
       RETURNING id`,
      [pubId, gameKey, mobile, prod.price_cents, productId]
    );
    const entryId = ins.rows[0].id;

    const successUrl = `${process.env.FRONTEND_URL}/enter/success?entry=${entryId}`;
    const cancelUrl  = `${process.env.FRONTEND_URL}/enter/cancel`;

    // Dynamic price (no Stripe Price object needed)
    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items: [{
        price_data: {
          currency: 'gbp',
          unit_amount: prod.price_cents,
          product_data: { name: `${gameKey.replaceAll('_',' ')} entry` },
        },
        quantity: 1,
      }],
      success_url: successUrl,
      cancel_url: cancelUrl,
      metadata: {
        pubId: String(pubId),
        gameKey,
        entryId,
        productId: String(productId),
      },
    });

    await pool.query('UPDATE raffle_entries SET stripe_cs=$1 WHERE id=$2', [session.id, entryId]);
    res.json({ checkoutUrl: session.url });
  } catch (e) {
    console.error('raffle enter error', e);
    res.status(500).json({ error: 'Unable to start entry' });
  }
});

// --- STAFF: list paid entries (today by default) ---
app.get('/api/raffle/entries', requireAuth, async (req, res) => {
  try {
    const pubId = Number(req.query.pubId);
    const gameKey = String(req.query.gameKey || '');
    if (!pubId || !gameKey) return res.status(400).json({ error: 'Missing pubId/gameKey' });

    const { rows } = await pool.query(
      `SELECT id, mobile_e164, status, amount_pennies, paid_at, created_at
         FROM raffle_entries
        WHERE pub_id=$1 AND game_key=$2 AND status='paid'
        ORDER BY paid_at DESC NULLS LAST, created_at DESC`,
      [pubId, gameKey]
    );

    const mask = (p) => p?.replace(/(\+\d{2})\d{5}(\d{3,4})/, '$1•••••$2') || '';
    res.json({ entries: rows.map(r => ({ ...r, mobile_masked: mask(r.mobile_e164) })) });
  } catch (e) {
    console.error('entries error', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// --- STAFF: draw a random winner from paid ---
app.post('/api/raffle/draw', requireAuth, async (req, res) => {
  try {
    const { pubId, gameKey } = req.body || {};
    if (!pubId || !gameKey) return res.status(400).json({ error: 'Missing pubId/gameKey' });

    const { rows } = await pool.query(`
      WITH c AS (
        SELECT id FROM raffle_entries
         WHERE pub_id=$1 AND game_key=$2 AND status='paid'
         ORDER BY random() LIMIT 1
      )
      UPDATE raffle_entries e
         SET status='won', won_at=NOW()
        FROM c
       WHERE e.id = c.id
       RETURNING e.id, e.mobile_e164;
    `, [pubId, gameKey]);

    if (!rows.length) return res.json({ winner: null });

    const win = rows[0];
    const masked = win.mobile_e164.replace(/(\+\d{2})\d{5}(\d{3,4})/, '$1•••••$2');
    res.json({ winner: { entryId: win.id, mobileMasked: masked } });
  } catch (e) {
    console.error('draw error', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// --- STAFF: consume winning entry when player starts game ---
app.post('/api/raffle/consume', requireAuth, async (req, res) => {
  try {
    const { entryId } = req.body || {};
    if (!entryId) return res.status(400).json({ error: 'Missing entryId' });

    const { rows } = await pool.query(
      `UPDATE raffle_entries SET status='used', used_at=NOW()
        WHERE id=$1 AND status='won'
        RETURNING id`,
      [entryId]
    );
    if (!rows.length) return res.status(400).json({ error: 'Entry not in won state' });
    res.json({ ok: true });
  } catch (e) {
    console.error('consume error', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// --- 404 fallback ---
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// --- Start ---
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});