// server.js — Pub Game backend (GBP) with Products + QR Entry + Raffle Draw
// Works on Render/Railway (PG + Stripe)

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

// ---------- Root / Health ----------
app.get('/', (_req, res) => {
  res.json({
    ok: true,
    service: 'pub-game-backend',
    health: '/healthz',
    login: 'POST /api/login',
    register: 'POST /api/register',
    me: 'GET /api/me',
    dashboard: 'GET /api/dashboard (auth)',
    products_manager: {
      list: 'GET /api/raffle/my-products?gameKey=crack_the_safe (auth)',
      create: 'POST /api/raffle/products (auth)',
      update: 'PUT /api/raffle/products/:id (auth)',
      reorder: 'POST /api/raffle/products/reorder (auth)',
      delete: 'DELETE /api/raffle/products/:id (auth)',
    },
    public_entry: {
      products: 'GET /api/raffle/products?pubId=1&gameKey=crack_the_safe',
      enter: 'POST /api/raffle/enter { pubId, gameKey, productId, mobile }',
    },
    staff_raffle: {
      listPaid: 'GET /api/raffle/entries?pubId=1&gameKey=crack_the_safe (auth)',
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

// ---------- Stripe Webhook (raw) ----------
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
      if (entryId) {
        await pool.query(
          `UPDATE raffle_entries
             SET status='paid', paid_at=NOW(), stripe_pi=$1
           WHERE id=$2`,
          [s.payment_intent, entryId]
        );
      }
      // (Keep any other Stripe logic you already had, e.g. subscription/expiry)
    }
    res.json({ received: true });
  } catch (e) {
    console.error('Webhook handling error:', e);
    res.status(500).json({ ok: false });
  }
});

// JSON parser AFTER webhook
app.use(express.json());

// ---------- Auth helpers ----------
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Missing or invalid token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}
async function getUserPubId(userId) {
  const { rows } = await pool.query('SELECT pub_id FROM users WHERE id=$1 LIMIT 1', [userId]);
  return rows[0]?.pub_id || null;
}

// ---------- Auth ----------
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

    const token = jwt.sign({ userId: user.id, pubName: user.pub_name || null }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/me', requireAuth, async (req, res) => {
  res.json({ userId: req.user.userId, pubName: req.user.pubName || null });
});

// ---------- Dashboard ----------
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
   PRODUCTS (manager CRUD)
   ========================= */

// List my products (filter by gameKey optional)
app.get('/api/raffle/my-products', requireAuth, async (req, res) => {
  try {
    const pubId = await getUserPubId(req.user.userId);
    if (!pubId) return res.json({ products: [] });

    const gameKey = req.query.gameKey || null;
    const args = [pubId];
    let where = 'pub_id=$1';
    if (gameKey) { args.push(gameKey); where += ' AND game_key=$2'; }

    const { rows } = await pool.query(
      `SELECT id, pub_id, game_key, name, price_cents, COALESCE(active,true) AS active, COALESCE(sort_order,0) AS sort_order, created_at
         FROM pub_game_products
        WHERE ${where}
        ORDER BY game_key, sort_order, created_at`,
      args
    );
    res.json({ products: rows });
  } catch (e) {
    console.error('my-products error', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create product
app.post('/api/raffle/products', requireAuth, async (req, res) => {
  try {
    const pubId = await getUserPubId(req.user.userId);
    if (!pubId) return res.status(400).json({ error: 'No pub linked' });

    const { gameKey, name, price_cents, sort_order = 0, active = true } = req.body || {};
    if (!gameKey || !name || !Number.isInteger(Number(price_cents))) {
      return res.status(400).json({ error: 'Missing gameKey/name/price_cents' });
    }

    const ins = await pool.query(
      `INSERT INTO pub_game_products (pub_id, game_key, name, price_cents, sort_order, active)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING id, pub_id, game_key, name, price_cents, active, sort_order, created_at`,
      [pubId, gameKey, name, Number(price_cents), Number(sort_order), !!active]
    );
    res.status(201).json({ product: ins.rows[0] });
  } catch (e) {
    console.error('create product error', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update product
app.put('/api/raffle/products/:id', requireAuth, async (req, res) => {
  try {
    const pubId = await getUserPubId(req.user.userId);
    if (!pubId) return res.status(400).json({ error: 'No pub linked' });

    const id = req.params.id;
    const { name, price_cents, sort_order, active } = req.body || {};

    const { rows: chk } = await pool.query('SELECT id FROM pub_game_products WHERE id=$1 AND pub_id=$2', [id, pubId]);
    if (!chk.length) return res.status(404).json({ error: 'Not found' });

    const upd = await pool.query(
      `UPDATE pub_game_products
          SET name = COALESCE($1, name),
              price_cents = COALESCE($2, price_cents),
              sort_order = COALESCE($3, sort_order),
              active = COALESCE($4, active)
        WHERE id=$5
        RETURNING id, pub_id, game_key, name, price_cents, active, sort_order, created_at`,
      [name ?? null, price_cents ?? null, sort_order ?? null, typeof active === 'boolean' ? active : null, id]
    );
    res.json({ product: upd.rows[0] });
  } catch (e) {
    console.error('update product error', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Reorder products (by array index)
app.post('/api/raffle/products/reorder', requireAuth, async (req, res) => {
  try {
    const pubId = await getUserPubId(req.user.userId);
    if (!pubId) return res.status(400).json({ error: 'No pub linked' });

    const { gameKey, order } = req.body || {};
    if (!gameKey || !Array.isArray(order)) return res.status(400).json({ error: 'Missing gameKey or order[]' });

    for (let i = 0; i < order.length; i++) {
      await pool.query(
        `UPDATE pub_game_products SET sort_order=$1 WHERE id=$2 AND pub_id=$3 AND game_key=$4`,
        [i, order[i], pubId, gameKey]
      );
    }
    res.json({ ok: true });
  } catch (e) {
    console.error('reorder error', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Soft delete (deactivate)
app.delete('/api/raffle/products/:id', requireAuth, async (req, res) => {
  try {
    const pubId = await getUserPubId(req.user.userId);
    if (!pubId) return res.status(400).json({ error: 'No pub linked' });

    const id = req.params.id;
    const { rows: chk } = await pool.query('SELECT id FROM pub_game_products WHERE id=$1 AND pub_id=$2', [id, pubId]);
    if (!chk.length) return res.status(404).json({ error: 'Not found' });

    await pool.query('UPDATE pub_game_products SET active=false WHERE id=$1', [id]);
    res.json({ ok: true });
  } catch (e) {
    console.error('delete product error', e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* =========================
   PUBLIC ENTRY (QR → pay)
   ========================= */

// Public list of products for a pub/game (GBP)
app.get('/api/raffle/products', async (req, res) => {
  try {
    const pubId = Number(req.query.pubId);
    const gameKey = String(req.query.gameKey || '');
    if (!pubId || !gameKey) return res.status(400).json({ error: 'Missing pubId/gameKey' });

    const { rows } = await pool.query(
      `SELECT id, name, price_cents, COALESCE(sort_order,0) AS sort_order
         FROM pub_game_products
        WHERE pub_id=$1 AND game_key=$2 AND COALESCE(active,true)=true
        ORDER BY sort_order, created_at`,
      [pubId, gameKey]
    );
    res.json({ products: rows });
  } catch (e) {
    console.error('public products error', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Start entry + Stripe Checkout (GBP) — public
app.post('/api/raffle/enter', async (req, res) => {
  try {
    const { pubId, gameKey, productId, mobile } = req.body || {};
    if (!pubId || !gameKey || !productId || !mobile) {
      return res.status(400).json({ error: 'Missing fields' });
    }

    // Load chosen product/amount
    const p = await pool.query(
      `SELECT id, price_cents FROM pub_game_products
        WHERE id=$1 AND pub_id=$2 AND game_key=$3 AND COALESCE(active,true)=true LIMIT 1`,
      [productId, pubId, gameKey]
    );
    const prod = p.rows[0];
    if (!prod) return res.status(400).json({ error: 'Invalid product' });

    // Create pending raffle entry (GBP)
    const ins = await pool.query(
      `INSERT INTO raffle_entries (pub_id, game_key, mobile_e164, amount_pennies, currency, status, product_id)
       VALUES ($1,$2,$3,$4,'gbp','pending',$5)
       RETURNING id`,
      [pubId, gameKey, mobile, prod.price_cents, productId]
    );
    const entryId = ins.rows[0].id;

    const successUrl = `${process.env.FRONTEND_URL}/enter/success?entry=${entryId}`;
    const cancelUrl  = `${process.env.FRONTEND_URL}/enter/cancel`;

    // Dynamic GBP price (no pre-made Stripe Price needed)
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
      metadata: { pubId: String(pubId), gameKey, entryId, productId: String(productId) },
    });

    await pool.query('UPDATE raffle_entries SET stripe_cs=$1 WHERE id=$2', [session.id, entryId]);
    res.json({ checkoutUrl: session.url });
  } catch (e) {
    console.error('raffle enter error', e);
    res.status(500).json({ error: 'Unable to start entry' });
  }
});

/* =========================
   STAFF RAFFLE (paid → draw → used)
   ========================= */

// List paid entries (latest first)
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

// Draw a random winner from paid
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

// Mark winner as used when the player starts
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

// ---------- 404 ----------
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});