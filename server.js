// Full drop-in server.js with Stripe billing (Checkout + Webhook + Portal + Invoices)
// - Keeps your existing health, auth, and dashboard endpoints
// - Adds /api/billing/checkout, /api/billing/webhook, /api/billing/portal, /api/billing/invoices
// - Auto-extends pubs.expires_at after successful Checkout (one-off payments)
//
// ENV (Render → Environment):
//   DATABASE_URL=postgres://...
//   JWT_SECRET=your_long_random_secret
//   STRIPE_SECRET_KEY=sk_test_...
//   STRIPE_WEBHOOK_SECRET=whsec_...
//   PRICE_ID=price_12345                // Stripe Price ID (one-off or recurring)
//   SUBSCRIPTION_DAYS=30                // days to extend on success (for one-off mode)
//   FRONTEND_URL=https://your-frontend  // used for success/cancel/portal return

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

// --- DB (Render/Railway compatible) ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// --- Health & Root ---
app.get('/', (req, res) => {
  res.json({
    ok: true,
    service: 'pub-game-backend',
    health: '/healthz',
    login: 'POST /api/login',
    register: 'POST /api/register',
    me: 'GET /api/me',
    dashboard: 'GET /api/dashboard (auth)',
    billing: {
      checkout: 'POST /api/billing/checkout (auth)',
      portal: 'POST /api/billing/portal (auth)',
      invoices: 'GET /api/billing/invoices (auth)',
      webhook: 'POST /api/billing/webhook (Stripe)'
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

// --- Stripe Webhook (MUST be before express.json to keep raw body) ---
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
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        const pubId = session.metadata?.pubId;
        const customerId = session.customer;
        const days = Number(process.env.SUBSCRIPTION_DAYS || 30);

        if (pubId) {
          // Save/reuse customer for portal & invoices
          if (customerId) {
            await pool.query('ALTER TABLE pubs ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT');
            await pool.query('UPDATE pubs SET stripe_customer_id = $1 WHERE id = $2', [customerId, pubId]);
          }
          // Extend expiry for one-off payments
          if (session.mode === 'payment') {
            await pool.query('ALTER TABLE pubs ADD COLUMN IF NOT EXISTS expires_at timestamptz');
            await pool.query(`
              UPDATE pubs
              SET expires_at = CASE
                WHEN expires_at IS NOT NULL AND expires_at > NOW()
                  THEN expires_at + ($1 || ' days')::interval
                ELSE NOW() + ($1 || ' days')::interval
              END
              WHERE id = $2
            `, [days, pubId]);
          }
        }
        break;
      }

      case 'invoice.payment_succeeded': {
        // If you switch to subscription mode, you can also react here.
        break;
      }

      default:
        // console.log('Unhandled event:', event.type);
        break;
    }

    res.json({ received: true });
  } catch (e) {
    console.error('Webhook handling error:', e);
    res.status(500).json({ ok: false });
  }
});

// --- JSON parser (after webhook) ---
app.use(express.json());

// --- Helpers ---
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const parts = authHeader.split(' ');
  const token = parts.length === 2 ? parts[1] : null;
  if (!token) return res.status(401).json({ error: 'Missing or invalid token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// --- Auth ---
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

// --- Dashboard (expects users.pub_id + pubs table) ---
app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    const uid = req.user.userId;

    const { rows: userRows } = await pool.query('SELECT pub_id FROM users WHERE id = $1 LIMIT 1', [uid]);
    if (!userRows.length || !userRows[0].pub_id) {
      return res.json({ pubs: [] });
    }

    const pubId = userRows[0].pub_id;
    const { rows: pubs } = await pool.query('SELECT * FROM pubs WHERE id = $1', [pubId]);
    res.json({ pubs });
  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// --- Billing: create Checkout session (one-off by default) ---
app.post('/api/billing/checkout', requireAuth, async (req, res) => {
  try {
    const uid = req.user.userId;

    const { rows: urows } = await pool.query('SELECT pub_id FROM users WHERE id = $1 LIMIT 1', [uid]);
    const pubId = urows[0]?.pub_id;
    if (!pubId) return res.status(400).json({ error: 'No pub linked to this user' });

    const priceId = process.env.PRICE_ID;
    const successUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/billing?success=1`;
    const cancelUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/billing?canceled=1`;

    // Re-use existing customer if we have one
    const { rows: prow } = await pool.query('SELECT stripe_customer_id FROM pubs WHERE id = $1 LIMIT 1', [pubId]);
    const existingCustomer = prow[0]?.stripe_customer_id || undefined;

    const session = await stripe.checkout.sessions.create({
      mode: 'payment', // switch to 'subscription' if using a recurring price
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: successUrl,
      cancel_url: cancelUrl,
      customer: existingCustomer,
      customer_creation: existingCustomer ? 'if_required' : 'always',
      client_reference_id: String(pubId),
      metadata: { pubId: String(pubId), userId: String(uid) },
    });

    res.json({ checkoutUrl: session.url });
  } catch (e) {
    console.error('Checkout error:', e);
    res.status(500).json({ error: 'Unable to create checkout session' });
  }
});

// --- Billing: customer portal ---
app.post('/api/billing/portal', requireAuth, async (req, res) => {
  try {
    const uid = req.user.userId;
    const returnUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/billing`;

    const { rows } = await pool.query(
      `SELECT p.stripe_customer_id
         FROM users u
         JOIN pubs p ON p.id = u.pub_id
        WHERE u.id = $1 LIMIT 1`,
      [uid]
    );
    const customer = rows[0]?.stripe_customer_id;
    if (!customer) return res.status(400).json({ error: 'No Stripe customer found for this pub' });

    const portal = await stripe.billingPortal.sessions.create({
      customer,
      return_url: returnUrl,
    });

    res.json({ url: portal.url });
  } catch (e) {
    console.error('Portal error:', e);
    res.status(500).json({ error: 'Unable to create portal session' });
  }
});

// --- Billing: list invoices ---
app.get('/api/billing/invoices', requireAuth, async (req, res) => {
  try {
    const uid = req.user.userId;
    const { rows } = await pool.query(
      `SELECT p.stripe_customer_id
         FROM users u
         JOIN pubs p ON p.id = u.pub_id
        WHERE u.id = $1 LIMIT 1`,
      [uid]
    );
    const customer = rows[0]?.stripe_customer_id;
    if (!customer) return res.json({ invoices: [] });

    const list = await stripe.invoices.list({ customer, limit: 10 });
    res.json({
      invoices: list.data.map((inv) => ({
        id: inv.id,
        amount_due: inv.amount_due,
        currency: inv.currency,
        status: inv.status,
        created: inv.created * 1000, // ms
        hosted_invoice_url: inv.hosted_invoice_url,
        number: inv.number || null,
      })),
    });
  } catch (e) {
    console.error('Invoices error:', e);
    res.status(500).json({ error: 'Unable to list invoices' });
  }
});

// --- 404 JSON fallback (keep LAST) ---
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// --- Start ---
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
