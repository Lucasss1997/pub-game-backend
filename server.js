const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Middleware for protected routes
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Missing token' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// -------------------- AUTH --------------------

// Register
app.post('/api/register', async (req, res) => {
  const { email, password, pubName } = req.body;
  if (!email || !password || !pubName) {
    return res.status(400).json({ error: 'Missing email, password, or pub name' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const pubResult = await pool.query(
      'INSERT INTO pubs (name) VALUES ($1) RETURNING id',
      [pubName]
    );
    const pubId = pubResult.rows[0].id;

    const result = await pool.query(
      'INSERT INTO users (email, password_hash, pub_id) VALUES ($1, $2, $3) RETURNING id',
      [email, hashedPassword, pubId]
    );

    res.json({ id: result.rows[0].id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user.id }, JWT_SECRET);
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// -------------------- DASHBOARD --------------------
app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    const userRes = await pool.query(
      'SELECT pubs.* FROM pubs JOIN users ON pubs.id = users.pub_id WHERE users.id = $1',
      [req.user.userId]
    );
    const pub = userRes.rows[0];
    if (!pub) return res.status(404).json({ error: 'Pub not found' });

    res.json({
      pub: {
        name: pub.name,
        city: pub.city || 'Unknown',
        address: pub.address || 'Unknown',
        expires: pub.expires_at || null
      },
      stats: {
        playersThisWeek: 12,
        prizesWon: 3
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// -------------------- ADMIN: PRODUCTS & JACKPOT --------------------
app.get('/api/admin/products', requireAuth, async (req, res) => {
  try {
    const { rows: urows } = await pool.query(
      'SELECT pub_id FROM users WHERE id = $1 LIMIT 1',
      [req.user.userId]
    );
    const pubId = urows[0]?.pub_id;
    if (!pubId) return res.status(400).json({ error: 'No pub linked to this user' });

    await pool.query(`
      CREATE TABLE IF NOT EXISTS pub_game_products (
        id SERIAL PRIMARY KEY,
        pub_id INTEGER NOT NULL,
        game_key TEXT NOT NULL,
        name TEXT NOT NULL,
        price_cents INTEGER NOT NULL DEFAULT 0,
        active BOOLEAN NOT NULL DEFAULT TRUE,
        sort_order INTEGER NOT NULL DEFAULT 0,
        created_at timestamptz NOT NULL DEFAULT NOW(),
        updated_at timestamptz NOT NULL DEFAULT NOW()
      );
      CREATE UNIQUE INDEX IF NOT EXISTS idx_products_pub_game
        ON pub_game_products (pub_id, game_key);
    `);

    const { rows } = await pool.query(
      `SELECT game_key, name, price_cents, active
         FROM pub_game_products
        WHERE pub_id = $1
        ORDER BY sort_order, game_key`,
      [pubId]
    );

    if (!rows.length) {
      await pool.query(
        `INSERT INTO pub_game_products (pub_id, game_key, name, price_cents, active, sort_order)
         VALUES
         ($1, 'crack', 'Crack the Safe Ticket', 200, TRUE, 1),
         ($1, 'box',   'What’s in the Box Ticket', 200, TRUE, 2)
         ON CONFLICT (pub_id, game_key) DO NOTHING`,
        [pubId]
      );
      const seeded = await pool.query(
        `SELECT game_key, name, price_cents, active
           FROM pub_game_products
          WHERE pub_id = $1
          ORDER BY sort_order, game_key`,
        [pubId]
      );
      return res.json({ products: seeded.rows });
    }

    res.json({ products: rows });
  } catch (e) {
    console.error('GET /api/admin/products error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/products', requireAuth, async (req, res) => {
  try {
    const { game_key, name, price_cents, active } = req.body || {};
    if (!game_key || name == null || price_cents == null)
      return res.status(400).json({ error: 'Missing game_key, name or price_cents' });

    const { rows: urows } = await pool.query(
      'SELECT pub_id FROM users WHERE id = $1 LIMIT 1',
      [req.user.userId]
    );
    const pubId = urows[0]?.pub_id;
    if (!pubId) return res.status(400).json({ error: 'No pub linked to this user' });

    await pool.query(
      `INSERT INTO pub_game_products (pub_id, game_key, name, price_cents, active, updated_at)
       VALUES ($1, $2, $3, $4, $5, NOW())
       ON CONFLICT (pub_id, game_key)
       DO UPDATE SET name = EXCLUDED.name,
                     price_cents = EXCLUDED.price_cents,
                     active = EXCLUDED.active,
                     updated_at = NOW()`,
      [pubId, game_key, name, Number(price_cents), !!active]
    );

    res.json({ ok: true });
  } catch (e) {
    console.error('POST /api/admin/products error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/jackpot', requireAuth, async (req, res) => {
  try {
    const { rows: urows } = await pool.query(
      'SELECT pub_id FROM users WHERE id = $1 LIMIT 1',
      [req.user.userId]
    );
    const pubId = urows[0]?.pub_id;
    if (!pubId) return res.status(400).json({ error: 'No pub linked to this user' });

    await pool.query(`
      CREATE TABLE IF NOT EXISTS pub_jackpots (
        pub_id INTEGER PRIMARY KEY,
        jackpot_cents INTEGER NOT NULL DEFAULT 0,
        updated_at timestamptz NOT NULL DEFAULT NOW()
      );
    `);

    const { rows } = await pool.query(
      'SELECT jackpot_cents FROM pub_jackpots WHERE pub_id = $1 LIMIT 1',
      [pubId]
    );
    const jackpot_cents = rows[0]?.jackpot_cents ?? 0;
    res.json({ jackpot_cents });
  } catch (e) {
    console.error('GET /api/admin/jackpot error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/jackpot', requireAuth, async (req, res) => {
  try {
    const { jackpot_cents } = req.body || {};
    if (jackpot_cents == null) return res.status(400).json({ error: 'Missing jackpot_cents' });

    const { rows: urows } = await pool.query(
      'SELECT pub_id FROM users WHERE id = $1 LIMIT 1',
      [req.user.userId]
    );
    const pubId = urows[0]?.pub_id;
    if (!pubId) return res.status(400).json({ error: 'No pub linked to this user' });

    await pool.query(
      `INSERT INTO pub_jackpots (pub_id, jackpot_cents, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (pub_id)
       DO UPDATE SET jackpot_cents = EXCLUDED.jackpot_cents,
                     updated_at = NOW()`,
      [pubId, Number(jackpot_cents)]
    );

    res.json({ ok: true });
  } catch (e) {
    console.error('POST /api/admin/jackpot error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// -------------------- SERVER START --------------------
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});