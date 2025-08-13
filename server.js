// server.js (Node/Express backend)
// Run with: node server.js
// Env needed:
// - PORT
// - DATABASE_URL
// - JWT_SECRET
// (Optionally: SMTP_* if you later enable email digests)

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const cookieParser = require("cookie-parser");
const WebSocket = require("ws");
require("dotenv").config();

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("localhost")
    ? false
    : { rejectUnauthorized: false },
});

/* --------------------- helpers --------------------- */

function requireAuth(req, res, next) {
  // Prefer cookie; fallback to Bearer
  const token = req.cookies.token || req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function parsePoundsToCents(input) {
  if (input === null || input === undefined) return 0;
  if (typeof input === "number" && Number.isFinite(input)) {
    return Math.round(input * 100);
  }
  let s = String(input).trim();
  s = s.replace(/[£\s,]/g, "").replace(/p$/i, "");
  if (s === "" || s === ".") return 0;
  if (!/^\d+(\.\d{0,2})?$/.test(s)) {
    const err = new Error("Invalid money format");
    err.status = 400;
    throw err;
  }
  return Math.round(parseFloat(s) * 100);
}

/* --------------------- auth --------------------- */

app.post("/api/register", async (req, res) => {
  const { email, password, pubName } = req.body || {};
  if (!email || !password || !pubName) {
    return res.status(400).json({ error: "Missing fields" });
  }
  try {
    const hashed = await bcrypt.hash(password, 10);

    // Create pub record if needed (simple demo: one pub per user)
    const pub = await pool.query(
      `INSERT INTO pubs(name) VALUES ($1) RETURNING id, name`,
      [pubName]
    );

    const user = await pool.query(
      `INSERT INTO users(email, password_hash, pub_id)
       VALUES ($1,$2,$3)
       RETURNING id, email, pub_id`,
      [email, hashed, pub.rows[0].id]
    );

    res.json({ id: user.rows[0].id, pub_id: user.rows[0].pub_id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Missing fields" });
  try {
    const r = await pool.query(`SELECT id, email, password_hash, pub_id FROM users WHERE email=$1`, [email]);
    if (!r.rows.length) return res.status(401).json({ error: "Invalid credentials" });
    const u = r.rows[0];
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: u.id, pub_id: u.pub_id }, JWT_SECRET, { expiresIn: "1d" });
    res.cookie("token", token, { httpOnly: true, sameSite: "lax", secure: true, maxAge: 86400000 });
    res.json({ token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ ok: true });
});

/* --------------------- dashboard --------------------- */

app.get("/api/dashboard", requireAuth, async (req, res) => {
  try {
    const pubId = req.user.pub_id;

    const [{ rows: pubRows }, { rows: prodRows }, { rows: statRows }] = await Promise.all([
      pool.query(`SELECT id, name FROM pubs WHERE id=$1`, [pubId]),
      pool.query(
        `SELECT game_key, name, price_cents, active
         FROM pub_game_products
         WHERE pub_id=$1
         ORDER BY game_key`,
        [pubId]
      ),
      pool.query(
        `SELECT COALESCE(SUM(jackpot_cents),0) AS jackpot_cents
         FROM pub_game_jackpots
         WHERE pub_id=$1`,
        [pubId]
      ),
    ]);

    res.json({
      pub: pubRows[0] || null,
      products: prodRows || [],
      stats: { jackpot_cents: statRows[0]?.jackpot_cents ?? 0 },
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

/* --------------------- admin: products --------------------- */

// upsert array of products: [{game_key, name, price, active}]
app.post("/api/admin/products", requireAuth, async (req, res) => {
  try {
    const pubId = req.user.pub_id;
    const rows = Array.isArray(req.body?.products) ? req.body.products : [];
    for (const p of rows) {
      const priceCents = parsePoundsToCents(p?.price);
      await pool.query(
        `INSERT INTO pub_game_products(pub_id, game_key, name, price_cents, active)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (pub_id, game_key)
         DO UPDATE SET name=EXCLUDED.name, price_cents=EXCLUDED.price_cents, active=EXCLUDED.active`,
        [pubId, p.game_key, p.name || "", priceCents, !!p.active]
      );
    }
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(e.status || 500).json({ error: e.message || "Server error" });
  }
});

// fetch products for admin UI
app.get("/api/admin/products", requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT game_key, name, price_cents, active
       FROM pub_game_products
       WHERE pub_id=$1
       ORDER BY game_key`,
      [req.user.pub_id]
    );
    res.json({ products: rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

/* --------------------- admin: per-game jackpot --------------------- */

// set jackpot for a single game
// body: { game_key, jackpot }  (jackpot pounds string/number)
app.post("/api/admin/jackpot", requireAuth, async (req, res) => {
  try {
    const pubId = req.user.pub_id;
    const gameKey = String(req.body?.game_key || "").trim();
    if (!gameKey) return res.status(400).json({ error: "Missing game_key" });

    const cents = parsePoundsToCents(req.body?.jackpot);
    await pool.query(
      `INSERT INTO pub_game_jackpots(pub_id, game_key, jackpot_cents)
       VALUES ($1,$2,$3)
       ON CONFLICT (pub_id, game_key)
       DO UPDATE SET jackpot_cents=EXCLUDED.jackpot_cents`,
      [pubId, gameKey, cents]
    );
    res.json({ ok: true, game_key: gameKey, jackpot_cents: cents });
  } catch (e) {
    console.error(e);
    res.status(e.status || 500).json({ error: e.message || "Server error" });
  }
});

// get jackpot for a single game
app.get("/api/admin/jackpot/:gameKey", requireAuth, async (req, res) => {
  try {
    const pubId = req.user.pub_id;
    const gameKey = req.params.gameKey;
    const { rows } = await pool.query(
      `SELECT jackpot_cents
       FROM pub_game_jackpots
       WHERE pub_id=$1 AND game_key=$2`,
      [pubId, gameKey]
    );
    res.json({ jackpot_cents: rows[0]?.jackpot_cents ?? 0 });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

/* --------------------- public game read --------------------- */

// used by player pages (no auth)
app.get("/api/game/:pubId/:gameKey", async (req, res) => {
  try {
    const { pubId, gameKey } = req.params;
    const { rows } = await pool.query(
      `SELECT p.game_key, p.name, p.price_cents, p.active,
              COALESCE(j.jackpot_cents,0) AS jackpot_cents
       FROM pub_game_products p
       LEFT JOIN pub_game_jackpots j
         ON j.pub_id = p.pub_id AND j.game_key = p.game_key
       WHERE p.pub_id=$1 AND p.game_key=$2`,
      [pubId, gameKey]
    );
    if (!rows.length) return res.status(404).json({ error: "Not found" });
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

/* --------------------- bootstrap tables (optional safety) --------------------- */

async function ensureTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pubs (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      pub_id INTEGER REFERENCES pubs(id) ON DELETE CASCADE
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pub_game_products (
      pub_id INTEGER NOT NULL REFERENCES pubs(id) ON DELETE CASCADE,
      game_key TEXT NOT NULL,
      name TEXT NOT NULL,
      price_cents INTEGER NOT NULL DEFAULT 0,
      active BOOLEAN NOT NULL DEFAULT false,
      PRIMARY KEY (pub_id, game_key)
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pub_game_jackpots (
      pub_id INTEGER NOT NULL REFERENCES pubs(id) ON DELETE CASCADE,
      game_key TEXT NOT NULL,
      jackpot_cents INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (pub_id, game_key)
    );
  `);
}
ensureTables().catch(console.error);

/* --------------------- websocket (optional) --------------------- */

const server = app.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`);
});
const wss = new WebSocket.Server({ server });
wss.on("connection", (ws) => {
  ws.on("message", (msg) => {
    ws.send(`Echo: ${msg}`);
  });
});