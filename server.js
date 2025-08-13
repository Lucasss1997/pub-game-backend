// server/index.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");

const app = express();
app.use(express.json());
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);
app.use(cookieParser());

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});

/* -------------------- helpers -------------------- */
function requireAuth(req, res, next) {
  const bearer = req.headers.authorization;
  const cookieTok = req.cookies?.token;
  const token = bearer?.startsWith("Bearer ") ? bearer.slice(7) : cookieTok;
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { id, pub_id }
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function parsePoundsToCents(v) {
  if (v === null || v === undefined || v === "") return 0;
  if (typeof v === "number") return Math.round(v * 100);
  let s = String(v).trim().replace(/[£,\s]/g, "").replace(/p$/i, "");
  if (!/^\d+(\.\d{0,2})?$/.test(s)) throw Object.assign(new Error("Invalid money format"), { status: 400 });
  return Math.round(parseFloat(s) * 100);
}

function centsToPounds(cents) {
  const n = Number(cents || 0);
  return (n / 100).toFixed(2);
}

/* -------------------- auth -------------------- */
// Minimal examples; your schema may already exist.
app.post("/api/register", async (req, res) => {
  const { email, password, pubName } = req.body || {};
  if (!email || !password || !pubName) return res.status(400).json({ error: "Missing fields" });

  try {
    const hash = await bcrypt.hash(password, 10);
    const { rows: pubRows } = await pool.query(
      `INSERT INTO pubs(name) VALUES ($1) RETURNING id`,
      [pubName]
    );
    const pubId = pubRows[0].id;

    const { rows } = await pool.query(
      `INSERT INTO users(email, password_hash, pub_id)
       VALUES ($1,$2,$3)
       RETURNING id, email, pub_id`,
      [email, hash, pubId]
    );
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Missing fields" });

  try {
    const { rows } = await pool.query(`SELECT * FROM users WHERE email=$1`, [email]);
    if (!rows.length) return res.status(401).json({ error: "Invalid credentials" });
    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: user.id, pub_id: user.pub_id }, JWT_SECRET, { expiresIn: "2d" });
    res.cookie("token", token, { httpOnly: true, sameSite: "lax", secure: true });
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

/* -------------------- dashboard (unchanged) -------------------- */
app.get("/api/dashboard", requireAuth, async (req, res) => {
  try {
    const pubId = req.user.pub_id;
    const [{ rows: pubRows }, { rows: prodRows }, { rows: jackRows }] = await Promise.all([
      pool.query(`SELECT name, city, address, expires_on FROM pubs WHERE id=$1`, [pubId]),
      pool.query(
        `SELECT game_key, name, price_cents, active
         FROM pub_game_products
         WHERE pub_id=$1
         ORDER BY game_key`,
        [pubId]
      ),
      pool.query(
        `SELECT game_key, jackpot_cents
         FROM pub_game_jackpots
         WHERE pub_id=$1`,
        [pubId]
      ),
    ]);

    // attach jackpots to products
    const jackpotByGame = Object.fromEntries(jackRows.map(r => [r.game_key, r.jackpot_cents]));
    const products = prodRows.map(p => ({
      ...p,
      jackpot_cents: jackpotByGame[p.game_key] || 0,
    }));

    res.json({
      pub: pubRows[0] || null,
      products,
      stats: { players_this_week: 0, prizes_won: 0 }, // fill as needed
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

/* -------------------- ADMIN: products & per-game jackpots -------------------- */

// Get all products for this pub + jackpots
app.get("/api/admin/products", requireAuth, async (req, res) => {
  try {
    const pubId = req.user.pub_id;
    const { rows: products } = await pool.query(
      `SELECT game_key, name, price_cents, active
       FROM pub_game_products
       WHERE pub_id=$1
       ORDER BY game_key`,
      [pubId]
    );
    const { rows: jackpots } = await pool.query(
      `SELECT game_key, jackpot_cents
       FROM pub_game_jackpots
       WHERE pub_id=$1`,
      [pubId]
    );
    res.json({
      products,
      jackpots: Object.fromEntries(jackpots.map(j => [j.game_key, j.jackpot_cents])),
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// Upsert a single product (name, price, active) for a given game_key
app.post("/api/admin/product", requireAuth, async (req, res) => {
  try {
    const pubId = req.user.pub_id;
    const { game_key, name, price, active } = req.body || {};
    if (!game_key) return res.status(400).json({ error: "Missing game_key" });

    const price_cents = parsePoundsToCents(price);
    await pool.query(
      `INSERT INTO pub_game_products(pub_id, game_key, name, price_cents, active)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (pub_id, game_key)
       DO UPDATE SET name=EXCLUDED.name, price_cents=EXCLUDED.price_cents, active=EXCLUDED.active`,
      [pubId, game_key, name || "", price_cents, !!active]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(e.status || 500).json({ error: e.message || "Server error" });
  }
});

// Get/set per-game jackpot
app.get("/api/admin/jackpot", requireAuth, async (req, res) => {
  try {
    const pubId = req.user.pub_id;
    const game_key = req.query.game_key;
    if (!game_key) return res.status(400).json({ error: "Missing game_key" });
    const { rows } = await pool.query(
      `SELECT jackpot_cents FROM pub_game_jackpots WHERE pub_id=$1 AND game_key=$2`,
      [pubId, game_key]
    );
    res.json({ game_key, jackpot_cents: rows[0]?.jackpot_cents || 0 });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/admin/jackpot", requireAuth, async (req, res) => {
  try {
    const pubId = req.user.pub_id;
    const { game_key, jackpot } = req.body || {};
    if (!game_key) return res.status(400).json({ error: "Missing game_key" });
    const cents = parsePoundsToCents(jackpot);
    await pool.query(
      `INSERT INTO pub_game_jackpots(pub_id, game_key, jackpot_cents)
       VALUES ($1,$2,$3)
       ON CONFLICT (pub_id, game_key)
       DO UPDATE SET jackpot_cents=EXCLUDED.jackpot_cents`,
      [pubId, game_key, cents]
    );
    res.json({ ok: true, game_key, jackpot_cents: cents });
  } catch (e) {
    console.error(e);
    res.status(e.status || 500).json({ error: e.message || "Server error" });
  }
});

/* -------------------- start -------------------- */
app.get("/", (_req, res) => res.json({ ok: true, service: "pub-game-backend" }));

app.listen(PORT, () => {
  console.log(`Backend running on :${PORT}`);
});