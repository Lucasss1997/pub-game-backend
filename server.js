// server.js
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const cookieParser = require('cookie-parser');
const WebSocket = require('ws');
require('dotenv').config();

const app = express();

const FRONTEND_ORIGIN = process.env.ALLOW_ORIGIN || '*';
app.use(cors({
  origin: FRONTEND_ORIGIN === '*' ? true : FRONTEND_ORIGIN,
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === 'disable' ? false : { rejectUnauthorized: false },
});

// ---------- helpers
function signToken(claims) {
  return jwt.sign(claims, JWT_SECRET, { expiresIn: '1d' });
}
function requireAuth(req, res, next) {
  const bearer = req.headers.authorization;
  const headerToken = bearer?.startsWith('Bearer ') ? bearer.slice(7) : null;
  const cookieToken = req.cookies?.token;
  const token = headerToken || cookieToken;
  if (!token) return res.status(401).json({ ok:false, error:'Unauthorized' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ ok:false, error:'Invalid token' });
  }
}
function parsePoundsToCents(v) {
  if (v == null) return 0;
  if (typeof v === 'number' && Number.isFinite(v)) return Math.round(v * 100);
  let s = String(v).trim().replace(/[£,\s]/g, '').replace(/p$/i,'');
  if (!/^\d+(\.\d{0,2})?$/.test(s)) {
    const err = new Error('Invalid money format'); err.status = 400; throw err;
  }
  return Math.round(parseFloat(s) * 100);
}

// ---------- health/index
app.get('/healthz', (_req,res)=>res.json({ok:true,service:'pub-game-backend'}));
app.get('/', (_req,res)=>{
  res.json({
    ok:true, service:'pub-game-backend',
    login:'POST /api/login', register:'POST /api/register',
    me:'GET /api/me (auth)', dashboard:'GET /api/dashboard (auth)',
    admin:{ products_get:'GET /api/admin/products', products_post:'POST /api/admin/products',
      jackpot_get:'GET /api/admin/jackpot', jackpot_post:'POST /api/admin/jackpot', debug:'GET /api/admin/debug' }
  });
});

// ---------- auth
app.post('/api/register', async (req,res)=>{
  const { email, password, pubId, pubName } = req.body || {};
  if (!email || !password) return res.status(400).json({ ok:false, error:'Missing fields' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query(
      `INSERT INTO users (email, password_hash, pub_id, pub_name)
       VALUES ($1,$2,$3,$4) RETURNING id, email, pub_id`,
      [email, hash, pubId || null, pubName || null]
    );
    const u = r.rows[0];
    const token = signToken({ id:u.id, email:u.email, pub_id:u.pub_id||null });
    res.cookie('token', token, { httpOnly:true, sameSite:'none', secure:true });
    res.json({ ok:true, token });
  } catch (e) {
    console.error('register', e);
    res.status(500).json({ ok:false, error:'Server error' });
  }
});

app.post('/api/login', async (req,res)=>{
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ ok:false, error:'Missing fields' });
  try {
    const r = await pool.query('SELECT id,email,password_hash,pub_id FROM users WHERE email=$1', [email]);
    if (!r.rows.length) return res.status(401).json({ ok:false, error:'Invalid credentials' });
    const u = r.rows[0];
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(401).json({ ok:false, error:'Invalid credentials' });
    const token = signToken({ id:u.id, email:u.email, pub_id:u.pub_id||null });
    res.cookie('token', token, { httpOnly:true, sameSite:'none', secure:true });
    res.json({ ok:true, token });
  } catch (e) {
    console.error('login', e);
    res.status(500).json({ ok:false, error:'Server error' });
  }
});

app.post('/api/logout', (req,res)=>{
  res.clearCookie('token'); res.json({ ok:true });
});

app.get('/api/me', requireAuth, (req,res)=> res.json({ ok:true, user:req.user }));

// ---------- dashboard
app.get('/api/dashboard', requireAuth, async (req,res)=>{
  const pubId = req.user?.pub_id;
  if (!pubId) return res.status(409).json({ ok:false, code:'NO_PUB_ID', error:'Account not linked to a pub' });
  try {
    const [pubRs, prodRs, statRs] = await Promise.all([
      pool.query('SELECT id,name,city,address,expires_on FROM pubs WHERE id=$1', [pubId]),
      pool.query('SELECT game_key,name,price_cents,active FROM pub_game_products WHERE pub_id=$1 ORDER BY game_key', [pubId]),
      pool.query('SELECT COALESCE(jackpot_cents,0) AS jackpot_cents, COALESCE(players_this_week,0) AS players_this_week, COALESCE(prizes_won,0) AS prizes_won FROM pub_stats WHERE pub_id=$1', [pubId]),
    ]);
    if (!pubRs.rows.length) return res.status(404).json({ ok:false, code:'PUB_NOT_FOUND', error:`No pub ${pubId}` });
    res.json({
      ok:true,
      pub: pubRs.rows[0],
      products: prodRs.rows || [],
      stats: statRs.rows[0] || { jackpot_cents:0, players_this_week:0, prizes_won:0 }
    });
  } catch (e) {
    console.error('dashboard', e);
    res.status(500).json({ ok:false, error:'Server error' });
  }
});

// ---------- admin
app.get('/api/admin/products', requireAuth, async (req,res)=>{
  const pubId = req.user?.pub_id;
  if (!pubId) return res.status(409).json({ ok:false, error:'NO_PUB_ID' });
  try {
    const { rows } = await pool.query(
      'SELECT game_key,name,price_cents,active FROM pub_game_products WHERE pub_id=$1 ORDER BY game_key', [pubId]
    );
    res.json({ ok:true, products: rows||[] });
  } catch (e) {
    console.error('get products', e);
    res.status(500).json({ ok:false, error:'Server error' });
  }
});

app.post('/api/admin/products', requireAuth, async (req,res)=>{
  const pubId = req.user?.pub_id;
  if (!pubId) return res.status(409).json({ ok:false, error:'NO_PUB_ID' });
  try {
    const rows = Array.isArray(req.body?.products) ? req.body.products : [];
    for (const p of rows) {
      const priceCents = parsePoundsToCents(p?.price);
      await pool.query(
        `INSERT INTO pub_game_products(pub_id,game_key,name,price_cents,active)
         VALUES($1,$2,$3,$4,$5)
         ON CONFLICT(pub_id,game_key) DO UPDATE
         SET name=EXCLUDED.name, price_cents=EXCLUDED.price_cents, active=EXCLUDED.active`,
        [pubId, p.game_key, p.name||'', priceCents, !!p.active]
      );
    }
    res.json({ ok:true });
  } catch (e) {
    console.error('post products', e);
    res.status(e.status||500).json({ ok:false, error:e.message||'Server error' });
  }
});

app.get('/api/admin/jackpot', requireAuth, async (req,res)=>{
  const pubId = req.user?.pub_id;
  if (!pubId) return res.status(409).json({ ok:false, error:'NO_PUB_ID' });
  try {
    const { rows } = await pool.query(
      'SELECT COALESCE(jackpot_cents,0) AS jackpot_cents FROM pub_settings WHERE pub_id=$1', [pubId]
    );
    res.json({ ok:true, jackpot_cents: rows[0]?.jackpot_cents ?? 0 });
  } catch (e) {
    console.error('get jackpot', e);
    res.status(500).json({ ok:false, error:'Server error' });
  }
});

app.post('/api/admin/jackpot', requireAuth, async (req,res)=>{
  const pubId = req.user?.pub_id;
  if (!pubId) return res.status(409).json({ ok:false, error:'NO_PUB_ID' });
  try {
    const cents = parsePoundsToCents(req.body?.jackpot);
    await pool.query(
      `INSERT INTO pub_settings(pub_id,jackpot_cents)
       VALUES($1,$2)
       ON CONFLICT(pub_id) DO UPDATE SET jackpot_cents=EXCLUDED.jackpot_cents`,
      [pubId, cents]
    );
    res.json({ ok:true, jackpot_cents:cents });
  } catch (e) {
    console.error('post jackpot', e);
    res.status(e.status||500).json({ ok:false, error:e.message||'Server error' });
  }
});

app.get('/api/admin/debug', requireAuth, async (req,res)=>{
  try {
    const pubId = req.user?.pub_id;
    const pub = await pool.query('SELECT id FROM pubs WHERE id=$1', [pubId]);
    const prods = await pool.query('SELECT COUNT(*)::int AS n FROM pub_game_products WHERE pub_id=$1', [pubId]);
    const jp = await pool.query('SELECT COALESCE(jackpot_cents,0) AS jackpot_cents FROM pub_settings WHERE pub_id=$1', [pubId]);
    res.json({ ok:true, user:req.user, pubExists:!!pub.rows.length, products:prods.rows[0]?.n??0, jackpot_cents:jp.rows[0]?.jackpot_cents??0 });
  } catch (e) { res.status(500).json({ ok:false, error:e.message }); }
});

// ---------- DEV: ensure user (use once, then remove/disable)
app.post('/api/dev/ensure-user', async (req,res)=>{
  try {
    const { email, password, pub_id=1 } = req.body || {};
    if (!email || !password) return res.status(400).json({ ok:false, error:'email/password required' });
    const r = await pool.query('SELECT id FROM users WHERE email=$1', [email]);
    if (r.rows.length) return res.json({ ok:true, created:false });
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users(email,password_hash,pub_id) VALUES ($1,$2,$3)', [email,hash,pub_id]);
    res.json({ ok:true, created:true });
  } catch (e) {
    console.error('ensure-user', e);
    res.status(500).json({ ok:false, error:'Server error' });
  }
});

// ---------- simple game stub
app.post('/api/games/crack_the_safe', (req,res)=>{
  const { guess } = req.body || {};
  if (!/^\d{3}$/.test(String(guess||''))) return res.status(400).json({ ok:false, error:'Guess must be three digits' });
  const correct = process.env.SAFE_CODE || '459';
  res.json({ ok:true, result: guess===correct ? 'correct':'incorrect' });
});

// ---------- start + websockets
const server = app.listen(PORT, ()=>console.log(`backend on :${PORT}`));
const wss = new WebSocket.Server({ server });
wss.on('connection', ws=>{
  ws.on('message', m=> ws.send(String(m)));
});