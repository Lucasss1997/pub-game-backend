const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const http = require('http');
const WebSocket = require('ws');
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

// HTTP + WebSocket server
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

function broadcast(message) {
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(message));
    }
  });
}

// Middleware for JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// --- AUTH ---
app.post('/api/register', async (req, res) => {
  const { email, password, pubName } = req.body;
  if (!email || !password || !pubName) {
    return res.status(400).json({ error: 'Missing email, password, or pub name' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, pub_name) VALUES ($1, $2, $3) RETURNING id',
      [email, hashedPassword, pubName]
    );
    res.status(201).json({ id: result.rows[0].id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid email or password' });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid email or password' });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- GAMES ---
app.get('/api/games', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM games ORDER BY id');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/games/:id/guess', async (req, res) => {
  const { id } = req.params;
  const { guess } = req.body;
  try {
    const result = await pool.query('SELECT * FROM games WHERE id = $1', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Game not found' });
    }
    const game = result.rows[0];
    const correct = guess === game.correct_code;

    // Broadcast guess result to all clients
    broadcast({
      type: 'guess_result',
      gameId: id,
      correct,
      guess
    });

    res.json({
      success: correct,
      message: correct ? 'Correct code!' : 'Wrong code, try again.'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- JACKPOT ---
app.get('/api/jackpot', async (req, res) => {
  try {
    const result = await pool.query('SELECT amount FROM jackpot LIMIT 1');
    res.json({ amount: result.rows.length ? result.rows[0].amount : 0 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/jackpot', authenticateToken, async (req, res) => {
  const { amount } = req.body;
  try {
    await pool.query('UPDATE jackpot SET amount = $1', [amount]);

    // Broadcast jackpot change to all clients
    broadcast({
      type: 'jackpot_update',
      amount
    });

    res.json({ message: 'Jackpot updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// WebSocket connection
wss.on('connection', (ws) => {
  console.log('New WebSocket connection');
  ws.send(JSON.stringify({ type: 'connected', message: 'Welcome to the game live feed' }));
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});