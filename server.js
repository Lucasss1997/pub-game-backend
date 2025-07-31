const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

app.use(cors());
app.use(express.json());

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

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

app.post('/api/register', async (req, res) => {
  const { email, password, pubName } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, pub_name) VALUES ($1, $2, $3) RETURNING id',
      [email, hashedPassword, pubName]
    );
    res.status(201).json({ userId: result.rows[0].id });
  } catch (err) {
    res.status(400).json({ error: 'User already exists or invalid data.' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = result.rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '2h' });
  res.json({ token });
});

app.get('/api/me', authenticateToken, async (req, res) => {
  const result = await pool.query('SELECT id, email, pub_name FROM users WHERE id = $1', [req.user.id]);
  res.json(result.rows[0]);
});

app.post('/api/games', authenticateToken, async (req, res) => {
  const { gameType, prizeValue } = req.body;
  const result = await pool.query(
    'INSERT INTO games (user_id, game_type, prize_value, status) VALUES ($1, $2, $3, $4) RETURNING *',
    [req.user.id, gameType, prizeValue, 'active']
  );
  res.status(201).json(result.rows[0]);
});

app.get('/api/games', authenticateToken, async (req, res) => {
  const result = await pool.query('SELECT * FROM games WHERE user_id = $1 ORDER BY created_at DESC', [req.user.id]);
  res.json(result.rows);
});

app.patch('/api/games/:id', authenticateToken, async (req, res) => {
  const { status, winnerName } = req.body;
  const result = await pool.query(
    'UPDATE games SET status = $1, winner_name = $2 WHERE id = $3 AND user_id = $4 RETURNING *',
    [status, winnerName || null, req.params.id, req.user.id]
  );
  res.json(result.rows[0]);
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));