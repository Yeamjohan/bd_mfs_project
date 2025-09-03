require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const cors = require('cors');

const app = express();
app.use(helmet());
app.use(cors());
app.use(bodyParser.json());

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
}).promise();

const jwtSecret = process.env.JWT_SECRET || 'secret';

// Middleware
function auth(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.userId = decoded.id;
    req.role = decoded.role;
    next();
  });
}
function adminOnly(req, res, next) {
  if (req.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// Helpers
async function query(sql, params) {
  const [rows] = await pool.query(sql, params);
  return rows;
}

// Auth routes
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  const hashed = bcrypt.hashSync(password, 10);
  try {
    await query('INSERT INTO users (name,email,password) VALUES (?,?,?)', [name, email, hashed]);
    res.json({ message: 'Registered' });
  } catch (e) {
    res.status(400).json({ error: 'Email exists' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const rows = await query('SELECT * FROM users WHERE email=?', [email]);
  if (!rows.length) return res.status(400).json({ error: 'User not found' });
  const user = rows[0];
  if (!bcrypt.compareSync(password, user.password)) return res.status(400).json({ error: 'Wrong password' });
  const token = jwt.sign({ id: user.id, role: user.role }, jwtSecret, { expiresIn: '1d' });
  res.json({ token, user: { id: user.id, email: user.email, role: user.role } });
});

// Deposit
app.post('/api/deposit', auth, async (req, res) => {
  const { amount, method, txn_id } = req.body;
  await query('INSERT INTO deposits (user_id, amount, method, txn_id) VALUES (?,?,?,?)', [req.userId, amount, method, txn_id]);
  res.json({ message: 'Deposit request submitted (pending admin approval).' });
});

// Withdraw
app.post('/api/withdraw', auth, async (req, res) => {
  const { amount } = req.body;
  await query('INSERT INTO withdraws (user_id, amount) VALUES (?,?)', [req.userId, amount]);
  res.json({ message: 'Withdraw request submitted (pending admin approval).' });
});

// Balance
app.get('/api/user/balance', auth, async (req, res) => {
  const dep = await query('SELECT SUM(amount) as total FROM deposits WHERE user_id=? AND status="approved"', [req.userId]);
  const wd = await query('SELECT SUM(amount) as total FROM withdraws WHERE user_id=? AND status="approved"', [req.userId]);
  const balance = (dep[0].total || 0) - (wd[0].total || 0);
  res.json({ balance });
});

// Admin
app.get('/api/admin/deposits', auth, adminOnly, async (req, res) => {
  const rows = await query('SELECT * FROM deposits WHERE status="pending"');
  res.json({ deposits: rows });
});
app.post('/api/admin/deposits/:id/approve', auth, adminOnly, async (req, res) => {
  await query('UPDATE deposits SET status="approved" WHERE id=?', [req.params.id]);
  res.json({ message: 'Deposit approved' });
});
app.post('/api/admin/deposits/:id/reject', auth, adminOnly, async (req, res) => {
  await query('UPDATE deposits SET status="rejected" WHERE id=?', [req.params.id]);
  res.json({ message: 'Deposit rejected' });
});

app.get('/api/admin/withdraws', auth, adminOnly, async (req, res) => {
  const rows = await query('SELECT * FROM withdraws WHERE status="pending"');
  res.json({ withdraws: rows });
});
app.post('/api/admin/withdraws/:id/approve', auth, adminOnly, async (req, res) => {
  await query('UPDATE withdraws SET status="approved" WHERE id=?', [req.params.id]);
  res.json({ message: 'Withdraw approved' });
});
app.post('/api/admin/withdraws/:id/reject', auth, adminOnly, async (req, res) => {
  await query('UPDATE withdraws SET status="rejected" WHERE id=?', [req.params.id]);
  res.json({ message: 'Withdraw rejected' });
});

app.listen(process.env.PORT, () => console.log('Server running...'));