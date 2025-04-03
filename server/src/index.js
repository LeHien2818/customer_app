import express from 'express';
import jwt from 'jsonwebtoken';
import pg from 'pg'; // Import default export
import cors from 'cors';
import bcrypt from 'bcrypt';

const { Pool } = pg; // Destructure Pool from the default export

const app = express();
app.use(express.json());
app.use(cors());

const pool = new Pool({
  user: 'postgres',
  host: 'db',
  database: 'crud_db',
  password: 'password',
  port: 5432,
});

const SECRET = 'your-secret-key';

// Initialize database tables
const initDb = async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('admin', 'user'))
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS items (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      created_by INTEGER REFERENCES users(id)
    )
  `);

  // Seed initial users if they don't exist
  const adminExists = await pool.query('SELECT * FROM users WHERE username = $1', ['admin']);
  if (adminExists.rowCount === 0) {
    const hashedPassword = await bcrypt.hash('admin123', 10);
    await pool.query(
      'INSERT INTO users (username, password, role) VALUES ($1, $2, $3)',
      ['admin', hashedPassword, 'admin']
    );
  }
  const userExists = await pool.query('SELECT * FROM users WHERE username = $1', ['user']);
  if (userExists.rowCount === 0) {
    const hashedPassword = await bcrypt.hash('user123', 10);
    await pool.query(
      'INSERT INTO users (username, password, role) VALUES ($1, $2, $3)',
      ['user', hashedPassword, 'user']
    );
  }
};

// Middleware to verify token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user.id, role: user.role }, SECRET);
    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// CRUD Operations
app.get('/api/items', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM items WHERE created_by = $1', [req.user.id]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/items', authenticateToken, async (req, res) => {
  const { name } = req.body;
  try {
    await pool.query('INSERT INTO items (name, created_by) VALUES ($1, $2)', [name, req.user.id]);
    res.sendStatus(201);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.listen(8081, async () => {
  await initDb();
  console.log('Server running on port 8081');
});