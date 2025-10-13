const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;

// --------------------
// Middleware
// --------------------
app.use(express.json());
app.use(cors());
app.use(helmet());
app.use(express.static(path.join(__dirname, 'public')));

// --------------------
// Security logging
// --------------------
function logEvent(type, details) {
  const log = `${new Date().toISOString()} [${type}] ${details}\n`;
  fs.appendFileSync(path.join(__dirname, 'security.log'), log);
}

// --------------------
// Global rate limiting (all routes)
const globalLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // max 100 requests per IP per minute
  handler: (req, res) => {
    res.status(429).json({ message: 'Too many requests. Try again later.' });
  }
});
app.use(globalLimiter);

// --------------------
// Login-specific rate limiting
const loginLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5, // max 5 login attempts per IP
  handler: (req, res) => {
    logEvent('WARN', `Too many login attempts from ${req.ip}`);
    res.status(429).json({ message: 'Too many login attempts. Try again later.' });
  },
});

// --------------------
// Mock database
let users = [
  { username: 'admin', password: bcrypt.hashSync('adminpass', 10), role: 'admin' },
];

// --------------------API
// Input validation 
function validateUsername(username) {
  return typeof username === 'string' && username.length >= 3 && username.length <= 20;
}

function validatePassword(password) {
  return typeof password === 'string' && password.length >= 6;
}

// --------------------
// Routes
// --------------------

// Signup SIGN UP API ENDPOINT
app.post('/signup', (req, res) => {
  const { username, password } = req.body;
  if (!validateUsername(username) || !validatePassword(password)) {
    return res.json({ message: 'Invalid username or password format.' });
  }

  if (users.find(u => u.username === username)) {
    return res.json({ message: 'Username already exists.' });
  }

  const hashed = bcrypt.hashSync(password, 10);
  users.push({ username, password: hashed, role: 'user' });
  logEvent('INFO', `User registered: ${username}`);
  res.json({ message: 'Signup successful!' });
});

// Login API ENDPOINT
app.post('/login', loginLimiter, (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);

  if (!user) {
    logEvent('WARN', `Failed login for unknown user: ${username}`);
    return res.json({ message: 'User not found.' });
  }

  const valid = bcrypt.compareSync(password, user.password);
  if (!valid) {
    logEvent('WARN', `Failed login for ${username}: invalid password`);
    return res.json({ message: 'Invalid password.' });
  }
//JWT token
  const token = jwt.sign({ username: user.username, role: user.role }, 'secretKey', { expiresIn: '1h' });
  logEvent('INFO', `Successful login: ${username}`);
  res.json({ token, message: 'Login successful!', role: user.role });
});

// Middleware: verify JWT token
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.json({ message: 'Missing token.' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, 'secretKey');
    req.user = decoded;
    next();
  } catch {
    logEvent('WARN', `Invalid token from ${req.ip}`);
    return res.json({ message: 'Invalid token.' });
  }
}

// Middleware: role check
function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      logEvent('WARN', `Unauthorized role access by ${req.user.username}`);
      return res.json({ message: 'Access denied.' });
    }
    next();
  };
}

// GET Profile API 
app.get('/profile', verifyToken, (req, res) => {
  res.json({ message: `Welcome ${req.user.username}!`, role: req.user.role });
});

// Admin feature API
app.get('/admin', verifyToken, requireRole('admin'), (req, res) => {
  res.json({ message: `Welcome Admin ${req.user.username}! Special feature here.` });
});

// --------------------
// Start server
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
