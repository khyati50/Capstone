const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// POST /api/auth/login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  // Demo user credentials
  const token = jwt.sign(
    { id: 1, email: email, role: 'analyst' },
    process.env.JWT_SECRET || 'capstone_super_secret_jwt_key_2026!',
    { expiresIn: '24h' }
  );

  res.json({
    message: 'Authentication successful',
    token: token,
    user: { id: 1, name: 'SOC Lead Analyst', email: email, role: 'analyst' }
  });
});

// POST /api/auth/register
router.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  res.status(201).json({ message: 'User registered successfully', email });
});

module.exports = router;
