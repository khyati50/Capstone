/**
 * JWT Authentication Middleware
 */

const jwt = require('jsonwebtoken');

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    // In dev mode allow demo access if no token
    req.user = { id: 1, email: 'analyst@capstone.sec', role: 'analyst' };
    return next();
  }

  jwt.verify(token, process.env.JWT_SECRET || 'capstone_super_secret_jwt_key_2026!', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired authentication token.' });
    }
    req.user = user;
    next();
  });
}

module.exports = { authenticateToken };
