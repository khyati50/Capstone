/**
 * Node.js Express Backend & Socket.IO WebSockets Entry Point
 */

const express = require('express');
const http = require('http');
const cors = require('cors');
const helmet = require('helmet');
require('dotenv').config();

const { initSocket } = require('./services/socketService');
const { authenticateToken } = require('./middleware/auth');
const errorHandler = require('./middleware/errorHandler');

const authRoutes = require('./routes/auth');
const eventRoutes = require('./routes/events');
const alertRoutes = require('./routes/alerts');
const timelineRoutes = require('./routes/timeline');
const riskRoutes = require('./routes/risk');
const mitreRoutes = require('./routes/mitre');
const simulateRoutes = require('./routes/simulate');

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 5000;

// Security & Parsing Middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.FRONTEND_ORIGIN || 'http://localhost:5173', credentials: true }));
app.use(express.json());

// Initialize WebSockets
initSocket(server);

// Route Mounting
app.use('/api/auth', authRoutes);
app.use('/api/events', authenticateToken, eventRoutes);
app.use('/api/alerts', authenticateToken, alertRoutes);
app.use('/api/timeline', authenticateToken, timelineRoutes);
app.use('/api/risk', authenticateToken, riskRoutes);
app.use('/api/mitre', authenticateToken, mitreRoutes);
app.use('/api/simulate', authenticateToken, simulateRoutes);

app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', service: 'Express Backend API', port: PORT });
});

// Global Error Handler
app.use(errorHandler);

server.listen(PORT, () => {
  console.log(`[Express Backend] Running on http://localhost:${PORT}`);
});

module.exports = app;
