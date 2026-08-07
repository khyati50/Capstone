const express = require('express');
const router = express.Router();
const { getAlerts, getAlertById } = require('../services/dbService');

// GET /api/alerts - List all alerts
router.get('/', async (req, res) => {
  const data = await getAlerts();
  res.json(data);
});

// GET /api/alerts/:id - Get detailed alert info
router.get('/:id', async (req, res) => {
  const alert = await getAlertById(req.params.id);
  res.json(alert);
});

module.exports = router;

