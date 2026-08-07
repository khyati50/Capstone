const express = require('express');
const router = express.Router();
const { getRiskMetrics } = require('../services/dbService');

// GET /api/risk - Dynamic risk metrics
router.get('/', async (req, res) => {
  const data = await getRiskMetrics();
  res.json(data);
});

module.exports = router;

