const express = require('express');
const router = express.Router();
const { getTimeline } = require('../services/dbService');

// GET /api/timeline - Get timeline for latest active incident
router.get('/', async (req, res) => {
  const data = await getTimeline();
  res.json(data);
});

// GET /api/timeline/:incidentId
router.get('/:incidentId', async (req, res) => {
  const data = await getTimeline(req.params.incidentId);
  res.json(data);
});

module.exports = router;

