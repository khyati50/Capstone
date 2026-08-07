const express = require('express');
const router = express.Router();
const { getMitreMatrix } = require('../services/dbService');

// GET /api/mitre - MITRE ATT&CK Matrix mapping
router.get('/', async (req, res) => {
  const data = await getMitreMatrix();
  res.json(data);
});

module.exports = router;

