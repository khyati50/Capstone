const express = require('express');
const router = express.Router();
const { broadcastAlert } = require('../services/socketService');

// POST /api/simulate/scenario - Trigger attack scenario
router.post('/scenario', (req, res) => {
  const { scenario_type } = req.body;
  const alertData = {
    alert_id: `ALT-SIM-${Date.now()}`,
    severity: 'Critical',
    status: 'New',
    summary: `[SIMULATION] ${scenario_type || 'FAILED_LOGIN_BURST'} executed on test workstation.`,
    confidence: 0.95,
    timestamp: new Date().toISOString()
  };
  broadcastAlert(alertData);
  res.json({ message: `Simulation scenario ${scenario_type} triggered successfully.`, alert: alertData });
});

// POST /api/simulate/reset
router.post('/reset', (req, res) => {
  res.json({ message: 'Simulation state reset successfully.' });
});

module.exports = router;
