const express = require('express');
const router = express.Router();

// GET /api/risk - Dynamic risk metrics
router.get('/', (req, res) => {
  res.json({
    overall_score: 84.5,
    overall_level: 'Critical',
    active_incidents_count: 3,
    breakdown: {
      ai_confidence_weight: 27.6,
      rule_hits_weight: 20.0,
      event_severity_weight: 15.0,
      chain_length_weight: 13.2,
      scope_weight: 8.7
    }
  });
});

module.exports = router;
