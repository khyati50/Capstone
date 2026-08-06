const express = require('express');
const router = express.Router();

// GET /api/timeline/:incidentId
router.get('/:incidentId', (req, res) => {
  res.json({
    incident_id: req.params.incidentId || 'INC-88A12',
    host: 'CORP-HOST-01',
    user: 'administrator',
    start_time: new Date(Date.now() - 7200000).toISOString(),
    chain_length: 4,
    nodes: [
      { step: 1, event_id: 4625, label: 'Failed Login Burst (4625)', timestamp: new Date(Date.now() - 7200000).toISOString(), severity: 'High' },
      { step: 2, event_id: 4624, label: 'Successful Login (4624)', timestamp: new Date(Date.now() - 5400000).toISOString(), severity: 'Medium' },
      { step: 3, event_id: 4672, label: 'Admin Privileges Assigned (4672)', timestamp: new Date(Date.now() - 3600000).toISOString(), severity: 'High' },
      { step: 4, event_id: 4688, label: 'Suspicious PowerShell Execution (4688)', timestamp: new Date(Date.now() - 1800000).toISOString(), severity: 'Critical' }
    ]
  });
});

module.exports = router;
