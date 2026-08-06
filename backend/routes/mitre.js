const express = require('express');
const router = express.Router();

// GET /api/mitre - MITRE ATT&CK Matrix mapping
router.get('/', (req, res) => {
  res.json({
    mapped_techniques: [
      { tactic: 'Credential Access', technique_name: 'Brute Force', technique_id: 'T1110', active_alerts: 4 },
      { tactic: 'Execution', technique_name: 'Command and Scripting Interpreter: PowerShell', technique_id: 'T1059.001', active_alerts: 2 },
      { tactic: 'Privilege Escalation', technique_name: 'Valid Accounts', technique_id: 'T1078', active_alerts: 3 },
      { tactic: 'Persistence', technique_name: 'Create Account: Local Account', technique_id: 'T1136.001', active_alerts: 1 }
    ]
  });
});

module.exports = router;
