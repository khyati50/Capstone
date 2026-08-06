const express = require('express');
const router = express.Router();

const mockAlerts = [
  {
    alert_id: 'ALT-1001',
    severity: 'Critical',
    status: 'Investigating',
    threat_type: 'Credential Access / Brute Force Attack',
    summary: 'High frequency of failed logins (6 attempts in 5m) detected on host CORP-HOST-01 for user administrator.',
    confidence: 0.94,
    hostname: 'CORP-HOST-01',
    username: 'administrator',
    shap_values: { failed_login_count_5m: 0.42, privilege_escalation_flag: 0.35 },
    explanation: 'High frequency of failed authentication attempts detected within 5 minutes.',
    recommendations: [
      '1. Lock user account administrator.',
      '2. Inspect active IP 192.168.1.105.',
      '3. Enforce multi-factor authentication reset.'
    ],
    timestamp: new Date().toISOString()
  },
  {
    alert_id: 'ALT-1002',
    severity: 'High',
    status: 'New',
    threat_type: 'Suspicious Execution / PowerShell Abuse',
    summary: 'PowerShell process launched with execution policy bypass parameters on DC-01.',
    confidence: 0.89,
    hostname: 'DC-01',
    username: 'jdoe',
    shap_values: { is_powershell_executed: 0.45, unusual_process_parent_ratio: 0.28 },
    explanation: 'Suspicious PowerShell process launched with script arguments.',
    recommendations: [
      '1. Terminate PowerShell process ID 4412.',
      '2. Inspect encoded command payload.'
    ],
    timestamp: new Date(Date.now() - 3600000).toISOString()
  }
];

// GET /api/alerts - List all alerts
router.get('/', (req, res) => {
  res.json({ count: mockAlerts.length, alerts: mockAlerts });
});

// GET /api/alerts/:id - Get detailed alert info
router.get('/:id', (req, res) => {
  const alert = mockAlerts.find(a => a.alert_id === req.params.id) || mockAlerts[0];
  res.json(alert);
});

module.exports = router;
