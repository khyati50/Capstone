const express = require('express');
const router = express.Router();
const { sendPredictionRequest } = require('../services/predictionProxy');
const { broadcastAlert } = require('../services/socketService');

// In-memory store fallback if DB is establishing connection
const logStore = [];

// POST /api/events - Ingest log event
router.post('/', async (req, res) => {
  const event = req.body;
  const prediction = await sendPredictionRequest(event);

  const logEntry = {
    id: logStore.length + 1,
    timestamp: event.TimeCreated || new Date().toISOString(),
    event_id: event.EventID || 4624,
    hostname: event.Computer || 'HOST-01',
    username: event.TargetUserName || 'jdoe',
    prediction: prediction.prediction,
    confidence: prediction.confidence,
    shap_values: prediction.shap_values
  };

  logStore.push(logEntry);

  if (prediction.prediction === 1) {
    const alertData = {
      alert_id: `ALT-${Date.now()}`,
      severity: prediction.confidence > 0.85 ? 'Critical' : 'High',
      status: 'New',
      summary: `Malicious behavior detected on ${logEntry.hostname} by user ${logEntry.username}`,
      confidence: prediction.confidence,
      shap_values: prediction.shap_values,
      timestamp: logEntry.timestamp
    };
    broadcastAlert(alertData);
  }

  res.json({ message: 'Event processed successfully', logId: logEntry.id, prediction });
});

// GET /api/events - Retrieve paginated events
router.get('/', (req, res) => {
  res.json({ count: logStore.length, events: logStore.slice(-50) });
});

module.exports = router;
