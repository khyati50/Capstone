const express = require('express');
const router = express.Router();
const { sendPredictionRequest } = require('../services/predictionProxy');
const { broadcastAlert, broadcastRiskUpdate, broadcastTimelineUpdate } = require('../services/socketService');
const { saveProcessedPipelineResult, getEvents } = require('../services/dbService');

// POST /api/events - Ingest log event
router.post('/', async (req, res) => {
  try {
    const event = req.body;
    const predictionResult = await sendPredictionRequest(event);
    predictionResult.raw_event = event;

    const { logEntry, alertEntry } = await saveProcessedPipelineResult(predictionResult);

    if (alertEntry) {
      broadcastAlert(alertEntry);
      if (predictionResult.risk_score) {
        broadcastRiskUpdate({ score: predictionResult.risk_score, level: predictionResult.risk_level, breakdown: predictionResult.risk_breakdown });
      }
      if (predictionResult.timeline_nodes) {
        broadcastTimelineUpdate({ incident_id: predictionResult.incident_id, nodes: predictionResult.timeline_nodes });
      }
    }

    res.json({ message: 'Event processed successfully', logId: logEntry.id, prediction: predictionResult });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/events - Retrieve paginated events
router.get('/', async (req, res) => {
  const data = await getEvents();
  res.json(data);
});

module.exports = router;

