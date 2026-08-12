const express = require('express');
const router = express.Router();
const { sendPredictionRequest } = require('../services/predictionProxy');
const { broadcastAlert, broadcastRiskUpdate, broadcastTimelineUpdate, broadcastMitreUpdate } = require('../services/socketService');
const { saveProcessedPipelineResult, getEvents, getRiskMetrics, getMitreMatrix, getTimeline } = require('../services/dbService');

// POST /api/events/pipeline-result - Ingest pre-processed live pipeline result from Python consumer
router.post('/pipeline-result', async (req, res) => {
  try {
    const pipelineResult = req.body;
    const { logEntry, alertEntry } = await saveProcessedPipelineResult(pipelineResult);

    if (alertEntry) {
      broadcastAlert(alertEntry);
    }

    // Broadcast updated cumulative SOC metrics
    const currentRisk = await getRiskMetrics();
    const currentMitre = await getMitreMatrix();
    const latestIncId = alertEntry ? alertEntry.incident_id : null;
    const currentTimeline = await getTimeline(latestIncId);

    broadcastRiskUpdate(currentRisk);
    broadcastMitreUpdate(currentMitre.mapped_techniques);
    broadcastTimelineUpdate(currentTimeline);

    res.json({
      message: 'Live pipeline result persisted and broadcasted successfully',
      logId: logEntry ? logEntry.id : null,
      alertId: alertEntry ? alertEntry.alert_id : null
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/events - Ingest log event via proxy
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

