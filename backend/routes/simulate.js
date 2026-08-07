const express = require('express');
const router = express.Router();
const { sendSimulationRequest, sendResetRequest } = require('../services/predictionProxy');
const { broadcastAlert, broadcastRiskUpdate, broadcastTimelineUpdate, broadcastMitreUpdate, broadcastResetState } = require('../services/socketService');
const { saveProcessedPipelineResult, resetState, getRiskMetrics, getMitreMatrix, getTimeline } = require('../services/dbService');

// POST /api/simulate/scenario - Trigger attack scenario through full AI pipeline
router.post('/scenario', async (req, res) => {
  try {
    const { scenario_type } = req.body;
    const simResult = await sendSimulationRequest(scenario_type || 'FAILED_LOGIN_BURST');

    const processedAlerts = [];
    if (simResult && simResult.pipeline_results) {
      for (const item of simResult.pipeline_results) {
        const { alertEntry } = await saveProcessedPipelineResult(item);
        if (alertEntry) {
          processedAlerts.push(alertEntry);
          broadcastAlert(alertEntry);
        }
      }
    }

    // Broadcast updated cumulative state over Socket.IO
    const latestIncId = processedAlerts.length > 0 ? processedAlerts[processedAlerts.length - 1].incident_id : null;
    const currentRisk = await getRiskMetrics();
    const currentMitre = await getMitreMatrix();
    const currentTimeline = await getTimeline(latestIncId);

    broadcastRiskUpdate(currentRisk);
    broadcastMitreUpdate(currentMitre.mapped_techniques);
    broadcastTimelineUpdate(currentTimeline);


    res.json({
      message: `Simulation scenario ${scenario_type} processed through full AI pipeline successfully.`,
      scenario_type: scenario_type,
      alerts_created: processedAlerts.length,
      alerts: processedAlerts,
      risk: currentRisk,
      mitre: currentMitre,
      timeline: currentTimeline
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/simulate/reset - Reset simulation and cumulative SOC state
router.post('/reset', async (req, res) => {
  try {
    await sendResetRequest();
    resetState();
    broadcastResetState();
    res.json({ message: 'Simulation state reset successfully across AI Engine, Backend DB, and WebSockets.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;


