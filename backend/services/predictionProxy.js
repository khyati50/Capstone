/**
 * Python Prediction Microservice HTTP Proxy Client
 */

const axios = require('axios');

const PYTHON_URL = process.env.PYTHON_SERVICE_URL || 'http://localhost:8000';

async function sendPredictionRequest(eventData) {
  try {
    const response = await axios.post(`${PYTHON_URL}/predict`, eventData, { timeout: 4000 });
    return response.data;
  } catch (error) {
    console.warn(`[Proxy Warning] FastAPI prediction server unreachable: ${error.message}. Using fallback.`);
    const failed = Number(eventData.failed_login_count_5m || 0);
    const isPs = Number(eventData.is_powershell_executed || 0);
    const isPriv = Number(eventData.privilege_escalation_flag || 0);

    const isMal = (failed >= 3 || isPs === 1 || isPriv === 1) ? 1 : 0;
    // Return a conservative fallback when the Python service is unreachable.
    // Do NOT provide hardcoded final `risk_score` values that mislead the UI/ops team.
    return {
      prediction: isMal,
      // Provide a moderate confidence for fallback-detected conditions, but do not finalize a risk score here.
      confidence: isMal ? 0.92 : 0.5,
      severity: isMal ? 'High' : 'Low',
      model_version: 'v1.0.0-fallback-proxy',
      shap_values: {
        failed_login_count_5m: failed >= 3 ? 0.42 : -0.05,
        is_powershell_executed: isPs === 1 ? 0.38 : -0.05,
        privilege_escalation_flag: isPriv === 1 ? 0.45 : -0.05
      },
      threat_summary: isMal ? `Fallback: suspicious activity detected` : `Fallback: benign event observed`,
      threat_type: isMal ? 'Behavioral Threat Anomaly (Fallback)' : 'Benign Activity',
      explanation: isMal ? 'Proxy fallback: heuristics flagged this event. Start Python service for accurate scoring.' : 'Event features within normal range.',
      recommendations: ['1. Start the Python prediction microservice to obtain accurate risk scores.', '2. Review event details.'],
      incident_id: `INC-${Date.now().toString().slice(-5)}`,
      chain_length: 1,
      // Do not set a definitive risk_score in proxy fallback; let downstream store mark it as fallback.
      risk_score: null,
      risk_level: isMal ? 'Fallback-Suspect' : 'Fallback-Unknown',
      is_fallback: true,
      mitre_mapping: [],
      timeline_nodes: [{ step: 1, event_id: eventData.EventID || 4624, label: 'Logged Event (Fallback)', timestamp: new Date().toISOString() }]
    };
  }
}

async function sendSimulationRequest(scenarioType) {
  try {
    const response = await axios.post(`${PYTHON_URL}/simulate`, { scenario_type: scenarioType }, { timeout: 5000 });
    return response.data;
  } catch (error) {
    console.warn(`[Proxy Warning] FastAPI simulation endpoint unreachable: ${error.message}. Using proxy fallback.`);
    const simulatedEvent = {
      scenario_id: scenarioType,
      EventID: scenarioType === 'SUSPICIOUS_POWERSHELL' ? 4688 : 4625,
      failed_login_count_5m: scenarioType === 'FAILED_LOGIN_BURST' ? 6 : 0,
      is_powershell_executed: scenarioType === 'SUSPICIOUS_POWERSHELL' ? 1 : 0,
      privilege_escalation_flag: scenarioType === 'PRIVILEGE_ESCALATION' ? 1 : 0,
      Computer: 'CORP-HOST-01',
      TargetUserName: 'administrator'
    };
    const predRes = await sendPredictionRequest(simulatedEvent);
    return {
      scenario_type: scenarioType,
      event_count: 1,
      pipeline_results: [predRes]
    };
  }
}

async function sendResetRequest() {
  try {
    const response = await axios.post(`${PYTHON_URL}/simulate/reset`, {}, { timeout: 3000 });
    return response.data;
  } catch (error) {
    console.warn(`[Proxy Warning] FastAPI simulation reset endpoint unreachable: ${error.message}`);
    return { message: 'Reset handled by proxy fallback.' };
  }
}

module.exports = { sendPredictionRequest, sendSimulationRequest, sendResetRequest };


