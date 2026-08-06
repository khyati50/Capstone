/**
 * Python Prediction Microservice HTTP Proxy Client
 */

const axios = require('axios');

const PYTHON_URL = process.env.PYTHON_SERVICE_URL || 'http://localhost:8000';

async function sendPredictionRequest(eventData) {
  try:
    const response = await axios.post(`${PYTHON_URL}/predict`, eventData, { timeout: 3000 });
    return response.data;
  } catch (error) {
    console.warn(`[Proxy Warning] FastAPI prediction server unreachable: ${error.message}. Using fallback.`);
    const failed = Number(eventData.failed_login_count_5m || 0);
    const isPs = Number(eventData.is_powershell_executed || 0);
    const isPriv = Number(eventData.privilege_escalation_flag || 0);

    const isMal = (failed >= 3 || isPs === 1 || isPriv === 1) ? 1 : 0;
    return {
      prediction: isMal,
      confidence: isMal ? 0.92 : 0.96,
      model_version: 'v1.0.0-fallback-proxy',
      shap_values: {
        failed_login_count_5m: failed >= 3 ? 0.42 : -0.05,
        is_powershell_executed: isPs === 1 ? 0.38 : -0.05,
        privilege_escalation_flag: isPriv === 1 ? 0.45 : -0.05
      }
    };
  }
}

module.exports = { sendPredictionRequest };
