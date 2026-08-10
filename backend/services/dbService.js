/**
 * Unified Database Persistence & Store Service
 * Persists raw logs, predictions, alerts, risk scores, timeline nodes, and MITRE mappings.
 * Uses MySQL if available, falls back to in-memory persistent store.
 */

const pool = require('../config/db');

// In-Memory Fallback Stores
const memoryStore = {
  logs: [],
  alerts: [],
  incidents: {},
  risk: {
    overall_score: 0.0,
    overall_level: 'Low',
    active_incidents_count: 0,
    breakdown: {
      ai_confidence_weight: 0.0,
      rule_hits_weight: 0.0,
      mitre_tactic_weight: 0.0,
      tactic_diversity_weight: 0.0,
      scope_weight: 0.0,
      corroboration_multiplier: 1.0,
      event_severity_weight: 0.0,
      chain_length_weight: 0.0
    },
    sublines: {}
  },
  mitre: []
};

function resetState() {
  memoryStore.logs = [];
  memoryStore.alerts = [];
  memoryStore.incidents = {};
  memoryStore.risk = {
    overall_score: 0.0,
    overall_level: 'Low',
    active_incidents_count: 0,
    breakdown: {
      ai_confidence_weight: 0.0,
      rule_hits_weight: 0.0,
      mitre_tactic_weight: 0.0,
      tactic_diversity_weight: 0.0,
      scope_weight: 0.0,
      corroboration_multiplier: 1.0,
      event_severity_weight: 0.0,
      chain_length_weight: 0.0
    },
    sublines: {}
  };
  memoryStore.mitre = [];
}

async function checkDbConnection() {
  try {
    const [rows] = await pool.query('SELECT 1');
    return true;
  } catch (err) {
    return false;
  }
}

async function saveProcessedPipelineResult(pipelineResult) {
  const isDbAvailable = await checkDbConnection();
  const rawEvt = pipelineResult.raw_event || {};
  const timestamp = rawEvt.TimeCreated || new Date().toISOString();
  const hostname = rawEvt.Computer || 'CORP-HOST-01';
  const username = rawEvt.TargetUserName || rawEvt.SubjectUserName || 'administrator';

  // 1. Save Log Entry
  const logEntry = {
    id: memoryStore.logs.length + 1,
    timestamp: timestamp,
    event_id: rawEvt.EventID || 4624,
    hostname: hostname,
    username: username,
    prediction: pipelineResult.prediction,
    confidence: pipelineResult.confidence,
    shap_values: pipelineResult.shap_values
  };
  memoryStore.logs.push(logEntry);

  let alertEntry = null;

  // 2. Save Alert Entry if Prediction == 1 or Severity >= High
  if (pipelineResult.prediction === 1 || pipelineResult.severity === 'Critical' || pipelineResult.severity === 'High') {
    alertEntry = {
      alert_id: `ALT-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      severity: pipelineResult.severity || (pipelineResult.confidence > 0.85 ? 'Critical' : 'High'),
      status: 'New',
      threat_type: pipelineResult.threat_type || 'Behavioral Anomaly Detected',
      summary: pipelineResult.threat_summary || `Malicious behavior on ${hostname} by user ${username}`,
      confidence: pipelineResult.confidence,
      hostname: hostname,
      username: username,
      shap_values: pipelineResult.shap_values,
      explanation: pipelineResult.explanation,
      recommendations: pipelineResult.recommendations,
      timestamp: timestamp,
      incident_id: pipelineResult.incident_id || 'INC-LIVE-01',
      risk_score: pipelineResult.risk_score || 85.0,
      risk_level: pipelineResult.risk_level || 'Critical',
      mitre_mapping: pipelineResult.mitre_mapping || []
    };
    memoryStore.alerts.unshift(alertEntry);

    // Update risk metrics
    memoryStore.risk.overall_score = pipelineResult.risk_score ?? memoryStore.risk.overall_score;
    memoryStore.risk.overall_level = pipelineResult.risk_level ?? memoryStore.risk.overall_level;
    memoryStore.risk.active_incidents_count = Object.keys(memoryStore.incidents).length || 1;
    if (pipelineResult.risk_breakdown) {
      memoryStore.risk.breakdown = pipelineResult.risk_breakdown;
    }
    if (pipelineResult.risk_sublines) {
      memoryStore.risk.sublines = pipelineResult.risk_sublines;
    }


    // Update incident timeline
    const incId = alertEntry.incident_id;
    memoryStore.latest_incident_id = incId;
    if (!memoryStore.incidents[incId]) {
      memoryStore.incidents[incId] = {
        incident_id: incId,
        host: hostname,
        user: username,
        start_time: timestamp,
        nodes: []
      };
    }
    const nodes = pipelineResult.timeline_nodes || [
      { step: memoryStore.incidents[incId].nodes.length + 1, event_id: logEntry.event_id, label: alertEntry.threat_type, timestamp: timestamp, severity: alertEntry.severity }
    ];
    memoryStore.incidents[incId].nodes = nodes;
  }

  // 3. Accumulate MITRE ATT&CK mappings
  const incomingMitre = pipelineResult.mitre_mapping || [];
  for (const m of incomingMitre) {
    const tid = m.technique_id || m.id;
    if (!tid) continue;
    const existing = memoryStore.mitre.find(x => (x.technique_id || x.id) === tid);
    if (existing) {
      existing.active_alerts = (existing.active_alerts || existing.count || 1) + 1;
      if (existing.active_alerts >= 3) {
        existing.level = 'Critical';
      }
    } else {
      memoryStore.mitre.push({
        tactic: m.tactic,
        technique_name: m.technique_name || m.name,
        technique_id: tid,
        active_alerts: m.active_alerts || 1,
        level: m.level || 'High'
      });
    }
  }

  // If MySQL is active, insert into tables
  if (isDbAvailable) {
    try {
      const [logRes] = await pool.query(
        'INSERT INTO raw_logs (timestamp, event_id, hostname, username, scenario_id) VALUES (?, ?, ?, ?, ?)',
        [new Date(timestamp), logEntry.event_id, hostname, username, rawEvt.scenario_id || 'live']
      );
      const logId = logRes.insertId;
      const [predRes] = await pool.query(
        'INSERT INTO predictions (log_id, prediction, confidence, model_version) VALUES (?, ?, ?, ?)',
        [logId, pipelineResult.prediction, pipelineResult.confidence, pipelineResult.model_version || 'v1.0.0']
      );
      if (alertEntry) {
        await pool.query(
          'INSERT INTO alerts (prediction_id, severity, status, summary, explanation) VALUES (?, ?, ?, ?, ?)',
          [predRes.insertId, alertEntry.severity, alertEntry.status, alertEntry.summary, JSON.stringify(alertEntry)]
        );
      }
    } catch (err) {
      console.warn('[DB Service] MySQL write error, using in-memory store:', err.message);
    }
  }

  return { logEntry, alertEntry };
}

async function getEvents() {
  return { count: memoryStore.logs.length, events: memoryStore.logs.slice(-50) };
}

async function getAlerts() {
  return { count: memoryStore.alerts.length, alerts: memoryStore.alerts };
}

async function getAlertById(alertId) {
  const alert = memoryStore.alerts.find(a => a.alert_id === alertId) || memoryStore.alerts[0];
  return alert;
}

async function getTimeline(incidentId) {
  if (incidentId && memoryStore.incidents[incidentId]) {
    return memoryStore.incidents[incidentId];
  }
  if (memoryStore.latest_incident_id && memoryStore.incidents[memoryStore.latest_incident_id]) {
    return memoryStore.incidents[memoryStore.latest_incident_id];
  }
  const incKeys = Object.keys(memoryStore.incidents);
  if (incKeys.length > 0) {
    return memoryStore.incidents[incKeys[incKeys.length - 1]];
  }
  return { incident_id: incidentId || 'INC-88A12', host: 'CORP-HOST-01', user: 'administrator', start_time: new Date().toISOString(), nodes: [] };
}


async function getRiskMetrics() {
  return memoryStore.risk;
}

async function getMitreMatrix() {
  return { mapped_techniques: memoryStore.mitre };
}

module.exports = {
  saveProcessedPipelineResult,
  getEvents,
  getAlerts,
  getAlertById,
  getTimeline,
  getRiskMetrics,
  getMitreMatrix,
  resetState,
  memoryStore
};
