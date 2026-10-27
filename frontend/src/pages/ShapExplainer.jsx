import React from 'react';
import { Cpu, HelpCircle, ShieldCheck, CheckCircle2, Activity, Link2 } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

export default function ShapExplainer({ selectedAlert }) {
  const alert = selectedAlert || {
    alert_id: 'ALT-1001',
    severity: 'Critical',
    threat_type: 'Credential Access / Brute Force Attack',
    explanation: 'High frequency of failed authentication attempts detected within 5 minutes.',
    shap_values: {
      failed_login_count_5m: 0.42,
      is_powershell_executed: 0.38,
      privilege_escalation_flag: 0.35,
      is_cmd_or_tool_executed: 0.28,
      is_known_attack_eventid: 0.31,
      suspicious_tool_count: 0.22,
      has_admin_keyword: 0.19,
      commandline_entropy: 0.15,
      commandline_length: 0.12,
      num_digits_cmdline: 0.08,
      unusual_process_parent_ratio: -0.05,
      time_delta_prev_event: -0.12,
      event_frequency_1h: -0.04,
      session_duration: -0.06,
      process_name_entropy: -0.03,
      path_depth: -0.05
    },
    recommendations: [
      '1. Immediately lock user account administrator.',
      '2. Inspect active IP address 192.168.1.105.',
      '3. Enforce multi-factor authentication reset.'
    ],
    incident_id: 'INC-7532CA60',
    chain_length: 2,
    is_multi_stage: true
  };

  const chartData = Object.entries(alert.shap_values || {}).map(([key, val]) => ({
    feature: key,
    weight: val,
  }));

  const alertSource = alert.alert_source || (alert.triggered_rules && alert.triggered_rules.length > 0 ? 'AI_AND_RULE_AGREEMENT' : 'AI_ANOMALY_ONLY');
  const modelConfidence = typeof alert.confidence === 'number' ? alert.confidence : 0.998;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-bold text-white flex items-center space-x-2">
          <Cpu className="w-5 h-5 text-blue-400" />
          <span>SHAP Explainability Drawer & Security Intelligence Layer</span>
        </h2>
        <p className="text-xs text-gray-400">Primary Research Novelty — Human-Readable AI Reasoning for Alert {alert.alert_id} (16 Telemetry Features)</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* SHAP Feature Weights Chart */}
        <div className="glass-panel p-5 rounded-xl">
          <h3 className="text-sm font-semibold text-gray-200 mb-3 flex items-center justify-between">
            <span>Local Feature Attribution (SHAP Weights)</span>
            <span className="text-[10px] text-gray-400 font-mono">+ Push Malicious | - Push Benign</span>
          </h3>
          <div className="h-[460px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} layout="vertical" margin={{ left: 40, right: 20 }}>
                <XAxis type="number" stroke="#6b7280" fontSize={11} domain={[-0.5, 0.5]} />
                <YAxis type="category" dataKey="feature" stroke="#9ca3af" fontSize={10} width={160} />
                <Tooltip contentStyle={{ backgroundColor: '#111827', borderColor: '#374151' }} />
                <Bar dataKey="weight">
                  {chartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.weight > 0 ? '#ef4444' : '#10b981'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Security Intelligence Panel (Primary Novelty) */}
        <div className="glass-panel p-5 rounded-xl border border-blue-500/30 space-y-4">
          <div>
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold text-blue-400 uppercase tracking-widest block mb-1">Security Intelligence Synthesis</span>
              {alert.is_multi_stage && (
                <span className="px-2 py-0.5 rounded bg-orange-500/20 text-orange-400 border border-orange-500/30 text-[10px] font-mono font-bold uppercase flex items-center space-x-1">
                  <Link2 className="w-2.5 h-2.5" />
                  <span>Multi-Stage Incident</span>
                </span>
              )}
            </div>
            <h4 className="text-sm font-bold text-white">{alert.threat_type}</h4>
            <p className="text-xs text-gray-300 mt-2 bg-blue-950/30 p-3 rounded-lg border border-blue-500/20 leading-relaxed">
              "{alert.explanation}"
            </p>
          </div>

          <div>
            <span className="text-[10px] font-bold text-emerald-400 uppercase tracking-widest block mb-2">SOC Response Guidance</span>
            <ul className="space-y-2">
              {(alert.recommendations || []).map((rec, idx) => (
                <li key={idx} className="flex items-start space-x-2 text-xs text-gray-300 bg-gray-900/60 p-2.5 rounded-md border border-gray-800">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  <span>{rec}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Incident ID & Chain Length (Phase 13C) */}
          <div className="pt-3 border-t border-gray-800 flex items-center justify-between text-xs font-mono">
            <span className="text-gray-400">Incident Context:</span>
            <div className="flex items-center space-x-2">
              <span className="text-amber-400 font-semibold">{alert.incident_id || 'N/A'}</span>
              <span className="text-gray-600">|</span>
              <span className="text-blue-300">Chain Length: {alert.chain_length ?? 1}</span>
            </div>
          </div>

          {/* XGBoost Decision Engine & Provenance Display */}
          <div className="pt-2 border-t border-gray-800/60 flex items-center justify-between text-xs font-mono">
            <span className="text-gray-400 flex items-center space-x-1.5">
              <Activity className="w-3.5 h-3.5 text-blue-400" />
              <span>XGBoost Decision Provenance:</span>
            </span>
            <span className="px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 font-semibold text-[10px] uppercase border border-blue-500/30">
              {alertSource}
            </span>
          </div>
          <div className="pt-1.5 flex items-center justify-between text-xs font-mono">
            <span className="text-gray-400 flex items-center space-x-1.5">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              <span>Model Confidence:</span>
            </span>
            <span className="text-emerald-400 font-semibold">
              {(modelConfidence * 100).toFixed(1)}% (XGBoost Ensemble)
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
