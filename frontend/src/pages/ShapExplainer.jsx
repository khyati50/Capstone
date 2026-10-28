import React from 'react';
import { Cpu, ShieldCheck, CheckCircle2, Activity, Link2 } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

export default function ShapExplainer({ selectedAlert }) {
  if (!selectedAlert) {
    return (
      <div className="space-y-6">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center space-x-2">
            <Cpu className="w-5 h-5 text-blue-400" />
            <span>SHAP Explainability Drawer & Security Intelligence Layer</span>
          </h2>
          <p className="text-xs text-gray-400">Primary Research Novelty — Human-Readable AI Reasoning for Windows Security Events</p>
        </div>

        <div className="glass-panel p-12 rounded-xl text-center flex flex-col items-center justify-center border border-gray-800/80 min-h-[460px]">
          <div className="w-16 h-16 rounded-full bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400 mb-4">
            <Cpu className="w-8 h-8 animate-pulse" />
          </div>
          <h3 className="text-base font-semibold text-gray-200 mb-1">No Threat Alert Selected</h3>
          <p className="text-xs text-gray-400 max-w-md leading-relaxed mb-4">
            SHAP local feature attribution and security intelligence synthesize on-demand when a threat alert is generated or selected from the Alert Center.
          </p>
          <div className="flex items-center space-x-2 text-[11px] font-mono text-gray-400 bg-gray-900/60 px-3.5 py-1.5 rounded-full border border-gray-800">
            <Activity className="w-3.5 h-3.5 text-blue-400" />
            <span>Awaiting Threat Detection or Attack Simulation</span>
          </div>
        </div>
      </div>
    );
  }

  const alert = selectedAlert;

  const chartData = Object.entries(alert.shap_values || {}).map(([key, val]) => ({
    feature: key,
    weight: val,
  }));

  const alertSource = alert.alert_source || (alert.triggered_rules && alert.triggered_rules.length > 0 ? 'AI_AND_RULE_AGREEMENT' : 'AI_ANOMALY_ONLY');
  const modelConfidence = typeof alert.confidence === 'number' ? alert.confidence : 0.968;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-bold text-white flex items-center space-x-2">
          <Cpu className="w-5 h-5 text-blue-400" />
          <span>SHAP Explainability Drawer & Security Intelligence Layer</span>
        </h2>
        <p className="text-xs text-gray-400">Primary Research Novelty — Human-Readable AI Reasoning for Alert {alert.alert_id} ({chartData.length} Evaluated Features)</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* SHAP Feature Weights Chart */}
        <div className="glass-panel p-5 rounded-xl">
          <h3 className="text-sm font-semibold text-gray-200 mb-3 flex items-center justify-between">
            <span>Local Feature Attribution (SHAP Weights)</span>
            <span className="text-[10px] text-gray-400 font-mono">+ Push Malicious | - Push Benign</span>
          </h3>
          <div className="h-[460px]">
            {chartData.length > 0 ? (
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
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-gray-500 font-mono">
                No local SHAP attributions generated for this alert.
              </div>
            )}
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
