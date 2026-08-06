import React from 'react';
import { Cpu, HelpCircle, ShieldCheck, CheckCircle2 } from 'lucide-react';
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
      unusual_process_parent_ratio: -0.05,
      time_delta_prev_event: -0.12
    },
    recommendations: [
      '1. Immediately lock user account administrator.',
      '2. Inspect active IP address 192.168.1.105.',
      '3. Enforce multi-factor authentication reset.'
    ]
  };

  const chartData = Object.entries(alert.shap_values || {}).map(([key, val]) => ({
    feature: key,
    weight: val,
  }));

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-bold text-white flex items-center space-x-2">
          <Cpu className="w-5 h-5 text-blue-400" />
          <span>SHAP Explainability Drawer & Security Intelligence Layer</span>
        </h2>
        <p className="text-xs text-gray-400">Primary Research Novelty — Human-Readable AI Reasoning for Alert {alert.alert_id}</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* SHAP Feature Weights Chart */}
        <div className="glass-panel p-5 rounded-xl">
          <h3 className="text-sm font-semibold text-gray-200 mb-3 flex items-center justify-between">
            <span>Local Feature Attribution (SHAP Weights)</span>
            <span className="text-[10px] text-gray-400 font-mono">+ Push Malicious | - Push Benign</span>
          </h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} layout="vertical" margin={{ left: 40, right: 20 }}>
                <XAxis type="number" stroke="#6b7280" fontSize={11} domain={[-0.5, 0.5]} />
                <YAxis type="category" dataKey="feature" stroke="#9ca3af" fontSize={10} width={150} />
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
            <span className="text-[10px] font-bold text-blue-400 uppercase tracking-widest block mb-1">Security Intelligence Synthesis</span>
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
        </div>
      </div>
    </div>
  );
}
