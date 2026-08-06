import React, { useState } from 'react';
import { AlertTriangle, Filter, Eye, ShieldCheck, Cpu } from 'lucide-react';

export default function AlertCenter({ alerts, onSelectAlert }) {
  const [filterSeverity, setFilterSeverity] = useState('ALL');

  const filtered = alerts.filter(a => {
    if (filterSeverity === 'ALL') return true;
    return a.severity.toUpperCase() === filterSeverity;
  });

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center space-x-2">
            <AlertTriangle className="w-5 h-5 text-amber-400" />
            <span>Alert Management Center</span>
          </h2>
          <p className="text-xs text-gray-400">Investigate, filter, and inspect AI-explainable security alerts</p>
        </div>

        {/* Filter Controls */}
        <div className="flex items-center space-x-2 bg-[#111827] p-1.5 rounded-lg border border-gray-800">
          <Filter className="w-4 h-4 text-gray-400 ml-2" />
          <span className="text-xs text-gray-400">Severity:</span>
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map(level => (
            <button
              key={level}
              onClick={() => setFilterSeverity(level)}
              className={`px-3 py-1 rounded text-xs font-semibold transition-colors ${
                filterSeverity === level ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white'
              }`}
            >
              {level}
            </button>
          ))}
        </div>
      </div>

      {/* Data Grid */}
      <div className="glass-panel rounded-xl overflow-hidden">
        <table className="w-full text-left text-xs">
          <thead className="bg-[#0f172a] text-gray-400 border-b border-gray-800 uppercase font-mono text-[10px]">
            <tr>
              <th className="p-4">Alert ID</th>
              <th className="p-4">Severity</th>
              <th className="p-4">Threat Type</th>
              <th className="p-4">Host / Target User</th>
              <th className="p-4">Confidence</th>
              <th className="p-4">Timestamp</th>
              <th className="p-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/60 text-gray-200">
            {filtered.map((a, idx) => (
              <tr key={idx} className="hover:bg-gray-800/40 transition-colors">
                <td className="p-4 font-mono text-blue-400 font-bold">{a.alert_id}</td>
                <td className="p-4">
                  <span className={`px-2.5 py-1 rounded text-[10px] font-bold uppercase ${
                    a.severity === 'Critical' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-amber-500/20 text-amber-400'
                  }`}>
                    {a.severity}
                  </span>
                </td>
                <td className="p-4 font-medium">{a.threat_type || 'Behavioral Anomaly'}</td>
                <td className="p-4 font-mono text-gray-300">{a.hostname || 'CORP-HOST-01'} \ {a.username || 'administrator'}</td>
                <td className="p-4">
                  <div className="flex items-center space-x-2">
                    <div className="w-16 bg-gray-800 h-1.5 rounded-full overflow-hidden">
                      <div className="bg-emerald-400 h-full" style={{ width: `${(a.confidence || 0.8) * 100}%` }}></div>
                    </div>
                    <span className="font-mono text-emerald-400 text-[11px]">{((a.confidence || 0.8) * 100).toFixed(0)}%</span>
                  </div>
                </td>
                <td className="p-4 font-mono text-gray-400 text-[11px]">{new Date(a.timestamp).toLocaleString()}</td>
                <td className="p-4 text-right">
                  <button
                    onClick={() => onSelectAlert(a)}
                    className="inline-flex items-center space-x-1.5 px-3 py-1.5 bg-blue-600/20 hover:bg-blue-600 text-blue-400 hover:text-white border border-blue-500/30 rounded-md transition-all text-xs font-medium"
                  >
                    <Cpu className="w-3.5 h-3.5" />
                    <span>Explain (SHAP)</span>
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
