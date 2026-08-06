import React from 'react';
import { Grid, ShieldAlert } from 'lucide-react';

export default function MitreMatrix() {
  const techniques = [
    { tactic: 'Credential Access', name: 'Brute Force', id: 'T1110', count: 4, level: 'Critical' },
    { tactic: 'Execution', name: 'PowerShell Interpreter', id: 'T1059.001', count: 2, level: 'High' },
    { tactic: 'Privilege Escalation', name: 'Valid Accounts', id: 'T1078', count: 3, level: 'High' },
    { tactic: 'Persistence', name: 'Local Account Creation', id: 'T1136.001', count: 1, level: 'Medium' },
    { tactic: 'Persistence', name: 'Windows Service Execution', id: 'T1543.003', count: 1, level: 'Medium' },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-bold text-white flex items-center space-x-2">
          <Grid className="w-5 h-5 text-blue-400" />
          <span>MITRE ATT&CK Framework Threat Navigator</span>
        </h2>
        <p className="text-xs text-gray-400">Standardized Tactic & Technique ID Mapping Grid</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {techniques.map((t, idx) => (
          <div key={idx} className="glass-panel p-5 rounded-xl border border-gray-800 hover:border-blue-500/40 transition-all">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono bg-blue-500/20 text-blue-400 px-2 py-0.5 rounded font-bold">{t.id}</span>
              <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded ${
                t.level === 'Critical' ? 'bg-red-500/20 text-red-400' : 'bg-amber-500/20 text-amber-400'
              }`}>{t.level}</span>
            </div>
            <h3 className="text-sm font-bold text-white mt-3">{t.name}</h3>
            <p className="text-xs text-gray-400 mt-1 font-mono">{t.tactic}</p>
            <div className="mt-4 pt-3 border-t border-gray-800 text-xs text-gray-300 flex justify-between">
              <span>Active Detections:</span>
              <strong className="text-blue-400 font-mono">{t.count} Alerts</strong>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
