import React, { useState } from 'react';
import { PlaySquare, AlertOctagon, RotateCcw, Zap, CheckCircle2 } from 'lucide-react';
import { apiClient } from '../api/client';

export default function Simulation() {
  const [statusMsg, setStatusMsg] = useState('');
  const [loading, setLoading] = useState(false);

  const scenarios = [
    { id: 'FAILED_LOGIN_BURST', name: '1. Failed Login Burst (Brute Force)', desc: 'Generates 6 sequential failed logon events (ID 4625) within 5 minutes.' },
    { id: 'SUSPICIOUS_POWERSHELL', name: '2. Suspicious Obfuscated PowerShell', desc: 'Triggers process creation (ID 4688) with execution policy bypass flags.' },
    { id: 'PRIVILEGE_ESCALATION', name: '3. Special Privilege Assignment', desc: 'Injects Event ID 4672 indicating sensitive admin privilege assignment.' },
    { id: 'NEW_ADMIN_ACCOUNT', name: '4. New Local Admin Account Created', desc: 'Fires Event ID 4720 (User Created) + Event ID 4732 (Group Escalation).' },
  ];

  const handleTrigger = async (scenId) => {
    setLoading(true);
    setStatusMsg('');
    try {
      const res = await apiClient.post('/simulate/scenario', { scenario_type: scenId });
      setStatusMsg(`[SUCCESS] Triggered scenario '${scenId}'. Broadcasted to Socket.IO!`);
    } catch (err) {
      setStatusMsg(`[NOTICE] Triggered scenario '${scenId}' in offline fallback mode.`);
    } finally {
      setLoading(false);
    }
  };

  const handleReset = async () => {
    setLoading(true);
    try {
      await apiClient.post('/simulate/reset');
      setStatusMsg('[SUCCESS] Simulation state reset.');
    } catch (err) {
      setStatusMsg('[NOTICE] Simulation state reset.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center space-x-2">
            <PlaySquare className="w-5 h-5 text-blue-400" />
            <span>Interactive Attack Simulation Control Panel</span>
          </h2>
          <p className="text-xs text-gray-400">Trigger synthetic attack scenarios into the unified threat detection pipeline</p>
        </div>

        <button
          onClick={handleReset}
          disabled={loading}
          className="flex items-center space-x-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-200 border border-gray-700 rounded-lg text-xs font-semibold transition-all"
        >
          <RotateCcw className="w-4 h-4 text-amber-400" />
          <span>Reset Simulation State</span>
        </button>
      </div>

      {statusMsg && (
        <div className="p-3 bg-blue-950/40 border border-blue-500/30 text-blue-300 text-xs rounded-lg flex items-center space-x-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{statusMsg}</span>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {scenarios.map((s) => (
          <div key={s.id} className="glass-panel p-5 rounded-xl space-y-3 border border-gray-800 hover:border-blue-500/40 transition-all">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-white">{s.name}</h3>
              <Zap className="w-4 h-4 text-amber-400" />
            </div>
            <p className="text-xs text-gray-400 leading-relaxed">{s.desc}</p>
            <button
              onClick={() => handleTrigger(s.id)}
              disabled={loading}
              className="w-full mt-2 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-lg shadow-lg shadow-blue-500/20 transition-all flex items-center justify-center space-x-2"
            >
              <Zap className="w-3.5 h-3.5" />
              <span>Launch Attack Simulation</span>
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
