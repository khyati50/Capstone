import React, { useState, useEffect } from 'react';
import { Grid, ShieldAlert } from 'lucide-react';
import { apiClient } from '../api/client';

export default function MitreMatrix({ mitreData }) {
  const [techniques, setTechniques] = useState(mitreData || []);

  useEffect(() => {
    if (mitreData && mitreData.length > 0) {
      setTechniques(mitreData);
    } else {
      apiClient.get('/mitre')
        .then(res => setTechniques(res.data.mapped_techniques || []))
        .catch(err => console.warn('MITRE fetch error:', err.message));
    }
  }, [mitreData]);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-bold text-white flex items-center space-x-2">
          <Grid className="w-5 h-5 text-blue-400" />
          <span>MITRE ATT&CK Framework Threat Navigator</span>
        </h2>
        <p className="text-xs text-gray-400">Standardized Tactic & Technique ID Mapping Grid ({techniques.length} Active Techniques)</p>
      </div>

      {techniques.length === 0 ? (
        <div className="glass-panel p-8 rounded-xl text-center text-gray-400 text-xs font-mono">
          No active MITRE ATT&CK techniques detected. Trigger attack simulations to map threat techniques in real-time.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {techniques.map((t, idx) => (
            <div key={idx} className="glass-panel p-5 rounded-xl border border-gray-800 hover:border-blue-500/40 transition-all">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono bg-blue-500/20 text-blue-400 px-2 py-0.5 rounded font-bold">{t.technique_id || t.id}</span>
                <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded ${
                  (t.level || 'High') === 'Critical' ? 'bg-red-500/20 text-red-400' : 'bg-amber-500/20 text-amber-400'
                }`}>{t.level || 'Active'}</span>
              </div>
              <h3 className="text-sm font-bold text-white mt-3">{t.technique_name || t.name}</h3>
              <p className="text-xs text-gray-400 mt-1 font-mono">{t.tactic}</p>
              <div className="mt-4 pt-3 border-t border-gray-800 text-xs text-gray-300 flex justify-between">
                <span>Active Detections:</span>
                <strong className="text-blue-400 font-mono">{t.active_alerts || t.count || 1} Alerts</strong>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}


