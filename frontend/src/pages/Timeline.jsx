import React, { useState, useEffect } from 'react';
import { GitCommit, ShieldAlert, Cpu } from 'lucide-react';
import { apiClient } from '../api/client';

export default function Timeline({ timelineData }) {
  const [data, setData] = useState(timelineData);

  useEffect(() => {
    if (timelineData) {
      setData(timelineData);
    } else {
      apiClient.get('/timeline/latest')
        .then(res => setData(res.data))
        .catch(err => console.warn('Timeline fetch fallback error:', err.message));
    }
  }, [timelineData]);

  const incidentId = data?.incident_id || 'INC-LIVE-01';
  const nodes = data?.nodes || [];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-bold text-white flex items-center space-x-2">
          <GitCommit className="w-5 h-5 text-blue-400" />
          <span>Interactive Attack Timeline & Chain Correlation</span>
        </h2>
        <p className="text-xs text-gray-400">Correlated multi-event incident sequence (Incident ID: {incidentId})</p>
      </div>

      {nodes.length === 0 ? (
        <div className="glass-panel p-8 rounded-xl text-center text-gray-400 text-xs font-mono">
          No correlated timeline events in active session. Trigger attack simulations to visualize sequence nodes.
        </div>
      ) : (
        <div className="glass-panel p-6 rounded-xl">
          <div className="relative border-l-2 border-blue-500/40 ml-4 pl-6 space-y-8">
            {nodes.map((n, idx) => (
              <div key={idx} className="relative group">
                {/* Node Marker */}
                <div className={`absolute -left-[31px] top-0 w-6 h-6 rounded-full border-2 flex items-center justify-center font-bold text-[10px] ${
                  n.severity === 'Critical' ? 'bg-red-950 border-red-500 text-red-400 animate-pulse' : 'bg-blue-950 border-blue-500 text-blue-400'
                }`}>
                  {n.step || (idx + 1)}
                </div>

                {/* Node Content */}
                <div className="p-4 bg-gray-900/90 border border-gray-800 rounded-lg group-hover:border-blue-500/50 transition-all">
                  <div className="flex items-center justify-between">
                    <h4 className="font-bold text-sm text-gray-100 flex items-center space-x-2">
                      <span>{n.label || n.title || `Event ${n.event_id}`}</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] uppercase ${
                        n.severity === 'Critical' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-amber-500/20 text-amber-400'
                      }`}>
                        {n.severity || 'High'}
                      </span>
                    </h4>
                    <span className="text-xs text-gray-400 font-mono">{n.timestamp ? new Date(n.timestamp).toLocaleTimeString() : (n.time || '')}</span>
                  </div>
                  <p className="text-xs text-gray-300 mt-2">{n.desc || `Event ID ${n.event_id} processed by correlation engine.`}</p>
                  <div className="mt-3 pt-2 border-t border-gray-800/80 flex items-center justify-between text-[11px] font-mono text-gray-400">
                    <span>Host: <strong className="text-gray-200">{n.computer || n.host || 'CORP-HOST-01'}</strong></span>
                    <span>Event ID: <strong className="text-blue-400">{n.event_id}</strong></span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}


