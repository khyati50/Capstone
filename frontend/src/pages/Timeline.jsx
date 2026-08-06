import React from 'react';
import { GitCommit, ArrowRight, ShieldAlert, Cpu, CheckCircle } from 'lucide-react';

export default function Timeline() {
  const nodes = [
    { step: 1, event_id: 4625, title: 'Failed Login Burst (4625)', time: '10:00:12 AM', host: 'CORP-HOST-01', desc: '6 failed authentication attempts within 5 minutes.', severity: 'High' },
    { step: 2, event_id: 4624, title: 'Successful Login (4624)', time: '10:02:45 AM', host: 'CORP-HOST-01', desc: 'Successful interactive logon for user administrator.', severity: 'Medium' },
    { step: 3, event_id: 4672, title: 'Admin Privileges Assigned (4672)', time: '10:03:01 AM', host: 'CORP-HOST-01', desc: 'SeDebugPrivilege assigned to active logon session.', severity: 'High' },
    { step: 4, event_id: 4688, title: 'Suspicious PowerShell Execution (4688)', time: '10:04:18 AM', host: 'CORP-HOST-01', desc: 'PowerShell executed with -ExecutionPolicy Bypass and encoded payload.', severity: 'Critical' },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-bold text-white flex items-center space-x-2">
          <GitCommit className="w-5 h-5 text-blue-400" />
          <span>Interactive Attack Timeline & Chain Correlation</span>
        </h2>
        <p className="text-xs text-gray-400">Correlated multi-event incident sequence (Incident ID: INC-88A12)</p>
      </div>

      <div className="glass-panel p-6 rounded-xl">
        <div className="relative border-l-2 border-blue-500/40 ml-4 pl-6 space-y-8">
          {nodes.map((n) => (
            <div key={n.step} className="relative group">
              {/* Node Marker */}
              <div className={`absolute -left-[31px] top-0 w-6 h-6 rounded-full border-2 flex items-center justify-center font-bold text-[10px] ${
                n.severity === 'Critical' ? 'bg-red-950 border-red-500 text-red-400 animate-pulse' : 'bg-blue-950 border-blue-500 text-blue-400'
              }`}>
                {n.step}
              </div>

              {/* Node Content */}
              <div className="p-4 bg-gray-900/90 border border-gray-800 rounded-lg group-hover:border-blue-500/50 transition-all">
                <div className="flex items-center justify-between">
                  <h4 className="font-bold text-sm text-gray-100 flex items-center space-x-2">
                    <span>{n.title}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] uppercase ${
                      n.severity === 'Critical' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-amber-500/20 text-amber-400'
                    }`}>
                      {n.severity}
                    </span>
                  </h4>
                  <span className="text-xs text-gray-400 font-mono">{n.time}</span>
                </div>
                <p className="text-xs text-gray-300 mt-2">{n.desc}</p>
                <div className="mt-3 pt-2 border-t border-gray-800/80 flex items-center justify-between text-[11px] font-mono text-gray-400">
                  <span>Host: <strong className="text-gray-200">{n.host}</strong></span>
                  <span>Event ID: <strong className="text-blue-400">{n.event_id}</strong></span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
