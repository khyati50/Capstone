import React from 'react';
import { 
  ShieldAlert, 
  AlertOctagon, 
  TrendingUp, 
  Activity, 
  CheckCircle2, 
  Flame 
} from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

export default function Dashboard({ alerts }) {
  const chartData = [
    { time: '08:00', alerts: 2, risk: 30 },
    { time: '09:00', alerts: 5, risk: 45 },
    { time: '10:00', alerts: 12, risk: 85 },
    { time: '11:00', alerts: 8, risk: 60 },
    { time: '12:00', alerts: 15, risk: 90 },
  ];

  return (
    <div className="space-y-6">
      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-5">
        <div className="glass-panel p-5 rounded-xl border border-blue-500/20 bg-blue-950/10">
          <div className="flex items-center justify-between">
            <span className="text-xs text-gray-400 font-medium">Total Ingested Events</span>
            <Activity className="w-5 h-5 text-blue-400" />
          </div>
          <p className="text-2xl font-extrabold text-white mt-2">1,064</p>
          <span className="text-[11px] text-blue-400 font-mono mt-1 block">● 100% Pipeline Coverage</span>
        </div>

        <div className="glass-panel p-5 rounded-xl border border-red-500/20 bg-red-950/10">
          <div className="flex items-center justify-between">
            <span className="text-xs text-gray-400 font-medium">Critical Alerts</span>
            <Flame className="w-5 h-5 text-red-500 animate-pulse" />
          </div>
          <p className="text-2xl font-extrabold text-white mt-2">4</p>
          <span className="text-[11px] text-red-400 font-mono mt-1 block">Requires Immediate Action</span>
        </div>

        <div className="glass-panel p-5 rounded-xl border border-amber-500/20 bg-amber-950/10">
          <div className="flex items-center justify-between">
            <span className="text-xs text-gray-400 font-medium">Dynamic Risk Score</span>
            <TrendingUp className="w-5 h-5 text-amber-400" />
          </div>
          <p className="text-2xl font-extrabold text-amber-400 mt-2">84.5 / 100</p>
          <span className="text-[11px] text-amber-400 font-mono mt-1 block">Level: CRITICAL</span>
        </div>

        <div className="glass-panel p-5 rounded-xl border border-emerald-500/20 bg-emerald-950/10">
          <div className="flex items-center justify-between">
            <span className="text-xs text-gray-400 font-medium">AI Model Confidence</span>
            <CheckCircle2 className="w-5 h-5 text-emerald-400" />
          </div>
          <p className="text-2xl font-extrabold text-white mt-2">94.2%</p>
          <span className="text-[11px] text-emerald-400 font-mono mt-1 block">XGBoost Production v1.0</span>
        </div>
      </div>

      {/* Chart & Live Stream */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="glass-panel p-5 rounded-xl lg:col-span-2">
          <h3 className="text-sm font-semibold text-gray-200 mb-4 flex items-center space-x-2">
            <Activity className="w-4 h-4 text-blue-400" />
            <span>Real-Time Incident Trend & Risk Escalation</span>
          </h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#6b7280" fontSize={11} />
                <YAxis stroke="#6b7280" fontSize={11} />
                <Tooltip contentStyle={{ backgroundColor: '#111827', borderColor: '#374151', borderRadius: '8px' }} />
                <Area type="monotone" dataKey="risk" stroke="#ef4444" fillOpacity={1} fill="url(#colorRisk)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Live Feed */}
        <div className="glass-panel p-5 rounded-xl">
          <h3 className="text-sm font-semibold text-gray-200 mb-4 flex items-center justify-between">
            <span className="flex items-center space-x-2">
              <ShieldAlert className="w-4 h-4 text-red-400" />
              <span>Live Alert Feed</span>
            </span>
            <span className="text-[10px] bg-red-500/20 text-red-400 px-2 py-0.5 rounded font-mono">SOCKET ACTIVE</span>
          </h3>

          <div className="space-y-3 max-h-64 overflow-y-auto pr-1">
            {alerts.slice(0, 5).map((a, idx) => (
              <div key={idx} className="p-3 bg-gray-900/80 rounded-lg border border-gray-800 text-xs hover:border-blue-500/40 transition-all">
                <div className="flex items-center justify-between">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                    a.severity === 'Critical' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-amber-500/20 text-amber-400'
                  }`}>
                    {a.severity}
                  </span>
                  <span className="text-[10px] text-gray-500 font-mono">{new Date(a.timestamp).toLocaleTimeString()}</span>
                </div>
                <p className="text-gray-200 font-medium mt-1 text-[11px] line-clamp-2">{a.summary}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
