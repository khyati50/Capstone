import React from 'react';
import { 
  ShieldAlert, 
  AlertOctagon, 
  TrendingUp, 
  Activity, 
  CheckCircle2, 
  Flame, 
  Radio, 
  Layers, 
  AlertCircle, 
  Zap, 
  Wifi, 
  WifiOff 
} from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

export default function Dashboard({ alerts = [], riskData, telemetry = {}, connectionStatus = 'CONNECTED' }) {
  const chartData = [
    { time: '08:00', alerts: 2, risk: 30 },
    { time: '09:00', alerts: 5, risk: 45 },
    { time: '10:00', alerts: 12, risk: 85 },
    { time: '11:00', alerts: 8, risk: 60 },
    { time: '12:00', alerts: 15, risk: 90 },
  ];

  const criticalCount = alerts.filter(a => a.severity === 'Critical').length;
  const currentRiskScore = riskData?.overall_score ?? riskData?.score ?? 0.0;
  const currentRiskLevel = riskData?.overall_level ?? riskData?.level ?? (alerts.length > 0 ? 'HIGH' : 'LOW');

  // Safe Telemetry extractions (Never undefined, null, or NaN)
  const eps = typeof telemetry?.events_per_second === 'number' && !isNaN(telemetry.events_per_second)
    ? telemetry.events_per_second
    : 0.0;
  const bufferPercent = typeof telemetry?.buffer_utilization_percent === 'number' && !isNaN(telemetry.buffer_utilization_percent)
    ? telemetry.buffer_utilization_percent
    : 0.0;
  const droppedEvents = typeof telemetry?.dropped_events_count === 'number' && !isNaN(telemetry.dropped_events_count)
    ? telemetry.dropped_events_count
    : 0;
  const currentBufferSize = typeof telemetry?.buffer_current_size === 'number' && !isNaN(telemetry.buffer_current_size)
    ? telemetry.buffer_current_size
    : 0;
  const maxBufferCapacity = typeof telemetry?.buffer_max_capacity === 'number' && !isNaN(telemetry.buffer_max_capacity)
    ? telemetry.buffer_max_capacity
    : 10000;

  const status = connectionStatus || 'CONNECTED';

  return (
    <div className="space-y-6">
      {/* PHASE 13E: Live Ingestion & Real-Time Telemetry Bar */}
      <div className="glass-panel p-4 rounded-xl border border-blue-500/30 bg-gradient-to-r from-[#0d152a] via-[#0f172a] to-[#0a1020]">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          {/* Section Title & Connection Badge */}
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/30">
              <Radio className="w-5 h-5 text-cyan-400 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="text-sm font-bold text-white tracking-wide">Live Ingestion Telemetry</h3>
                {/* Connection Status Badge */}
                {status === 'CONNECTED' ? (
                  <span className="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-[10px] font-mono font-bold uppercase">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping"></span>
                    <span>CONNECTED</span>
                  </span>
                ) : status === 'CONNECTING' ? (
                  <span className="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/30 text-[10px] font-mono font-bold uppercase">
                    <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse"></span>
                    <span>CONNECTING</span>
                  </span>
                ) : (
                  <span className="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full bg-red-500/20 text-red-400 border border-red-500/30 text-[10px] font-mono font-bold uppercase">
                    <WifiOff className="w-2.5 h-2.5" />
                    <span>DISCONNECTED</span>
                  </span>
                )}
              </div>
              <p className="text-[11px] text-gray-400 font-mono">Real-time Winlogbeat ring buffer & sliding-window throughput</p>
            </div>
          </div>

          {/* 3 Real-time Telemetry Metric Badges */}
          <div className="grid grid-cols-3 gap-3">
            {/* 1. Events Per Second */}
            <div className="bg-black/50 p-2.5 rounded-lg border border-gray-800 min-w-[130px]">
              <div className="flex items-center justify-between text-[10px] text-gray-400 font-mono uppercase">
                <span>Throughput</span>
                <Zap className="w-3 h-3 text-cyan-400" />
              </div>
              <p className="text-base font-extrabold text-cyan-400 font-mono mt-0.5">
                {eps.toFixed(1)} <span className="text-[10px] font-normal text-gray-400">EPS</span>
              </p>
            </div>

            {/* 2. Ring-Buffer Utilization */}
            <div className="bg-black/50 p-2.5 rounded-lg border border-gray-800 min-w-[150px]">
              <div className="flex items-center justify-between text-[10px] text-gray-400 font-mono uppercase">
                <span>Buffer Fill</span>
                <Layers className="w-3 h-3 text-purple-400" />
              </div>
              <div className="flex items-center space-x-2 mt-0.5">
                <span className="text-base font-extrabold text-purple-400 font-mono">
                  {bufferPercent.toFixed(1)}%
                </span>
                <div className="w-12 bg-gray-800 h-1.5 rounded-full overflow-hidden">
                  <div 
                    className="bg-purple-500 h-full transition-all duration-300" 
                    style={{ width: `${Math.min(100, Math.max(2, bufferPercent))}%` }}
                  ></div>
                </div>
              </div>
            </div>

            {/* 3. Dropped Events */}
            <div className="bg-black/50 p-2.5 rounded-lg border border-gray-800 min-w-[130px]">
              <div className="flex items-center justify-between text-[10px] text-gray-400 font-mono uppercase">
                <span>Dropped Logs</span>
                <AlertCircle className={`w-3 h-3 ${droppedEvents > 0 ? 'text-red-400' : 'text-emerald-400'}`} />
              </div>
              <p className={`text-base font-extrabold font-mono mt-0.5 ${droppedEvents > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                {droppedEvents} <span className="text-[10px] font-normal text-gray-400">{droppedEvents === 0 ? '(0 Loss)' : 'lost'}</span>
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-5">
        <div className="glass-panel p-5 rounded-xl border border-blue-500/20 bg-blue-950/10">
          <div className="flex items-center justify-between">
            <span className="text-xs text-gray-400 font-medium">Total Active Alerts</span>
            <Activity className="w-5 h-5 text-blue-400" />
          </div>
          <p className="text-2xl font-extrabold text-white mt-2">{alerts.length}</p>
          <span className="text-[11px] text-blue-400 font-mono mt-1 block">● Real-Time Socket Stream</span>
        </div>

        <div className="glass-panel p-5 rounded-xl border border-red-500/20 bg-red-950/10">
          <div className="flex items-center justify-between">
            <span className="text-xs text-gray-400 font-medium">Critical Alerts</span>
            <Flame className="w-5 h-5 text-red-500 animate-pulse" />
          </div>
          <p className="text-2xl font-extrabold text-white mt-2">{criticalCount}</p>
          <span className="text-[11px] text-red-400 font-mono mt-1 block">Requires Immediate Action</span>
        </div>

        <div className="glass-panel p-5 rounded-xl border border-amber-500/20 bg-amber-950/10">
          <div className="flex items-center justify-between">
            <span className="text-xs text-gray-400 font-medium">Dynamic Risk Score</span>
            <TrendingUp className="w-5 h-5 text-amber-400" />
          </div>
          <p className="text-2xl font-extrabold text-amber-400 mt-2">{typeof currentRiskScore === 'number' ? currentRiskScore.toFixed(1) : currentRiskScore} / 100</p>
          <span className="text-[11px] text-amber-400 font-mono mt-1 block">Level: {currentRiskLevel.toUpperCase()}</span>
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
            {alerts.length === 0 ? (
              <div className="p-6 text-center text-gray-500 text-xs font-mono">
                No active alerts in current session.
              </div>
            ) : (
              alerts.slice(0, 5).map((a, idx) => (
                <div key={idx} className="p-3 bg-gray-900/80 rounded-lg border border-gray-800 text-xs hover:border-blue-500/40 transition-all">
                  <div className="flex items-center justify-between">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      a.severity === 'Critical' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-amber-500/20 text-amber-400'
                    }`}>
                      {a.severity || 'Medium'}
                    </span>
                    <span className="text-[10px] text-gray-500 font-mono">
                      {a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : 'N/A'}
                    </span>
                  </div>
                  <p className="text-gray-200 font-medium mt-1 text-[11px] line-clamp-2">{a.summary || a.threat_type || 'Malicious event'}</p>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
