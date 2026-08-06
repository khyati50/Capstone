import React from 'react';
import { Gauge, ShieldAlert, AlertOctagon } from 'lucide-react';

export default function RiskGauge() {
  const score = 84.5;
  const level = 'CRITICAL';

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-bold text-white flex items-center space-x-2">
          <Gauge className="w-5 h-5 text-amber-400" />
          <span>Dynamic Risk Assessment Engine</span>
        </h2>
        <p className="text-xs text-gray-400">Multi-factor Dynamic Threat Scoring (0 - 100 Escalation Scale)</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Dynamic Risk Gauge */}
        <div className="glass-panel p-6 rounded-xl flex flex-col items-center justify-center text-center border border-red-500/30">
          <span className="text-xs text-gray-400 font-mono">ENTERPRISE THREAT RATING</span>
          <div className="relative my-6 flex items-center justify-center">
            <div className="w-44 h-44 rounded-full border-8 border-red-500/20 border-t-red-500 border-r-red-500 flex items-center justify-center animate-pulse">
              <span className="text-4xl font-black text-white">{score}</span>
            </div>
          </div>
          <span className="px-4 py-1.5 bg-red-500/20 text-red-400 border border-red-500/40 rounded-full text-xs font-bold font-mono uppercase">
            LEVEL: {level}
          </span>
        </div>

        {/* Multi-Factor Score Breakdown */}
        <div className="glass-panel p-6 rounded-xl lg:col-span-2 space-y-4">
          <h3 className="text-sm font-semibold text-gray-200">Risk Calculation Score Breakdown</h3>
          <div className="space-y-3 text-xs">
            <div>
              <div className="flex justify-between text-gray-400 mb-1">
                <span>AI Confidence Weight (30%)</span>
                <span className="font-mono text-emerald-400">27.6 / 30.0</span>
              </div>
              <div className="w-full bg-gray-800 h-2 rounded-full"><div className="bg-emerald-400 h-full rounded-full" style={{ width: '92%' }}></div></div>
            </div>

            <div>
              <div className="flex justify-between text-gray-400 mb-1">
                <span>Triggered Rules Weight (20%)</span>
                <span className="font-mono text-amber-400">20.0 / 20.0</span>
              </div>
              <div className="w-full bg-gray-800 h-2 rounded-full"><div className="bg-amber-400 h-full rounded-full" style={{ width: '100%' }}></div></div>
            </div>

            <div>
              <div className="flex justify-between text-gray-400 mb-1">
                <span>Event Severity Rating (15%)</span>
                <span className="font-mono text-red-400">15.0 / 15.0</span>
              </div>
              <div className="w-full bg-gray-800 h-2 rounded-full"><div className="bg-red-400 h-full rounded-full" style={{ width: '100%' }}></div></div>
            </div>

            <div>
              <div className="flex justify-between text-gray-400 mb-1">
                <span>Attack Chain Length Progression (20%)</span>
                <span className="font-mono text-blue-400">13.2 / 20.0</span>
              </div>
              <div className="w-full bg-gray-800 h-2 rounded-full"><div className="bg-blue-400 h-full rounded-full" style={{ width: '66%' }}></div></div>
            </div>

            <div>
              <div className="flex justify-between text-gray-400 mb-1">
                <span>Impacted Host & User Scope (15%)</span>
                <span className="font-mono text-purple-400">8.7 / 15.0</span>
              </div>
              <div className="w-full bg-gray-800 h-2 rounded-full"><div className="bg-purple-400 h-full rounded-full" style={{ width: '58%' }}></div></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
