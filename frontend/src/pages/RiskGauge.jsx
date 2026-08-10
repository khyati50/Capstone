import React, { useState, useEffect } from 'react';
import { Gauge, ShieldAlert, AlertOctagon } from 'lucide-react';
import { apiClient } from '../api/client';

export default function RiskGauge({ riskData }) {
  const [data, setData] = useState(riskData);

  useEffect(() => {
    if (riskData) {
      setData(riskData);
    } else {
      apiClient.get('/risk')
        .then(res => setData(res.data))
        .catch(err => console.warn('Risk fetch fallback error:', err.message));
    }
  }, [riskData]);

  const score = data?.overall_score ?? data?.score ?? data?.risk_score ?? 0.0;
  const level = data?.overall_level ?? data?.level ?? data?.risk_level ?? 'LOW';
  const bd = data?.breakdown || data?.risk_breakdown || {};
  const sub = data?.sublines || {};

  const aiConf = bd.ai_confidence_weight ?? 0.0;
  const ruleHits = bd.rule_hits_weight ?? 0.0;
  const mitreTactic = bd.mitre_tactic_weight ?? bd.event_severity_weight ?? 0.0;
  const tacticDiversity = bd.tactic_diversity_weight ?? bd.chain_length_weight ?? 0.0;
  const scope = bd.scope_weight ?? 0.0;
  const multiplier = bd.corroboration_multiplier ?? 1.0;

  const isIdle = score === 0;

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
              <span className="text-4xl font-black text-white">{typeof score === 'number' ? score.toFixed(1) : score}</span>
            </div>
          </div>
          <div className="flex flex-col items-center space-y-2">
            <span className="px-4 py-1.5 bg-red-500/20 text-red-400 border border-red-500/40 rounded-full text-xs font-bold font-mono uppercase">
              LEVEL: {level}
            </span>
            {multiplier > 1.0 && (
              <span className="px-3 py-1 bg-amber-500/20 text-amber-300 border border-amber-500/40 rounded-full text-[11px] font-mono">
                Corroboration Multiplier: ×{multiplier.toFixed(2)}
              </span>
            )}
          </div>
        </div>

        {/* Multi-Factor Score Breakdown */}
        <div className="glass-panel p-6 rounded-xl lg:col-span-2 space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-sm font-semibold text-gray-200">Risk Calculation Score Breakdown</h3>
            <span className="text-xs font-mono text-gray-400">Multiplier: ×{multiplier.toFixed(2)}</span>
          </div>

          <div className="space-y-3.5 text-xs">
            {/* Factor 1: AI Confidence */}
            <div>
              <div className="flex justify-between text-gray-400 mb-1">
                <span>AI Confidence Weight (25%)</span>
                <span className="font-mono text-emerald-400">{aiConf.toFixed(1)} / 25.0</span>
              </div>
              <div className="w-full bg-gray-800 h-2 rounded-full">
                <div className="bg-emerald-400 h-full rounded-full" style={{ width: `${(aiConf / 25.0) * 100}%` }}></div>
              </div>
              {!isIdle && sub.ai_confidence_subline && (
                <p className="text-[11px] text-emerald-400/80 font-mono mt-1 pl-2 border-l border-emerald-500/30">
                  └─ {sub.ai_confidence_subline}
                </p>
              )}
            </div>

            {/* Factor 2: Rule Coverage */}
            <div>
              <div className="flex justify-between text-gray-400 mb-1">
                <span>Triggered Rules Coverage (20%)</span>
                <span className="font-mono text-amber-400">{ruleHits.toFixed(1)} / 20.0</span>
              </div>
              <div className="w-full bg-gray-800 h-2 rounded-full">
                <div className="bg-amber-400 h-full rounded-full" style={{ width: `${(ruleHits / 20.0) * 100}%` }}></div>
              </div>
              {!isIdle && sub.rule_hits_subline && (
                <p className="text-[11px] text-amber-400/80 font-mono mt-1 pl-2 border-l border-amber-500/30">
                  └─ {sub.rule_hits_subline}
                </p>
              )}
            </div>

            {/* Factor 3: MITRE Tactic Stage */}
            <div>
              <div className="flex justify-between text-gray-400 mb-1">
                <span>MITRE Tactic Stage (20%)</span>
                <span className="font-mono text-red-400">{mitreTactic.toFixed(1)} / 20.0</span>
              </div>
              <div className="w-full bg-gray-800 h-2 rounded-full">
                <div className="bg-red-400 h-full rounded-full" style={{ width: `${(mitreTactic / 20.0) * 100}%` }}></div>
              </div>
              {!isIdle && sub.mitre_tactic_subline && (
                <p className="text-[11px] text-red-400/80 font-mono mt-1 pl-2 border-l border-red-500/30">
                  └─ {sub.mitre_tactic_subline}
                </p>
              )}
            </div>

            {/* Factor 4: Tactic Diversity */}
            <div>
              <div className="flex justify-between text-gray-400 mb-1">
                <span>Attack Tactic Diversity (20%)</span>
                <span className="font-mono text-blue-400">{tacticDiversity.toFixed(1)} / 20.0</span>
              </div>
              <div className="w-full bg-gray-800 h-2 rounded-full">
                <div className="bg-blue-400 h-full rounded-full" style={{ width: `${(tacticDiversity / 20.0) * 100}%` }}></div>
              </div>
              {!isIdle && sub.tactic_diversity_subline && (
                <p className="text-[11px] text-blue-400/80 font-mono mt-1 pl-2 border-l border-blue-500/30">
                  └─ {sub.tactic_diversity_subline}
                </p>
              )}
            </div>

            {/* Factor 5: Scope */}
            <div>
              <div className="flex justify-between text-gray-400 mb-1">
                <span>Impacted Host & User Scope (15%)</span>
                <span className="font-mono text-purple-400">{scope.toFixed(1)} / 15.0</span>
              </div>
              <div className="w-full bg-gray-800 h-2 rounded-full">
                <div className="bg-purple-400 h-full rounded-full" style={{ width: `${(scope / 15.0) * 100}%` }}></div>
              </div>
              {!isIdle && sub.scope_subline && (
                <p className="text-[11px] text-purple-400/80 font-mono mt-1 pl-2 border-l border-purple-500/30">
                  └─ {sub.scope_subline}
                </p>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
