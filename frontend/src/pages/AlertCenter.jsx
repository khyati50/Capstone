import React, { useState } from 'react';
import { 
  AlertTriangle, 
  Filter, 
  ChevronDown, 
  ChevronUp, 
  Terminal, 
  ShieldAlert, 
  Cpu, 
  CheckCircle2, 
  ListFilter, 
  Activity, 
  Link2, 
  GitCommit 
} from 'lucide-react';

export default function AlertCenter({ alerts, onSelectAlert }) {
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [expandedAlertId, setExpandedAlertId] = useState(null);

  const filtered = alerts.filter(a => {
    if (filterSeverity === 'ALL') return true;
    return a.severity && a.severity.toUpperCase() === filterSeverity;
  });

  const toggleExpand = (alertId) => {
    setExpandedAlertId(prev => (prev === alertId ? null : alertId));
  };

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center space-x-2">
            <AlertTriangle className="w-5 h-5 text-amber-400" />
            <span>Alert Management Center</span>
          </h2>
          <p className="text-xs text-gray-400">Investigate, filter, and inspect AI-explainable security alerts & forensic evidence</p>
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
      <div className="glass-panel rounded-xl overflow-hidden border border-gray-800">
        <table className="w-full text-left text-xs">
          <thead className="bg-[#0f172a] text-gray-400 border-b border-gray-800 uppercase font-mono text-[10px]">
            <tr>
              <th className="p-4 w-8"></th>
              <th className="p-4">Alert ID</th>
              <th className="p-4">Severity</th>
              <th className="p-4">Threat Type</th>
              <th className="p-4">Incident / Chain</th>
              <th className="p-4">Host / Target User</th>
              <th className="p-4">Confidence</th>
              <th className="p-4">Timestamp</th>
              <th className="p-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/60 text-gray-200">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan="9" className="p-8 text-center text-gray-500 font-mono text-xs">
                  No active security alerts matching the selected filter criteria.
                </td>
              </tr>
            ) : (
              filtered.map((a, idx) => {
                const isExpanded = expandedAlertId === a.alert_id;
                const evidence = a.evidence_package || {};
                const rawContext = evidence.raw_log_context || a.raw_event || {};
                const primaryIndicators = evidence.primary_indicators || (a.explanation ? [a.explanation] : []);
                const triggeredRules = a.triggered_rules || [];
                const isoScore = a.isolation_forest_score ?? a.anomaly_score ?? evidence.isolation_forest_score ?? evidence.anomaly_score ?? null;
                const isoStatus = a.isolation_forest_status ?? a.anomaly_status ?? evidence.isolation_forest_status ?? evidence.anomaly_status ?? null;

                const eventId = rawContext.EventID ?? a.event_id ?? 'N/A';
                const computer = rawContext.Computer || a.hostname || 'N/A';
                const targetUser = rawContext.TargetUserName || rawContext.User || a.username || 'N/A';
                const processName = rawContext.ProcessName || 'N/A';
                const commandLine = rawContext.CommandLine || 'N/A';

                const incidentId = a.incident_id || 'N/A';
                const chainLength = a.chain_length ?? 1;
                const isMultiStage = Boolean(a.is_multi_stage);

                return (
                  <React.Fragment key={a.alert_id || idx}>
                    <tr className={`hover:bg-gray-800/40 transition-colors ${isExpanded ? 'bg-gray-800/30' : ''}`}>
                      <td className="p-4 text-center cursor-pointer" onClick={() => toggleExpand(a.alert_id)}>
                        {isExpanded ? (
                          <ChevronUp className="w-4 h-4 text-blue-400" />
                        ) : (
                          <ChevronDown className="w-4 h-4 text-gray-400 hover:text-white" />
                        )}
                      </td>
                      <td className="p-4 font-mono text-blue-400 font-bold cursor-pointer" onClick={() => toggleExpand(a.alert_id)}>
                        {a.alert_id}
                      </td>
                      <td className="p-4">
                        <span className={`px-2.5 py-1 rounded text-[10px] font-bold uppercase ${
                          a.severity === 'Critical'
                            ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                            : a.severity === 'High'
                            ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                            : 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                        }`}>
                          {a.severity || 'Medium'}
                        </span>
                      </td>
                      <td className="p-4">
                        <div className="font-medium text-gray-100 flex items-center space-x-1.5 flex-wrap">
                          <span>{a.threat_type || 'Behavioral Anomaly'}</span>
                          {/* Multi-Stage Badge (Phase 13C) */}
                          {isMultiStage && (
                            <span className="inline-flex items-center space-x-1 px-1.5 py-0.5 bg-orange-500/20 text-orange-400 border border-orange-500/30 rounded text-[9px] font-bold font-mono uppercase">
                              <Link2 className="w-2.5 h-2.5" />
                              <span>Multi-Stage</span>
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Incident ID & Chain Length (Phase 13C) */}
                      <td className="p-4 font-mono text-xs">
                        <div className="flex flex-col space-y-0.5">
                          <span className="text-amber-400 font-semibold">{incidentId}</span>
                          <span className="text-[10px] text-gray-400 flex items-center space-x-1">
                            <GitCommit className="w-3 h-3 text-purple-400 inline" />
                            <span>Chain Length: {chainLength}</span>
                          </span>
                        </div>
                      </td>

                      <td className="p-4 font-mono text-gray-300">{computer} \ {targetUser}</td>
                      <td className="p-4">
                        <div className="flex items-center space-x-2">
                          <div className="w-16 bg-gray-800 h-1.5 rounded-full overflow-hidden">
                            <div className="bg-emerald-400 h-full" style={{ width: `${(a.confidence || 0.8) * 100}%` }}></div>
                          </div>
                          <span className="font-mono text-emerald-400 text-[11px]">{((a.confidence || 0.8) * 100).toFixed(0)}%</span>
                        </div>
                      </td>
                      <td className="p-4 font-mono text-gray-400 text-[11px]">
                        {a.timestamp ? new Date(a.timestamp).toLocaleString() : 'N/A'}
                      </td>
                      <td className="p-4 text-right space-x-2">
                        <button
                          onClick={() => toggleExpand(a.alert_id)}
                          className="inline-flex items-center space-x-1 px-2.5 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 hover:text-white border border-gray-700 rounded-md transition-all text-xs font-medium"
                          title="Toggle Forensic Evidence Drawer"
                        >
                          <Terminal className="w-3.5 h-3.5 text-amber-400" />
                          <span>{isExpanded ? 'Hide Evidence' : 'Evidence'}</span>
                        </button>
                        <button
                          onClick={() => onSelectAlert(a)}
                          className="inline-flex items-center space-x-1 px-3 py-1.5 bg-blue-600/20 hover:bg-blue-600 text-blue-400 hover:text-white border border-blue-500/30 rounded-md transition-all text-xs font-medium"
                        >
                          <Cpu className="w-3.5 h-3.5" />
                          <span>Explain (SHAP)</span>
                        </button>
                      </td>
                    </tr>

                    {/* Collapsible Forensic Evidence Drawer */}
                    {isExpanded && (
                      <tr className="bg-[#0b1329]/90 border-b border-blue-500/20">
                        <td colSpan="9" className="p-5">
                          <div className="space-y-4">
                            {/* Header / Summary with Phase 13C Multi-Stage & Chain Length */}
                            <div className="flex items-center justify-between border-b border-gray-800 pb-3 flex-wrap gap-2">
                              <div className="flex items-center space-x-2">
                                <ShieldAlert className="w-4 h-4 text-blue-400" />
                                <span className="text-xs font-bold text-white uppercase tracking-wider">
                                  Forensic Evidence Package — {a.alert_id}
                                </span>
                              </div>
                              <div className="flex items-center space-x-3 text-xs font-mono">
                                <span className="text-gray-400">
                                  Incident ID: <span className="text-amber-400 font-bold">{incidentId}</span>
                                </span>
                                <span className="px-2.5 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30 font-semibold">
                                  Chain Length: {chainLength}
                                </span>
                                {isMultiStage && (
                                  <span className="px-2.5 py-0.5 rounded bg-orange-500/20 text-orange-400 border border-orange-500/40 font-bold uppercase flex items-center space-x-1">
                                    <Link2 className="w-3 h-3" />
                                    <span>Multi-Stage Incident</span>
                                  </span>
                                )}
                              </div>
                            </div>

                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                              {/* 1. PRIMARY INDICATORS, TRIGGERED RULES & ISOLATION FOREST */}
                              <div className="space-y-3">
                                {/* Primary Indicators */}
                                <div className="bg-gray-900/80 p-3.5 rounded-lg border border-gray-800">
                                  <div className="flex items-center space-x-1.5 text-xs font-semibold text-emerald-400 mb-2">
                                    <CheckCircle2 className="w-3.5 h-3.5" />
                                    <span>Primary Detection Indicators</span>
                                  </div>
                                  {primaryIndicators.length === 0 ? (
                                    <p className="text-xs text-gray-500 italic">No specific detection indicators recorded.</p>
                                  ) : (
                                    <ul className="space-y-1.5">
                                      {primaryIndicators.map((ind, iIdx) => (
                                        <li key={iIdx} className="text-xs text-gray-300 flex items-start space-x-2 bg-black/40 p-2 rounded border border-gray-800/80">
                                          <span className="text-emerald-400 font-bold">•</span>
                                          <span className="leading-relaxed">{ind}</span>
                                        </li>
                                      ))}
                                    </ul>
                                  )}
                                </div>

                                {/* Triggered Rules */}
                                <div className="bg-gray-900/80 p-3.5 rounded-lg border border-gray-800">
                                  <div className="flex items-center space-x-1.5 text-xs font-semibold text-purple-400 mb-2">
                                    <ListFilter className="w-3.5 h-3.5" />
                                    <span>Triggered Detection Rules</span>
                                  </div>
                                  {triggeredRules.length === 0 ? (
                                    <span className="inline-block px-2.5 py-1 rounded bg-gray-800/60 text-gray-400 text-[11px] font-mono border border-gray-700">
                                      None (Pure Unsupervised Anomaly / ML Decision)
                                    </span>
                                  ) : (
                                    <div className="flex flex-wrap gap-2">
                                      {triggeredRules.map((rule, rIdx) => {
                                        const ruleDisplay = typeof rule === 'object' && rule !== null
                                          ? (rule.rule_id ? `${rule.rule_id} (${rule.rule_name || 'Signature Rule'})` : (rule.rule_name || rule.name || JSON.stringify(rule)))
                                          : String(rule);
                                        return (
                                          <span
                                            key={rIdx}
                                            className="px-2.5 py-1 bg-purple-500/20 text-purple-300 border border-purple-500/40 rounded font-mono text-[11px] font-semibold"
                                          >
                                            {ruleDisplay}
                                          </span>
                                        );
                                      })}
                                    </div>
                                  )}
                                </div>

                                {/* Isolation Forest Anomaly Score */}
                                <div className="bg-gray-900/80 p-3.5 rounded-lg border border-gray-800">
                                  <div className="flex items-center justify-between mb-2">
                                    <div className="flex items-center space-x-1.5 text-xs font-semibold text-cyan-400">
                                      <Activity className="w-3.5 h-3.5" />
                                      <span>Isolation Forest Anomaly Score</span>
                                    </div>
                                    {isoStatus && (
                                      <span className="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-mono text-[10px] uppercase border border-cyan-500/30">
                                        {isoStatus}
                                      </span>
                                    )}
                                  </div>
                                  {isoScore !== null && isoScore !== undefined ? (
                                    <div className="flex items-center space-x-3 bg-black/40 p-2 rounded border border-gray-800/80">
                                      <span className="text-amber-400 font-mono font-bold text-sm">
                                        {typeof isoScore === 'number' ? isoScore.toFixed(4) : isoScore}
                                      </span>
                                      <span className="text-gray-400 text-[11px] font-mono">
                                        (Raw Anomaly Decision Metric)
                                      </span>
                                    </div>
                                  ) : (
                                    <div className="bg-black/40 p-2 rounded border border-gray-800/80 text-gray-500 text-xs italic font-mono">
                                      Not available
                                    </div>
                                  )}
                                </div>
                              </div>

                              {/* 2. RAW LOG CONTEXT */}
                              <div className="bg-gray-900/80 p-3.5 rounded-lg border border-gray-800 space-y-3">
                                <div className="flex items-center space-x-1.5 text-xs font-semibold text-blue-400">
                                  <Terminal className="w-3.5 h-3.5" />
                                  <span>Raw Security Log Context</span>
                                </div>

                                <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                                  <div className="bg-black/50 p-2 rounded border border-gray-800">
                                    <span className="text-gray-500 text-[10px] block uppercase">Event ID</span>
                                    <span className="text-amber-400 font-bold">{eventId}</span>
                                  </div>
                                  <div className="bg-black/50 p-2 rounded border border-gray-800">
                                    <span className="text-gray-500 text-[10px] block uppercase">Endpoint / Host</span>
                                    <span className="text-gray-200 truncate block">{computer}</span>
                                  </div>
                                  <div className="bg-black/50 p-2 rounded border border-gray-800">
                                    <span className="text-gray-500 text-[10px] block uppercase">Target User</span>
                                    <span className="text-gray-200 truncate block">{targetUser}</span>
                                  </div>
                                  <div className="bg-black/50 p-2 rounded border border-gray-800">
                                    <span className="text-gray-500 text-[10px] block uppercase">Process Name</span>
                                    <span className="text-gray-200 truncate block">{processName}</span>
                                  </div>
                                </div>

                                {/* Full CommandLine */}
                                <div className="bg-black/60 p-2.5 rounded border border-gray-800 font-mono text-[11px]">
                                  <span className="text-gray-500 text-[10px] block uppercase mb-1">Command Line / Execution Arguments</span>
                                  <div className="text-emerald-300 font-mono break-all whitespace-pre-wrap max-h-24 overflow-y-auto bg-gray-950 p-2 rounded border border-gray-900">
                                    {commandLine}
                                  </div>
                                </div>
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
