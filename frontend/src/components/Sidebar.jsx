import React from 'react';
import { 
  ShieldAlert, 
  LayoutDashboard, 
  AlertTriangle, 
  GitCommit, 
  Cpu, 
  Gauge, 
  Grid, 
  PlaySquare 
} from 'lucide-react';

export default function Sidebar({ activeTab, setActiveTab }) {
  const navItems = [
    { id: 'dashboard', label: 'SOC Overview', icon: LayoutDashboard },
    { id: 'alerts', label: 'Alert Center', icon: AlertTriangle },
    { id: 'timeline', label: 'Attack Timeline', icon: GitCommit },
    { id: 'shap', label: 'SHAP Explainability', icon: Cpu },
    { id: 'risk', label: 'Risk Assessment', icon: Gauge },
    { id: 'mitre', label: 'MITRE Matrix', icon: Grid },
    { id: 'simulation', label: 'Attack Simulation', icon: PlaySquare },
  ];

  return (
    <aside className="w-64 bg-[#0d1322] border-r border-[#1f2937] flex flex-col h-screen select-none">
      <div className="p-5 border-b border-[#1f2937] flex items-center space-x-3">
        <ShieldAlert className="w-8 h-8 text-blue-500 animate-pulse" />
        <div>
          <h1 className="font-bold text-white tracking-wide text-sm">AEGIS-XAI</h1>
          <p className="text-[10px] text-blue-400 font-mono uppercase tracking-wider">Windows Threat SIEM</p>
        </div>
      </div>

      <nav className="flex-1 p-4 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-xs font-medium transition-all duration-200 ${
                isActive
                  ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30 shadow-lg shadow-blue-500/10'
                  : 'text-gray-400 hover:bg-gray-800/60 hover:text-gray-200'
              }`}
            >
              <Icon className={`w-4 h-4 ${isActive ? 'text-blue-400' : 'text-gray-400'}`} />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      <div className="p-4 border-t border-[#1f2937]">
        <div className="glass-panel p-3 rounded-lg text-xs">
          <p className="text-gray-400 font-medium">Model Engine</p>
          <p className="text-emerald-400 font-mono text-[11px] mt-0.5">● Active (XGBoost v1.0)</p>
          <p className="text-gray-500 text-[10px] mt-1">WDAC Enforced Mode</p>
        </div>
      </div>
    </aside>
  );
}
