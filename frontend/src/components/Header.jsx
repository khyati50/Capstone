import React from 'react';
import { Bell, Activity, UserCheck, Search } from 'lucide-react';

export default function Header({ alertCount }) {
  return (
    <header className="h-16 bg-[#0d1322]/80 backdrop-blur-md border-b border-[#1f2937] px-6 flex items-center justify-between sticky top-0 z-30">
      <div className="flex items-center space-x-4">
        <div className="relative">
          <Search className="w-4 h-4 text-gray-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search EventID, Host, User, Technique..."
            className="bg-[#111827] border border-gray-800 text-xs text-gray-200 pl-9 pr-4 py-2 rounded-lg w-72 focus:outline-none focus:border-blue-500/50 transition-colors"
          />
        </div>
      </div>

      <div className="flex items-center space-x-5">
        <div className="flex items-center space-x-2 text-xs text-gray-400 bg-gray-900/60 px-3 py-1.5 rounded-full border border-gray-800">
          <Activity className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
          <span>Pipeline Status: <strong className="text-emerald-400 font-mono">LIVE INGESTION</strong></span>
        </div>

        <button className="relative p-2 text-gray-400 hover:text-white transition-colors">
          <Bell className="w-5 h-5" />
          {alertCount > 0 && (
            <span className="absolute top-1 right-1 w-4 h-4 bg-red-500 text-white text-[10px] font-bold rounded-full flex items-center justify-center animate-bounce">
              {alertCount}
            </span>
          )}
        </button>

        <div className="flex items-center space-x-2 pl-3 border-l border-gray-800">
          <div className="w-8 h-8 rounded-full bg-blue-600/30 border border-blue-500/50 flex items-center justify-center text-blue-400">
            <UserCheck className="w-4 h-4" />
          </div>
          <div className="text-left hidden md:block">
            <p className="text-xs font-semibold text-gray-200">SOC Analyst</p>
            <p className="text-[10px] text-gray-500">Tier-2 Security Lead</p>
          </div>
        </div>
      </div>
    </header>
  );
}
