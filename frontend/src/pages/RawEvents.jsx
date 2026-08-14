import React, { useState, useEffect } from 'react';
import { 
  Database, 
  RefreshCw, 
  ChevronLeft, 
  ChevronRight, 
  ShieldCheck, 
  AlertTriangle, 
  Terminal, 
  Search, 
  AlertCircle, 
  Clock, 
  Server, 
  User 
} from 'lucide-react';
import { apiClient } from '../api/client';

export default function RawEvents() {
  const [events, setEvents] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');

  const fetchEvents = (page = currentPage, limit = pageSize) => {
    setLoading(true);
    setError(null);
    apiClient.get(`/events?page=${page}&limit=${limit}`)
      .then(res => {
        const data = res.data || {};
        const eventList = data.events || [];
        setEvents(eventList);
        setTotalCount(data.total_count ?? data.count ?? eventList.length);
        setTotalPages(data.total_pages ?? Math.ceil((data.total_count ?? eventList.length) / limit) ?? 1);
        setCurrentPage(data.page ?? page);
      })
      .catch(err => {
        console.error('Failed to fetch raw events:', err);
        setError(err.response?.data?.error || err.message || 'Failed to load event logs from backend API.');
      })
      .finally(() => {
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchEvents(currentPage, pageSize);
  }, [currentPage, pageSize]);

  const handlePrevPage = () => {
    if (currentPage > 1) {
      setCurrentPage(prev => prev - 1);
    }
  };

  const handleNextPage = () => {
    if (currentPage < totalPages) {
      setCurrentPage(prev => prev + 1);
    }
  };

  // Client-side quick filter on current page rows
  const filteredEvents = events.filter(e => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    const eid = String(e.event_id || '');
    const host = String(e.hostname || '').toLowerCase();
    const user = String(e.username || '').toLowerCase();
    const proc = String(e.process_name || '').toLowerCase();
    const cmd = String(e.command_line || '').toLowerCase();
    return eid.includes(q) || host.includes(q) || user.includes(q) || proc.includes(q) || cmd.includes(q);
  });

  return (
    <div className="space-y-6">
      {/* Header & Controls */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center space-x-2">
            <Database className="w-5 h-5 text-blue-400" />
            <span>Enterprise Raw Security Event Log Repository</span>
          </h2>
          <p className="text-xs text-gray-400">
            Real-time ingested Windows EVTX audit stream (Benign & Alert events)
          </p>
        </div>

        <div className="flex items-center space-x-3">
          {/* Quick Search */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-gray-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search host, user, process..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-[#111827] border border-gray-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500 transition-colors w-52"
            />
          </div>

          {/* Refresh Button */}
          <button
            onClick={() => fetchEvents(currentPage, pageSize)}
            disabled={loading}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 hover:text-white border border-gray-700 rounded-lg text-xs font-medium transition-all"
            title="Refresh logs from server"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-blue-400' : 'text-gray-400'}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Main Table Container */}
      <div className="glass-panel rounded-xl overflow-hidden border border-gray-800">
        {/* Loading State */}
        {loading && events.length === 0 ? (
          <div className="p-12 text-center space-y-3">
            <RefreshCw className="w-8 h-8 text-blue-400 animate-spin mx-auto" />
            <p className="text-xs text-gray-400 font-mono">Loading raw security event logs from database...</p>
          </div>
        ) : error ? (
          /* Error State */
          <div className="p-8 text-center space-y-4">
            <AlertCircle className="w-8 h-8 text-red-400 mx-auto" />
            <div className="space-y-1">
              <h3 className="text-sm font-semibold text-white">Failed to Load Event Stream</h3>
              <p className="text-xs text-red-400 font-mono">{error}</p>
            </div>
            <button
              onClick={() => fetchEvents(currentPage, pageSize)}
              className="px-4 py-1.5 bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/40 rounded-lg text-xs font-semibold transition-all"
            >
              Retry Request
            </button>
          </div>
        ) : filteredEvents.length === 0 ? (
          /* Empty State */
          <div className="p-12 text-center space-y-3">
            <Database className="w-8 h-8 text-gray-600 mx-auto" />
            <h3 className="text-sm font-semibold text-gray-300">No Security Events Recorded</h3>
            <p className="text-xs text-gray-500 max-w-sm mx-auto">
              No audit logs have been ingested yet. Launch an attack simulation or start the live Winlogbeat collector to populate the stream.
            </p>
          </div>
        ) : (
          /* Event Table */
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#0f172a] text-gray-400 border-b border-gray-800 uppercase font-mono text-[10px]">
                <tr>
                  <th className="p-4 w-12 text-center">#</th>
                  <th className="p-4">Timestamp</th>
                  <th className="p-4">Event ID</th>
                  <th className="p-4">Classification</th>
                  <th className="p-4">Endpoint / Host</th>
                  <th className="p-4">Target User</th>
                  <th className="p-4">Process Name</th>
                  <th className="p-4">Execution Command Line</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/60 text-gray-200">
                {filteredEvents.map((e, idx) => {
                  const isMalicious = e.prediction === 1 || e.severity === 'Critical' || e.severity === 'High';
                  const eventId = e.event_id || (e.raw_event && e.raw_event.EventID) || 4624;
                  const hostname = e.hostname || (e.raw_event && e.raw_event.Computer) || 'N/A';
                  const username = e.username || (e.raw_event && (e.raw_event.TargetUserName || e.raw_event.SubjectUserName)) || 'N/A';
                  const processName = e.process_name || (e.raw_event && e.raw_event.ProcessName) || 'N/A';
                  const commandLine = e.command_line || (e.raw_event && e.raw_event.CommandLine) || 'N/A';

                  return (
                    <tr key={e.id || idx} className="hover:bg-gray-800/40 transition-colors">
                      <td className="p-4 text-center font-mono text-gray-500 text-[10px]">
                        {e.id || (currentPage - 1) * pageSize + idx + 1}
                      </td>
                      <td className="p-4 font-mono text-gray-400 text-[11px] whitespace-nowrap">
                        <div className="flex items-center space-x-1.5">
                          <Clock className="w-3 h-3 text-gray-500" />
                          <span>{e.timestamp ? new Date(e.timestamp).toLocaleString() : 'N/A'}</span>
                        </div>
                      </td>
                      <td className="p-4">
                        <span className={`px-2 py-0.5 rounded font-mono text-[11px] font-bold border ${
                          eventId === 4625
                            ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                            : eventId === 4688
                            ? 'bg-blue-500/20 text-blue-300 border-blue-500/30'
                            : eventId === 4672 || eventId === 4720 || eventId === 4732
                            ? 'bg-purple-500/20 text-purple-300 border-purple-500/30'
                            : 'bg-gray-800 text-gray-300 border-gray-700'
                        }`}>
                          ID {eventId}
                        </span>
                      </td>
                      <td className="p-4">
                        {isMalicious ? (
                          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded text-[10px] font-bold uppercase bg-red-500/20 text-red-400 border border-red-500/30">
                            <AlertTriangle className="w-3 h-3" />
                            <span>{e.severity || 'Alert'}</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                            <ShieldCheck className="w-3 h-3" />
                            <span>Benign</span>
                          </span>
                        )}
                      </td>
                      <td className="p-4 font-mono text-gray-300 text-xs">
                        <span className="truncate block max-w-[120px]" title={hostname}>{hostname}</span>
                      </td>
                      <td className="p-4 font-mono text-gray-300 text-xs">
                        <span className="truncate block max-w-[120px]" title={username}>{username}</span>
                      </td>
                      <td className="p-4 font-mono text-gray-300 text-xs">
                        <span className="truncate block max-w-[140px]" title={processName}>{processName}</span>
                      </td>
                      <td className="p-4 font-mono text-[11px] text-gray-400 max-w-xs">
                        <div className="truncate bg-black/40 px-2 py-1 rounded border border-gray-800/80 text-emerald-400/90" title={commandLine}>
                          {commandLine}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Footer */}
        <div className="p-4 bg-[#0a0f1d] border-t border-gray-800 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 text-xs font-mono text-gray-400">
          <div className="flex items-center space-x-2">
            <span>Showing {filteredEvents.length} of {totalCount} total logged events</span>
          </div>

          <div className="flex items-center space-x-3">
            <span className="text-gray-300">
              Page <span className="text-white font-bold">{currentPage}</span> of <span className="text-white font-bold">{totalPages || 1}</span>
            </span>

            <div className="flex items-center space-x-1">
              <button
                onClick={handlePrevPage}
                disabled={currentPage <= 1 || loading}
                className="p-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-300 disabled:opacity-40 disabled:cursor-not-allowed border border-gray-700 transition-colors"
                title="Previous Page"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <button
                onClick={handleNextPage}
                disabled={currentPage >= totalPages || loading}
                className="p-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-300 disabled:opacity-40 disabled:cursor-not-allowed border border-gray-700 transition-colors"
                title="Next Page"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
