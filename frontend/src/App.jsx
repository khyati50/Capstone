import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import Dashboard from './pages/Dashboard';
import AlertCenter from './pages/AlertCenter';
import RawEvents from './pages/RawEvents';
import Timeline from './pages/Timeline';
import ShapExplainer from './pages/ShapExplainer';
import RiskGauge from './pages/RiskGauge';
import MitreMatrix from './pages/MitreMatrix';
import Simulation from './pages/Simulation';
import { socket, apiClient } from './api/client';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [riskData, setRiskData] = useState(null);
  const [timelineData, setTimelineData] = useState(null);
  const [mitreData, setMitreData] = useState([]);
  const [connectionStatus, setConnectionStatus] = useState(socket.connected ? 'CONNECTED' : 'CONNECTING');
  const [telemetry, setTelemetry] = useState({
    events_per_second: 0.0,
    buffer_utilization_percent: 0.0,
    dropped_events_count: 0,
    buffer_current_size: 0,
    buffer_max_capacity: 10000
  });

  useEffect(() => {
    // Initial fetch from backend REST APIs
    apiClient.get('/alerts')
      .then(res => setAlerts(res.data.alerts || []))
      .catch(err => console.warn('Could not fetch alerts from backend:', err.message));

    apiClient.get('/risk')
      .then(res => setRiskData(res.data))
      .catch(err => console.warn('Could not fetch risk from backend:', err.message));

    apiClient.get('/mitre')
      .then(res => setMitreData(res.data.mapped_techniques || []))
      .catch(err => console.warn('Could not fetch MITRE from backend:', err.message));

    // Socket.IO Connection Lifecycle Handlers
    const onConnect = () => setConnectionStatus('CONNECTED');
    const onDisconnect = () => setConnectionStatus('DISCONNECTED');
    const onConnecting = () => setConnectionStatus('CONNECTING');

    socket.on('connect', onConnect);
    socket.on('disconnect', onDisconnect);
    socket.on('connect_error', onDisconnect);
    socket.on('reconnect_attempt', onConnecting);
    socket.on('reconnect', onConnect);

    // Socket.IO Real-time Data Listeners
    socket.on('new_alert', (newAlert) => {
      setAlerts((prev) => [newAlert, ...prev]);
    });

    socket.on('risk_update', (newRisk) => {
      setRiskData(newRisk);
    });

    socket.on('timeline_update', (newTimeline) => {
      setTimelineData(newTimeline);
    });

    socket.on('mitre_update', (newMitre) => {
      setMitreData(newMitre || []);
    });

    socket.on('telemetry_update', (data) => {
      if (data) {
        setTelemetry({
          events_per_second: typeof data.events_per_second === 'number' ? data.events_per_second : 0.0,
          buffer_utilization_percent: typeof data.buffer_utilization_percent === 'number' ? data.buffer_utilization_percent : 0.0,
          dropped_events_count: typeof data.dropped_events_count === 'number' ? data.dropped_events_count : 0,
          buffer_current_size: typeof data.buffer_current_size === 'number' ? data.buffer_current_size : 0,
          buffer_max_capacity: typeof data.buffer_max_capacity === 'number' ? data.buffer_max_capacity : 10000
        });
      }
    });

    socket.on('reset_state', () => {
      setAlerts([]);
      setRiskData(null);
      setTimelineData(null);
      setMitreData([]);
      setSelectedAlert(null);
      setTelemetry({
        events_per_second: 0.0,
        buffer_utilization_percent: 0.0,
        dropped_events_count: 0,
        buffer_current_size: 0,
        buffer_max_capacity: 10000
      });
    });

    return () => {
      socket.off('connect', onConnect);
      socket.off('disconnect', onDisconnect);
      socket.off('connect_error', onDisconnect);
      socket.off('reconnect_attempt', onConnecting);
      socket.off('reconnect', onConnect);
      socket.off('new_alert');
      socket.off('risk_update');
      socket.off('timeline_update');
      socket.off('mitre_update');
      socket.off('telemetry_update');
      socket.off('reset_state');
    };
  }, []);

  const handleSelectAlert = (alert) => {
    setSelectedAlert(alert);
    setActiveTab('shap');
  };

  return (
    <div className="flex h-screen overflow-hidden bg-[#0b0f19]">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Header alertCount={alerts.length} />
        <main className="flex-1 overflow-y-auto p-6">
          {activeTab === 'dashboard' && (
            <Dashboard 
              alerts={alerts} 
              riskData={riskData} 
              telemetry={telemetry} 
              connectionStatus={connectionStatus} 
            />
          )}
          {activeTab === 'alerts' && <AlertCenter alerts={alerts} onSelectAlert={handleSelectAlert} />}
          {activeTab === 'events' && <RawEvents />}
          {activeTab === 'timeline' && <Timeline timelineData={timelineData} />}
          {activeTab === 'shap' && <ShapExplainer selectedAlert={selectedAlert} />}
          {activeTab === 'risk' && <RiskGauge riskData={riskData} />}
          {activeTab === 'mitre' && <MitreMatrix mitreData={mitreData} />}
          {activeTab === 'simulation' && <Simulation />}
        </main>
      </div>
    </div>
  );
}
