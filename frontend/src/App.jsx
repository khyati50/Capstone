import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import Dashboard from './pages/Dashboard';
import AlertCenter from './pages/AlertCenter';
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

    // Socket.IO Real-time event listeners
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

    socket.on('reset_state', () => {
      setAlerts([]);
      setRiskData(null);
      setTimelineData(null);
      setMitreData([]);
      setSelectedAlert(null);
    });

    return () => {
      socket.off('new_alert');
      socket.off('risk_update');
      socket.off('timeline_update');
      socket.off('mitre_update');
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
          {activeTab === 'dashboard' && <Dashboard alerts={alerts} riskData={riskData} />}
          {activeTab === 'alerts' && <AlertCenter alerts={alerts} onSelectAlert={handleSelectAlert} />}
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


