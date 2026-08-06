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
import { socket } from './api/client';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [alerts, setAlerts] = useState([
    {
      alert_id: 'ALT-1001',
      severity: 'Critical',
      status: 'Investigating',
      threat_type: 'Credential Access / Brute Force Attack',
      summary: 'High frequency of failed logins (6 attempts in 5m) detected on host CORP-HOST-01 for user administrator.',
      confidence: 0.94,
      hostname: 'CORP-HOST-01',
      username: 'administrator',
      explanation: 'High frequency of failed authentication attempts detected within 5 minutes.',
      shap_values: { failed_login_count_5m: 0.42, privilege_escalation_flag: 0.35, is_powershell_executed: 0.15 },
      recommendations: [
        '1. Lock user account administrator.',
        '2. Inspect active IP 192.168.1.105.',
        '3. Enforce multi-factor authentication reset.'
      ],
      timestamp: new Date().toISOString()
    },
    {
      alert_id: 'ALT-1002',
      severity: 'High',
      status: 'New',
      threat_type: 'Suspicious Execution / PowerShell Abuse',
      summary: 'PowerShell process launched with execution policy bypass parameters on DC-01.',
      confidence: 0.89,
      hostname: 'DC-01',
      username: 'jdoe',
      explanation: 'Suspicious PowerShell process launched with script arguments.',
      shap_values: { is_powershell_executed: 0.45, unusual_process_parent_ratio: 0.28 },
      recommendations: [
        '1. Terminate PowerShell process ID 4412.',
        '2. Inspect encoded command payload.'
      ],
      timestamp: new Date(Date.now() - 3600000).toISOString()
    }
  ]);

  useEffect(() => {
    socket.on('new_alert', (newAlert) => {
      setAlerts((prev) => [newAlert, ...prev]);
    });
    return () => socket.off('new_alert');
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
          {activeTab === 'dashboard' && <Dashboard alerts={alerts} />}
          {activeTab === 'alerts' && <AlertCenter alerts={alerts} onSelectAlert={handleSelectAlert} />}
          {activeTab === 'timeline' && <Timeline />}
          {activeTab === 'shap' && <ShapExplainer selectedAlert={selectedAlert} />}
          {activeTab === 'risk' && <RiskGauge />}
          {activeTab === 'mitre' && <MitreMatrix />}
          {activeTab === 'simulation' && <Simulation />}
        </main>
      </div>
    </div>
  );
}
