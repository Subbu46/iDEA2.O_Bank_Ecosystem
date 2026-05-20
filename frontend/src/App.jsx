import React, { useState, useEffect } from 'react';
import Dashboard from './components/Dashboard';
import KnowledgeGraph from './components/KnowledgeGraph';
import AlertPanel from './components/AlertPanel';
import PlaybookViewer from './components/PlaybookViewer';
import RedTeamSim from './components/RedTeamSim';
import { alertsApi } from './api/client';

export default function App() {
  const [alerts, setAlerts] = useState([]);
  const [selectedItem, setSelectedItem] = useState(null);
  const [itemType, setItemType] = useState('alert'); // 'alert' or 'node'
  const [statsTrigger, setStatsTrigger] = useState(0);

  const fetchAlerts = () => {
    alertsApi.listAlerts()
      .then(data => {
        setAlerts(data);
        setStatsTrigger(prev => prev + 1);
      })
      .catch(() => {});
  };

  useEffect(() => {
    fetchAlerts();
    // Poll alerts every 10 seconds for real-time security tracking
    const interval = setInterval(fetchAlerts, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleSelectAlert = (alert) => {
    setSelectedItem(alert);
    setItemType('alert');
  };

  const handleSelectNode = (node) => {
    setSelectedItem(node);
    setItemType('node');
  };

  const handleSimulationTriggered = () => {
    fetchAlerts();
  };

  const sidePanel = (
    <div className="flex flex-col gap-6">
      <AlertPanel 
        alerts={alerts} 
        onSelectAlert={handleSelectAlert} 
        onRefreshAlerts={fetchAlerts} 
      />
      <PlaybookViewer 
        selectedItem={selectedItem} 
        type={itemType} 
      />
    </div>
  );

  return (
    <Dashboard stats={statsTrigger} sidePanel={sidePanel}>
      <div className="flex-1 flex flex-col gap-6">
        {/* Force Graph Viewport */}
        <KnowledgeGraph onSelectNode={handleSelectNode} />
        
        {/* Red Team Controls */}
        <RedTeamSim onSimulationTriggered={handleSimulationTriggered} />
      </div>
    </Dashboard>
  );
}
