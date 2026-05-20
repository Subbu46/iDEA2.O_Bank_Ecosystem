import React, { useState, useEffect } from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { alertsApi, graphApi } from '../api/client';

export default function Dashboard({ children, sidePanel, stats }) {
  const [activeAlertsCount, setActiveAlertsCount] = useState(0);
  const [resolvedCount, setResolvedCount] = useState(0);
  const [isSyncing, setIsSyncing] = useState(false);
  const [syncResult, setSyncResult] = useState(null);

  const handleSyncThreatIntel = () => {
    setIsSyncing(true);
    setSyncResult(null);
    graphApi.syncThreatIntel()
      .then(data => {
        setIsSyncing(false);
        setSyncResult(data);
      })
      .catch(err => {
        setIsSyncing(false);
        console.error("Sync failed", err);
      });
  };

  useEffect(() => {
    alertsApi.listAlerts()
      .then(data => {
        const unresolved = data.filter(a => a.status === 'UNRESOLVED').length;
        const resolved = data.filter(a => a.status === 'RESOLVED').length;
        setActiveAlertsCount(unresolved);
        setResolvedCount(resolved);
      })
      .catch(() => {});
  }, [stats]);

  // Cyber threat intelligence metrics timeline
  const threatHistoryData = [
    { time: '12:00', load: 45 },
    { time: '13:00', load: 60 },
    { time: '14:00', load: 50 },
    { time: '15:00', load: 85 },
    { time: '16:00', load: 70 },
    { time: '17:00', load: 95 },
    { time: '18:00', load: 90 },
  ];

  const overallThreatLevel = activeAlertsCount > 4 ? 'CRITICAL' : activeAlertsCount > 1 ? 'HIGH' : 'STABLE';
  const severityColors = {
    CRITICAL: 'text-rose-500 border-rose-500/20 bg-rose-500/5',
    HIGH: 'text-amber-500 border-amber-500/20 bg-amber-500/5',
    STABLE: 'text-emerald-500 border-emerald-500/20 bg-emerald-500/5',
  };

  return (
    <div className="min-h-screen flex flex-col font-sans text-slate-100 cyber-grid relative">
      {/* Top Banner Navigation */}
      <header className="glass-panel border-b border-cyber-border px-6 py-4 flex justify-between items-center z-10">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 flex items-center justify-center border border-cyan-500/30 shadow-glow-cyan">
            <span className="text-2xl">🛡️</span>
          </div>
          <div>
            <h1 className="text-xl font-extrabold tracking-wider bg-gradient-to-r from-cyan-400 to-indigo-400 bg-clip-text text-transparent font-sans">
              SARATHI CYBERDEFENSE
            </h1>
            <p className="text-[10px] tracking-widest text-slate-400 uppercase">Intelligent Breach Orchestrator</p>
          </div>
        </div>
        
        <div className="flex items-center gap-6">
          <div className={`px-4 py-1.5 rounded-full border text-xs font-semibold tracking-wider ${severityColors[overallThreatLevel]}`}>
            STATUS: {overallThreatLevel}
          </div>
          <div className="text-right">
            <p className="text-xs text-slate-400">SOC operator session</p>
            <p className="text-sm font-bold text-cyan-400">SYS-ADMIN@sarathi.local</p>
          </div>
        </div>
      </header>

      {/* Main Workspace Layout */}
      <main className="flex-1 p-6 grid grid-cols-1 lg:grid-cols-12 gap-6 overflow-hidden">
        {/* Left column: Analytics & Controls */}
        <div className="lg:col-span-8 flex flex-col gap-6">
          {/* Stats Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="glass-panel p-4 rounded-xl flex flex-col justify-between">
              <span className="text-xs text-slate-400 font-medium">TOTAL INGESTED NODES</span>
              <span className="text-2xl font-black text-slate-100 mt-2">12</span>
            </div>
            <div className="glass-panel p-4 rounded-xl flex flex-col justify-between">
              <span className="text-xs text-rose-400 font-medium">ACTIVE ALERTS</span>
              <span className="text-2xl font-black text-rose-500 mt-2">{activeAlertsCount}</span>
            </div>
            <div className="glass-panel p-4 rounded-xl flex flex-col justify-between">
              <span className="text-xs text-emerald-400 font-medium">RESOLVED THREATS</span>
              <span className="text-2xl font-black text-emerald-500 mt-2">{resolvedCount}</span>
            </div>
            <div className="glass-panel p-4 rounded-xl flex flex-col justify-between border-l-4 border-l-cyan-500 relative overflow-hidden group">
              <div className="flex justify-between items-start">
                <span className="text-xs text-cyan-400 font-medium">INTELLIGENCE SYNC</span>
                <button
                  onClick={handleSyncThreatIntel}
                  disabled={isSyncing}
                  className={`text-[10px] uppercase font-bold tracking-wider px-2 py-1 rounded transition-all duration-300 flex items-center gap-1 ${
                    isSyncing
                      ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 cursor-wait'
                      : 'bg-cyan-500/20 text-cyan-300 hover:bg-cyan-500/40 hover:text-white border border-cyan-500/40 active:scale-95 shadow-glow-cyan/20 cursor-pointer'
                  }`}
                  title="Trigger live threat feed download and Neo4j sync"
                >
                  {isSyncing ? (
                    <>
                      <svg className="animate-spin h-3 w-3 text-cyan-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                      </svg>
                      Syncing...
                    </>
                  ) : (
                    <>🔄 Sync Feed</>
                  )}
                </button>
              </div>
              <div className="mt-2 flex flex-col gap-1">
                <span className="text-xs font-semibold text-slate-300">
                  {isSyncing ? 'Synchronizing datasets...' : 'NVD / KEV / EPSS - ACTIVE'}
                </span>
                {syncResult && (
                  <div className="text-[9px] text-emerald-400 mt-1 font-mono leading-tight bg-emerald-500/5 border border-emerald-500/10 p-1.5 rounded animate-pulse">
                    ✓ Synced: {syncResult.metrics?.nvd_cves || 0} CVEs | {syncResult.metrics?.mitre_techniques || 0} MITRE | {syncResult.metrics?.cisa_kev || 0} KEV
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Interactive Children (e.g. Graph / Sim) */}
          <div className="flex-1 min-h-[450px] flex flex-col gap-6">
            {children}
          </div>
        </div>

        {/* Right column: Action Center (Alert logs, LLM reports) */}
        <div className="lg:col-span-4 flex flex-col gap-6 overflow-hidden">
          {/* Recharts Activity Timeline */}
          <div className="glass-panel p-4 rounded-xl h-44 flex flex-col justify-between">
            <div className="flex justify-between items-center mb-2">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">NETWORK EXPOSURE LEVEL</h3>
              <span className="text-cyan-400 text-xs font-mono">Real-time Load</span>
            </div>
            <div className="flex-1 w-full h-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={threatHistoryData}>
                  <defs>
                    <linearGradient id="colorLoad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <Tooltip 
                    contentStyle={{ background: '#0f172a', border: '1px solid rgba(55,65,81,0.5)', borderRadius: '8px' }}
                    labelStyle={{ color: '#94a3b8' }}
                  />
                  <XAxis dataKey="time" stroke="#475569" fontSize={10} tickLine={false} />
                  <YAxis hide />
                  <Area type="monotone" dataKey="load" stroke="#06b6d4" fillOpacity={1} fill="url(#colorLoad)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Incident panel elements rendered natively */}
          <div className="flex-1 flex flex-col gap-6 overflow-y-auto max-h-[500px]">
            {sidePanel}
          </div>
        </div>
      </main>
      
      {/* Footer Info */}
      <footer className="glass-panel border-t border-cyber-border py-2 px-6 flex justify-between items-center text-[10px] text-slate-500 z-10">
        <span>SARATHI DEFENSE PLATFORM v1.0.0</span>
        <span>CONNECTED ENGINE: FastApi &amp; Neo4j (bolt://localhost:7687)</span>
      </footer>
    </div>
  );
}
