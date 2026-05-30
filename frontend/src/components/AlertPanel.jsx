import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldAlert, Bell, CheckCircle, Eye, EyeOff, Filter, RefreshCw, AlertTriangle, BookOpen, Loader2 } from 'lucide-react';
import client, { alertsApi } from '../api/client';
import PlaybookModal, { playbookCache, buildFallbackPlaybook } from './PlaybookModal';

export default function AlertPanel() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [filterStatus, setFilterStatus] = useState('UNRESOLVED');
  const [playbookAlert, setPlaybookAlert] = useState(null);
  const [playbookLoading, setPlaybookLoading] = useState(null); // holds alert.id when loading

  const fetchAlerts = (silent = false) => {
    if (!silent) setLoading(true);
    else setRefreshing(true);

    alertsApi.listAlerts()
      .then((data) => {
        setAlerts(data);
        setLoading(false);
        setRefreshing(false);
        
        // Pre-calculate and cache lightweight playbooks instantly
        if (data && Array.isArray(data)) {
          data.forEach(alert => {
            const key = alert?.cve_id || alert?.id;
            if (key && !playbookCache[key]) {
              console.log(`[AlertPanel] Pre-computing and caching playbook for ${key}`);
              playbookCache[key] = buildFallbackPlaybook(alert);
            }
          });
        }
      })
      .catch((err) => {
        console.error("Failed to poll alerts:", err);
        setLoading(false);
        setRefreshing(false);
      });
  };

  // Poll alerts every 10 seconds
  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(() => {
      fetchAlerts(true);
    }, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleAcknowledge = async (alertId) => {
    try {
      await client.post(`/alerts/${alertId}/acknowledge`);
      fetchAlerts(true);
    } catch (err) {
      console.error("Acknowledge failed:", err);
    }
  };

  const handleResolve = async (alertId) => {
    try {
      await alertsApi.resolveAlert(alertId, 'RESOLVED');
      fetchAlerts(true);
    } catch (err) {
      console.error("Resolve failed:", err);
    }
  };

  const handleGeneratePlaybook = (alert) => {
    setPlaybookAlert(alert);
  };

  const getSeverityBadge = (severity) => {
    switch (severity) {
      case 'CRITICAL':
        return 'shadow-[0_0_12px_rgba(239,68,68,0.45)] bg-rose-500/20 border-rose-500 text-rose-300';
      case 'HIGH':
        return 'shadow-[0_0_12px_rgba(245,158,11,0.45)] bg-amber-100 dark:bg-amber-500/20 border-amber-500 text-amber-300';
      case 'MEDIUM':
        return 'shadow-[0_0_12px_rgba(59,130,246,0.45)] bg-blue-100 dark:bg-blue-500/20 border-blue-500 text-blue-300';
      default:
        return 'bg-slate-50 dark:bg-slate-500/10 text-slate-500 dark:text-slate-600 dark:text-slate-400 border border-slate-500/30';
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'UNRESOLVED':
        return 'bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/20';
      case 'ACKNOWLEDGED':
        return 'bg-amber-50 dark:bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20';
      case 'RESOLVED':
        return 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20';
      default:
        return 'bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-600 dark:text-slate-400';
    }
  };

  // Helper to generate a deterministic risk score
  const getRiskScore = (severity, cveId) => {
    let score = 50;
    if (severity === 'CRITICAL') score = 92;
    else if (severity === 'HIGH') score = 78;
    else if (severity === 'MEDIUM') score = 55;
    else score = 25;

    // Add a bit of unique hashing based on CVE ID
    if (cveId) {
      const charSum = cveId.split('').reduce((sum, ch) => sum + ch.charCodeAt(0), 0);
      score += (charSum % 7) - 3;
    }
    return Math.min(100, Math.max(0, score));
  };

  const filteredAlerts = alerts.filter(alert => {
    const matchSev = filterSeverity === 'ALL' || alert.severity === filterSeverity;
    const matchStat = filterStatus === 'ALL' || alert.status === filterStatus;
    return matchSev && matchStat;
  });

  return (
    <div className="flex flex-col gap-8 w-full max-w-[92rem] mx-auto pb-12 h-full">
      {/* Header Panel */}
      <div className="flex justify-between items-center border-b border-slate-800/80 pb-5">
        <div>
          <h2 className="text-3xl font-extrabold tracking-tight text-white flex items-center gap-3">
            <Bell className="text-rose-500 animate-bounce" size={32} />
            Live Threat Console
          </h2>
          <p className="text-sm text-slate-500 dark:text-slate-600 dark:text-slate-400 mt-1.5">Real-time incident response queue and risk mitigations (polling 10s)</p>
        </div>
        
        <button
          onClick={() => fetchAlerts(false)}
          className="px-5 py-2.5 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 text-slate-700 dark:text-slate-300 rounded-lg text-sm font-bold uppercase tracking-wider flex items-center gap-2 hover:bg-slate-100 dark:hover:bg-slate-800 transition-all duration-200"
        >
          <RefreshCw size={16} className={loading || refreshing ? 'animate-spin' : ''} />
          Sync Queue
        </button>
      </div>

      {/* Filter Toolbar */}
      <div className="bg-[#111827]/80 backdrop-blur border border-slate-800/80 p-5 rounded-xl shadow-lg flex flex-wrap gap-5 items-center justify-between">
        <div className="flex flex-wrap gap-5 items-center">
          <div className="flex items-center gap-3 text-sm font-semibold text-slate-500 dark:text-slate-600 dark:text-slate-400">
            <Filter size={16} className="text-blue-600 dark:text-blue-400" />
            <span>Severity:</span>
            <div className="flex rounded-lg bg-slate-950 p-1 border border-slate-200 dark:border-slate-800/60">
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map(sev => (
                <button
                  key={sev}
                  onClick={() => setFilterSeverity(sev)}
                  className={`px-3.5 py-2 rounded-md text-xs font-extrabold uppercase transition-all duration-200 ${
                    filterSeverity === sev 
                      ? 'bg-blue-100 dark:bg-blue-500/20 text-blue-600 dark:text-blue-400 border border-blue-300 dark:border-blue-500/30' 
                      : 'text-slate-500 dark:text-slate-500 hover:text-slate-300'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          <div className="flex items-center gap-3 text-sm font-semibold text-slate-500 dark:text-slate-600 dark:text-slate-400">
            <span>Status:</span>
            <div className="flex rounded-lg bg-slate-950 p-1 border border-slate-200 dark:border-slate-800/60">
              {['ALL', 'UNRESOLVED', 'ACKNOWLEDGED', 'RESOLVED'].map(stat => (
                <button
                  key={stat}
                  onClick={() => setFilterStatus(stat)}
                  className={`px-3.5 py-2 rounded-md text-xs font-extrabold uppercase transition-all duration-200 ${
                    filterStatus === stat 
                      ? 'bg-blue-100 dark:bg-blue-500/20 text-blue-600 dark:text-blue-400 border border-blue-300 dark:border-blue-500/30' 
                      : 'text-slate-500 dark:text-slate-500 hover:text-slate-300'
                  }`}
                >
                  {stat}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="text-xs font-mono text-slate-500 dark:text-slate-500">
          Showing {filteredAlerts.length} of {alerts.length} registered events
        </div>
      </div>

      {/* Alerts Grid */}
      {loading ? (
        <div className="h-[45vh] flex flex-col items-center justify-center gap-3">
          <div className="animate-spin w-10 h-10 border-4 border-rose-500 border-t-transparent rounded-full"></div>
          <span className="text-xs text-slate-500 dark:text-slate-600 dark:text-slate-400 tracking-widest font-mono uppercase animate-pulse">Querying real-time incident storage...</span>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-start">
          <AnimatePresence mode="popLayout">
            {filteredAlerts.map((alert) => {
              const risk = getRiskScore(alert.severity, alert.cve_id);
              return (
                <motion.div
                  layout
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.95 }}
                  transition={{ duration: 0.25 }}
                  key={alert.id}
                  className="bg-white/95 dark:bg-[#0f172a]/95 backdrop-blur border border-slate-750 rounded-xl p-8 shadow-2xl flex flex-col justify-between hover:border-slate-650 transition-all duration-200 relative group overflow-hidden min-h-[250px] h-auto shrink-0 gap-5"
                >
                  {/* Left edge coloring based on severity */}
                  <div className={`absolute left-0 top-0 bottom-0 w-1.5 ${
                    alert.severity === 'CRITICAL' ? 'bg-red-500 shadow-[0_0_12px_rgba(239,68,68,0.5)]' :
                    alert.severity === 'HIGH' ? 'bg-amber-500 shadow-[0_0_12px_rgba(245,158,11,0.5)]' :
                    'bg-blue-500 shadow-[0_0_12px_rgba(59,130,246,0.5)]'
                  }`}></div>

                  {/* Top Row: Severity Badge, Status Badge & Timestamp */}
                  <div className="flex flex-wrap items-center justify-between gap-4 w-full border-b border-slate-800/40 pb-3">
                    <div className="flex items-center gap-2.5">
                      <span className={`px-2.5 py-1 rounded text-xs font-black uppercase border ${getSeverityBadge(alert.severity)}`}>
                        {alert.severity}
                      </span>
                      <span className={`px-2.5 py-1 rounded text-xs font-mono border ${getStatusBadge(alert.status)}`}>
                        {alert.status}
                      </span>
                      {alert.severity === 'CRITICAL' && alert.status === 'UNRESOLVED' && (
                        <span className="flex h-2.5 w-2.5 relative">
                          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                          <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-red-500"></span>
                        </span>
                      )}
                    </div>
                    
                    <span className="text-[13px] text-slate-500 dark:text-slate-600 dark:text-slate-400 font-mono font-semibold">
                      {alert.timestamp ? alert.timestamp.replace('T', ' ').substring(0, 16) : 'Now'}
                    </span>
                  </div>

                  {/* Middle Row: Bold High-Contrast Alert Title */}
                  <div className="w-full">
                    <p className="text-[17px] sm:text-lg font-extrabold text-slate-900 dark:text-slate-100 break-words whitespace-normal leading-relaxed">
                      {alert.message}
                    </p>
                  </div>

                  {/* Bottom Row: Details block */}
                  <div className="w-full">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3.5 text-sm font-mono text-slate-500 dark:text-slate-600 dark:text-slate-400 bg-slate-950/50 p-5 rounded-lg border border-slate-900/60">
                      <div className="flex items-center gap-2">
                        <span className="text-slate-500 dark:text-slate-500 font-bold uppercase text-[11px] tracking-wider">Asset Affected:</span>
                        <span className="text-cyan-600 dark:text-cyan-400 font-extrabold text-[13px]">{alert.asset_id}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-slate-500 dark:text-slate-500 font-bold uppercase text-[11px] tracking-wider">Risk Index:</span>
                        <span className={`font-black text-[12px] px-2.5 py-0.5 rounded ${
                          risk > 80 ? 'bg-red-50 dark:bg-red-500/15 text-red-600 dark:text-red-400 border border-red-500/25' :
                          risk > 60 ? 'bg-amber-500/15 text-amber-600 dark:text-amber-400 border border-amber-500/25' :
                          'bg-blue-500/15 text-blue-600 dark:text-blue-400 border border-blue-500/25'
                        }`}>
                          {risk}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-slate-500 dark:text-slate-500 font-bold uppercase text-[11px] tracking-wider">Mapped CVE:</span>
                        <span className="text-slate-800 dark:text-slate-200 font-bold text-[13px]">{alert.cve_id || 'N/A'}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-slate-500 dark:text-slate-500 font-bold uppercase text-[11px] tracking-wider">MITRE ID:</span>
                        <span className="text-slate-800 dark:text-slate-200 font-bold text-[13px]">{alert.technique_id || 'N/A'}</span>
                      </div>
                    </div>
                  </div>

                  {/* Actions footer */}
                  <div className="pt-4 border-t border-slate-200 dark:border-slate-800/60 flex flex-wrap justify-end gap-3 w-full mt-2">
                    {/* Generate Playbook — always visible */}
                    <button
                      onClick={() => handleGeneratePlaybook(alert)}
                      className="px-4 py-2 bg-violet-600/15 hover:bg-violet-600/30 border border-violet-500/30 hover:border-violet-500/60 text-violet-300 hover:text-violet-200 rounded-lg transition-all text-sm font-bold uppercase tracking-wider flex items-center gap-1.5 shadow-[0_0_8px_rgba(139,92,246,0.2)] hover:shadow-[0_0_16px_rgba(139,92,246,0.35)]"
                    >
                      <BookOpen size={14} />
                      Generate Playbook
                    </button>

                    {alert.status === 'UNRESOLVED' && (
                      <button
                        onClick={() => handleAcknowledge(alert.id)}
                        className="px-4 py-2 bg-amber-50 dark:bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/20 hover:border-amber-500/40 text-amber-600 dark:text-amber-400 rounded-lg transition-all text-sm font-bold uppercase tracking-wider flex items-center gap-1.5"
                      >
                        <Eye size={14} />
                        Acknowledge
                      </button>
                    )}
                    
                    {alert.status !== 'RESOLVED' && (
                      <button
                        onClick={() => handleResolve(alert.id)}
                        className="px-4 py-2 bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/20 hover:border-emerald-500/40 text-emerald-400 rounded-lg transition-all text-sm font-bold uppercase tracking-wider flex items-center gap-1.5"
                      >
                        <CheckCircle size={14} />
                        Resolve Incident
                      </button>
                    )}
                    
                    {alert.status === 'RESOLVED' && (
                      <span className="text-xs font-mono text-slate-500 dark:text-slate-500 py-2 italic flex items-center gap-1">
                        ✓ Case closed by system operator
                      </span>
                    )}
                  </div>
                </motion.div>
              );
            })}
          </AnimatePresence>

          {filteredAlerts.length === 0 && (
            <div className="col-span-full h-[30vh] flex flex-col items-center justify-center text-slate-500 dark:text-slate-500 text-sm gap-2">
              <span><span role="img" aria-label="shield">🛡️</span></span>
              <span>All clear. No active alerts meet the selected query filters.</span>
            </div>
          )}
        </div>
      )}

      {/* Playbook Modal */}
      <AnimatePresence>
        {playbookAlert && (
          <PlaybookModal
            alert={playbookAlert}
            onClose={() => setPlaybookAlert(null)}
          />
        )}
      </AnimatePresence>
    </div>
  );
}
