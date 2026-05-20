import React from 'react';
import { alertsApi } from '../api/client';

export default function AlertPanel({ alerts, onSelectAlert, onRefreshAlerts }) {
  const getSeverityBadge = (severity) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/20';
      case 'HIGH':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
      case 'MEDIUM':
        return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
      default:
        return 'bg-slate-500/10 text-slate-400 border-slate-500/20';
    }
  };

  const handleResolve = (e, alertId) => {
    e.stopPropagation();
    alertsApi.resolveAlert(alertId, 'RESOLVED')
      .then(() => {
        if (onRefreshAlerts) onRefreshAlerts();
      })
      .catch(() => {});
  };

  const activeAlerts = alerts.filter(a => a.status === 'UNRESOLVED');

  return (
    <div className="glass-panel rounded-xl flex flex-col h-full max-h-[300px]">
      <div className="px-4 py-3 border-b border-cyber-border bg-slate-900/40 flex justify-between items-center">
        <div>
          <h2 className="text-xs font-bold uppercase tracking-wider text-slate-400">SOC ALERT LOGGER</h2>
          <p className="text-[10px] text-slate-500">Real-time threat notifications</p>
        </div>
        <span className="px-2 py-0.5 rounded-md bg-rose-500/10 text-rose-400 border border-rose-500/20 text-[10px] font-bold">
          {activeAlerts.length} TRIGGERED
        </span>
      </div>

      <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-3 min-h-[150px]">
        {activeAlerts.length === 0 ? (
          <div className="flex-1 flex flex-col items-center justify-center text-slate-500 text-xs gap-1.5 py-6">
            <span>🛡️</span>
            <span>All systems stable. No active alerts.</span>
          </div>
        ) : (
          activeAlerts.map((alert) => (
            <div
              key={alert.id}
              onClick={() => onSelectAlert(alert)}
              className="p-3 rounded-lg border border-slate-800 bg-slate-950/40 hover:bg-slate-900/30 hover:border-cyan-500/30 transition-all cursor-pointer flex flex-col gap-2 relative group"
            >
              <div className="flex justify-between items-start gap-2">
                <span className={`px-2 py-0.5 rounded border text-[9px] font-extrabold ${getSeverityBadge(alert.severity)}`}>
                  {alert.severity}
                </span>
                <span className="text-[9px] font-mono text-slate-500">
                  {alert.timestamp ? alert.timestamp.substring(11, 16) : 'Now'}
                </span>
              </div>
              
              <p className="text-xs text-slate-300 font-medium leading-relaxed">
                {alert.message}
              </p>
              
              <div className="flex justify-between items-center mt-1 border-t border-slate-800/40 pt-2 text-[10px] text-slate-400">
                <span>Asset: <strong className="text-cyan-400 font-mono">{alert.asset_id}</strong></span>
                <button
                  onClick={(e) => handleResolve(e, alert.id)}
                  className="px-2 py-0.5 bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/20 hover:border-emerald-500/40 text-emerald-400 rounded transition-all text-[9px]"
                >
                  RESOLVE
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
