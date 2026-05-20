import React, { useState } from 'react';
import { redteamApi } from '../api/client';

export default function RedTeamSim({ onSimulationTriggered }) {
  const [activeSim, setActiveSim] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSimulate = (scenario) => {
    setLoading(true);
    setActiveSim(scenario);
    redteamApi.triggerBreach(scenario)
      .then(res => {
        setLoading(false);
        setActiveSim('');
        if (onSimulationTriggered) {
          onSimulationTriggered(res);
        }
      })
      .catch(() => {
        setLoading(false);
        setActiveSim('');
      });
  };

  return (
    <div className="glass-panel p-4 rounded-xl flex flex-col gap-4">
      <div>
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">RED TEAM BREACH SIMULATOR</h3>
        <p className="text-[10px] text-slate-500 mt-0.5">Trigger controlled threat campaigns to evaluate defensive structures</p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {/* Scenario 1: Lateral Movement */}
        <div className="p-4 rounded-lg border border-slate-800 bg-slate-950/20 flex flex-col gap-3 justify-between">
          <div>
            <h4 className="text-xs font-bold text-slate-200">Gateway Lateral Intrusion</h4>
            <p className="text-[10px] text-slate-400 mt-1 leading-relaxed">
              Simulates web entry via CVE-2026-1043, spawning an unauthorized interactive shell, and attempting credential dumps (T1110) on internal Auth nodes.
            </p>
          </div>
          <button
            disabled={loading}
            onClick={() => handleSimulate('web_compromise')}
            className={`w-full py-2 bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 hover:border-rose-500/50 text-rose-400 rounded-lg text-xs font-semibold tracking-wider transition-all uppercase ${loading && activeSim === 'web_compromise' ? 'animate-pulse' : ''}`}
          >
            {loading && activeSim === 'web_compromise' ? 'SIMULATING BREACH...' : 'LAUNCH SIMULATION'}
          </button>
        </div>

        {/* Scenario 2: Data Exfiltration */}
        <div className="p-4 rounded-lg border border-slate-800 bg-slate-950/20 flex flex-col gap-3 justify-between">
          <div>
            <h4 className="text-xs font-bold text-slate-200">Crown-Jewel DB Exfiltration</h4>
            <p className="text-[10px] text-slate-400 mt-1 leading-relaxed">
              Simulates escalation of internal Auth nodes, initiating targeted SQL injection attempts on the central DB cluster, and staging high-volume data exfil.
            </p>
          </div>
          <button
            disabled={loading}
            onClick={() => handleSimulate('database_exfil')}
            className={`w-full py-2 bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 hover:border-rose-500/50 text-rose-400 rounded-lg text-xs font-semibold tracking-wider transition-all uppercase ${loading && activeSim === 'database_exfil' ? 'animate-pulse' : ''}`}
          >
            {loading && activeSim === 'database_exfil' ? 'SIMULATING BREACH...' : 'LAUNCH SIMULATION'}
          </button>
        </div>
      </div>
    </div>
  );
}
