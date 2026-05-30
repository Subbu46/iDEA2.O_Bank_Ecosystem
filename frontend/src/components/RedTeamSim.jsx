import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldAlert,
  Flame,
  CheckCircle,
  AlertTriangle,
  Play,
  Terminal,
  TrendingUp,
  Compass,
  Layers,
  Cpu,
  BookOpen,
  ArrowRight,
  ShieldCheck,
  RefreshCw,
  Skull
} from 'lucide-react';
import { redteamApi } from '../api/client';
import { useNavigate } from 'react-router-dom';

// Rich local metadata for scenarios to guarantee exceptional cyber-ops aesthetics
const SCENARIO_META = {
  lateral_movement: {
    title: "DMZ Web Gateway Lateral Pivot",
    subtitle: "Outer Boundary to Central Network Segment",
    description: "Simulates entry via public facing web endpoints, deploying interactive shells, extracting active credential hashes, and pivoting towards deep central databases.",
    icon: Layers,
    color: "from-orange-500/20 to-red-500/20 border-orange-500/30 text-orange-400 hover:border-orange-500/50",
    badgeColor: "bg-orange-500/10 text-orange-400 border-orange-500/20"
  },
  credential_stuffing: {
    title: "Auth Gateway Credential Stuffing",
    subtitle: "High-Volume Account Takeover & Session Abuse",
    description: "Launches high-frequency brute-force dictionary attacks against core auth endpoints and IAM routers to compromise internal operator accounts.",
    icon: Compass,
    color: "from-blue-500/20 to-indigo-500/20 border-blue-300 dark:border-blue-500/30 text-blue-600 dark:text-blue-400 hover:border-blue-500/50",
    badgeColor: "bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20"
  },
  swift_fraud: {
    title: "SWIFT Transaction Hijack",
    subtitle: "High-Risk Core Banking Payment Manipulation",
    description: "Simulates compromised internal nodes injecting malicious payload scripts into SWIFT Gateway queues to bypass secondary transaction audits.",
    icon: Cpu,
    color: "from-red-500/20 to-rose-600/20 border-red-500/30 text-rose-400 hover:border-red-500/50 animate-pulse",
    badgeColor: "bg-rose-500/10 text-rose-400 border-rose-500/20"
  },
  ransomware_spread: {
    title: "Wormhole Ransomware Propagation",
    subtitle: "Rapid Active Directory Host Disruption",
    description: "Simulates rapid endpoint encryption spreading laterally via SMB/RPC interfaces to render file servers and application gateways unserviceable.",
    icon: Flame,
    color: "from-amber-500/20 to-orange-600/20 border-amber-500/30 text-amber-600 dark:text-amber-400 hover:border-amber-500/50",
    badgeColor: "bg-amber-50 dark:bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20"
  },
  insider_threat: {
    title: "Privileged Insider Rogue Abuse",
    subtitle: "Internal Domain Administrator Sabotage",
    description: "Simulates high-privilege credentials executing massive data dumps and service stops while attempting to clear security log audits.",
    icon: ShieldAlert,
    color: "from-purple-500/20 to-indigo-600/20 border-purple-500/30 text-purple-400 hover:border-purple-500/50",
    badgeColor: "bg-purple-500/10 text-purple-400 border-purple-500/20"
  }
};

export default function RedTeamSim() {
  const navigate = useNavigate();
  const [scenarios, setScenarios] = useState([]);
  const [loadingScenarios, setLoadingScenarios] = useState(true);
  const [activeSim, setActiveSim] = useState('');
  const [loading, setLoading] = useState(false);

  // Live Simulation state
  const [simRunning, setSimRunning] = useState(false);
  const [currentStepIndex, setCurrentStepIndex] = useState(-1);
  const [simulationSteps, setSimulationSteps] = useState([]);
  const [simProgress, setSimProgress] = useState(0);
  const [simVerdict, setSimVerdict] = useState(null);

  // Load scenarios on mount
  useEffect(() => {
    setLoadingScenarios(true);
    redteamApi.getScenarios()
      .then(res => {
        // res.scenarios is an array of strings e.g. ["lateral_movement", ...]
        setScenarios(res.scenarios || []);
        setLoadingScenarios(false);
      })
      .catch(err => {
        console.error("Failed to load breach scenarios:", err);
        setLoadingScenarios(false);
      });
  }, []);

  const handleSimulate = (scenarioId) => {
    setLoading(true);
    setActiveSim(scenarioId);
    setSimRunning(true);
    setSimulationSteps([]);
    setCurrentStepIndex(-1);
    setSimProgress(0);
    setSimVerdict(null);

    redteamApi.triggerBreach(scenarioId)
      .then(res => {
        // res contains: status, scenario, injected_details
        const steps = res.injected_details || [];
        setSimulationSteps(steps);
        setLoading(false);

        // Progressively reveal steps to the user with a cinematic log stream
        let stepIdx = 0;
        setCurrentStepIndex(0);

        const interval = setInterval(() => {
          stepIdx++;
          if (stepIdx < steps.length) {
            setCurrentStepIndex(stepIdx);
            setSimProgress((stepIdx / (steps.length - 1)) * 100);
          } else {
            clearInterval(interval);
            // End simulation and build breach verdict
            const successCount = steps.filter(s => s.message.includes('SUCCESS')).length;
            const rate = steps.length > 0 ? successCount / steps.length : 0;
            let finalVerdict = "DEFENCES HOLDING";
            if (rate > 0.6) finalVerdict = "CRITICAL GAPS FOUND";
            else if (rate >= 0.3) finalVerdict = "MODERATE GAPS";

            setSimVerdict({
              verdict: finalVerdict,
              successRate: Math.round(rate * 100),
              compromisedAssets: [...new Set(steps.map(s => s.asset_id))],
              discoveredCVEs: [...new Set(steps.map(s => s.cve_id || 'CVE-2026-1043'))],
              mitreTechniques: [...new Set(steps.map(s => s.technique_id || 'T1190'))],
              executiveSummary: `Red team campaign finished execution. Evaluated ${steps.length} multi-stage network propagation routes. Attack modules yielded a ${Math.round(rate * 100)}% exploit rate with compromised telemetry indicators logged at key interfaces.`
            });
            setSimProgress(100);
          }
        }, 1200); // 1.2 second latency per action step
      })
      .catch(err => {
        console.error("Breach simulation failed:", err);
        setLoading(false);
        setSimRunning(false);
      });
  };

  const handleNavigatePlaybook = (cveId) => {
    navigate('/playbooks', { state: { cveId } });
  };

  return (
    <div className="flex flex-col gap-8 w-full max-w-[92rem] mx-auto pb-12">
      {/* Page Header */}
      <div className="flex justify-between items-center border-b border-slate-200 dark:border-slate-800 pb-6">
        <div>
          <h2 className="text-3xl font-extrabold tracking-tight text-white flex items-center gap-4">
            <ShieldAlert className="text-rose-500 animate-pulse" size={32} />
            Red Team Breach Simulator
          </h2>
          <p className="text-sm text-slate-500 dark:text-slate-600 dark:text-slate-400 mt-2">
            Trigger automated adversary emulation scenarios to validate core control effectiveness
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-8 items-start">
        {/* Scenario Selection Grid */}
        <div className="xl:col-span-6 flex flex-col gap-6">
          <div className="bg-white/95 dark:bg-[#0f172a]/95 backdrop-blur border border-slate-750 rounded-xl p-7 shadow-2xl">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-500 dark:text-slate-600 dark:text-slate-400 border-b border-slate-200 dark:border-slate-800 pb-3 mb-6 flex items-center gap-2.5">
              <Terminal size={16} className="text-rose-500" />
              Available Breach Scenarios
            </h3>

            {loadingScenarios ? (
              <div className="py-32 flex flex-col items-center justify-center gap-3">
                <div className="w-6 h-6 border-2 border-rose-500 border-t-transparent rounded-full animate-spin"></div>
                <span className="text-[10px] text-slate-500 dark:text-slate-500 tracking-wider font-mono">LOADING SIMULATOR DIRECTORY...</span>
              </div>
            ) : (
              <div className="flex flex-col gap-5">
                {scenarios.map((id) => {
                  const meta = SCENARIO_META[id] || {
                    title: id.replace('_', ' ').toUpperCase(),
                    subtitle: "Custom Network Simulation Campaign",
                    description: "Emulates tactical breach steps to stress-test firewall zones.",
                    icon: ShieldAlert,
                    color: "border-slate-200 dark:border-slate-800 bg-slate-900/35 hover:border-slate-300 dark:hover:border-slate-700 text-slate-700 dark:text-slate-300",
                    badgeColor: "bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-600 dark:text-slate-400 border-slate-700"
                  };
                  const Icon = meta.icon;
                  const isLaunching = activeSim === id && loading;

                  return (
                    <motion.div
                      whileHover={{ scale: 1.01 }}
                      key={id}
                      className={`p-6 rounded-xl border bg-slate-50 dark:bg-slate-950/20 transition-all duration-300 flex flex-col justify-between gap-5 ${meta.color}`}
                    >
                      <div className="flex justify-between items-start gap-4">
                        <div className="flex items-center gap-4">
                          <div className={`p-3.5 rounded-lg bg-slate-950/80 border ${meta.badgeColor.replace('bg-', 'border-')}`}>
                            <Icon size={24} />
                          </div>
                          <div>
                            <h4 className="text-sm font-bold text-slate-900 dark:text-slate-100">{meta.title}</h4>
                            <p className="text-xs text-slate-500 dark:text-slate-500 font-mono mt-0.5">{meta.subtitle}</p>
                          </div>
                        </div>
                        <span className={`text-[10px] font-bold px-2.5 py-1 rounded border uppercase tracking-wider ${id === 'swift_fraud' ? 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/25 shadow-[0_0_8px_rgba(239,68,68,0.15)]' :
                            id === 'insider_threat' || id === 'lateral_movement' ? 'bg-orange-500/10 text-orange-400 border-orange-500/25' :
                              'bg-amber-50 dark:bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/25'
                          }`}>
                          {id === 'swift_fraud' ? 'CRITICAL' : id === 'insider_threat' || id === 'lateral_movement' ? 'HIGH' : 'MEDIUM'}
                        </span>
                      </div>

                      <p className="text-sm text-slate-500 dark:text-slate-600 dark:text-slate-400 leading-relaxed">
                        {meta.description}
                      </p>

                      <div className="flex justify-between items-center pt-4 border-t border-slate-900 text-[11px] font-mono text-slate-500 dark:text-slate-500">
                        <div className="flex gap-4">
                          <span>Start: <span className="text-cyan-600 dark:text-cyan-400 font-bold">{id === 'credential_stuffing' || id === 'lateral_movement' ? 'Asset_1 (Gateway)' : id === 'insider_threat' ? 'Asset_2 (Auth Router)' : 'Asset_3 (Host)'}</span></span>
                          <span>Target: <span className="text-rose-400 font-bold">{id === 'swift_fraud' ? 'Asset_5 (SWIFT)' : id === 'credential_stuffing' ? 'Asset_2 (Auth Router)' : 'Asset_4 (DB)'}</span></span>
                        </div>

                        <button
                          disabled={simRunning}
                          onClick={() => handleSimulate(id)}
                          className="px-4.5 py-2.5 bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/20 hover:border-rose-500/40 disabled:border-slate-800 disabled:bg-slate-900/10 disabled:text-slate-600 text-rose-400 rounded-lg text-xs font-bold flex items-center gap-1.5 transition-all duration-200 uppercase tracking-wide"
                        >
                          <Play size={12} className={isLaunching ? 'animate-spin' : ''} />
                          {isLaunching ? 'STAGING...' : 'LAUNCH'}
                        </button>
                      </div>
                    </motion.div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* Live Attack Feed & Diagnostics */}
        <div className="xl:col-span-6 flex flex-col gap-8">
          {/* Terminal Console */}
          <div className="bg-slate-950 border border-slate-750 rounded-xl overflow-hidden shadow-2xl flex flex-col h-[520px] relative before:absolute before:inset-0 before:bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] before:bg-[size:100%_4px,3px_100%] before:pointer-events-none before:z-10">
            <div className="px-5 py-3.5 bg-slate-50 dark:bg-slate-900/60 border-b border-slate-200 dark:border-slate-800 flex justify-between items-center font-mono relative z-20">
              <span className="text-xs font-bold text-rose-400 uppercase tracking-wider flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-ping"></span>
                Threat Injection Console
              </span>
              <span className="text-[10px] text-slate-500 dark:text-slate-500 font-mono font-bold">CYBERDEFENSE_SIMULATOR_v1.0</span>
            </div>

            <div className="flex-1 p-5 overflow-y-auto font-mono text-[12px] leading-relaxed text-slate-700 dark:text-slate-300 flex flex-col gap-2.5 custom-scrollbar relative z-20">
              {!simRunning ? (
                <div className="m-auto text-center text-slate-500 dark:text-slate-600 flex flex-col items-center gap-2">
                  <Terminal size={32} className="text-slate-800" />
                  <p className="text-sm">Adversary emulations offline. Select a scenario to begin injection.</p>
                </div>
              ) : (
                <>
                  <div className="text-slate-500 dark:text-slate-500 select-none">
                    [SYSTEM] Staging threat agent container for scenario {activeSim}...
                  </div>
                  <div className="text-slate-500 dark:text-slate-500 select-none">
                    [SYSTEM] Adversary container successfully attached. Initiating hop validation...
                  </div>

                  {simulationSteps.slice(0, currentStepIndex + 1).map((step, idx) => {
                    const isSuccess = step.message.includes('SUCCESS');
                    const isBlocked = step.message.includes('BLOCKED');
                    let statusColor = "text-amber-600 dark:text-amber-400 border border-amber-500/20 bg-amber-500/5";
                    if (isSuccess) statusColor = "text-rose-400 border border-rose-500/20 bg-rose-500/5";
                    if (isBlocked) statusColor = "text-emerald-400 border border-emerald-500/20 bg-emerald-500/5";

                    return (
                      <motion.div
                        initial={{ opacity: 0, x: -5 }}
                        animate={{ opacity: 1, x: 0 }}
                        key={step.id || idx}
                        className="flex flex-col gap-1.5 p-3.5 bg-slate-900/75 border border-slate-200 dark:border-slate-800 rounded-lg shadow-md mb-2"
                      >
                        <div className="flex justify-between items-center gap-4 text-[11px]">
                          <span className="text-slate-500 dark:text-slate-500">[{step.timestamp?.replace('T', ' ')}]</span>
                          <span className="text-cyan-600 dark:text-cyan-400 font-bold uppercase">{step.asset_id}</span>
                        </div>
                        <p className="text-slate-800 dark:text-slate-200 text-xs">{step.message}</p>
                        <div className="flex gap-2 mt-1">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-950 border border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-600 dark:text-slate-400">
                            TECH: {step.technique_id || 'T1190'}
                          </span>
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-950 border border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-600 dark:text-slate-400">
                            CVE: {step.cve_id || 'CVE-2026-1043'}
                          </span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-wider ${statusColor}`}>
                            {isSuccess ? 'SUCCESS' : isBlocked ? 'BLOCKED' : 'DETECTED'}
                          </span>
                        </div>
                      </motion.div>
                    );
                  })}

                  {/* Progressive loading line */}
                  {currentStepIndex < simulationSteps.length - 1 && (
                    <div className="flex items-center gap-1.5 text-cyan-600 dark:text-cyan-400 font-bold animate-pulse mt-2 text-xs">
                      <RefreshCw size={12} className="animate-spin" />
                      <span>Exfiltrating next vector hop segment...</span>
                    </div>
                  )}
                </>
              )}
            </div>

            {/* Simulated execution progress bar */}
            {simRunning && (
              <div className="h-1 bg-slate-50 dark:bg-slate-900 w-full relative z-20">
                <div
                  className="h-full bg-rose-500 transition-all duration-500"
                  style={{ width: `${simProgress}%` }}
                ></div>
              </div>
            )}
          </div>

          {/* Post-Attack Assessment Report */}
          <AnimatePresence>
            {simVerdict && (
              <motion.div
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -15 }}
                className="bg-white/95 dark:bg-[#0f172a]/95 backdrop-blur border border-slate-750 rounded-xl p-7 shadow-2xl flex flex-col gap-6"
              >
                <div className="flex justify-between items-center border-b border-slate-200 dark:border-slate-800 pb-4">
                  <h3 className="text-sm font-bold uppercase tracking-wider text-slate-500 dark:text-slate-600 dark:text-slate-400 flex items-center gap-2.5">
                    <Skull size={16} className="text-rose-500" />
                    Adversary Assessment Report
                  </h3>
                  <span className={`text-[11px] font-black px-3 py-1.5 rounded-lg border uppercase tracking-wider transition-all duration-300 ${simVerdict.verdict === 'CRITICAL GAPS FOUND' ? 'shadow-[0_0_15px_rgba(239,68,68,0.5)] bg-red-100 dark:bg-red-500/20 border-red-500 text-red-300' :
                      simVerdict.verdict === 'MODERATE GAPS' ? 'shadow-[0_0_15px_rgba(245,158,11,0.5)] bg-amber-100 dark:bg-amber-500/20 border-amber-500 text-amber-300' :
                        'shadow-[0_0_15px_rgba(34,197,94,0.5)] bg-emerald-500/20 border-emerald-500 text-emerald-300'
                    }`}>
                    {simVerdict.verdict}
                  </span>
                </div>

                <p className="text-[13px] text-slate-700 dark:text-slate-300 leading-relaxed font-mono bg-slate-950/60 p-4.5 rounded-xl border border-slate-900">
                  {simVerdict.executiveSummary}
                </p>

                <div className="grid grid-cols-2 gap-6">
                  <div className="bg-slate-950/40 p-4.5 rounded-xl border border-slate-900 flex flex-col gap-1.5">
                    <span className="text-[10px] font-mono text-slate-500 dark:text-slate-500 uppercase">Success Penetration Rate</span>
                    <span className="text-3xl font-bold font-mono text-white flex items-center gap-2">
                      <TrendingUp size={20} className="text-rose-500" />
                      {simVerdict.successRate}%
                    </span>
                  </div>

                  <div className="bg-slate-950/40 p-4.5 rounded-xl border border-slate-900 flex flex-col gap-1.5">
                    <span className="text-[10px] font-mono text-slate-500 dark:text-slate-500 uppercase">Assets Breached</span>
                    <span className="text-3xl font-bold font-mono text-white flex items-center gap-2">
                      <Layers size={20} className="text-cyan-600 dark:text-cyan-400" />
                      {simVerdict.compromisedAssets.length} / 5
                    </span>
                  </div>
                </div>

                <div className="flex flex-col gap-3 pt-3 border-t border-slate-900">
                  <span className="text-[10px] font-mono text-slate-500 dark:text-slate-500 uppercase">Discovered Vulnerability Links</span>
                  <div className="flex flex-wrap gap-3">
                    {simVerdict.discoveredCVEs.map((cve, idx) => (
                      <div
                        key={idx}
                        className="px-3.5 py-2 bg-slate-950/80 border border-slate-200 dark:border-slate-800 hover:border-cyan-500/40 rounded-xl flex items-center justify-between gap-4 text-xs font-mono text-slate-700 dark:text-slate-300 w-full sm:w-auto"
                      >
                        <span>{cve}</span>
                        <button
                          onClick={() => handleNavigatePlaybook(cve)}
                          className="text-[10px] font-bold text-cyan-600 dark:text-cyan-400 hover:text-cyan-300 uppercase tracking-wide flex items-center gap-0.5 border-l border-slate-200 dark:border-slate-800 pl-3.5"
                        >
                          Mitigate <ArrowRight size={12} />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}
