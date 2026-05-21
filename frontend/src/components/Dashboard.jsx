import React, { useState, useEffect, useRef, useCallback } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, CartesianGrid } from 'recharts';
import { ShieldAlert, Target, Network, AlertOctagon, LayoutDashboard, Clock, Eye, AlertTriangle, Cpu, Zap, Radio, ChevronRight } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import client, { alertsApi, graphApi, genaiApi } from '../api/client';

// â”€â”€ AI Processing log messages â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const AI_LOGS = [
  '> initializing threat intelligence engine...',
  '> ingesting CVE graph from Neo4j...',
  '> correlating attack paths...',
  '> evaluating exploitability scores (EPSS)...',
  '> mapping MITRE ATT&CK techniques...',
  '> predicting kill chain...',
  '> calculating AI confidence score...',
  '> generating prioritised attack vectors...',
];

export default function Dashboard() {
  const [stats, setStats] = useState({
    totalCves: 0,
    criticalAlerts: 0,
    assetsAtRisk: 0,
    attackPaths: 0,
    severityBreakdown: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  });
  
  const [topRisks, setTopRisks] = useState([]);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [isLoading, setIsLoading] = useState(true);

  // â”€â”€ Gen-AI state â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const [aiState, setAiState] = useState('idle'); // idle | loading | streaming | done | error
  const [aiLogs, setAiLogs] = useState([]);
  const [aiFullText, setAiFullText] = useState('');
  const [aiDisplayText, setAiDisplayText] = useState('');
  const [aiError, setAiError] = useState(null);
  const typewriterRef = useRef(null);
  const terminalRef = useRef(null);

  const fetchData = async () => {
    setIsLoading(true);
    try {
      const [alertsData, statsData, risksData, assetsData, pathsData] = await Promise.all([
        alertsApi.listAlerts(),
        client.get('/alerts/stats').then(r => r.data),
        graphApi.getTopRisks(10),
        graphApi.getCriticalAssets(7),
        graphApi.getAttackPaths()
      ]);
      
      setRecentAlerts(alertsData.slice(0, 6));
      setTopRisks(risksData);
      
      const uniqueCves = new Set(risksData.map(r => r.cveId));
      
      setStats({
        totalCves: uniqueCves.size > 0 ? uniqueCves.size : 12,
        criticalAlerts: alertsData.filter(a => a.severity === 'CRITICAL' && a.status === 'UNRESOLVED').length,
        assetsAtRisk: assetsData.length,
        attackPaths: pathsData.length,
        severityBreakdown: statsData.severities || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
      });
    } catch (error) {
      console.error("Dashboard fetch error:", error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // â”€â”€ Typewriter effect â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const startTypewriter = useCallback((text) => {
    setAiDisplayText('');
    setAiState('streaming');
    let idx = 0;
    if (typewriterRef.current) clearInterval(typewriterRef.current);
    typewriterRef.current = setInterval(() => {
      idx++;
      setAiDisplayText(text.substring(0, idx));
      if (terminalRef.current) {
        terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
      }
      if (idx >= text.length) {
        clearInterval(typewriterRef.current);
        setAiState('done');
      }
    }, 12);
  }, []);

  useEffect(() => () => {
    if (typewriterRef.current) clearInterval(typewriterRef.current);
  }, []);

  // â”€â”€ AI analysis trigger â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const handleRunAnalysis = async () => {
    if (aiState === 'loading' || aiState === 'streaming') return;
    setAiState('loading');
    setAiLogs([]);
    setAiDisplayText('');
    setAiFullText('');
    setAiError(null);

    // Play fake processing logs with delays
    for (let i = 0; i < AI_LOGS.length; i++) {
      await new Promise(r => setTimeout(r, 380));
      setAiLogs(prev => [...prev, AI_LOGS[i]]);
    }

    try {
      const result = await genaiApi.analyseThreats();
      const text = result?.analysis || 'No analysis returned.';
      setAiFullText(text);
      await new Promise(r => setTimeout(r, 200));
      startTypewriter(text);
    } catch (err) {
      console.error('AI analysis failed:', err);
      setAiError('Analysis failed. Please check backend connection.');
      setAiState('error');
    }
  };

  // â”€â”€ Sub-components â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

  const StatCard = ({ title, value, icon: Icon, colorClass, delay, breakdown }) => (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay }}
      className="bg-[#0f172a]/95 backdrop-blur border border-slate-750 rounded-2xl p-7 flex flex-col justify-between shadow-2xl relative overflow-hidden group hover:border-slate-650 transition-all duration-300"
    >
      <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-bl from-cyan-500/5 to-transparent rounded-bl-full pointer-events-none group-hover:from-cyan-500/10 transition-all duration-300"></div>
      
      <div className="flex items-center justify-between">
        <div>
          <p className="text-slate-400 text-sm font-bold tracking-wider uppercase mb-2">{title}</p>
          <h3 className="text-5xl font-black text-slate-100 tracking-tight">{value}</h3>
        </div>
        <div className={`p-4 rounded-xl ${colorClass} shadow-inner`}>
          <Icon size={32} />
        </div>
      </div>

      {breakdown && (
        <div className="mt-5 pt-4 border-t border-slate-800/60 flex items-center justify-between text-xs font-mono text-slate-500">
          <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-red-500"></span>C: {breakdown.CRITICAL}</span>
          <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-amber-500"></span>H: {breakdown.HIGH}</span>
          <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-blue-500"></span>M: {breakdown.MEDIUM}</span>
          <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-slate-500"></span>L: {breakdown.LOW}</span>
        </div>
      )}
    </motion.div>
  );

  const getSeverityBadge = (severity) => {
    switch (severity) {
      case 'CRITICAL':
        return 'shadow-[0_0_12px_rgba(239,68,68,0.45)] bg-rose-500/20 border-rose-500 text-rose-300';
      case 'HIGH':
        return 'shadow-[0_0_12px_rgba(245,158,11,0.45)] bg-amber-500/20 border-amber-500 text-amber-300';
      case 'MEDIUM':
        return 'shadow-[0_0_12px_rgba(59,130,246,0.45)] bg-blue-500/20 border-blue-500 text-blue-300';
      default:
        return 'bg-slate-500/10 text-slate-400 border border-slate-500/30';
    }
  };

  return (
    <div className="flex flex-col gap-8 w-full max-w-[92rem] mx-auto pb-14 px-4">
      {/* Header */}
      <div className="flex justify-between items-center border-b border-slate-800/80 pb-6">
        <div>
          <h2 className="text-3xl font-extrabold tracking-tight text-white flex items-center gap-3">
            <LayoutDashboard className="text-blue-500 animate-pulse" size={32} />
            SOC Command Center
          </h2>
          <p className="text-sm text-slate-400 mt-1">Real-time digital vulnerability mapping and intrusion diagnostics</p>
        </div>
        <button
          onClick={fetchData}
          className="px-5 py-2.5 bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-350 rounded-xl text-xs font-bold uppercase tracking-wider flex items-center gap-2 hover:bg-slate-800 transition-all duration-200"
        >
          <Clock size={16} className="animate-spin" />
          Refresh Feed
        </button>
      </div>
      
      {isLoading ? (
        <div className="h-[60vh] flex flex-col items-center justify-center gap-3">
          <div className="animate-spin w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full"></div>
          <span className="text-sm text-slate-400 tracking-widest font-mono uppercase animate-pulse">Syncing SOC overview telemetry...</span>
        </div>
      ) : (
        <>
          {/* Stats Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-8">
            <StatCard title="Total CVEs Mapped" value={stats.totalCves} icon={ShieldAlert} colorClass="bg-red-500/10 text-red-500 border border-red-500/20" delay={0.05} />
            <StatCard title="Critical Unresolved" value={stats.criticalAlerts} icon={AlertOctagon} colorClass="bg-red-500/10 text-red-500 border border-red-500/20 shadow-[0_0_20px_rgba(239,68,68,0.15)]" delay={0.1} breakdown={stats.severityBreakdown} />
            <StatCard title="Critical Assets At Risk" value={stats.assetsAtRisk} icon={Target} colorClass="bg-blue-500/10 text-blue-400 border border-blue-500/20" delay={0.15} />
            <StatCard title="Attack Paths Found" value={stats.attackPaths} icon={Network} colorClass="bg-purple-500/10 text-purple-400 border border-purple-500/20" delay={0.2} />
          </div>

          {/* -- Gen-AI Threat Intelligence Analysis Section -- */}
          <motion.div
            initial={{ opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.25 }}
            className="relative bg-[#050d18] border border-cyan-900/40 rounded-2xl overflow-hidden shadow-[0_0_40px_rgba(0,200,255,0.04)]"
          >
            {/* Subtle scanline overlay */}
            <div
              className="absolute inset-0 pointer-events-none opacity-30"
              style={{
                background: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,255,255,0.01) 2px, rgba(0,255,255,0.01) 4px)',
              }}
            />
            {/* Corner accent glow */}
            <div className="absolute top-0 right-0 w-64 h-32 bg-gradient-to-bl from-cyan-500/5 to-transparent pointer-events-none" />
            <div className="absolute bottom-0 left-0 w-40 h-40 bg-gradient-to-tr from-blue-600/4 to-transparent pointer-events-none" />

            {/* Header */}
            <div className="relative flex flex-col sm:flex-row sm:items-center justify-between gap-5 p-7 border-b border-cyan-900/30">
              <div>
                <h3 className="text-2xl font-extrabold text-white flex items-center gap-3 tracking-tight">
                  <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/20 shadow-[0_0_12px_rgba(6,182,212,0.15)]">
                    <Cpu className="text-cyan-400" size={22} />
                  </div>
                  <span role="img" aria-label="robot">🤖</span> Gen-AI Threat Intelligence Analysis
                </h3>
                <p className="text-sm text-slate-400 mt-1.5 ml-1">
                  Gemini AI analyses your full CVE dataset, maps MITRE ATT&CK techniques, and predicts the most likely kill chain
                </p>
              </div>

              {/* Run Analysis button */}
              <motion.button
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.97 }}
                onClick={handleRunAnalysis}
                disabled={aiState === 'loading' || aiState === 'streaming'}
                className={`shrink-0 flex items-center gap-3 px-7 py-4 rounded-xl font-extrabold text-[15px] uppercase tracking-wider transition-all duration-200 border
                  ${aiState === 'loading' || aiState === 'streaming'
                    ? 'bg-cyan-950/40 border-cyan-800/40 text-cyan-600 cursor-not-allowed'
                    : 'bg-gradient-to-r from-cyan-600/25 to-blue-600/25 border-cyan-500/50 text-cyan-300 hover:border-cyan-400 hover:text-cyan-200 hover:shadow-[0_0_25px_rgba(6,182,212,0.3)] shadow-[0_0_15px_rgba(6,182,212,0.15)]'
                  }`}
              >
                {aiState === 'loading' ? (
                  <>
                    <div className="w-5 h-5 border-2 border-cyan-500/40 border-t-cyan-400 rounded-full animate-spin" />
                    AI THINKING
                    <span className="animate-pulse">...</span>
                  </>
                ) : aiState === 'streaming' ? (
                  <>
                    <Radio size={18} className="animate-pulse text-cyan-400" />
                    STREAMING
                  </>
                ) : (
                  <>
                    <Zap size={18} className="text-cyan-400" />
                    RUN AI Analysis on Vulnerability Dataset
                  </>
                )}
              </motion.button>
            </div>

            {/* Body */}
            <div className="relative p-7">
              {/* Idle state */}
              {aiState === 'idle' && (
                <div className="flex flex-col items-center justify-center py-14 gap-4 text-center">
                  <div className="w-16 h-16 rounded-2xl bg-cyan-500/5 border border-cyan-500/15 flex items-center justify-center shadow-[0_0_20px_rgba(6,182,212,0.05)]">
                    <Cpu className="text-cyan-800" size={28} />
                  </div>
                  <p className="text-slate-500 text-sm max-w-md font-mono">
                    Click <span className="text-cyan-500 font-bold">"Run AI Analysis"</span> to instruct Gemini AI to analyse your full CVE dataset,
                    rank attack vectors by exploitability, and predict the most likely kill chain toward your core banking assets.
                  </p>
                </div>
              )}

              {/* Loading - fake AI logs */}
              {(aiState === 'loading' || (aiState === 'streaming' && aiLogs.length > 0 && aiDisplayText.length === 0)) && (
                <div className="bg-black/60 rounded-xl border border-cyan-950/60 p-5 font-mono text-xs text-cyan-400 space-y-1.5 min-h-[180px]">
                  <div className="text-cyan-600 mb-3 text-[11px] tracking-widest uppercase">
                    Sarathi AI Engine | Gemini 1.5 Pro | Threat Analysis Mode
                  </div>
                  <AnimatePresence>
                    {aiLogs.map((log, i) => (
                      <motion.div
                        key={i}
                        initial={{ opacity: 0, x: -8 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.2 }}
                        className="flex items-center gap-2"
                      >
                        <ChevronRight size={11} className="text-cyan-700 shrink-0" />
                        <span>{log}</span>
                      </motion.div>
                    ))}
                  </AnimatePresence>
                  {aiState === 'loading' && (
                    <div className="flex items-center gap-2 text-cyan-600 mt-2">
                      <ChevronRight size={11} />
                      <span className="animate-pulse">processing</span>
                      <span className="inline-flex gap-1">
                        {[0,1,2].map(i => (
                          <span key={i} className="w-1 h-1 rounded-full bg-cyan-500 animate-bounce" style={{ animationDelay: `${i * 0.15}s` }} />
                        ))}
                      </span>
                    </div>
                  )}
                </div>
              )}

              {/* Streaming / Done - typewriter terminal */}
              {(aiState === 'streaming' || aiState === 'done') && aiDisplayText && (
                <motion.div
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="relative"
                >
                  {/* Terminal header bar */}
                  <div className="flex items-center gap-2 bg-slate-950 border border-slate-800 rounded-t-xl px-4 py-3 border-b-0">
                    <span className="w-3 h-3 rounded-full bg-red-500/70" />
                    <span className="w-3 h-3 rounded-full bg-amber-500/70" />
                    <span className="w-3 h-3 rounded-full bg-emerald-500/70" />
                    <span className="ml-4 text-[11px] font-mono text-slate-600 tracking-widest uppercase">
                      sarathi-ai | threat-intelligence-analysis | {new Date().toLocaleTimeString()}
                    </span>
                    {aiState === 'streaming' && (
                      <div className="ml-auto flex items-center gap-1.5 text-[11px] font-mono text-cyan-500">
                        <div className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                        LIVE
                      </div>
                    )}
                    {aiState === 'done' && (
                      <div className="ml-auto flex items-center gap-1.5 text-[11px] font-mono text-emerald-500">
                        <div className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                        COMPLETE
                      </div>
                    )}
                  </div>

                  {/* Terminal body */}
                  <div
                    ref={terminalRef}
                    className="bg-black/90 border border-slate-800 rounded-b-xl max-h-[520px] overflow-y-auto [&::-webkit-scrollbar]:w-1 [&::-webkit-scrollbar-thumb]:bg-slate-800 [&::-webkit-scrollbar-thumb]:rounded-full"
                    style={{ padding: '24px', minHeight: '400px' }}
                  >
                    <pre
                      className="whitespace-pre-wrap break-words"
                      style={{
                        fontSize: '14px',
                        lineHeight: '1.8',
                        fontFamily: 'monospace',
                        color: '#00ff88',
                        letterSpacing: '0.3px',
                      }}
                    >
                      {aiDisplayText}
                      {aiState === 'streaming' && (
                        <span className="inline-block w-2 h-4 bg-emerald-400 animate-pulse ml-0.5 translate-y-0.5" style={{ backgroundColor: '#00ff88' }} />
                      )}
                    </pre>
                  </div>
                </motion.div>
              )}

              {/* Error state */}
              {aiState === 'error' && (
                <div className="flex flex-col items-center gap-3 py-10 text-center">
                  <AlertTriangle className="text-red-500" size={32} />
                  <p className="text-red-400 font-bold text-sm">{aiError}</p>
                  <button
                    onClick={handleRunAnalysis}
                    className="px-4 py-2 text-xs font-bold uppercase tracking-wider bg-red-500/10 border border-red-500/20 text-red-400 rounded-lg hover:bg-red-500/20 transition-all"
                  >
                    Retry
                  </button>
                </div>
              )}
            </div>
          </motion.div>

          {/* CVE Chart + Recent Alerts */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch mt-2">
            {/* Chart */}
            <motion.div
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.5, delay: 0.3 }}
              className="lg:col-span-7 bg-[#0f172a]/95 backdrop-blur border border-slate-750 rounded-2xl p-7 shadow-2xl flex flex-col h-[580px]"
            >
              <div className="mb-6">
                <h3 className="text-xl font-extrabold text-slate-200 flex items-center gap-2">
                  <AlertTriangle className="text-amber-500" size={22} />
                  Top 10 Risk-Scored CVEs
                </h3>
                <p className="text-sm text-slate-400">Risk index calculated from CVSS, EPSS, KEV status &amp; Asset Criticality</p>
              </div>
              
              <div className="flex-1 min-h-0">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={topRisks} layout="vertical" margin={{ top: 5, right: 30, left: 10, bottom: 5 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" horizontal={true} vertical={false} />
                    <XAxis type="number" domain={[0, 100]} stroke="#475569" fontSize={13} fontWeight="bold" />
                    <YAxis dataKey="cveId" type="category" width={140} stroke="#94a3b8" fontSize={13} tickLine={false} fontWeight="bold" />
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#1f2937', borderColor: '#374151', borderRadius: '12px', color: '#f8fafc', padding: '12px' }}
                      itemStyle={{ color: '#38bdf8', fontSize: '14px', fontWeight: 'bold' }}
                      cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                    />
                    <Bar dataKey="riskScore" radius={[0, 8, 8, 0]} barSize={24}>
                      {topRisks.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.riskScore > 80 ? '#ef4444' : entry.riskScore > 60 ? '#f59e0b' : '#3b82f6'} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </motion.div>

            {/* Recent Alerts Panel */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.5, delay: 0.35 }}
              className="lg:col-span-5 bg-[#0f172a]/95 backdrop-blur border border-slate-750 rounded-2xl p-7 shadow-2xl flex flex-col h-[580px]"
            >
              <div className="mb-6">
                <h3 className="text-xl font-extrabold text-slate-200 flex items-center gap-2">
                  <ShieldAlert className="text-red-500 animate-pulse" size={22} />
                  Live SOC Alerts
                </h3>
                <p className="text-sm text-slate-400">Chronological telemetry feed of active cyber threats</p>
              </div>

              <div className="flex-1 overflow-y-auto pr-1.5 flex flex-col gap-4 [&::-webkit-scrollbar]:w-1.5 [&::-webkit-scrollbar-track]:bg-slate-950/40 [&::-webkit-scrollbar-thumb]:bg-slate-800 [&::-webkit-scrollbar-thumb]:rounded-full hover:[&::-webkit-scrollbar-thumb]:bg-slate-700">
                {recentAlerts.map((alert, idx) => (
                  <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.4 + idx * 0.05 }}
                    key={alert.id}
                    className="bg-slate-950/85 border border-slate-800/90 p-6 rounded-xl flex flex-col gap-4 hover:border-slate-700/80 hover:bg-slate-900/40 transition-all duration-200 relative group overflow-hidden min-h-[165px] h-auto shrink-0 justify-between"
                  >
                    {/* Glow left border */}
                    <div className={`absolute left-0 top-0 bottom-0 w-1.5 ${
                      alert.severity === 'CRITICAL' ? 'bg-red-500 shadow-[0_0_12px_rgba(239,68,68,0.5)]' :
                      alert.severity === 'HIGH' ? 'bg-amber-500 shadow-[0_0_12px_rgba(245,158,11,0.5)]' :
                      'bg-blue-500 shadow-[0_0_12px_rgba(59,130,246,0.5)]'
                    }`}></div>

                    {/* Top Row */}
                    <div className="flex items-center justify-between w-full gap-2">
                      <div className="flex items-center gap-2">
                        <span className={`px-2.5 py-1 rounded text-xs font-black uppercase border ${getSeverityBadge(alert.severity)}`}>
                          {alert.severity}
                        </span>
                        {alert.severity === 'CRITICAL' && (
                          <span className="flex h-2 w-2 relative">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                            <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500"></span>
                          </span>
                        )}
                      </div>
                      <span className="text-[13px] text-slate-400 font-mono font-semibold shrink-0">
                        {alert.timestamp ? alert.timestamp.substring(11, 16) : 'Now'}
                      </span>
                    </div>

                    {/* Middle Row */}
                    <div className="w-full">
                      <p className="text-[15px] font-extrabold text-slate-100 break-words whitespace-normal leading-relaxed">
                        {alert.message}
                      </p>
                    </div>

                    {/* Bottom Row */}
                    <div className="w-full pt-3.5 border-t border-slate-800/50 flex flex-wrap gap-x-4 gap-y-2 text-xs font-mono text-slate-400">
                      <div>Asset: <span className="text-cyan-400 font-extrabold">{alert.asset_id}</span></div>
                      <div>CVE: <span className="text-slate-300 font-bold">{alert.cve_id || 'N/A'}</span></div>
                      <div>MITRE: <span className="text-slate-300 font-bold">{alert.technique_id || 'N/A'}</span></div>
                    </div>
                  </motion.div>
                ))}
                {recentAlerts.length === 0 && (
                  <div className="flex-1 flex flex-col items-center justify-center text-slate-500 text-sm gap-2">
                    <span><span role="img" aria-label="shield">🛡️</span></span>
                    <span>All systems clear. No incidents detected.</span>
                  </div>
                )}
              </div>
            </motion.div>
          </div>
        </>
      )}
    </div>
  );
}
