import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, CartesianGrid, PieChart, Pie } from 'recharts';
import {
  ShieldAlert, Target, Network, AlertOctagon, LayoutDashboard, Clock,
  AlertTriangle, Cpu, Zap, ChevronRight, ChevronDown, Shield,
  Database, Crosshair, TrendingUp, BookOpen, Filter
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import client, { alertsApi, graphApi, genaiApi } from '../api/client';

// ── AI Pipeline step labels (for the progress UI) ──────────────────────────
const PIPELINE_STEPS = [
  { id: 1, label: 'Monitoring Bank Ecosystem' },
  { id: 2, label: 'Connecting to real-time databases (like CVSS, EPSS, and KEV) and Detecting all the vulnerabilities' },
  { id: 3, label: 'RandomForest Model Ranking' },
  { id: 4, label: 'Generating Priority Attack Vectors' },
  { id: 5, label: 'Detecting Attack Paths' },
  { id: 6, label: 'Syncing Knowledge Graph' },
  { id: 7, label: 'Auto-Generating Playbooks' },
];

// ── Severity config ────────────────────────────────────────────────────────
const SEVERITY_CONFIG = {
  CRITICAL: {
    label: 'CRITICAL',
    bg: 'bg-red-50 dark:bg-red-500/15',
    border: 'border-red-300 dark:border-red-500/60',
    text: 'text-red-600 dark:text-red-400',
    glow: 'shadow-[0_0_16px_rgba(239,68,68,0.35)]',
    leftBar: 'bg-red-500 shadow-[0_0_12px_rgba(239,68,68,0.6)]',
    dot: 'bg-red-500',
    barFill: '#ef4444',
    badge: 'bg-red-100 dark:bg-red-500/20 border border-red-500/50 text-red-300',
    pingSvg: true,
  },
  HIGH: {
    label: 'HIGH',
    bg: 'bg-amber-50 dark:bg-amber-500/10',
    border: 'border-amber-300 dark:border-amber-500/40',
    text: 'text-amber-600 dark:text-amber-400',
    glow: 'shadow-[0_0_16px_rgba(245,158,11,0.2)]',
    leftBar: 'bg-amber-500 shadow-[0_0_12px_rgba(245,158,11,0.5)]',
    dot: 'bg-amber-500',
    barFill: '#f59e0b',
    badge: 'bg-amber-100 dark:bg-amber-500/20 border border-amber-500/50 text-amber-300',
    pingSvg: false,
  },
  MEDIUM: {
    label: 'MEDIUM',
    bg: 'bg-blue-50 dark:bg-blue-500/10',
    border: 'border-blue-300 dark:border-blue-500/30',
    text: 'text-blue-600 dark:text-blue-400',
    glow: '',
    leftBar: 'bg-blue-500',
    dot: 'bg-blue-500',
    barFill: '#3b82f6',
    badge: 'bg-blue-100 dark:bg-blue-500/20 border border-blue-500/50 text-blue-300',
    pingSvg: false,
  },
  LOW: {
    label: 'LOW',
    bg: 'bg-slate-50 dark:bg-slate-500/10',
    border: 'border-slate-300 dark:border-slate-600/30',
    text: 'text-slate-500 dark:text-slate-600 dark:text-slate-400',
    glow: '',
    leftBar: 'bg-slate-600',
    dot: 'bg-slate-500',
    barFill: '#64748b',
    badge: 'bg-slate-100 dark:bg-slate-600/20 border border-slate-600/50 text-slate-500 dark:text-slate-600 dark:text-slate-400',
    pingSvg: false,
  },
};

// ── Format timestamp ───────────────────────────────────────────────────────
function formatTimestamp(ts) {
  if (!ts) return null;
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return ts;
    return d.toLocaleString('en-IN', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: true,
    });
  } catch {
    return ts;
  }
}

// ── Robust regex parser for dynamic on-the-fly streaming AI text ───────────
function parseAiAnalysis(text) {
  const lines = text.split('\n');
  const items = [];
  let currentItem = null;
  let inAssessment = false;
  let assessmentLines = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    // Match "#1 [CRITICAL]" or similar
    const headerMatch = line.match(/^#(\d+)\s+\[(CRITICAL|HIGH|MEDIUM|LOW)\]/i);
    if (headerMatch) {
      if (currentItem) {
        if (assessmentLines.length > 0) {
          currentItem.description = assessmentLines.join(' ').replace(/^"|"$/g, '');
        }
        items.push(currentItem);
      }
      const sev = headerMatch[2].toUpperCase();
      currentItem = {
        severity: sev,
        riskScore: sev === 'CRITICAL' ? 95 : sev === 'HIGH' ? 75 : sev === 'MEDIUM' ? 55 : 35,
        cvssScore: sev === 'CRITICAL' ? 9.8 : sev === 'HIGH' ? 7.8 : sev === 'MEDIUM' ? 5.8 : 3.8,
        isKEV: sev === 'CRITICAL',
        assetCriticality: 8,
        isAiCorrelated: true
      };
      inAssessment = false;
      assessmentLines = [];
      continue;
    }

    if (currentItem) {
      // Match "CVE-2021-44228 → Enterprise Service Bus"
      const cveMatch = line.match(/^(CVE-\d+-\d+)\s*→\s*(.+)$/i);
      if (cveMatch) {
        currentItem.cveId = cveMatch[1];
        currentItem.assetName = cveMatch[2];
        continue;
      }

      // Match "MITRE: T1190 - Exploit Public-Facing Application"
      const mitreMatch = line.match(/^MITRE:\s*(T\d+)(?:\s*-\s*(.+))?$/i);
      if (mitreMatch) {
        currentItem.techniqueId = mitreMatch[1];
        currentItem.techniqueName = mitreMatch[2] || '';
        continue;
      }

      // Match "EPSS: 0.98"
      const epssMatch = line.match(/^EPSS:\s*([\d.]+)/i);
      if (epssMatch) {
        currentItem.epssScore = parseFloat(epssMatch[1]);
        if (currentItem.epssScore > 1) currentItem.epssScore /= 100;
        continue;
      }

      // Match "AI Assessment:"
      if (line.match(/^AI\s+Assessment:/i)) {
        inAssessment = true;
        continue;
      }

      if (inAssessment) {
        if (line.startsWith('---') || line.startsWith('===')) {
          inAssessment = false;
        } else {
          assessmentLines.push(line);
        }
      }
    }
  }

  if (currentItem) {
    if (assessmentLines.length > 0) {
      currentItem.description = assessmentLines.join(' ').replace(/^"|"$/g, '');
    }
    items.push(currentItem);
  }

  return items;
}

export default function Dashboard() {
  const navigate = useNavigate();
  const [stats, setStats] = useState({
    totalCves: 0,
    criticalAlerts: 0,
    assetsAtRisk: 0,
    attackPaths: 0,
    severityBreakdown: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  });

  const [topRisks, setTopRisks] = useState([]);
  const [criticalAssets, setCriticalAssets] = useState([]);
  const [attackPaths, setAttackPaths] = useState([]);
  const [aiPrioritizedRisks, setAiPrioritizedRisks] = useState([]);
  const [analysisTimestamp, setAnalysisTimestamp] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedCveId, setSelectedCveId] = useState(null);
  const [expandedCveId, setExpandedCveId] = useState(null);

  // Card refs for scroll-to-highlight
  const cardRefs = useRef({});

  // ── Gen-AI state ──────────────────────────────────────────────────────────
  const [aiState, setAiState] = useState('idle'); // idle | running | done | error
  const [aiError, setAiError] = useState(null);
  const [aiDisplayText, setAiDisplayText] = useState(''); // final analysis text
  const [aiFullText, setAiFullText] = useState('');
  const [aiLogs, setAiLogs] = useState([]);
  const terminalRef = useRef(null);
  const lastParsedRef = useRef('');
  const typewriterRef = useRef(null);

  // ── Pipeline step tracking ────────────────────────────────────────────────
  const [pipelineSteps, setPipelineSteps] = useState([]); // [{step, title, detail, status}]
  const [currentStep, setCurrentStep] = useState(0);
  const [playbookProgress, setPlaybookProgress] = useState(null); // {current, total, cveId}
  const [generatedPlaybooks, setGeneratedPlaybooks] = useState({}); // cveId → playbook
  const eventSourceRef = useRef(null);

  // ── Cache auto-generated playbooks to localStorage as they arrive ──────────
  useEffect(() => {
    Object.entries(generatedPlaybooks).forEach(([cveId, playbook]) => {
      if (!cveId || cveId === 'CVE-UNKNOWN') return;
      const cacheKey = `playbook_cache_v2_${cveId}`;
      if (!localStorage.getItem(cacheKey)) {
        localStorage.setItem(cacheKey, JSON.stringify(playbook));
        console.log(`[Pipeline] Playbook cached for ${cveId}`);
      }
    });
  }, [generatedPlaybooks]);

  // ── Cleanup EventSource on unmount ───────────────────────────────────────
  useEffect(() => {
    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
      if (typewriterRef.current) clearInterval(typewriterRef.current);
    };
  }, []);

  // ── Filter state ──────────────────────────────────────────────────────────
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [filterStatus, setFilterStatus] = useState('UNRESOLVED');
  const [alerts, setAlerts] = useState([]);

  const fetchData = async () => {
    setIsLoading(true);
    try {
      const [alertsData, statsData, risksData, assetsData, pathsData] = await Promise.all([
        alertsApi.listAlerts(),
        client.get('/alerts/stats').then(r => r.data),
        graphApi.getTopRisks(100),
        graphApi.getCriticalAssets(7),
        graphApi.getAttackPaths()
      ]);

      setAlerts(alertsData);
      setTopRisks(risksData);
      setAiPrioritizedRisks(risksData.slice(0, 10)); // Top 10 initially
      setCriticalAssets(assetsData);
      setAttackPaths(pathsData);

      const uniqueCves = new Set(risksData.map(r => r.cveId));

      setStats({
        totalCves: uniqueCves.size > 0 ? uniqueCves.size : 12,
        criticalAlerts: alertsData.filter(a => a.severity === 'CRITICAL' && a.status === 'UNRESOLVED').length,
        assetsAtRisk: assetsData.length,
        attackPaths: pathsData.length,
        severityBreakdown: statsData.severities || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
      });
    } catch (error) {
      console.error('Dashboard fetch error:', error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    window.addEventListener('alerts-updated', fetchData);
    return () => window.removeEventListener('alerts-updated', fetchData);
  }, []);

  // ── Typewriter effect for AI analysis text ────────────────────────────────
  const startTypewriter = useCallback((text) => {
    setAiDisplayText('');
    let idx = 0;
    if (typewriterRef.current) clearInterval(typewriterRef.current);
    typewriterRef.current = setInterval(() => {
      idx += 12; // 12 chars per tick
      setAiDisplayText(text.substring(0, idx));
      if (terminalRef.current) terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
      if (idx >= text.length) {
        setAiDisplayText(text);
        clearInterval(typewriterRef.current);
      }
    }, 30); // 30ms interval to reduce UI blocking
  }, []);

  // ── Dynamic parsing hook to update priority list as text streams in ────────
  useEffect(() => {
    if (aiFullText) {
      const parsedItems = parseAiAnalysis(aiFullText);
      const parsedStr = JSON.stringify(parsedItems);
      if (parsedStr !== lastParsedRef.current && parsedItems.length > 0) {
        lastParsedRef.current = parsedStr;
        setAiPrioritizedRisks(prev => {
          // Merge parsed items with existing data — preserve riskScore from RF ranking
          const merged = parsedItems.map(item => {
            const existing = prev.find(p => p.cveId === item.cveId);
            return existing ? { ...existing, ...item } : item;
          });
          return merged.slice(0, 10);
        });
      }
    }
  }, [aiFullText]);

  // ── AI analysis trigger — SSE 7-step streaming pipeline ──────────────────
  const handleRunAnalysis = () => {
    if (aiState === 'running') return;

    // Reset all state
    setAiState('running');
    setPipelineSteps([]);
    setCurrentStep(0);
    setPlaybookProgress(null);
    setAiDisplayText('');
    setAiFullText('');
    setAiError(null);
    lastParsedRef.current = '';
    setAiPrioritizedRisks([]);
    setGeneratedPlaybooks({});

    // Close any existing connection
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    // Dispatch start notification
    window.dispatchEvent(new CustomEvent('add-notification', {
      detail: {
        id: `scan_start_${Date.now()}`,
        type: 'custom',
        message: '🔍 GenAI full threat analysis pipeline started.',
        timestamp: new Date().toISOString()
      }
    }));

    const es = genaiApi.runFullAnalysis();
    eventSourceRef.current = es;

    // ── Step events ─────────────────────────────────────────────────────────
    es.addEventListener('step', (e) => {
      const data = JSON.parse(e.data);
      setCurrentStep(data.step);

      setPipelineSteps(prev => {
        const existing = prev.findIndex(s => s.step === data.step);
        if (existing > -1) {
          const updated = [...prev];
          updated[existing] = data;
          return updated;
        }
        return [...prev, data];
      });

      // Step 2: populate all vulnerabilities immediately
      if (data.step === 2 && data.status === 'done' && data.vulnerabilities) {
        setTopRisks(data.vulnerabilities.map((v, i) => ({
          ...v,
          riskScore: v.riskScore || (100 - i * 3),
          isAiCorrelated: false,
        })));
        setStats(prev => ({
          ...prev,
          totalCves: data.totalCves || data.vulnerabilities.length,
          severityBreakdown: data.severityBreakdown || prev.severityBreakdown,
        }));
      }

      // Step 3: update with RF-ranked scores immediately
      if (data.step === 3 && data.status === 'done' && data.rankedVulnerabilities) {
        setTopRisks(data.rankedVulnerabilities.map(v => ({ ...v, isAiCorrelated: false })));
      }

      // Step 4: update priority list + start streaming the analysis text
      if (data.step === 4 && data.status === 'done') {
        if (data.prioritizedVectors) {
          const prioritized = data.prioritizedVectors.map(v => ({ ...v, isAiCorrelated: true }));
          setAiPrioritizedRisks(prioritized);
          // Also mark these as AI-correlated in the full list
          setTopRisks(prev => prev.map(r => ({
            ...r,
            isAiCorrelated: prioritized.some(p => p.cveId === r.cveId),
          })));
        }
        if (data.analysis) {
          setAiFullText(data.analysis);
          if (data.generatedAt) setAnalysisTimestamp(data.generatedAt);
          startTypewriter(data.analysis);
        }
      }

      // Step 5: attack paths
      if (data.step === 5 && data.status === 'done' && data.attackPaths) {
        setAttackPaths(data.attackPaths);
        setStats(prev => ({ ...prev, attackPaths: data.attackPaths.length }));
        // Signal KnowledgeGraph to refresh
        window.dispatchEvent(new CustomEvent('attack-paths-updated', { detail: { paths: data.attackPaths } }));
      }
    });

    // ── Playbook progress ────────────────────────────────────────────────────
    es.addEventListener('playbook_progress', (e) => {
      const data = JSON.parse(e.data);
      setPlaybookProgress({ current: data.current, total: data.total, cveId: data.cveId });
    });

    // ── Individual playbook ready ─────────────────────────────────────────────
    es.addEventListener('playbook_ready', (e) => {
      const data = JSON.parse(e.data);
      if (data.cveId && data.playbook) {
        setGeneratedPlaybooks(prev => ({ ...prev, [data.cveId]: data.playbook }));
        // Cache immediately
        const cacheKey = `playbook_cache_v2_${data.cveId}`;
        localStorage.setItem(cacheKey, JSON.stringify(data.playbook));
      }
    });

    // ── Pipeline complete ─────────────────────────────────────────────────────
    es.addEventListener('complete', (e) => {
      const data = JSON.parse(e.data);
      setAiState('done');
      setPlaybookProgress(null);
      setCurrentStep(7);
      es.close();
      eventSourceRef.current = null;

      window.dispatchEvent(new CustomEvent('add-notification', {
        detail: {
          id: `scan_done_${Date.now()}`,
          type: 'custom',
          message: `✅ AI analysis complete. ${data.summary?.prioritizedCount || 10} priority vectors identified. ${data.summary?.playbooksGenerated || 0} playbooks auto-generated.`,
          timestamp: new Date().toISOString()
        }
      }));

      window.dispatchEvent(new CustomEvent('add-notification', {
        detail: {
          id: `scan_paths_${Date.now()}`,
          type: 'custom',
          message: `🔗 ${data.summary?.attackPathsFound || 0} attack path(s) detected. Knowledge Graph updated.`,
          timestamp: new Date().toISOString(),
          action: 'knowledge-graph'
        }
      }));
    });

    // ── Error handling ────────────────────────────────────────────────────────
    es.onerror = (err) => {
      console.error('SSE pipeline error:', err);
      es.close();
      eventSourceRef.current = null;
      setAiState('error');
      setAiError('Analysis pipeline failed. Please check backend connection and try again.');
    };
  };

  // ── Click bar → scroll & highlight card ────────────────────────────────────
  const handleBarClick = (data) => {
    if (!data || !data.cveId) return;
    const cveId = data.cveId;
    setSelectedCveId(cveId);
    setExpandedCveId(cveId);
    setTimeout(() => {
      const el = cardRefs.current[cveId];
      if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }, 80);
  };

  // ── Sub-components ──────────────────────────────────────────────────────────

  const StatCard = ({ title, value, icon: Icon, colorClass, delay, children }) => {
    const [isExpanded, setIsExpanded] = useState(false);
    return (
      <motion.div
        layout
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay }}
        className="bg-white/95 dark:bg-[#0f172a]/95 backdrop-blur border border-slate-200 dark:border-slate-800 rounded-2xl p-6 flex flex-col justify-between shadow-2xl relative overflow-hidden group hover:border-slate-300 dark:hover:border-slate-700 transition-all duration-300 min-h-[140px]"
      >
        <div className="absolute top-0 right-0 w-28 h-28 bg-gradient-to-bl from-cyan-500/5 to-transparent rounded-bl-full pointer-events-none group-hover:from-cyan-500/8 transition-all duration-300" />

        <div className="flex items-center justify-between">
          <div>
            <p className="text-slate-500 dark:text-slate-600 dark:text-slate-400 text-xs font-bold tracking-widest uppercase mb-2">{title}</p>
            <h3 className="text-5xl font-black text-slate-900 dark:text-slate-100 tracking-tight">{value}</h3>
          </div>
          <div className="flex items-center gap-3">
            <div className={`p-4 rounded-xl ${colorClass} shadow-inner`}>
              <Icon size={28} />
            </div>
            <button
              onClick={() => setIsExpanded(!isExpanded)}
              className="p-1.5 hover:bg-slate-100 dark:hover:bg-slate-800/80 rounded-lg text-slate-500 dark:text-slate-600 dark:text-slate-400 hover:text-white transition-all duration-200 border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 bg-slate-50 dark:bg-slate-900/60 flex items-center justify-center shrink-0 self-center"
              title={isExpanded ? "Hide Details" : "Show Details"}
            >
              <ChevronDown
                size={18}
                className={`transition-transform duration-300 ${isExpanded ? 'rotate-180 text-cyan-600 dark:text-cyan-400' : ''}`}
              />
            </button>
          </div>
        </div>

        <AnimatePresence>
          {isExpanded && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              transition={{ duration: 0.3 }}
              className="overflow-hidden"
            >
              {children}
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>
    );
  };

  // ── Custom Recharts tooltip ────────────────────────────────────────────────
  const CustomBarTooltip = ({ active, payload }) => {
    if (!active || !payload?.length) return null;
    const d = payload[0].payload;
    return (
      <div className="bg-white dark:bg-[#0f172a] border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-1.5 shadow-2xl text-xs font-mono">
        <span className="text-slate-900 dark:text-slate-100 font-extrabold">{d.riskScore?.toFixed(0)}%</span>
      </div>
    );
  };

  // ── Vulnerability card (left panel) ───────────────────────────────────────
  const VulnCard = ({ item, index, isSelected }) => {
    const sev = SEVERITY_CONFIG[item.severity] || SEVERITY_CONFIG.MEDIUM;
    const isExpanded = expandedCveId === item.cveId;
    const isPriority = item.isAiCorrelated || aiPrioritizedRisks.some(r => r.cveId === item.cveId);

    return (
      <motion.div
        ref={el => { cardRefs.current[item.cveId] = el; }}
        initial={{ opacity: 0, x: -16 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ duration: 0.35, delay: index * 0.03 }}
        className={`relative border rounded-xl overflow-hidden transition-all duration-300 group shrink-0 flex flex-col justify-between
          ${isSelected
            ? `${sev.bg} ${sev.border} ${sev.glow} ring-1 ring-offset-0 ring-offset-transparent ${sev.border.replace('border-', 'ring-')}`
            : item.isAiCorrelated
              ? 'bg-cyan-50 dark:bg-cyan-950/20 border-cyan-300 dark:border-cyan-500/40 hover:border-cyan-400 hover:bg-cyan-955/40 shadow-[0_0_12px_rgba(6,182,212,0.15)]'
              : 'bg-white dark:bg-slate-950/70 border-slate-200 dark:border-slate-800/70 hover:border-slate-300 dark:hover:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-900/60'
          }`}
      >
        <div className="flex-1">
          {/* Left severity bar */}
          <div className={`absolute left-0 top-0 bottom-0 w-1 ${sev.leftBar}`} />

          {/* Top row */}
          <div
            onClick={() => {
              setExpandedCveId(isExpanded ? null : item.cveId);
              setSelectedCveId(item.cveId);
            }}
            className="pl-4 pr-4 pt-4 pb-3 cursor-pointer"
          >
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-2.5 flex-wrap">
                {/* Sequence number */}
                <span className="text-[11px] font-black text-slate-500 dark:text-slate-600 font-mono bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 px-2 py-0.5 rounded">
                  #{String(index + 1).padStart(3, '0')}
                </span>

                {/* Severity badge */}
                <span className={`text-[11px] font-black px-2.5 py-1 rounded tracking-wider ${sev.badge}`}>
                  {sev.pingSvg && (
                    <span className="inline-flex mr-1.5 relative h-2 w-2 translate-y-[1px]">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500" />
                    </span>
                  )}
                  {sev.label}
                </span>

                {/* KEV badge */}
                {item.isKEV && (
                  <span className="text-[11px] font-bold text-red-600 dark:text-red-400 bg-red-500/10 border border-red-500/30 px-2 py-0.5 rounded tracking-wide">
                    🔴 KEV
                  </span>
                )}

                {/* CVE ID */}
                {item.cveId && item.cveId !== 'CVE-UNKNOWN' && (
                  <span className="text-[11px] font-mono font-semibold text-cyan-600 dark:text-cyan-400 bg-cyan-50 dark:bg-cyan-500/8 border border-cyan-200 dark:border-cyan-500/20 px-2 py-0.5 rounded">
                    {item.cveId}
                  </span>
                )}

                {/* AI Correlated Badge */}
                {item.isAiCorrelated && (
                  <span className="text-[11px] font-bold text-cyan-600 dark:text-cyan-400 bg-cyan-100 dark:bg-cyan-950/60 border border-cyan-300 dark:border-cyan-500/40 px-2.5 py-0.5 rounded tracking-wide flex items-center gap-1 shadow-[0_0_8px_rgba(6,182,212,0.2)] animate-pulse">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                    🤖 AI CORRELATED
                  </span>
                )}
              </div>

              {/* Risk score + expand chevron */}
              <div className="flex items-center gap-2 shrink-0">
                <div className="text-right">
                  <div className="text-[10px] text-slate-500 dark:text-slate-500 font-mono uppercase">Risk</div>
                  <div className={`text-base font-black ${item.riskScore > 80 ? 'text-red-600 dark:text-red-400' : item.riskScore > 60 ? 'text-amber-600 dark:text-amber-400' : 'text-blue-600 dark:text-blue-400'
                    }`}>{item.riskScore?.toFixed(0)}</div>
                </div>
                <motion.div
                  animate={{ rotate: isExpanded ? 180 : 0 }}
                  transition={{ duration: 0.2 }}
                  className="text-slate-500 dark:text-slate-600 group-hover:text-slate-400"
                >
                  <ChevronDown size={16} />
                </motion.div>
              </div>
            </div>

            {/* Asset name */}
            <div className="flex items-center gap-2 mt-2.5">
              <Database size={13} className="text-slate-500 dark:text-slate-500 shrink-0" />
              <span className="text-sm font-bold text-slate-800 dark:text-slate-200 leading-tight">{item.assetName || 'Unknown Asset'}</span>
              {item.assetCriticality && (
                <span className="text-[10px] font-mono text-slate-500 dark:text-slate-500 ml-auto shrink-0">
                  Criticality: <span className="text-slate-700 dark:text-slate-300 font-bold">{item.assetCriticality}/10</span>
                </span>
              )}
            </div>

            {/* Short description — always visible when collapsed */}
            {!isExpanded && item.description && (
              <p className="text-[13px] text-slate-500 dark:text-slate-600 dark:text-slate-400 mt-2 leading-relaxed line-clamp-2">
                {item.description}
              </p>
            )}
          </div>

          {/* Expandable section */}
          {isExpanded && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="px-4 pb-4 border-t border-slate-200 dark:border-slate-800/50 pt-3 space-y-3"
            >
              {/* Full description */}
              {item.description && (
                <div>
                  <p className="text-[11px] font-bold text-slate-500 dark:text-slate-500 uppercase tracking-wider mb-1">
                    Vulnerability Description
                  </p>
                  <p className="text-[13px] text-slate-700 dark:text-slate-300 leading-relaxed">{item.description}</p>
                </div>
              )}

              {/* Exploit impact */}
              {item.explanation && (
                <div>
                  <p className="text-[11px] font-bold text-red-500/70 uppercase tracking-wider mb-1 flex items-center gap-1">
                    <Crosshair size={11} /> Exploit Impact & Harm
                  </p>
                  <p className="text-[13px] text-slate-700 dark:text-slate-300 leading-relaxed">{item.explanation}</p>
                </div>
              )}

              {/* Metrics row */}
              <div className="grid grid-cols-3 gap-2 pt-1">
                <div className="bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-lg p-2 text-center">
                  <div className="text-[10px] text-slate-500 dark:text-slate-500 font-mono uppercase">CVSS</div>
                  <div className="text-base font-black text-slate-900 dark:text-slate-100">{item.cvssScore?.toFixed(1) ?? 'N/A'}</div>
                </div>
                <div className="bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-lg p-2 text-center">
                  <div className="text-[10px] text-slate-500 dark:text-slate-500 font-mono uppercase">EPSS</div>
                  <div className="text-base font-black text-slate-900 dark:text-slate-100">
                    {item.epssScore != null ? `${(item.epssScore * 100).toFixed(1)}%` : 'N/A'}
                  </div>
                </div>
                <div className="bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-lg p-2 text-center">
                  <div className="text-[10px] text-slate-500 dark:text-slate-500 font-mono uppercase">Risk</div>
                  <div className={`text-base font-black ${item.riskScore > 80 ? 'text-red-600 dark:text-red-400' : item.riskScore > 60 ? 'text-amber-600 dark:text-amber-400' : 'text-blue-600 dark:text-blue-400'
                    }`}>{item.riskScore?.toFixed(1) ?? 'N/A'}</div>
                </div>
              </div>

              {/* MITRE technique */}
              {(item.techniqueId || item.techniqueName) && (
                <div className="flex items-center gap-2 text-xs font-mono">
                  <Shield size={12} className="text-purple-400 shrink-0" />
                  <span className="text-purple-400 font-bold">{item.techniqueId}</span>
                  {item.techniqueName && <span className="text-slate-500 dark:text-slate-600 dark:text-slate-400">— {item.techniqueName}</span>}
                </div>
              )}

              {/* Description fallback if not parsed */}
              {!item.description && (
                <p className="text-xs text-slate-500 dark:text-slate-500 italic">No description details parsed yet.</p>
              )}

              {/* Timestamp */}
              {analysisTimestamp && (
                <div className="flex items-center gap-2 text-[11px] font-mono text-slate-500 dark:text-slate-600 pt-1 border-t border-slate-800/40">
                  <Clock size={11} className="shrink-0" />
                  <span>Recorded at: <span className="text-slate-500 dark:text-slate-600 dark:text-slate-400">{formatTimestamp(analysisTimestamp)}</span></span>
                </div>
              )}
            </motion.div>
          )}

          {/* Bottom compact row (when collapsed) */}
          {!isExpanded && (
            <div className="pl-4 pr-4 pb-3 flex items-center gap-4 text-[11px] font-mono text-slate-500 dark:text-slate-600">
              {item.cvssScore != null && <span>CVSS <span className="text-slate-500 dark:text-slate-600 dark:text-slate-400 font-bold">{item.cvssScore.toFixed(1)}</span></span>}
              {item.epssScore != null && <span>EPSS <span className="text-slate-500 dark:text-slate-600 dark:text-slate-400 font-bold">{(item.epssScore * 100).toFixed(1)}%</span></span>}
              {item.techniqueId && <span className="text-purple-500">{item.techniqueId}</span>}
              {analysisTimestamp && (
                <span className="ml-auto flex items-center gap-1 text-slate-700">
                  <Clock size={10} />
                  {formatTimestamp(analysisTimestamp)}
                </span>
              )}
            </div>
          )}
        </div>

        {/* Playbook redirection button - Always visible at the bottom of the box */}
        <div className="px-4 pb-3.5 pt-1 border-t border-slate-900 bg-slate-50 dark:bg-slate-950/20">
          <button
            onClick={(e) => {
              e.stopPropagation();
              navigate('/playbooks', { state: { selectedCveId: item.cveId, cve: item } });
            }}
            className={`w-full py-2 px-3 rounded-lg font-bold text-[11px] uppercase tracking-wider transition-all duration-200 border flex items-center justify-center gap-1.5
              ${isPriority
                ? 'bg-cyan-100 dark:bg-cyan-500/10 hover:bg-cyan-200 dark:hover:bg-cyan-500/20 border-cyan-300 dark:border-cyan-500/35 hover:border-cyan-400 dark:hover:border-cyan-500/50 text-cyan-600 dark:text-cyan-400 hover:text-cyan-300 shadow-[0_0_10px_rgba(6,182,212,0.06)]'
                : 'bg-slate-50 dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 text-slate-500 dark:text-slate-600 dark:text-slate-400 hover:text-slate-200'
              }`}
          >
            <BookOpen size={12} className={isPriority ? 'text-cyan-600 dark:text-cyan-400' : 'text-slate-500 dark:text-slate-600 dark:text-slate-400'} />
            {isPriority ? "Check the Remediation playbook" : "Generate the Remidiation playbook"}
          </button>
        </div>
      </motion.div>
    );
  };

  // ── Custom Y-axis tick (truncated CVE ID) ──────────────────────────────────
  const CustomYAxisTick = ({ x, y, payload }) => {
    const label = payload.value?.length > 16 ? payload.value.substring(0, 16) + '…' : payload.value;
    return (
      <text x={x} y={y} dy={4} textAnchor="end" fill="#94a3b8" fontSize={11} fontFamily="monospace" fontWeight="bold">
        {label}
      </text>
    );
  };

  const getCveStatus = (cveId) => {
    const matchingAlerts = alerts.filter(a => a.cve_id === cveId);
    if (matchingAlerts.length === 0) return 'UNRESOLVED';
    if (matchingAlerts.some(a => a.status === 'UNRESOLVED')) return 'UNRESOLVED';
    if (matchingAlerts.some(a => a.status === 'ACKNOWLEDGED')) return 'ACKNOWLEDGED';
    return 'RESOLVED';
  };

  const filteredRisks = topRisks.filter(item => {
    const matchSeverity = filterSeverity === 'ALL' || item.severity === filterSeverity;
    const status = getCveStatus(item.cveId);
    const matchStatus = filterStatus === 'ALL' || status === filterStatus;
    return matchSeverity && matchStatus;
  });

  // unique CVE list
  const uniqueCvesList = Array.from(new Set(topRisks.map(r => r.cveId))).filter(Boolean);

  // unresolved critical alerts
  const unresolvedCriticalAlerts = alerts.filter(a => a.severity === 'CRITICAL' && a.status === 'UNRESOLVED');

  // ── Prioritised chart data: sorted by riskScore descending ─────────────────
  const chartData = [...aiPrioritizedRisks].sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0));

  return (
    <div className="flex flex-col gap-8 w-full max-w-[96rem] mx-auto pb-14 px-4">

      {/* ── Header ────────────────────────────────────────────────────── */}
      <div className="flex justify-between items-center border-b border-slate-800/80 pb-6">
        <div>
          <h2 className="text-3xl font-extrabold tracking-tight text-white flex items-center gap-3">
            <LayoutDashboard className="text-blue-500" size={30} />
            SOC Command Center
          </h2>
          <p className="text-sm text-slate-500 dark:text-slate-600 dark:text-slate-400 mt-1">Real-time vulnerability mapping, risk prioritisation &amp; AI threat intelligence</p>
        </div>
        <button
          onClick={fetchData}
          className="px-5 py-2.5 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 text-slate-500 dark:text-slate-600 dark:text-slate-400 rounded-xl text-xs font-bold uppercase tracking-wider flex items-center gap-2 hover:bg-slate-100 dark:hover:bg-slate-800 transition-all duration-200"
        >
          <Clock size={15} />
          Refresh
        </button>
      </div>

      {isLoading ? (
        <div className="h-[60vh] flex flex-col items-center justify-center gap-3">
          <div className="animate-spin w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full" />
          <span className="text-sm text-slate-500 dark:text-slate-600 dark:text-slate-400 tracking-widest font-mono uppercase animate-pulse">Syncing SOC telemetry...</span>
        </div>
      ) : (
        <>
          {/* ── Stat Cards ─────────────────────────────────────────────── */}
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
            <StatCard title="Total CVEs Mapped" value={stats.totalCves} icon={ShieldAlert} colorClass="bg-red-500/10 text-red-500 border border-red-500/20" delay={0.05}>
              <div className="flex flex-col gap-4 mt-5 pt-4 border-t border-slate-800/80 flex-1">
                {/* Severity Donut & Legend */}
                <div className="flex items-center justify-between gap-4 h-24">
                  <div className="flex-1 flex flex-col justify-center text-xs font-mono text-slate-700 dark:text-slate-300 gap-2">
                    <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-pulse" />Critical: <span className="text-rose-400 font-bold">{stats.severityBreakdown.CRITICAL || 5}</span></div>
                    <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-amber-500" />High: <span className="text-amber-600 dark:text-amber-400 font-bold">{stats.severityBreakdown.HIGH || 6}</span></div>
                  </div>
                  <div className="flex-1 flex flex-col justify-center text-xs font-mono text-slate-700 dark:text-slate-300 gap-2">
                    <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-blue-500" />Medium: <span className="text-blue-600 dark:text-blue-400 font-bold">{stats.severityBreakdown.MEDIUM || 1}</span></div>
                    <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-slate-500" />Low: <span className="text-slate-500 dark:text-slate-600 dark:text-slate-400 font-bold">{stats.severityBreakdown.LOW || 0}</span></div>
                  </div>
                  <div className="w-20 h-20 shrink-0 flex items-center justify-center relative">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={[
                            { name: 'Critical', value: stats.severityBreakdown.CRITICAL || 5, color: '#f43f5e' },
                            { name: 'High', value: stats.severityBreakdown.HIGH || 6, color: '#f59e0b' },
                            { name: 'Medium', value: stats.severityBreakdown.MEDIUM || 1, color: '#3b82f6' },
                            { name: 'Low', value: stats.severityBreakdown.LOW || 0, color: '#64748b' }
                          ].filter(d => d.value > 0)}
                          innerRadius={20}
                          outerRadius={35}
                          paddingAngle={3}
                          dataKey="value"
                        >
                          {[
                            { name: 'Critical', value: stats.severityBreakdown.CRITICAL || 5, color: '#f43f5e' },
                            { name: 'High', value: stats.severityBreakdown.HIGH || 6, color: '#f59e0b' },
                            { name: 'Medium', value: stats.severityBreakdown.MEDIUM || 1, color: '#3b82f6' },
                            { name: 'Low', value: stats.severityBreakdown.LOW || 0, color: '#64748b' }
                          ].filter(d => d.value > 0).map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Compact tags list of actual CVEs */}
                <div className="flex flex-col gap-1.5 mt-1">
                  <p className="text-[10px] text-slate-500 dark:text-slate-500 font-mono uppercase tracking-wider font-bold">Mapped CVE Registry:</p>
                  <div className="flex flex-wrap gap-1.5 max-h-[100px] overflow-y-auto [&::-webkit-scrollbar]:w-1.5 [&::-webkit-scrollbar-thumb]:bg-slate-800/80 pr-1 pr-1">
                    {uniqueCvesList.map(cveId => {
                      const risk = topRisks.find(r => r.cveId === cveId);
                      const sev = risk?.severity || 'HIGH';
                      const color = sev === 'CRITICAL' ? 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/20 hover:bg-red-500/20 shadow-[0_0_8px_rgba(239,68,68,0.05)]' :
                        sev === 'HIGH' ? 'bg-amber-50 dark:bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20 hover:bg-amber-500/20 shadow-[0_0_8px_rgba(245,158,11,0.05)]' :
                          sev === 'MEDIUM' ? 'bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20 hover:bg-blue-500/20' :
                            'bg-slate-50 dark:bg-slate-500/10 text-slate-500 dark:text-slate-600 dark:text-slate-400 border-slate-500/20 hover:bg-slate-500/20';
                      return (
                        <span
                          key={cveId}
                          onClick={() => {
                            setSelectedCveId(cveId);
                            setExpandedCveId(cveId);
                            setTimeout(() => {
                              const el = cardRefs.current[cveId];
                              if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
                            }, 80);
                          }}
                          className={`text-[10px] font-mono font-extrabold px-2.5 py-1 rounded cursor-pointer transition-all border ${color}`}
                          title={`Click to view ${cveId}`}
                        >
                          {cveId}
                        </span>
                      );
                    })}
                  </div>
                </div>
              </div>
            </StatCard>

            <StatCard title="Critical Unresolved" value={stats.criticalAlerts} icon={AlertOctagon} colorClass="bg-rose-500/10 text-rose-400 border border-rose-500/20" delay={0.1}>
              <div className="flex flex-col gap-3 mt-5 pt-4 border-t border-slate-800/80 flex-1">
                <p className="text-[10px] text-slate-500 dark:text-slate-500 font-mono uppercase tracking-wider font-bold mb-1">Active Security Threats:</p>
                {unresolvedCriticalAlerts.length > 0 ? (
                  <div className="flex flex-col gap-2.5 max-h-[180px] overflow-y-auto [&::-webkit-scrollbar]:w-1.5 [&::-webkit-scrollbar-thumb]:bg-slate-800/80 pr-1">
                    {unresolvedCriticalAlerts.map(alert => (
                      <div key={alert.id} className="flex flex-col gap-1.5 bg-red-500/5 border border-red-500/20 rounded-xl p-3.5 relative overflow-hidden hover:bg-red-500/10 transition-colors">
                        <div className="absolute top-0 left-0 bottom-0 w-1 bg-red-500 animate-pulse" />
                        <div className="flex items-center justify-between text-[11px] font-mono pl-1">
                          <span className="font-extrabold text-red-600 dark:text-red-400">{alert.cve_id || alert.cveId || 'CVE-UNKNOWN'}</span>
                          <span className="text-[9px] bg-red-100 dark:bg-red-500/20 text-red-300 px-2 py-0.5 rounded uppercase font-black tracking-widest animate-pulse">UNRESOLVED</span>
                        </div>
                        <p className="text-[11px] text-slate-800 dark:text-slate-200 leading-normal pl-1 font-semibold" title={alert.message}>
                          {alert.message}
                        </p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center py-6 gap-3">
                    <div className="w-12 h-12 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
                      <div className="w-4 h-4 rounded-full bg-emerald-500 animate-pulse" />
                    </div>
                    <span className="text-xs text-emerald-400 font-mono font-bold uppercase tracking-widest">All Threats Resolved</span>
                  </div>
                )}
              </div>
            </StatCard>

            <StatCard title="Critical Assets at Risk" value={stats.assetsAtRisk} icon={Target} colorClass="bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20" delay={0.15}>
              <div className="flex flex-col gap-3 mt-5 pt-4 border-t border-slate-800/80 flex-1">
                <p className="text-[10px] text-slate-500 dark:text-slate-500 font-mono uppercase tracking-wider font-bold mb-1">Impacted Host Systems:</p>
                {criticalAssets.length > 0 ? (
                  <div className="flex flex-col gap-2 max-h-[180px] overflow-y-auto [&::-webkit-scrollbar]:w-1.5 [&::-webkit-scrollbar-thumb]:bg-slate-800/80 pr-1">
                    {criticalAssets.map(asset => (
                      <div key={asset.name} className="flex items-center justify-between text-xs font-mono bg-slate-50 dark:bg-slate-900/60 border border-slate-850 rounded-xl px-3.5 py-2.5 hover:border-slate-300 dark:hover:border-slate-700 hover:bg-slate-900 transition-all duration-200">
                        <div className="flex items-center gap-2 truncate">
                          <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
                          <span className="text-slate-900 dark:text-slate-100 font-black truncate max-w-[150px]" title={asset.name}>
                            {asset.name && asset.name !== 'Unknown' ? asset.name : asset.assetId || 'Asset'}
                          </span>
                        </div>
                        <div className="flex items-center gap-3 shrink-0">
                          <span className="text-slate-500 dark:text-slate-600 dark:text-slate-400 text-[10px] uppercase font-bold">Crit: <span className="text-cyan-600 dark:text-cyan-400">{asset.criticality}/10</span></span>
                          <span className="bg-red-50 dark:bg-red-500/15 text-red-600 dark:text-red-400 border border-red-500/30 px-2 py-0.5 rounded text-[10px] font-black uppercase">
                            {asset.vulnerabilityCount} Vulns
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <span className="text-xs text-slate-500 dark:text-slate-500 italic py-2">No critical assets found.</span>
                )}
              </div>
            </StatCard>

            <StatCard title="Attack Paths Found" value={stats.attackPaths} icon={Network} colorClass="bg-purple-500/10 text-purple-400 border border-purple-500/20" delay={0.2}>
              <div className="flex flex-col gap-3 mt-5 pt-4 border-t border-slate-800/80 flex-1">
                <p className="text-[10px] text-slate-500 dark:text-slate-500 font-mono uppercase tracking-wider font-bold mb-1">Lateral Compromise Paths:</p>
                {attackPaths.length > 0 ? (
                  <div className="flex flex-col gap-3 max-h-[180px] overflow-y-auto [&::-webkit-scrollbar]:w-1.5 [&::-webkit-scrollbar-thumb]:bg-slate-800/80 pr-1">
                    {attackPaths.map((path, idx) => (
                      <div key={idx} className="flex flex-col gap-2.5 p-3.5 bg-purple-500/5 border border-purple-500/20 rounded-xl hover:bg-purple-500/10 transition-colors">
                        <div className="flex items-center justify-between text-[10px] font-mono text-purple-400 font-black">
                          <span>PATH SCENARIO #{idx + 1} · {path.hop_count} HOPS</span>
                          <span>RISK: {path.total_risk_score?.toFixed(0)}/100</span>
                        </div>
                        <div className="flex items-center gap-2 text-xs font-mono text-slate-800 dark:text-slate-200 font-bold overflow-x-auto whitespace-nowrap py-2.5 px-2 bg-slate-950 border border-slate-850 rounded-lg custom-scrollbar">
                          {path.path_nodes?.map((node, nIdx) => (
                            <React.Fragment key={nIdx}>
                              {nIdx > 0 && <span className="text-purple-500 font-black px-0.5">→</span>}
                              <span className="bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 px-2 py-1 rounded text-[11px] font-extrabold text-slate-900 dark:text-slate-100" title={node}>
                                {node}
                              </span>
                            </React.Fragment>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex items-center gap-2.5 text-emerald-400 text-xs font-mono font-bold py-3">
                    <span className="w-2 h-2 rounded-full bg-emerald-500 animate-ping" />
                    <span>No lateral compromise paths detected.</span>
                  </div>
                )}
              </div>
            </StatCard>
          </div>

          {/* ── Gen-AI Panel ───────────────────────────────────────────── */}
          <motion.div
            initial={{ opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.25 }}
            className="relative bg-[#050d18] border border-cyan-900/40 rounded-2xl overflow-hidden shadow-[0_0_40px_rgba(0,200,255,0.04)]"
          >
            {/* Scanline overlay */}
            <div
              className="absolute inset-0 pointer-events-none opacity-20"
              style={{ background: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,255,255,0.012) 2px, rgba(0,255,255,0.012) 4px)' }}
            />
            <div className="absolute top-0 right-0 w-64 h-32 bg-gradient-to-bl from-cyan-500/5 to-transparent pointer-events-none" />

            {/* Header */}
            <div className="relative flex flex-col sm:flex-row sm:items-center justify-between gap-5 p-7 border-b border-cyan-900/30">
              <div>
                <h3 className="text-xl font-extrabold text-white flex items-center gap-3 tracking-tight">
                  <div className="p-2 rounded-xl bg-cyan-100 dark:bg-cyan-500/10 border border-cyan-200 dark:border-cyan-500/20 shadow-[0_0_12px_rgba(6,182,212,0.12)]">
                    <Cpu className="text-cyan-600 dark:text-cyan-400" size={20} />
                  </div>
                  <span role="img" aria-label="robot">🤖</span> Gen-AI Threat Intelligence Analysis
                </h3>
                <p className="text-sm text-slate-500 dark:text-slate-600 dark:text-slate-400 mt-1.5 ml-1">
                  Gemini AI analyses your full CVE dataset, maps MITRE ATT&amp;CK techniques, and predicts the most likely kill chain
                </p>
              </div>

              <motion.button
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.97 }}
                onClick={handleRunAnalysis}
                disabled={aiState === 'running'}
                className={`shrink-0 flex items-center gap-3 px-7 py-4 rounded-xl font-extrabold text-[14px] uppercase tracking-wider transition-all duration-200 border
                  ${aiState === 'running'
                    ? 'bg-cyan-950/40 border-cyan-800/40 text-cyan-600 cursor-not-allowed'
                    : 'bg-gradient-to-r from-cyan-600/25 to-blue-600/25 border-cyan-500/50 text-cyan-700 dark:text-cyan-300 hover:border-cyan-400 hover:text-cyan-200 hover:shadow-[0_0_25px_rgba(6,182,212,0.3)] shadow-[0_0_15px_rgba(6,182,212,0.12)]'
                  }`}
              >
                {aiState === 'running' ? (
                  <><div className="w-4 h-4 border-2 border-cyan-300 dark:border-cyan-500/40 border-t-cyan-400 rounded-full animate-spin" />PIPELINE RUNNING<span className="animate-pulse">...</span></>
                ) : (
                  <><Zap size={16} className="text-cyan-600 dark:text-cyan-400" />RUN AI Analysis</>
                )}
              </motion.button>
            </div>

            {/* Body */}
            <div className="relative p-7 space-y-5">
              {/* ── Idle state ─────────────────────────────────────────────── */}
              {aiState === 'idle' && (
                <div className="flex flex-col items-center justify-center py-12 gap-4 text-center">
                  <div className="w-14 h-14 rounded-2xl bg-cyan-500/5 border border-cyan-500/15 flex items-center justify-center">
                    <Cpu className="text-cyan-800" size={24} />
                  </div>
                  <p className="text-slate-500 dark:text-slate-500 text-sm max-w-md font-mono">
                    Click <span className="text-cyan-500 font-bold">"Run AI Analysis"</span> to run the full 7-step threat intelligence pipeline:
                    ecosystem monitoring → vulnerability detection → RF model ranking → AI priority generation → attack path detection → graph sync → auto-playbook generation.
                  </p>
                </div>
              )}

              {/* ── Pipeline step tracker (running or done) ────────────────── */}
              {(aiState === 'running' || aiState === 'done') && pipelineSteps.length > 0 && (
                <motion.div
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2"
                >
                  {PIPELINE_STEPS.map((step) => {
                    const stepData = pipelineSteps.find(s => s.step === step.id);
                    const isDone = stepData?.status === 'done';
                    const isRunning = stepData?.status === 'running';
                    const isPending = !stepData;
                    return (
                      <div
                        key={step.id}
                        className={`flex flex-col items-center gap-1.5 p-3 rounded-xl border text-center transition-all duration-300
                          ${isDone ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' :
                            isRunning ? 'bg-cyan-100 dark:bg-cyan-500/10 border-cyan-300 dark:border-cyan-500/40 text-cyan-600 dark:text-cyan-400 shadow-[0_0_12px_rgba(6,182,212,0.15)]' :
                            'bg-slate-50 dark:bg-slate-900/60 border-slate-200 dark:border-slate-800/60 text-slate-500 dark:text-slate-600'
                          }`}
                      >
                        <div className="relative flex items-center justify-center w-7 h-7">
                          {isRunning && (
                            <div className="absolute w-7 h-7 rounded-full border-2 border-cyan-500/30 border-t-cyan-400 animate-spin" />
                          )}
                          <span className={`text-[11px] font-black ${isDone ? 'text-emerald-400' : isRunning ? 'text-cyan-600 dark:text-cyan-400' : 'text-slate-500 dark:text-slate-600'}`}>
                            {isDone ? '✓' : step.id}
                          </span>
                        </div>
                        <span className="text-[9px] font-bold uppercase tracking-wide leading-tight">{step.label}</span>
                      </div>
                    );
                  })}
                </motion.div>
              )}

              {/* ── Latest step detail ─────────────────────────────────────── */}
              {aiState === 'running' && pipelineSteps.length > 0 && (() => {
                const latest = [...pipelineSteps].reverse()[0];
                return (
                  <div className="bg-black/40 border border-cyan-900/40 rounded-xl px-4 py-3 font-mono text-xs text-cyan-600 dark:text-cyan-400 flex items-center gap-3">
                    <div className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse shrink-0" />
                    <span className="text-cyan-600 font-bold">[STEP {latest.step}/7]</span>
                    <span className="text-cyan-700 dark:text-cyan-300">{latest.detail || latest.title}</span>
                  </div>
                );
              })()}

              {/* ── Playbook generation progress bar ───────────────────────── */}
              {playbookProgress && (
                <motion.div
                  initial={{ opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="bg-slate-900/80 border border-slate-200 dark:border-slate-800 rounded-xl p-4 space-y-2"
                >
                  <div className="flex items-center justify-between text-[11px] font-mono">
                    <span className="text-cyan-600 dark:text-cyan-400 font-bold flex items-center gap-2">
                      <BookOpen size={11} /> Auto-Generating Playbooks
                    </span>
                    <span className="text-slate-500 dark:text-slate-500">{playbookProgress.current}/{playbookProgress.total}</span>
                  </div>
                  <div className="w-full bg-slate-100 dark:bg-slate-800 rounded-full h-1.5 overflow-hidden">
                    <motion.div
                      className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full"
                      initial={{ width: 0 }}
                      animate={{ width: `${(playbookProgress.current / playbookProgress.total) * 100}%` }}
                      transition={{ duration: 0.4 }}
                    />
                  </div>
                  <p className="text-[10px] text-slate-500 dark:text-slate-500 font-mono truncate">
                    Generating: <span className="text-cyan-500 font-bold">{playbookProgress.cveId}</span>
                  </p>
                </motion.div>
              )}

              {/* ── Generated playbooks counter ────────────────────────────── */}
              {Object.keys(generatedPlaybooks).length > 0 && (
                <div className="flex flex-wrap gap-2">
                  {Object.entries(generatedPlaybooks).map(([cveId]) => (
                    <motion.span
                      key={cveId}
                      initial={{ opacity: 0, scale: 0.8 }}
                      animate={{ opacity: 1, scale: 1 }}
                      className="text-[10px] font-mono font-extrabold px-2.5 py-1 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 flex items-center gap-1"
                    >
                      <BookOpen size={9} />
                      {cveId}
                    </motion.span>
                  ))}
                </div>
              )}

              {/* ── AI Terminal (analysis text) ────────────────────────────── */}
              {aiDisplayText && (
                <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="relative">
                  <div className="flex items-center gap-2 bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-t-xl px-4 py-2.5 border-b-0">
                    <span className="w-2.5 h-2.5 rounded-full bg-red-500/70" />
                    <span className="w-2.5 h-2.5 rounded-full bg-amber-500/70" />
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/70" />
                    <span className="ml-4 text-[10px] font-mono text-slate-500 dark:text-slate-600 tracking-widest uppercase">
                      cyberdefense-ai | priority-attack-vectors | {new Date().toLocaleTimeString()}
                    </span>
                    {aiState === 'running' && aiDisplayText && (
                      <div className="ml-auto flex items-center gap-1.5 text-[10px] font-mono text-cyan-500">
                        <div className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />LIVE
                      </div>
                    )}
                    {aiState === 'done' && aiDisplayText && (
                      <div className="ml-auto flex items-center gap-1.5 text-[10px] font-mono text-emerald-500">
                        <div className="w-1.5 h-1.5 rounded-full bg-emerald-400" />COMPLETE
                      </div>
                    )}
                  </div>
                  <div
                    ref={terminalRef}
                    className="bg-black/90 border border-slate-200 dark:border-slate-800 rounded-b-xl max-h-[400px] overflow-y-auto [&::-webkit-scrollbar]:w-1 [&::-webkit-scrollbar-thumb]:bg-slate-800 [&::-webkit-scrollbar-thumb]:rounded-full"
                    style={{ padding: '22px', minHeight: '280px' }}
                  >
                    <pre
                      className="whitespace-pre-wrap break-words"
                      style={{ fontSize: '13px', lineHeight: '1.8', fontFamily: 'monospace', color: '#00ff88', letterSpacing: '0.3px' }}
                    >
                      {aiDisplayText}
                      {aiState === 'running' && aiDisplayText && (
                        <span className="inline-block w-2 h-4 animate-pulse ml-0.5 translate-y-0.5" style={{ backgroundColor: '#00ff88' }} />
                      )}
                    </pre>
                  </div>
                </motion.div>
              )}

              {/* ── Error state ─────────────────────────────────────────────── */}
              {aiState === 'error' && (
                <div className="flex flex-col items-center gap-3 py-10 text-center">
                  <AlertTriangle className="text-red-500" size={30} />
                  <p className="text-red-600 dark:text-red-400 font-bold text-sm">{aiError}</p>
                  <button
                    onClick={handleRunAnalysis}
                    className="px-4 py-2 text-xs font-bold uppercase tracking-wider bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 rounded-lg hover:bg-red-500/20 transition-all"
                  >
                    Retry
                  </button>
                </div>
              )}
            </div>
          </motion.div>

          {/* ── Main Two-Column: Vulnerability List (L) + Priority Chart (R) ── */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">

            {/* ── LEFT: Full Vulnerability List ─────────────────────────────── */}
            <motion.div
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.5, delay: 0.3 }}
              className="lg:col-span-7 flex flex-col gap-3"
            >
              <div className="flex items-center justify-between mb-2">
                <div>
                  <h3 className="text-lg font-extrabold text-slate-800 dark:text-slate-200 flex items-center gap-2">
                    <Shield className="text-blue-600 dark:text-blue-400" size={20} />
                    All Vulnerabilities
                  </h3>
                  <p className="text-sm text-slate-500 dark:text-slate-500 mt-0.5">
                    {filteredRisks.length} entries — sorted by risk score · click any bar in chart to highlight
                  </p>
                </div>
                <div className="flex items-center gap-3 text-[11px] font-mono">
                  {Object.entries(SEVERITY_CONFIG).map(([k, v]) => {
                    const count = filteredRisks.filter(r => r.severity === k).length;
                    return count > 0 ? (
                      <span key={k} className="flex items-center gap-1">
                        <span className={`w-2.5 h-2.5 rounded-full ${v.dot}`} />{count}
                      </span>
                    ) : null;
                  })}
                </div>
              </div>

              {/* Filter Toolbar */}
              <div className="bg-[#111827]/80 backdrop-blur border border-slate-800/80 p-4 rounded-xl shadow-lg flex flex-wrap gap-4 items-center justify-between">
                <div className="flex flex-wrap gap-4 items-center">
                  <div className="flex items-center gap-2.5 text-xs font-semibold text-slate-500 dark:text-slate-600 dark:text-slate-400">
                    <Filter size={14} className="text-blue-600 dark:text-blue-400" />
                    <span>Severity:</span>
                    <div className="flex rounded-lg bg-slate-950 p-0.5 border border-slate-200 dark:border-slate-800/60">
                      {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map(sev => (
                        <button
                          key={sev}
                          onClick={() => setFilterSeverity(sev)}
                          className={`px-2.5 py-1.5 rounded-md text-[10px] font-extrabold uppercase transition-all duration-200 ${filterSeverity === sev
                            ? 'bg-blue-100 dark:bg-blue-500/20 text-blue-600 dark:text-blue-400 border border-blue-300 dark:border-blue-500/30'
                            : 'text-slate-500 dark:text-slate-500 hover:text-slate-300'
                            }`}
                        >
                          {sev}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="flex items-center gap-2.5 text-xs font-semibold text-slate-500 dark:text-slate-600 dark:text-slate-400">
                    <span>Status:</span>
                    <div className="flex rounded-lg bg-slate-950 p-0.5 border border-slate-200 dark:border-slate-800/60">
                      {['ALL', 'UNRESOLVED', 'ACKNOWLEDGED', 'RESOLVED'].map(stat => (
                        <button
                          key={stat}
                          onClick={() => setFilterStatus(stat)}
                          className={`px-2.5 py-1.5 rounded-md text-[10px] font-extrabold uppercase transition-all duration-200 ${filterStatus === stat
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

                <div className="text-[11px] font-mono text-slate-500 dark:text-slate-500">
                  {filteredRisks.length}/{topRisks.length}
                </div>
              </div>

              <div className="flex flex-col gap-3 max-h-[900px] overflow-y-auto pr-1 [&::-webkit-scrollbar]:w-1.5 [&::-webkit-scrollbar-track]:bg-slate-950/40 [&::-webkit-scrollbar-thumb]:bg-slate-800 [&::-webkit-scrollbar-thumb]:rounded-full hover:[&::-webkit-scrollbar-thumb]:bg-slate-700">
                {filteredRisks.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-20 gap-3 text-slate-500 dark:text-slate-500">
                    <Shield size={40} className="opacity-30" />
                    <p className="text-sm">No vulnerabilities match the selected filters.</p>
                  </div>
                ) : (
                  [...filteredRisks]
                    .sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0))
                    .map((item, idx) => (
                      <VulnCard
                        key={item.cveId + idx}
                        item={item}
                        index={idx}
                        isSelected={selectedCveId === item.cveId}
                      />
                    ))
                )}
              </div>
            </motion.div>

            {/* ── RIGHT: Priority Attack Vectors Chart ─────────────────────── */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.5, delay: 0.35 }}
              className="lg:col-span-5 bg-white/95 dark:bg-[#0f172a]/95 backdrop-blur border border-slate-200 dark:border-slate-800 rounded-2xl p-7 shadow-2xl flex flex-col sticky top-6"
              style={{ maxHeight: '900px' }}
            >
              <div className="mb-5 shrink-0">
                <h3 className="text-lg font-extrabold text-slate-800 dark:text-slate-200 flex items-center gap-2">
                  <TrendingUp className="text-amber-500" size={20} />
                  Prioritized Attack Vectors
                </h3>
                <p className="text-sm text-slate-500 dark:text-slate-600 dark:text-slate-400 mt-0.5">Most Vulnerable — ranked by composite risk</p>
                <p className="text-[11px] text-slate-500 dark:text-slate-600 mt-1 font-mono">
                  Click any bar to highlight &amp; expand that vulnerability →
                </p>
              </div>

              {/* Legend */}
              <div className="flex items-center gap-4 mb-4 shrink-0">
                {[['#ef4444', 'Critical (>80)'], ['#f59e0b', 'High (>60)'], ['#3b82f6', 'Medium']].map(([color, label]) => (
                  <span key={label} className="flex items-center gap-1.5 text-[11px] text-slate-500 dark:text-slate-500 font-mono">
                    <span className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: color }} />{label}
                  </span>
                ))}
              </div>

              <div className="flex-1 overflow-y-auto min-h-0">
                {chartData.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-20 gap-3 text-slate-500 dark:text-slate-500">
                    <TrendingUp size={32} className="opacity-30" />
                    <p className="text-xs text-slate-500 dark:text-slate-600 font-mono">Waiting for prioritized analysis data...</p>
                  </div>
                ) : (
                  <div style={{ height: Math.max(300, chartData.length * 36) }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart
                        data={chartData}
                        layout="vertical"
                        margin={{ top: 4, right: 16, left: 12, bottom: 4 }}
                        onClick={(e) => {
                          if (e && e.activePayload && e.activePayload[0]) {
                            handleBarClick(e.activePayload[0].payload);
                          }
                        }}
                      >
                        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} vertical={true} />
                        <XAxis type="number" domain={[0, 100]} stroke="#334155" fontSize={10} fontWeight="bold" tickLine={false} />
                        <YAxis
                          dataKey="cveId"
                          type="category"
                          width={120}
                          tick={<CustomYAxisTick />}
                          tickLine={false}
                          axisLine={false}
                        />
                        <Tooltip content={<CustomBarTooltip />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
                        <Bar
                          dataKey="riskScore"
                          radius={[0, 6, 6, 0]}
                          barSize={22}
                          style={{ cursor: 'pointer' }}
                        >
                          {chartData.map((entry, index) => (
                            <Cell
                              key={`cell-${index}`}
                              fill={
                                selectedCveId === entry.cveId
                                  ? '#ffffff'
                                  : entry.riskScore > 80 ? '#ef4444'
                                    : entry.riskScore > 60 ? '#f59e0b'
                                      : '#3b82f6'
                              }
                              opacity={selectedCveId && selectedCveId !== entry.cveId ? 0.4 : 1}
                            />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </div>

              {/* Selected state hint */}
              {selectedCveId && (
                <div className="mt-4 pt-3 border-t border-slate-200 dark:border-slate-800/60 flex items-center justify-between shrink-0">
                  <span className="text-[11px] font-mono text-slate-500 dark:text-slate-500">
                    Selected: <span className="text-cyan-600 dark:text-cyan-400 font-bold">{selectedCveId}</span>
                  </span>
                  <button
                    onClick={() => { setSelectedCveId(null); setExpandedCveId(null); }}
                    className="text-[11px] font-bold text-slate-500 dark:text-slate-600 hover:text-slate-400 transition-colors"
                  >
                    Clear ✕
                  </button>
                </div>
              )}
            </motion.div>

          </div>
        </>
      )}
    </div>
  );
}
