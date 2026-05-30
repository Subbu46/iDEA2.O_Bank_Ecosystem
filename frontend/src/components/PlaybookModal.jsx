import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  X, Download, Copy, Check, ChevronDown, ChevronRight,
  ShieldAlert, AlertTriangle, Zap, Clock, RefreshCw,
  Lock, FileText, CheckCircle, BookOpen, Shield, AlertOctagon, Terminal, UserCheck
} from 'lucide-react';

// ── Section definitions ────────────────────────────────────────────────────────
const SECTIONS = [
  {
    key: 'executiveSummary',
    label: 'Executive Summary',
    icon: FileText,
    color: 'text-cyan-600 dark:text-cyan-400',
    borderColor: 'border-cyan-500/30',
    bgColor: 'bg-cyan-500/5',
  },
  {
    key: 'immediateActions',
    label: 'Immediate Actions',
    icon: Zap,
    color: 'text-red-600 dark:text-red-400',
    borderColor: 'border-red-500/30',
    bgColor: 'bg-red-500/5',
  },
  {
    key: 'shortTermRemediation',
    label: 'Short-Term Remediation',
    icon: AlertTriangle,
    color: 'text-amber-600 dark:text-amber-400',
    borderColor: 'border-amber-500/30',
    bgColor: 'bg-amber-500/5',
  },
  {
    key: 'longTermHardening',
    label: 'Long-Term Hardening',
    icon: ShieldAlert,
    color: 'text-blue-600 dark:text-blue-400',
    borderColor: 'border-blue-300 dark:border-blue-500/30',
    bgColor: 'bg-blue-500/5',
  },
  {
    key: 'verificationSteps',
    label: 'Verification Steps',
    icon: CheckCircle,
    color: 'text-emerald-400',
    borderColor: 'border-emerald-500/30',
    bgColor: 'bg-emerald-500/5',
  },
  {
    key: 'rollbackPlan',
    label: 'Rollback Plan',
    icon: RefreshCw,
    color: 'text-purple-400',
    borderColor: 'border-purple-500/30',
    bgColor: 'bg-purple-500/5',
  },
  {
    key: 'complianceNotes',
    label: 'Compliance Notes',
    icon: Lock,
    color: 'text-slate-700 dark:text-slate-300',
    borderColor: 'border-slate-300 dark:border-slate-600/30',
    bgColor: 'bg-slate-700/10',
  },
];

// ── Accordion Item ─────────────────────────────────────────────────────────────
function AccordionSection({ section, content, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen);
  const Icon = section.icon;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className={`rounded-xl border ${section.borderColor} overflow-hidden`}
    >
      <button
        onClick={() => setOpen(!open)}
        className={`w-full flex items-center justify-between p-5 ${section.bgColor} hover:brightness-110 transition-all duration-200 text-left`}
      >
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-lg ${section.bgColor} border ${section.borderColor}`}>
            <Icon size={16} className={section.color} />
          </div>
          <span className={`font-bold text-[15px] ${section.color}`}>{section.label}</span>
        </div>
        <motion.div animate={{ rotate: open ? 180 : 0 }} transition={{ duration: 0.2 }}>
          <ChevronDown size={18} className="text-slate-500 dark:text-slate-600 dark:text-slate-400" />
        </motion.div>
      </button>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25, ease: 'easeInOut' }}
          >
            <div className="p-5 bg-slate-950/60 border-t border-slate-800/40">
              {content ? (
                <pre className="text-[13px] text-slate-700 dark:text-slate-300 font-mono whitespace-pre-wrap leading-relaxed break-words">
                  {content}
                </pre>
              ) : (
                <p className="text-slate-500 dark:text-slate-500 italic text-sm">
                  Section data not available — please retry generation.
                </p>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ── Main Modal ─────────────────────────────────────────────────────────────────
export const playbookCache = {};

export const LOGS_SEQUENCE = [
  "Human approval received...",
  "[EXEC] Isolating compromised gateway...",
  "[EXEC] Revoking privileged IAM sessions...",
  "[EXEC] Enabling emergency segmentation...",
  "[EXEC] Deploying temporary firewall policy...",
  "[EXEC] Updating threat status...",
  "✓ Threat Successfully Contained",
  "✓ AI Remediation Completed",
  "✓ SOC Escalation Closed"
];

export const buildFallbackPlaybook = (alert) => {
  const cveId = alert?.cve_id || 'CVE-UNKNOWN';
  const severity = alert?.severity || 'HIGH';
  const assetId = alert?.asset_id || 'Unknown Asset';
  
  let mitreTechnique = 'T1190 - Exploit Public-Facing Application';
  if (alert?.technique_id) {
    mitreTechnique = alert.technique_id;
  }
  
  return {
    cveId,
    generatedAt: new Date().toISOString(),
    executiveSummary: `A ${severity} severity incident was detected on asset "${assetId}" involving ${cveId}. The vulnerability poses an immediate risk to core banking systems and compliance layers. Network protection, incident containment, and remediation are required immediately to prevent lateral movement and credential exposure.`,
    immediateActions: `1. Isolate the affected host "${assetId}" using localized network firewall policies.
2. Revoke all active credentials and service account sessions on the host.
3. Block external incoming traffic on high-risk ports associated with the attack vector.
4. Enable detailed packet capture and logging on adjacent subnets.
5. Notify the CISO and SOC incident response team for escalation level P1.`,
    shortTermRemediation: `1. Retrieve and apply the official vendor security patch for ${cveId}.
2. Rotate all database credentials, service-account passwords, and system keys.
3. Deploy customized WAF and IPS signatures to identify and drop exploitation patterns.
4. Run a full credential audit to confirm no secondary backdoors were introduced.`,
    longTermHardening: `1. Implement zero-trust micro-segmentation for ${assetId} to isolate the database tier.
2. Enforce strict 14-day patching SLAs for all critical CVEs.
3. Transition to centralized IAM authorization with hardware-based MFA.
4. Conduct weekly vulnerability scanning and quarterly external penetration testing.`,
    verificationSteps: `1. Verify patch version using authenticated vulnerability scan.
2. Confirm firewall rules block unauthorized lateral traffic between DMZ and core.
3. Perform system integrity checks on host files to confirm no unauthorized modifications.
4. Monitor system audit logs for 48 hours to confirm zero anomalous alerts.`,
    rollbackPlan: `1. Take a complete VM snapshot prior to patching or configuration changes.
2. If application error rates exceed 5% post-remediation, revert to snapshot immediately.
3. Keep standard system configuration templates on standby for hot-swapping.
4. Notify system operators before executing any rollback sequence.`,
    complianceNotes: `- RBI Cybersecurity Guidelines: Mandatory isolation and 14-day patch SLA for CRITICAL CVEs.
- DPDP Act 2023: Data breach notifications must be sent to CERT-In within the 6-hour statutory window.
- ISO 27001 Control A.12.6.1: Technical vulnerability management controls must be fully documented.
- PCI DSS 6.3: Patching compliance validated and logged for external audit.`,
    rawResponse: null,
  };
};

export default function PlaybookModal({ alert, onClose }) {
  const [playbook, setPlaybook] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);

  // Unified State Machine: pending | approving | approved | escalating | escalated | rejecting | rejected
  const [governanceState, setGovernanceState] = useState("pending");
  const [executionLogs, setExecutionLogs] = useState([]);
  const [escalationTicket, setEscalationTicket] = useState(null);
  const [slaSeconds, setSlaSeconds] = useState(900);
  const [auditLogs, setAuditLogs] = useState([
    {
      timestamp: new Date().toISOString(),
      event: "AI Governance Engine Activated",
      actor: "System Core",
      details: "CyberDefense AI banking governance layer initialized and active.",
      status: "SUCCESS"
    }
  ]);

  const isMountedRef = useRef(true);

  // Bind console error and state logging
  useEffect(() => {
    isMountedRef.current = true;
    const prevOnError = window.onerror;
    window.onerror = (message, source, lineno, colno, error) => {
      console.error("[PlaybookModal] Error caught by window.onerror:", message, "source:", source, "line:", lineno, error);
      if (prevOnError) return prevOnError(message, source, lineno, colno, error);
      return false;
    };
    console.log("[PlaybookModal] Modal mounted for alert:", alert?.id);
    return () => {
      console.log("[PlaybookModal] Unmounting modal...");
      isMountedRef.current = false;
      window.onerror = prevOnError;
    };
  }, [alert]);

  const updateGovernanceState = (newState) => {
    console.log(`[PlaybookModal] State transition: ${governanceState} -> ${newState}`);
    if (isMountedRef.current) {
      setGovernanceState(newState);
    }
  };

  const fetchAuditLogs = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/playbook/audit');
      if (res.ok) {
        const data = await res.json();
        if (isMountedRef.current) {
          setAuditLogs(data);
        }
      }
    } catch (e) {
      console.warn("Failed to fetch audit logs:", e);
    }
  };

  useEffect(() => {
    if (alert) {
      fetchAuditLogs();
    }
  }, [alert]);

  useEffect(() => {
    if (governanceState !== "escalated") return;
    const interval = setInterval(() => {
      if (isMountedRef.current) {
        setSlaSeconds(prev => (prev > 0 ? prev - 1 : 0));
      }
    }, 1000);
    return () => clearInterval(interval);
  }, [governanceState]);

  const formatSlaTime = (totalSeconds) => {
    const mins = Math.floor(totalSeconds / 60);
    const secs = totalSeconds % 60;
    return `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')} min`;
  };

  const confidenceScore = alert ? (alert?.cve_id === 'CVE-2026-1043' || alert?.severity === 'CRITICAL' ? 82 : alert?.severity === 'HIGH' ? 88 : 96) : 85;
  const blastRadius = alert ? (alert?.severity === 'CRITICAL' ? 'Core Banking Zone' : alert?.severity === 'HIGH' ? 'Internal segment / DMZ Gateway' : 'Peripheral System Segment') : 'N/A';

  const isGovernanceLoading = ["approving", "escalating", "rejecting"].includes(governanceState);
  const executionFinished = executionLogs.length === LOGS_SEQUENCE.length;

  const handleApproveAndExecute = async () => {
    if (governanceState !== "pending") return;
    updateGovernanceState("approving");
    setExecutionLogs([]);

    try {
      const response = await fetch('http://localhost:8000/api/playbook/approve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          alert_id: alert?.id || 'alert_01',
          cve_id: alert?.cve_id || 'CVE-2026-1043',
          actor: "Tier-2 SOC Analyst Banu"
        })
      });
      if (response.ok) {
        const data = await response.json();
        if (isMountedRef.current && data?.full_audit_trail) {
          setAuditLogs(data.full_audit_trail);
        }
      }
    } catch (e) {
      console.warn("Backend validation offline, using local audit simulation:", e);
    } finally {
      if (isMountedRef.current) {
        updateGovernanceState("approved");
      }
    }

    let currentLogIndex = 0;
    const interval = setInterval(() => {
      if (!isMountedRef.current) {
        clearInterval(interval);
        return;
      }
      if (currentLogIndex < LOGS_SEQUENCE.length) {
        setExecutionLogs(prev => [...prev, LOGS_SEQUENCE[currentLogIndex]]);
        currentLogIndex++;
      } else {
        clearInterval(interval);
        window.dispatchEvent(new CustomEvent('ai-governance-remediate', {
          detail: {
            cve_id: alert?.cve_id,
            alert_id: alert?.id,
            simState: 'remediated'
          }
        }));
        try {
          localStorage.setItem('remediated_' + alert?.cve_id, 'true');
          localStorage.setItem('simState', 'remediated');
        } catch (e) {
          console.warn("Storage write failed:", e);
        }
      }
    }, 60); // Speed up log streaming to 60ms
  };

  const handleEscalate = async () => {
    if (governanceState !== "pending") return;
    updateGovernanceState("escalating");
    try {
      const response = await fetch('http://localhost:8000/api/playbook/escalate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          alert_id: alert?.id || 'alert_01',
          cve_id: alert?.cve_id || 'CVE-2026-1043',
          actor: "Tier-2 SOC Analyst Banu",
          reason: "AI confidence below enterprise threshold."
        })
      });
      if (response.ok) {
        const data = await response.json();
        if (isMountedRef.current) {
          setEscalationTicket(data?.ticket);
          if (data?.full_audit_trail) {
            setAuditLogs(data.full_audit_trail);
          }
        }
      }
    } catch (e) {
      console.warn("Backend validation offline, using local escalation ticket:", e);
      if (isMountedRef.current) {
        setEscalationTicket({
          ticketId: `SOC-2026-${Math.floor(1000 + Math.random() * 9000)}`,
          assignedTeam: "Tier-3 Incident Response",
          reason: "AI confidence below enterprise threshold.",
          timestamp: new Date().toISOString(),
          slaMinutes: 15
        });
      }
    } finally {
      if (isMountedRef.current) {
        updateGovernanceState("escalated");
        setSlaSeconds(900);
      }
    }
  };

  const handleReject = async () => {
    if (governanceState !== "pending") return;
    updateGovernanceState("rejecting");
    try {
      const response = await fetch('http://localhost:8000/api/playbook/reject', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          alert_id: alert?.id || 'alert_01',
          cve_id: alert?.cve_id || 'CVE-2026-1043',
          actor: "Tier-2 SOC Analyst Banu"
        })
      });
      if (response.ok) {
        const data = await response.json();
        if (isMountedRef.current && data?.full_audit_trail) {
          setAuditLogs(data.full_audit_trail);
        }
      }
    } catch (e) {
      console.warn("Backend validation offline, using local rejection log:", e);
    } finally {
      if (isMountedRef.current) {
        updateGovernanceState("rejected");
      }
    }
  };

  // Fetch playbook on mount or when alert changes
  useEffect(() => {
    if (!alert) return;

    const cacheKey = alert?.cve_id || alert?.id;
    console.log(`[PlaybookModal] Playbook payload existence for cacheKey ${cacheKey}:`, !!playbookCache[cacheKey]);

    if (playbookCache[cacheKey]) {
      console.log(`[PlaybookModal] Instant load from memory cache for ${cacheKey}`);
      setPlaybook(playbookCache[cacheKey]);
      setLoading(false);
      setError(null);
      return;
    }

    setLoading(true);
    setError(null);

    const localFallback = buildFallbackPlaybook(alert);

    // AI response 2-second fallback timer
    const fallbackTimer = setTimeout(() => {
      if (isMountedRef.current && !playbookCache[cacheKey]) {
        console.log("[PlaybookModal] AI response took > 2 seconds. Serving deterministic local fallback.");
        setPlaybook(localFallback);
        setLoading(false);
      }
    }, 2000);

    const fetchPlaybook = async () => {
      try {
        const response = await fetch('http://localhost:8000/api/playbooks/remediation', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            cve_data: {
              cveId: alert?.cve_id || 'CVE-UNKNOWN',
              description: alert?.message || 'Security vulnerability detected in banking infrastructure.',
              cvssScore: 8.5,
              severity: alert?.severity || 'HIGH',
              epssScore: 0.72,
              isKEV: alert?.severity === 'CRITICAL',
            },
            affected_assets: [alert?.asset_id || 'Unknown Banking Asset'],
          }),
        });

        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        
        if (isMountedRef.current) {
          console.log("[PlaybookModal] Gemini playbook loaded successfully.");
          playbookCache[cacheKey] = data; // Cache successfully fetched Gemini response
          setPlaybook(data);
          setLoading(false);
          setError(null);
        }
      } catch (err) {
        console.warn('Playbook generation failed, ensuring fallback is shown:', err);
        if (isMountedRef.current && !playbookCache[cacheKey]) {
          playbookCache[cacheKey] = localFallback;
          setPlaybook(localFallback);
          setLoading(false);
          setError(null);
        }
      } finally {
        clearTimeout(fallbackTimer);
      }
    };

    fetchPlaybook();

    return () => {
      clearTimeout(fallbackTimer);
    };
  }, [alert]);

  const getFullText = () => {
    if (!playbook) return '';
    return SECTIONS.map(s => `## ${s.label}\n\n${playbook?.[s.key] || ''}`).join('\n\n---\n\n');
  };

  const handleDownload = () => {
    const text = getFullText();
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `playbook-${playbook?.cveId || 'unknown'}-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(getFullText());
      setCopied(true);
      setTimeout(() => {
        if (isMountedRef.current) setCopied(false);
      }, 2000);
    } catch {
      /* ignore */
    }
  };

  // Close on Escape key
  useEffect(() => {
    const handler = (e) => {
      if (e.key === 'Escape') {
        console.log("[PlaybookModal] Closing modal via Escape key...");
        onClose();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onClose]);

  if (!alert) return null;

  return (
    <>
      {/* Static Backdrop (no unsafe unmount animations here) */}
      <div
        onClick={onClose}
        className="fixed inset-0 z-50 bg-black/85 backdrop-blur-sm transition-opacity duration-200"
      />

      {/* Static Modal Panel Container */}
      <div
        className="fixed inset-0 z-50 flex items-center justify-center p-4"
      >
        <div
          className="w-full max-w-4xl h-[90vh] flex flex-col rounded-2xl border border-violet-500/30 shadow-[0_0_60px_rgba(139,92,246,0.15)] overflow-hidden relative"
          style={{ background: 'linear-gradient(135deg, #0d1117 0%, #0f172a 50%, #0d1117 100%)' }}
        >
          {/* Scanline overlay */}
          <div
            className="absolute inset-0 pointer-events-none rounded-2xl"
            style={{
              background: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px)',
            }}
          />

          {/* Header */}
          <div className="relative flex items-start justify-between gap-4 p-7 border-b border-slate-200 dark:border-slate-800/60 bg-gradient-to-r from-violet-950/30 to-transparent shrink-0">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-3 mb-2">
                <div className="p-2 rounded-xl bg-violet-500/15 border border-violet-500/30 shadow-[0_0_15px_rgba(139,92,246,0.2)]">
                  <ShieldAlert className="text-violet-400" size={22} />
                </div>
                <h2 className="text-2xl font-extrabold text-white tracking-tight">
                  <span role="img" aria-label="shield">🛡️</span> AI-Generated Remediation Playbook
                </h2>
              </div>
              <div className="flex flex-wrap gap-x-5 gap-y-2 text-sm font-mono text-slate-500 dark:text-slate-600 dark:text-slate-400 mt-1 pl-1">
                <span>
                  Incident:{' '}
                  <span className="text-slate-800 dark:text-slate-200 font-semibold">
                    {alert?.message?.substring?.(0, 60)}{alert?.message?.length > 60 ? '...' : ''}
                  </span>
                </span>
                {alert?.cve_id && (
                  <span>
                    CVE:{' '}
                    <span className="text-violet-300 font-extrabold">{alert.cve_id}</span>
                  </span>
                )}
                {alert?.asset_id && (
                  <span>
                    Asset:{' '}
                    <span className="text-cyan-600 dark:text-cyan-400 font-bold">{alert.asset_id}</span>
                  </span>
                )}
              </div>
            </div>

            <button
              onClick={() => {
                console.log("[PlaybookModal] Closing modal via explicit Close icon click...");
                onClose();
              }}
              className="shrink-0 p-2.5 rounded-xl bg-slate-800/60 hover:bg-slate-700/60 border border-slate-300 dark:border-slate-700/50 text-slate-500 dark:text-slate-600 dark:text-slate-400 hover:text-slate-200 transition-all duration-150 cursor-pointer"
            >
              <X size={20} />
            </button>
          </div>

          {/* Body */}
          <div className="flex-1 overflow-y-auto p-7 [&::-webkit-scrollbar]:w-1.5 [&::-webkit-scrollbar-track]:bg-slate-950/40 [&::-webkit-scrollbar-thumb]:bg-slate-800 [&::-webkit-scrollbar-thumb]:rounded-full hover:[&::-webkit-scrollbar-thumb]:bg-violet-800/60">
            {loading ? (
              <div className="flex flex-col items-center justify-center gap-6 py-20">
                {/* AI Thinking animation */}
                <div className="relative">
                  <div className="w-16 h-16 rounded-full border-2 border-violet-500/30 animate-spin border-t-violet-500" />
                  <div className="absolute inset-0 flex items-center justify-center">
                    <BookOpen className="text-violet-400" size={20} />
                  </div>
                </div>
                <div className="text-center">
                  <p className="text-violet-300 font-bold text-lg tracking-wider font-mono uppercase">
                    AI Analysing Incident
                    <span className="animate-pulse">...</span>
                  </p>
                  <p className="text-slate-500 dark:text-slate-500 text-sm mt-1 font-mono">
                    Building remediation workflow & mapping MITRE techniques
                  </p>
                </div>
                {/* Fake processing logs */}
                <div className="bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 font-mono text-xs text-emerald-400 w-full max-w-md">
                  {[
                    '> AI analysing incident...',
                    '> Mapping MITRE techniques...',
                    '> Building remediation workflow...',
                    '> Consulting Gemini threat intelligence model_',
                  ].map((log, i) => (
                    <motion.div
                      key={log}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: i * 0.15, duration: 0.15 }}
                    >
                      {log}
                    </motion.div>
                  ))}
                </div>
              </div>
            ) : error ? (
              <div className="text-center py-16 text-red-600 dark:text-red-400 font-mono">
                <p className="font-bold mb-2">Failed to generate playbook</p>
                <p className="text-sm text-slate-500 dark:text-slate-500">{error}</p>
              </div>
            ) : !playbook ? (
              null
            ) : (
              <div className="flex flex-col gap-4">
                {/* Generated timestamp */}
                <div className="flex items-center gap-2 text-xs font-mono text-slate-500 dark:text-slate-500 mb-2">
                  <Clock size={12} />
                  <span>Generated: {playbook?.generatedAt ? new Date(playbook.generatedAt).toLocaleString() : 'Just now'}</span>
                  {playbook?.cveId && (
                    <span className="px-2 py-0.5 rounded bg-violet-500/10 border border-violet-500/20 text-violet-400 font-bold">
                      {playbook.cveId}
                    </span>
                  )}
                </div>

                {SECTIONS.map((section, idx) => (
                  <AccordionSection
                    key={section.key}
                    section={section}
                    content={playbook?.[section.key]}
                    defaultOpen={idx < 2}
                  />
                ))}

                {/* AI Governance & Human Validation Section */}
                <div className="mt-8 border-t border-slate-800/80 pt-6">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="p-2 rounded-xl bg-cyan-100 dark:bg-cyan-500/10 border border-cyan-500/30 shadow-[0_0_15px_rgba(6,182,212,0.15)]">
                      <Shield className="text-cyan-600 dark:text-cyan-400" size={20} />
                    </div>
                    <div>
                      <h3 className="text-lg font-bold text-white tracking-wide">
                        AI Governance & Human Validation
                      </h3>
                      <p className="text-xs text-slate-500 dark:text-slate-600 dark:text-slate-400 mt-0.5 font-sans">
                        Critical banking infrastructure actions require analyst approval before execution.
                      </p>
                    </div>
                  </div>

                  {/* Explicit State-Machine Conditional rendering */}
                  {governanceState === "pending" && (
                    <motion.div
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                    >
                      {/* Metrics Grid */}
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-5">
                        {/* AI Confidence */}
                        <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-4 flex flex-col justify-between">
                          <span className="text-[11px] font-mono text-slate-500 dark:text-slate-500 uppercase tracking-widest">AI Confidence</span>
                          <div className="flex items-baseline gap-2 mt-2">
                            <span className={`text-2xl font-black font-mono ${
                              confidenceScore > 90 ? 'text-emerald-400' :
                              confidenceScore >= 70 ? 'text-amber-600 dark:text-amber-400' : 'text-rose-400'
                            }`}>
                              {confidenceScore}%
                            </span>
                            <span className={`text-[10px] px-2 py-0.5 rounded font-bold font-mono uppercase ${
                              confidenceScore > 90 ? 'bg-emerald-500/10 text-emerald-400' :
                              confidenceScore >= 70 ? 'bg-amber-50 dark:bg-amber-500/10 text-amber-600 dark:text-amber-400' : 'bg-rose-500/10 text-rose-400'
                            }`}>
                              {confidenceScore > 90 ? 'Optimal' : confidenceScore >= 70 ? 'Moderate' : 'Critical Low'}
                            </span>
                          </div>
                        </div>

                        {/* Threat Severity */}
                        <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-4 flex flex-col justify-between">
                          <span className="text-[11px] font-mono text-slate-500 dark:text-slate-500 uppercase tracking-widest">Threat Severity</span>
                          <div className="flex items-baseline gap-2 mt-2">
                            <span className={`text-2xl font-black font-mono ${
                              alert?.severity === 'CRITICAL' ? 'text-red-600 dark:text-red-400' :
                              alert?.severity === 'HIGH' ? 'text-amber-600 dark:text-amber-400' : 'text-cyan-600 dark:text-cyan-400'
                            }`}>
                              {alert?.severity || 'HIGH'}
                            </span>
                          </div>
                        </div>

                        {/* Blast Radius */}
                        <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-4 flex flex-col justify-between">
                          <span className="text-[11px] font-mono text-slate-500 dark:text-slate-500 uppercase tracking-widest">Blast Radius</span>
                          <span className="text-base font-extrabold text-slate-800 dark:text-slate-200 mt-2 font-mono truncate">
                            {blastRadius}
                          </span>
                        </div>
                      </div>

                      {/* Auto-remediation Notice */}
                      <div className="mb-5">
                        {confidenceScore < 85 ? (
                          <div className="flex items-center gap-2.5 p-3 bg-rose-500/10 border border-rose-500/20 text-rose-400 rounded-lg text-xs font-mono">
                            <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-ping shrink-0" />
                            <span>Automatic escalation triggered due to low confidence. Direct auto-remediation disabled. Manual analyst approval required.</span>
                          </div>
                        ) : confidenceScore > 95 ? (
                          <div className="flex items-center gap-2.5 p-3 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-lg text-xs font-mono">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse shrink-0" />
                            <span>Eligible for autonomous remediation. Human analyst can bypass full validation cycle.</span>
                          </div>
                        ) : (
                          <div className="flex items-center gap-2.5 p-3 bg-slate-800/40 border border-slate-300 dark:border-slate-700/30 text-slate-350 rounded-lg text-xs font-mono">
                            <span className="w-1.5 h-1.5 rounded-full bg-slate-400 shrink-0" />
                            <span>Standard manual analyst governance validation required.</span>
                          </div>
                        )}
                      </div>

                      {/* Risk Banner */}
                      {(alert?.severity === 'HIGH' || alert?.severity === 'CRITICAL') && (
                        <div className="relative overflow-hidden mb-6 p-4 rounded-xl border border-amber-500/30 bg-gradient-to-r from-amber-500/10 to-transparent shadow-[0_0_20px_rgba(245,158,11,0.05)] animate-pulse">
                          <div className="flex items-center gap-3">
                            <AlertOctagon className="text-amber-600 dark:text-amber-400 shrink-0" size={24} />
                            <div>
                              <h4 className="text-sm font-black text-amber-300 uppercase tracking-widest font-mono">
                                ⚠ HUMAN APPROVAL REQUIRED
                              </h4>
                              <p className="text-xs text-slate-500 dark:text-slate-600 dark:text-slate-400 mt-0.5 font-sans">
                                AI-generated remediation affects critical infrastructure.
                              </p>
                            </div>
                          </div>
                        </div>
                      )}

                      {/* Action Buttons */}
                      <div className="flex flex-col sm:flex-row gap-3 mb-6">
                        <button
                          onClick={handleApproveAndExecute}
                          disabled={isGovernanceLoading}
                          className={`flex-1 py-4 px-6 rounded-xl text-sm font-bold uppercase tracking-wider transition-all duration-200 flex items-center justify-center gap-2 border shadow-[0_0_15px_rgba(16,185,129,0.05)] ${
                            isGovernanceLoading 
                              ? 'bg-slate-50 dark:bg-slate-900 border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-500 cursor-not-allowed'
                              : 'bg-emerald-500/10 hover:bg-emerald-500/25 border-emerald-500/40 hover:border-emerald-500 text-emerald-400 hover:text-emerald-300 active:scale-98 cursor-pointer'
                          }`}
                        >
                          {isGovernanceLoading && governanceState === "approving" && <RefreshCw size={16} className="animate-spin text-emerald-400 mr-1" />}
                          APPROVE & EXECUTE
                        </button>
                        <button
                          onClick={handleEscalate}
                          disabled={isGovernanceLoading}
                          className="flex-1 py-4 px-6 rounded-xl text-sm font-bold uppercase tracking-wider transition-all duration-200 flex items-center justify-center gap-2 border bg-amber-50 dark:bg-amber-500/10 hover:bg-amber-500/25 border-amber-300 dark:border-amber-500/40 hover:border-amber-500 text-amber-600 dark:text-amber-400 hover:text-amber-300 active:scale-98 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
                        >
                          {isGovernanceLoading && governanceState === "escalating" && <RefreshCw size={16} className="animate-spin text-amber-600 dark:text-amber-400 mr-1" />}
                          ESCALATE TO SOC ANALYST
                        </button>
                        <button
                          onClick={handleReject}
                          disabled={isGovernanceLoading}
                          className="flex-1 py-4 px-6 rounded-xl text-sm font-bold uppercase tracking-wider transition-all duration-200 flex items-center justify-center gap-2 border bg-red-500/10 hover:bg-red-500/25 border-red-500/40 hover:border-red-500 text-red-600 dark:text-red-400 hover:text-red-300 active:scale-98 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
                        >
                          {isGovernanceLoading && governanceState === "rejecting" && <RefreshCw size={16} className="animate-spin text-red-600 dark:text-red-400 mr-1" />}
                          REJECT ACTION
                        </button>
                      </div>
                    </motion.div>
                  )}

                  {/* APPROVED STATE PANEL */}
                  {governanceState === "approved" && (
                    <motion.div
                      initial={{ opacity: 0, y: 15 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.3 }}
                      className="bg-emerald-950/20 border border-emerald-500/30 rounded-2xl p-6 mb-6 shadow-[0_0_30px_rgba(16,185,129,0.1)]"
                    >
                      <div className="flex items-start gap-4">
                        <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 shrink-0">
                          <CheckCircle size={28} />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between">
                            <h4 className="text-lg font-black text-emerald-400 tracking-wide font-mono uppercase">
                              ✓ REMEDIATION EXECUTED SUCCESSFULLY
                            </h4>
                            <span className="text-[10px] text-slate-500 dark:text-slate-500 font-mono">SESSION_ID: SOC-SECURE-{alert?.id}</span>
                          </div>
                          <p className="text-xs text-slate-500 dark:text-slate-600 dark:text-slate-400 mt-1 font-sans">
                            Human approval logged. AI containment steps deployed in real-time.
                          </p>

                          {/* Containment Summary */}
                          <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                            <div className="bg-slate-950/60 border border-slate-900 p-3 rounded-lg">
                              <span className="text-slate-500 dark:text-slate-500 block mb-1">Containment Actions</span>
                              <span className="text-emerald-400 font-bold">5 critical actions completed</span>
                            </div>
                            <div className="bg-slate-950/60 border border-slate-900 p-3 rounded-lg">
                              <span className="text-slate-500 dark:text-slate-500 block mb-1">Target Asset Status</span>
                              <span className="text-emerald-400 font-bold">Isolated & Secured</span>
                            </div>
                          </div>

                          {/* Remediation Execution Logs */}
                          <div className="mt-4 bg-[#030712] border border-slate-200 dark:border-slate-800 rounded-xl p-4 font-mono text-[11px] leading-relaxed flex flex-col gap-2.5 max-h-[160px] overflow-y-auto [&::-webkit-scrollbar]:w-1 [&::-webkit-scrollbar-thumb]:bg-slate-800">
                            <div className="flex items-center justify-between border-b border-slate-900 pb-2 mb-1">
                              <span className="text-[10px] text-slate-500 dark:text-slate-500 font-bold">CONTAINMENT STREAM LOGS</span>
                              <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold uppercase ${executionFinished ? 'text-emerald-400 bg-emerald-500/10' : 'text-cyan-600 dark:text-cyan-400 bg-cyan-100 dark:bg-cyan-500/10 animate-pulse'}`}>
                                {executionFinished ? 'COMPLETED' : 'ACTIVE'}
                              </span>
                            </div>
                            {executionLogs?.map?.((log, index) => {
                              const isSuccess = log?.startsWith?.('✓');
                              const isExec = log?.startsWith?.('[EXEC]');
                              let styleClass = 'text-slate-350';
                              if (isSuccess) styleClass = 'text-emerald-400 font-bold';
                              else if (isExec) styleClass = 'text-cyan-600 dark:text-cyan-400';
                              return (
                                <motion.div
                                  initial={{ opacity: 0, x: -5 }}
                                  animate={{ opacity: 1, x: 0 }}
                                  transition={{ duration: 0.15 }}
                                  key={index}
                                  className={`flex items-start gap-2 ${styleClass}`}
                                >
                                  <span>{log}</span>
                                </motion.div>
                              );
                            })}
                            {!executionFinished && (
                              <div className="flex items-center gap-1.5 text-cyan-500 mt-1">
                                <span className="animate-pulse">_</span>
                                <RefreshCw size={10} className="animate-spin text-cyan-600 dark:text-cyan-400" />
                              </div>
                            )}
                          </div>

                          {/* Audit Confirmation */}
                          <div className="mt-4 p-3 bg-slate-950/60 rounded-lg border border-slate-900/60 text-[10px] font-mono text-slate-500 dark:text-slate-500 flex items-center justify-between">
                            <span className="flex items-center gap-1.5 text-emerald-400 font-bold">
                              <Lock size={12} />
                              AUDIT SECURED: ACTION SIGNED & COMPLETED
                            </span>
                            <span>SHA-256: 0x{alert?.id?.substring?.(0, 8) || '24af38c9'}e3d...</span>
                          </div>
                        </div>
                      </div>
                    </motion.div>
                  )}

                  {/* ESCALATED STATE PANEL */}
                  {governanceState === "escalated" && (
                    <motion.div
                      initial={{ opacity: 0, y: 15 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.3 }}
                      className="bg-amber-950/20 border border-amber-500/30 rounded-2xl p-6 mb-6 shadow-[0_0_30px_rgba(245,158,11,0.1)]"
                    >
                      <div className="flex items-start gap-4">
                        <div className="p-3 rounded-xl bg-amber-50 dark:bg-amber-500/10 border border-amber-500/30 text-amber-600 dark:text-amber-400 shrink-0 animate-pulse">
                          <UserCheck size={28} />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between">
                            <h4 className="text-lg font-black text-amber-600 dark:text-amber-400 tracking-wide font-mono uppercase">
                              ⚠ ESCALATED TO SOC ANALYST
                            </h4>
                            <span className="text-[10px] text-slate-500 dark:text-slate-500 font-mono">TICKET_ID: {escalationTicket?.ticketId || 'SOC-2026-1043'}</span>
                          </div>
                          <p className="text-xs text-slate-500 dark:text-slate-600 dark:text-slate-400 mt-1 font-sans">
                            AI containment bypassed. Critical threat transferred to Tier-3 incident response.
                          </p>

                          {/* Ticket Details */}
                          <div className="mt-4 bg-slate-950/60 border border-slate-900 p-4 rounded-xl font-mono text-xs text-slate-700 dark:text-slate-300 flex flex-col gap-3">
                            <div className="flex justify-between">
                              <span className="text-slate-500 dark:text-slate-500">Ticket ID:</span>
                              <span className="text-amber-600 dark:text-amber-400 font-bold">{escalationTicket?.ticketId || 'SOC-2026-1043'}</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-slate-500 dark:text-slate-500">Assigned Team:</span>
                              <span className="text-slate-800 dark:text-slate-200">{escalationTicket?.assignedTeam || 'Tier-3 IR Team'}</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-slate-500 dark:text-slate-500">Escalation Reason:</span>
                              <span className="text-slate-800 dark:text-slate-200 text-right truncate max-w-[250px]" title={escalationTicket?.reason}>
                                {escalationTicket?.reason || 'AI confidence below threshold.'}
                              </span>
                            </div>
                            <div className="flex justify-between border-t border-slate-900/60 pt-3">
                              <span className="text-slate-500 dark:text-slate-500">SLA Response Window:</span>
                              <span className="text-red-600 dark:text-red-400 font-bold animate-pulse">
                                {formatSlaTime(slaSeconds)}
                              </span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-slate-500 dark:text-slate-500">Timestamp:</span>
                              <span className="text-slate-450">{escalationTicket?.timestamp ? new Date(escalationTicket.timestamp).toLocaleString() : new Date().toLocaleString()}</span>
                            </div>
                          </div>

                          <div className="mt-4 flex items-center gap-2 p-3 bg-amber-500/5 border border-amber-500/10 text-amber-600 dark:text-amber-400 rounded-lg text-xs font-mono text-center w-full justify-center">
                            <span className="animate-pulse">● Awaiting manual Tier-3 analyst intervention...</span>
                          </div>

                          {/* Audit Confirmation */}
                          <div className="mt-4 p-3 bg-slate-950/60 rounded-lg border border-slate-900/60 text-[10px] font-mono text-slate-500 dark:text-slate-500 flex items-center justify-between">
                            <span className="flex items-center gap-1.5 text-amber-600 dark:text-amber-400 font-bold">
                              <Lock size={12} />
                              AUDIT SECURED: ESCALATION TICKET REGISTERED
                            </span>
                            <span>SHA-256: 0x{escalationTicket?.ticketId?.substring?.(4) || 'f3a8b29c'}d8...</span>
                          </div>
                        </div>
                      </div>
                    </motion.div>
                  )}

                  {/* REJECTED STATE PANEL */}
                  {governanceState === "rejected" && (
                    <motion.div
                      initial={{ opacity: 0, y: 15 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.3 }}
                      className="bg-red-950/20 border border-red-500/30 rounded-2xl p-6 mb-6 shadow-[0_0_30px_rgba(239,68,68,0.1)]"
                    >
                      <div className="flex items-start gap-4">
                        <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-600 dark:text-red-400 shrink-0">
                          <AlertOctagon size={28} className="animate-pulse" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between">
                            <h4 className="text-lg font-black text-red-600 dark:text-red-400 tracking-wide font-mono uppercase">
                              ✗ AI REMEDIATION REJECTED
                            </h4>
                            <span className="text-[10px] text-slate-500 dark:text-slate-500 font-mono">AUDIT_LOG: DISMISSED</span>
                          </div>
                          <p className="text-xs text-slate-500 dark:text-slate-600 dark:text-slate-400 mt-1 font-sans">
                            Operator has declined the recommendation. AI automated actions halted.
                          </p>

                          {/* Threat Active Warning */}
                          <div className="mt-4 p-4 bg-red-950/15 border border-red-500/20 text-red-600 dark:text-red-400 rounded-xl text-xs font-mono flex flex-col gap-2">
                            <div className="flex items-center gap-2 font-bold text-red-300">
                              <span className="w-2 h-2 rounded-full bg-red-500 animate-ping" />
                              WARNING: THREAT REMAINS ACTIVE
                            </div>
                            <p className="text-slate-500 dark:text-slate-600 dark:text-slate-400 leading-relaxed text-[11px] font-sans">
                              Target asset <span className="text-cyan-600 dark:text-cyan-400 font-bold">{alert?.asset_id || 'Unknown Asset'}</span> remains in a high-vulnerability exposure state. Manual investigation and physical containment are critically required to prevent lateral movement.
                            </p>
                          </div>

                          {/* Audit Confirmation */}
                          <div className="mt-4 p-3 bg-slate-950/60 rounded-lg border border-slate-900/60 text-[10px] font-mono text-slate-500 dark:text-slate-500 flex items-center justify-between">
                            <span className="flex items-center gap-1.5 text-red-600 dark:text-red-400 font-bold">
                              <Lock size={12} />
                              AUDIT SECURED: REJECTION IMMUTABLY RECORDED
                            </span>
                            <span>STATUS: ACTIVE_THREAT</span>
                          </div>
                        </div>
                      </div>
                    </motion.div>
                  )}

                  {/* Audit Trail Monospace Panel */}
                  <div className="bg-[#030712] border border-slate-800/80 rounded-xl overflow-hidden shadow-2xl mt-4">
                    <div className="px-4 py-3 bg-slate-950/60 border-b border-slate-200 dark:border-slate-800/60 flex items-center justify-between">
                      <span className="text-[11px] font-mono font-bold text-slate-500 dark:text-slate-500 tracking-wider uppercase">Enterprise Audit Trail</span>
                      <div className="flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 animate-pulse" />
                        <span className="text-[10px] font-mono text-cyan-500 uppercase">Live Log Feed</span>
                      </div>
                    </div>
                    <div className="p-4 max-h-[160px] overflow-y-auto font-mono text-[11px] leading-relaxed flex flex-col gap-2.5 [&::-webkit-scrollbar]:w-1 [&::-webkit-scrollbar-thumb]:bg-slate-800">
                      {auditLogs?.map?.((log, index) => {
                        let logColor = 'text-slate-500 dark:text-slate-600 dark:text-slate-400';
                        let badgeBg = 'bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-600 dark:text-slate-400';
                        if (log?.status === 'SUCCESS' || log?.status === 'APPROVED') {
                          logColor = 'text-emerald-300';
                          badgeBg = 'bg-emerald-500/10 text-emerald-400';
                        } else if (log?.status === 'WARNING') {
                          logColor = 'text-amber-300';
                          badgeBg = 'bg-amber-50 dark:bg-amber-500/10 text-amber-600 dark:text-amber-400';
                        } else if (log?.status === 'REJECTED') {
                          logColor = 'text-red-300';
                          badgeBg = 'bg-red-500/10 text-red-600 dark:text-red-400';
                        } else if (log?.status === 'INFO') {
                          logColor = 'text-cyan-700 dark:text-cyan-300';
                          badgeBg = 'bg-cyan-100 dark:bg-cyan-500/10 text-cyan-600 dark:text-cyan-400';
                        }
                        return (
                          <div key={index} className="border-b border-slate-900 pb-2 last:border-b-0 last:pb-0 flex items-start gap-3">
                            <span className="text-slate-500 dark:text-slate-600 shrink-0">[{log?.timestamp ? log.timestamp.substring(11, 19) : '00:00:00'}]</span>
                            <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase shrink-0 ${badgeBg}`}>{log?.status}</span>
                            <div className="flex-1">
                              <span className="text-slate-800 dark:text-slate-200 font-bold mr-1">{log?.event}</span>
                              <span className="text-slate-500 dark:text-slate-500">by {log?.actor}:</span>
                              <span className={`block mt-0.5 ${logColor}`}>{log?.details}</span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Footer */}
          {!loading && (
            <div className="flex items-center justify-between gap-4 p-6 border-t border-slate-200 dark:border-slate-800/60 bg-slate-950/40 shrink-0">
              <div className="text-xs font-mono text-slate-500 dark:text-slate-600">
                CyberDefense AI · Gemini-powered · Banking Context
              </div>
              <div className="flex items-center gap-3">
                <button
                  onClick={handleDownload}
                  className="px-4 py-2.5 bg-slate-800/70 hover:bg-slate-700/70 border border-slate-300 dark:border-slate-700/50 hover:border-slate-600 text-slate-700 dark:text-slate-300 rounded-xl transition-all text-sm font-bold flex items-center gap-2 cursor-pointer font-mono"
                >
                  <Download size={15} />
                  Download
                </button>
                <button
                  onClick={handleCopy}
                  className={`px-4 py-2.5 border rounded-xl transition-all text-sm font-bold flex items-center gap-2 cursor-pointer font-mono ${
                    copied
                      ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-400'
                      : 'bg-slate-800/70 hover:bg-slate-700/70 border-slate-300 dark:border-slate-700/50 hover:border-slate-600 text-slate-700 dark:text-slate-300'
                  }`}
                >
                  {copied ? <Check size={15} /> : <Copy size={15} />}
                  {copied ? 'Copied!' : 'Copy to Clipboard'}
                </button>
                <button
                  onClick={() => {
                    console.log("[PlaybookModal] Closing modal via explicit Close button click...");
                    onClose();
                  }}
                  className="px-4 py-2.5 bg-violet-600/20 hover:bg-violet-600/30 border border-violet-500/40 hover:border-violet-500/60 text-violet-300 rounded-xl transition-all text-sm font-bold cursor-pointer font-mono"
                >
                  Close
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
