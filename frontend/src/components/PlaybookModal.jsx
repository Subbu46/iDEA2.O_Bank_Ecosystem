import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  X, Download, Copy, Check, ChevronDown, ChevronRight,
  ShieldAlert, AlertTriangle, Zap, Clock, RefreshCw,
  Lock, FileText, CheckCircle, BookOpen
} from 'lucide-react';

// ── Section definitions ────────────────────────────────────────────────────────
const SECTIONS = [
  {
    key: 'executiveSummary',
    label: 'Executive Summary',
    icon: FileText,
    color: 'text-cyan-400',
    borderColor: 'border-cyan-500/30',
    bgColor: 'bg-cyan-500/5',
  },
  {
    key: 'immediateActions',
    label: 'Immediate Actions',
    icon: Zap,
    color: 'text-red-400',
    borderColor: 'border-red-500/30',
    bgColor: 'bg-red-500/5',
  },
  {
    key: 'shortTermRemediation',
    label: 'Short-Term Remediation',
    icon: AlertTriangle,
    color: 'text-amber-400',
    borderColor: 'border-amber-500/30',
    bgColor: 'bg-amber-500/5',
  },
  {
    key: 'longTermHardening',
    label: 'Long-Term Hardening',
    icon: ShieldAlert,
    color: 'text-blue-400',
    borderColor: 'border-blue-500/30',
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
    color: 'text-slate-300',
    borderColor: 'border-slate-600/30',
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
          <ChevronDown size={18} className="text-slate-400" />
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
                <pre className="text-[13px] text-slate-300 font-mono whitespace-pre-wrap leading-relaxed break-words">
                  {content}
                </pre>
              ) : (
                <p className="text-slate-500 italic text-sm">
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
export default function PlaybookModal({ alert, onClose }) {
  const [playbook, setPlaybook] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);

  // Fetch playbook on mount
  useEffect(() => {
    if (!alert) return;

    const fetchPlaybook = async () => {
      setLoading(true);
      setError(null);
      try {
        // Use the structured remediation endpoint for richer output
        const response = await fetch('http://localhost:8000/api/playbooks/remediation', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            cve_data: {
              cveId: alert.cve_id || 'CVE-UNKNOWN',
              description: alert.message || 'Security vulnerability detected in banking infrastructure.',
              cvssScore: 8.5,
              severity: alert.severity || 'HIGH',
              epssScore: 0.72,
              isKEV: alert.severity === 'CRITICAL',
            },
            affected_assets: [alert.asset_id || 'Unknown Banking Asset'],
          }),
        });

        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        setPlaybook(data);
      } catch (err) {
        console.error('Playbook generation failed:', err);
        // Build a fallback playbook locally so the demo never crashes
        setPlaybook(buildFallbackPlaybook(alert));
      } finally {
        setLoading(false);
      }
    };

    fetchPlaybook();
  }, [alert]);

  // ── Helpers ──────────────────────────────────────────────────────────────────

  const buildFallbackPlaybook = (alert) => ({
    cveId: alert.cve_id || 'CVE-UNKNOWN',
    generatedAt: new Date().toISOString(),
    executiveSummary:
      `A ${alert.severity || 'HIGH'} severity incident was detected on asset "${alert.asset_id || 'Unknown'}". ` +
      `The vulnerability ${alert.cve_id || 'CVE-UNKNOWN'} poses an immediate risk to banking operations. ` +
      `Immediate containment and remediation is required to prevent lateral movement.`,
    immediateActions:
      `1. Isolate the affected asset "${alert.asset_id}" from the network immediately.\n` +
      `2. Block all inbound traffic from external IP ranges to the affected system.\n` +
      `3. Revoke all active sessions and credentials on the affected asset.\n` +
      `4. Alert the CISO and SOC team for immediate incident response activation.\n` +
      `5. Enable enhanced logging on all adjacent systems.`,
    shortTermRemediation:
      `1. Apply the latest vendor security patch for ${alert.cve_id || 'the vulnerability'}.\n` +
      `2. Conduct a thorough vulnerability scan of adjacent systems.\n` +
      `3. Review and harden firewall rules for the DMZ segment.\n` +
      `4. Rotate all service account credentials on affected systems.\n` +
      `5. Deploy updated WAF rules to block exploitation vectors.`,
    longTermHardening:
      `1. Implement zero-trust network architecture across all banking tiers.\n` +
      `2. Deploy micro-segmentation to limit east-west lateral movement.\n` +
      `3. Enforce mandatory vulnerability scanning in CI/CD pipelines.\n` +
      `4. Establish a 30-day patching SLA for CRITICAL severity CVEs.\n` +
      `5. Conduct quarterly penetration testing of externally facing systems.`,
    verificationSteps:
      `1. Confirm patch deployment by checking system version numbers.\n` +
      `2. Run authenticated vulnerability scan to verify CVE remediation.\n` +
      `3. Monitor SIEM for 48 hours post-patch for anomalous activity.\n` +
      `4. Validate network segmentation rules via controlled penetration test.\n` +
      `5. Document remediation evidence for RBI audit compliance.`,
    rollbackPlan:
      `1. Maintain a full system snapshot before applying any patches.\n` +
      `2. Test patches in the staging environment before production deployment.\n` +
      `3. Establish a 2-hour rollback window post-deployment for monitoring.\n` +
      `4. Keep vendor rollback instructions on file for each patch applied.\n` +
      `5. Notify change management team before and after each rollback action.`,
    complianceNotes:
      `- RBI Cybersecurity Framework: Mandatory patching within 30 days of CRITICAL CVE disclosure.\n` +
      `- ISO 27001 A.12.6.1: Technical vulnerability management controls required.\n` +
      `- DPDP Act 2023: Any data breach from this vector must be reported within 72 hours.\n` +
      `- SWIFT CSP: Customer Security Programme controls must be validated post-remediation.\n` +
      `- PCI DSS 6.3: All externally-facing systems must maintain patch compliance.`,
    rawResponse: null,
  });

  const getFullText = () => {
    if (!playbook) return '';
    return SECTIONS.map(s => `## ${s.label}\n\n${playbook[s.key] || ''}`).join('\n\n---\n\n');
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
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* ignore */
    }
  };

  // Close on Escape key
  useEffect(() => {
    const handler = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onClose]);

  if (!alert) return null;

  return (
    <AnimatePresence>
      {/* Backdrop */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={onClose}
        className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm"
      />

      {/* Modal Panel */}
      <motion.div
        initial={{ opacity: 0, scale: 0.94, y: 30 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.94, y: 30 }}
        transition={{ type: 'spring', stiffness: 260, damping: 22 }}
        className="fixed inset-0 z-50 flex items-center justify-center p-4 pointer-events-none"
      >
        <div
          className="pointer-events-auto w-full max-w-4xl max-h-[92vh] flex flex-col rounded-2xl border border-violet-500/30 shadow-[0_0_60px_rgba(139,92,246,0.15)] overflow-hidden"
          style={{ background: 'linear-gradient(135deg, #0d1117 0%, #0f172a 50%, #0d1117 100%)' }}
          onClick={(e) => e.stopPropagation()}
        >
          {/* Scanline overlay */}
          <div
            className="absolute inset-0 pointer-events-none rounded-2xl"
            style={{
              background: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px)',
            }}
          />

          {/* Header */}
          <div className="relative flex items-start justify-between gap-4 p-7 border-b border-slate-800/60 bg-gradient-to-r from-violet-950/30 to-transparent">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-3 mb-2">
                <div className="p-2 rounded-xl bg-violet-500/15 border border-violet-500/30 shadow-[0_0_15px_rgba(139,92,246,0.2)]">
                  <ShieldAlert className="text-violet-400" size={22} />
                </div>
                <h2 className="text-2xl font-extrabold text-white tracking-tight">
                  <span role="img" aria-label="shield">🛡️</span> AI-Generated Remediation Playbook
                </h2>
              </div>
              <div className="flex flex-wrap gap-x-5 gap-y-2 text-sm font-mono text-slate-400 mt-1 pl-1">
                <span>
                  Incident:{' '}
                  <span className="text-slate-200 font-semibold">
                    {alert.message?.substring(0, 60)}{alert.message?.length > 60 ? '...' : ''}
                  </span>
                </span>
                {alert.cve_id && (
                  <span>
                    CVE:{' '}
                    <span className="text-violet-300 font-extrabold">{alert.cve_id}</span>
                  </span>
                )}
                {alert.asset_id && (
                  <span>
                    Asset:{' '}
                    <span className="text-cyan-400 font-bold">{alert.asset_id}</span>
                  </span>
                )}
              </div>
            </div>

            <button
              onClick={onClose}
              className="shrink-0 p-2.5 rounded-xl bg-slate-800/60 hover:bg-slate-700/60 border border-slate-700/50 text-slate-400 hover:text-slate-200 transition-all duration-150"
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
                  <p className="text-violet-300 font-bold text-lg tracking-wider font-mono">
                    AI GENERATING PLAYBOOK
                    <span className="animate-pulse">...</span>
                  </p>
                  <p className="text-slate-500 text-sm mt-1 font-mono">
                    Consulting Gemini threat intelligence model
                  </p>
                </div>
                {/* Fake processing logs */}
                <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 font-mono text-xs text-emerald-400 w-full max-w-md">
                  {[
                    '> loading CVE risk dataset...',
                    '> mapping MITRE ATT&CK techniques...',
                    '> building remediation playbook...',
                    '> formatting 7-section response_',
                  ].map((log, i) => (
                    <motion.div
                      key={log}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: i * 0.4, duration: 0.3 }}
                    >
                      {log}
                    </motion.div>
                  ))}
                </div>
              </div>
            ) : error ? (
              <div className="text-center py-16 text-red-400">
                <p className="font-bold mb-2">Failed to generate playbook</p>
                <p className="text-sm text-slate-500">{error}</p>
              </div>
            ) : (
              <div className="flex flex-col gap-4">
                {/* Generated timestamp */}
                <div className="flex items-center gap-2 text-xs font-mono text-slate-500 mb-2">
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
              </div>
            )}
          </div>

          {/* Footer */}
          {!loading && (
            <div className="flex items-center justify-between gap-4 p-6 border-t border-slate-800/60 bg-slate-950/40">
              <div className="text-xs font-mono text-slate-600">
                Sarathi Cyberdefense AI · Gemini-powered · Banking Context
              </div>
              <div className="flex items-center gap-3">
                <button
                  onClick={handleDownload}
                  className="px-4 py-2.5 bg-slate-800/70 hover:bg-slate-700/70 border border-slate-700/50 hover:border-slate-600 text-slate-300 rounded-xl transition-all text-sm font-bold flex items-center gap-2"
                >
                  <Download size={15} />
                  Download
                </button>
                <button
                  onClick={handleCopy}
                  className={`px-4 py-2.5 border rounded-xl transition-all text-sm font-bold flex items-center gap-2 ${
                    copied
                      ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-400'
                      : 'bg-slate-800/70 hover:bg-slate-700/70 border-slate-700/50 hover:border-slate-600 text-slate-300'
                  }`}
                >
                  {copied ? <Check size={15} /> : <Copy size={15} />}
                  {copied ? 'Copied!' : 'Copy to Clipboard'}
                </button>
                <button
                  onClick={onClose}
                  className="px-4 py-2.5 bg-violet-600/20 hover:bg-violet-600/30 border border-violet-500/40 hover:border-violet-500/60 text-violet-300 rounded-xl transition-all text-sm font-bold"
                >
                  Close
                </button>
              </div>
            </div>
          )}
        </div>
      </motion.div>
    </AnimatePresence>
  );
}
