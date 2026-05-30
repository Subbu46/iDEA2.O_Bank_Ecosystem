import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  BookOpen,
  ShieldAlert,
  Download,
  Copy,
  Check,
  FileText,
  AlertCircle,
  Server,
  TrendingUp,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  ChevronLeft,
  ChevronRight,
  Cpu,
  RefreshCw,
  Clock,
  Layers,
  ShieldCheck
} from 'lucide-react';
import client, { graphApi, playbooksApi } from '../api/client';

export default function PlaybookViewer({ selectedItem, type }) {
  const location = useLocation();
  // Navigation Tabs
  const [activeTab, setActiveTab] = useState('remediation'); // 'remediation', 'rca', 'policy'

  // States for Left Column (Top Risks)
  const [topRisks, setTopRisks] = useState([]);
  const [selectedCve, setSelectedCve] = useState(null);
  const [risksLoading, setRisksLoading] = useState(false);
  const [leftPanelCollapsed, setLeftPanelCollapsed] = useState(false);

  // States for Remediation Playbook Tab
  const [remediationPlaybook, setRemediationPlaybook] = useState(null);
  const [remLoading, setRemLoading] = useState(false);
  const [expandedSections, setExpandedSections] = useState({
    executiveSummary: true,
    immediateActions: true,
    shortTermRemediation: false,
    longTermHardening: false,
    verificationSteps: false,
    rollbackPlan: false,
    complianceNotes: false,
  });

  // States for RCA Tab
  const [rcaForm, setRcaForm] = useState({
    incidentId: '',
    attackType: 'Lateral Movement',
    affectedAssets: 'Asset_1, Asset_4',
    attackVector: 'CVE-2026-1043 Exploit',
    detectionTime: '12 minutes',
  });
  const [rcaReport, setRcaReport] = useState(null);
  const [rcaLoading, setRcaLoading] = useState(false);



  // Global UI states
  const [copied, setCopied] = useState(false);

  // Auto-generate Incident ID
  useEffect(() => {
    const randomId = `INC-${Math.floor(100000 + Math.random() * 900000)}`;
    setRcaForm(prev => ({ ...prev, incidentId: randomId }));
  }, []);

  // Fetch Top Risks for Left Panel
  const fetchTopRisks = () => {
    setRisksLoading(true);
    graphApi.getTopRisks(100)
      .then(data => {
        let updatedRisks = [...data];

        // If we have a redirected CVE, make sure it is in the list
        const redirectedId = location.state?.selectedCveId;
        if (redirectedId) {
          const exists = updatedRisks.some(r => r.cveId === redirectedId);
          if (!exists) {
            const redirCve = location.state.cve || {
              cveId: redirectedId,
              assetName: 'Affected Host System',
              severity: 'HIGH',
              cvssScore: 8.0,
              explanation: 'Vulnerability selected from Home Page.'
            };
            updatedRisks = [redirCve, ...updatedRisks];
          }
        }

        setTopRisks(updatedRisks);

        // Auto-select redirected CVE or fallback
        if (redirectedId) {
          const found = updatedRisks.find(r => r.cveId === redirectedId);
          if (found) {
            setSelectedCve(found);
          }
        } else if (data && data.length > 0 && !selectedCve) {
          setSelectedCve(data[0]);
        }
        setRisksLoading(false);
      })
      .catch(err => {
        console.error("Failed to load top risks:", err);
        setRisksLoading(false);
      });
  };

  useEffect(() => {
    fetchTopRisks();
  }, [location.state?.selectedCveId]);

  // Sync redirected CVE if state changes while mounted
  useEffect(() => {
    if (location.state?.selectedCveId) {
      const redirectedId = location.state.selectedCveId;
      const found = topRisks.find(r => r.cveId === redirectedId);
      if (found) {
        setSelectedCve(found);
      }
    }
  }, [location.state?.selectedCveId, topRisks]);

  // If a selectedItem is passed (from App.jsx, though standard routing won't have it, DigitalTwin or KnowledgeGraph might pass it)
  useEffect(() => {
    if (selectedItem) {
      if (type === 'alert') {
        const mockCve = {
          cveId: selectedItem.cve_id || 'CVE-2026-1043',
          assetId: selectedItem.asset_id || 'Asset_1',
          assetName: 'Affected Host System',
          severity: selectedItem.severity || 'HIGH',
          cvssScore: selectedItem.severity === 'CRITICAL' ? 9.8 : 7.5,
          explanation: selectedItem.message || 'Intrusion Alert Mapped CVE'
        };
        setSelectedCve(mockCve);
      } else {
        // node properties
        const props = selectedItem.properties || {};
        const mockCve = {
          cveId: props.cve_id || 'CVE-2026-1043',
          assetId: selectedItem.id || 'Asset_1',
          assetName: props.name || selectedItem.name || 'Graph Node Host',
          severity: props.severity || 'HIGH',
          cvssScore: props.cvss_score || 8.0,
          explanation: props.description || 'Knowledge Graph Node Vulnerability'
        };
        setSelectedCve(mockCve);
      }
    }
  }, [selectedItem, type]);

  // Trigger Remediation Playbook Generation
  const generateRemediation = (cve) => {
    if (!cve) return;
    const cveId = cve.cveId || cve.cve_id || 'CVE-2026-1043';

    // Check local cache first
    const cacheKey = `playbook_cache_v2_${cveId}`;
    const cached = localStorage.getItem(cacheKey);
    if (cached) {
      try {
        setRemediationPlaybook(JSON.parse(cached));
        setRemLoading(false);
        return;
      } catch (e) {
        console.error("Failed to parse cached playbook:", e);
      }
    }

    setRemLoading(true);
    setRemediationPlaybook(null);

    const payload = {
      cve_data: {
        cveId: cveId,
        description: cve.explanation || cve.description || 'RCE in application interface.',
        cvssScore: cve.cvssScore || cve.cvss_score || 8.5,
        severity: cve.severity || 'HIGH',
        epssScore: cve.epssScore || 0.85,
        isKEV: cve.isKEV || false,
      },
      affected_assets: [cve.assetName || cve.assetId || 'Asset_1']
    };

    playbooksApi.generateRemediationPlaybook(payload)
      .then(res => {
        localStorage.setItem(cacheKey, JSON.stringify(res));
        setRemediationPlaybook(res);
        setRemLoading(false);
      })
      .catch(err => {
        console.error("Playbook generation failed:", err);
        setRemLoading(false);
      });
  };

  // Trigger RCA Report Generation
  const handleGenerateRca = (e) => {
    if (e) e.preventDefault();
    setRcaLoading(true);
    setRcaReport(null);

    const payload = {
      incidentId: rcaForm.incidentId,
      attackType: rcaForm.attackType,
      affectedAssets: rcaForm.affectedAssets.split(',').map(s => s.trim()),
      attackVector: rcaForm.attackVector,
      timestamp: new Date().toISOString(),
      detectionTime: rcaForm.detectionTime,
    };

    playbooksApi.generateRca(payload)
      .then(res => {
        setRcaReport(res.rca_report);
        setRcaLoading(false);
      })
      .catch(err => {
        console.error("RCA generation failed:", err);
        setRcaLoading(false);
      });
  };

  // Auto trigger on selected CVE change
  useEffect(() => {
    if (selectedCve) {
      if (activeTab === 'remediation') {
        generateRemediation(selectedCve);
      }
    }
  }, [selectedCve, activeTab]);

  const toggleSection = (section) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  const handleCopy = (text) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = (filename, content) => {
    const element = document.createElement("a");
    const file = new Blob([content], { type: 'text/plain' });
    element.href = URL.createObjectURL(file);
    element.download = filename;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  const getRemediationMarkdown = () => {
    if (!remediationPlaybook) return '';
    return `# MITIGATION PLAYBOOK: ${remediationPlaybook.cveId}
Generated At: ${remediationPlaybook.generatedAt}

## 1. EXECUTIVE SUMMARY
${remediationPlaybook.executiveSummary}

## 2. IMMEDIATE ACTIONS
${remediationPlaybook.immediateActions}

## 3. SHORT-TERM REMEDIATION
${remediationPlaybook.shortTermRemediation}

## 4. LONG-TERM HARDENING
${remediationPlaybook.longTermHardening}

## 5. VERIFICATION STEPS
${remediationPlaybook.verificationSteps}

## 6. ROLLBACK PLAN
${remediationPlaybook.rollbackPlan}

## 7. COMPLIANCE NOTES
${remediationPlaybook.complianceNotes}
`;
  };

  const getRcaMarkdown = () => {
    if (!rcaReport) return '';
    return `# ROOT CAUSE ANALYSIS (RCA): ${rcaReport.incidentId}
Attack Type: ${rcaForm.attackType}
Vector: ${rcaForm.attackVector}

## 1. EXECUTIVE SUMMARY
${rcaReport.executiveSummary}

## 2. TIMELINE
${rcaReport.timeline}

## 3. ROOT CAUSE
${rcaReport.rootCause}

## 4. CONTRIBUTING FACTORS
${rcaReport.contributingFactors}

## 5. IMMEDIATE IMPACT
${rcaReport.immediateImpact}

## 6. LESSON LEARNED
${rcaReport.lessonLearned}

## 7. PREVENTION MEASURES
${rcaReport.preventionMeasures}
`;
  };

  return (
    <div className="flex flex-col gap-8 w-full max-w-[92rem] mx-auto pb-12">
      {/* Header Banner */}
      <div className="flex justify-between items-center border-b border-slate-200 dark:border-slate-800 pb-6">
        <div>
          <h2 className="text-3xl font-extrabold tracking-tight text-white flex items-center gap-4">
            <BookOpen className="text-cyan-500" size={32} />
            GenAI Incident Response & Playbooks
          </h2>
          <p className="text-sm text-slate-500 dark:text-slate-600 dark:text-slate-400 mt-2">
            Automated compliance orchestrator & technical directives powered by Gemini 1.5 Pro
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* Left Column: Top Risk Vulnerabilities */}
        {!leftPanelCollapsed && (
          <div className="lg:col-span-4 flex flex-col gap-6">
            <div className="bg-white/95 dark:bg-[#0f172a]/95 backdrop-blur border border-slate-750 rounded-xl p-6 shadow-2xl flex flex-col gap-4">
              <div className="flex justify-between items-center border-b border-slate-200 dark:border-slate-800 pb-3">
                <h3 className="text-sm font-bold uppercase tracking-wider text-slate-500 dark:text-slate-600 dark:text-slate-400 flex items-center gap-2">
                  <ShieldAlert className="text-rose-500" size={16} />
                  All Vulnerabilities
                </h3>
                <div className="flex items-center gap-1.5">
                  <button
                    onClick={fetchTopRisks}
                    className="p-1.5 hover:bg-slate-100 dark:hover:bg-slate-800 rounded text-slate-500 dark:text-slate-600 dark:text-slate-400 hover:text-white transition-all"
                    title="Refresh Risks"
                  >
                    <RefreshCw size={14} className={risksLoading ? 'animate-spin' : ''} />
                  </button>
                  <button
                    onClick={() => setLeftPanelCollapsed(true)}
                    className="p-1.5 hover:bg-slate-100 dark:hover:bg-slate-800 rounded text-slate-500 dark:text-slate-600 dark:text-slate-400 hover:text-white transition-all"
                    title="Close Side Panel"
                  >
                    <ChevronLeft size={16} />
                  </button>
                </div>
              </div>

              {risksLoading ? (
                <div className="py-20 flex flex-col items-center justify-center gap-3">
                  <div className="w-5 h-5 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin"></div>
                  <span className="text-[10px] text-slate-500 dark:text-slate-500 tracking-wider font-mono">LOADING RISKS...</span>
                </div>
              ) : (
                <div className="flex flex-col gap-3 max-h-[600px] overflow-y-auto custom-scrollbar">
                  {topRisks.map((risk, idx) => {
                    const isSelected = selectedCve && (selectedCve.cveId === risk.cveId || selectedCve.cve_id === risk.cveId);
                    return (
                      <motion.div
                        whileHover={{ scale: 1.01 }}
                        key={risk.cveId || idx}
                        onClick={() => setSelectedCve(risk)}
                        className={`p-4 rounded-xl border transition-all duration-200 cursor-pointer flex flex-col gap-2.5 ${isSelected
                            ? 'bg-cyan-100 dark:bg-cyan-500/10 border-cyan-500/50 shadow-[0_0_10px_rgba(6,182,212,0.1)]'
                            : 'bg-slate-900/40 border-slate-200 dark:border-slate-800/60 hover:border-slate-300 dark:hover:border-slate-700'
                          }`}
                      >
                        <div className="flex justify-between items-center">
                          <span className="text-sm font-bold font-mono text-slate-800 dark:text-slate-200">{risk.cveId}</span>
                          <span className={`text-[10px] font-black px-2 py-0.5 rounded ${risk.riskLevel === 'CRITICAL' || risk.severity === 'CRITICAL' ? 'bg-red-100 dark:bg-red-500/20 text-red-600 dark:text-red-400 border border-red-500/30' :
                              risk.riskLevel === 'HIGH' || risk.severity === 'HIGH' ? 'bg-amber-100 dark:bg-amber-500/20 text-amber-600 dark:text-amber-400 border border-amber-500/30' :
                                'bg-blue-100 dark:bg-blue-500/20 text-blue-600 dark:text-blue-400 border border-blue-300 dark:border-blue-500/30'
                            }`}>
                            {risk.riskLevel || risk.severity || 'HIGH'}
                          </span>
                        </div>
                        <p className="text-xs text-slate-500 dark:text-slate-600 dark:text-slate-400 line-clamp-2 leading-relaxed">
                          {risk.explanation || risk.description || 'Exploitation risk linked to critical bank interfaces.'}
                        </p>
                        <div className="flex justify-between items-center mt-1 pt-2 border-t border-slate-200 dark:border-slate-800/60 text-[11px] font-mono text-slate-500 dark:text-slate-500">
                          <span className="flex items-center gap-1.5">
                            <Server size={12} className="text-cyan-600 dark:text-cyan-400" />
                            {risk.assetName || risk.assetId || 'Asset_1'}
                          </span>
                          <span className="flex items-center gap-1 font-bold">
                            CVSS: <span className="text-slate-700 dark:text-slate-300">{risk.cvssScore || risk.cvss_score || 'N/A'}</span>
                          </span>
                        </div>
                      </motion.div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Right Column: Tabbed Playbook Panel */}
        <div className={leftPanelCollapsed ? "lg:col-span-12 flex flex-col gap-6" : "lg:col-span-8 flex flex-col gap-6"}>
          {/* Navigation Segments */}
          <div className="bg-slate-950 p-1.5 rounded-xl border border-slate-200 dark:border-slate-800 flex gap-2 items-center">
            {leftPanelCollapsed && (
              <button
                onClick={() => setLeftPanelCollapsed(false)}
                className="px-3.5 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 rounded-lg text-cyan-600 dark:text-cyan-400 hover:text-cyan-300 transition-all flex items-center gap-1.5 shrink-0"
                title="Show Risks Panel"
              >
                <ChevronRight size={16} />
                <span className="text-xs font-bold uppercase tracking-wider">Show Risks</span>
              </button>
            )}
            <button
              onClick={() => setActiveTab('remediation')}
              className={`flex-1 py-3 text-sm font-bold rounded-lg uppercase tracking-wider transition-all duration-200 ${activeTab === 'remediation'
                  ? 'bg-cyan-100 dark:bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border border-cyan-500/30 shadow-[0_0_10px_rgba(6,182,212,0.1)]'
                  : 'text-slate-500 dark:text-slate-600 dark:text-slate-400 hover:text-slate-200'
                }`}
            >
              Remediation Playbook
            </button>
            <button
              onClick={() => setActiveTab('rca')}
              className={`flex-1 py-3 text-sm font-bold rounded-lg uppercase tracking-wider transition-all duration-200 ${activeTab === 'rca'
                  ? 'bg-cyan-100 dark:bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border border-cyan-500/30 shadow-[0_0_10px_rgba(6,182,212,0.1)]'
                  : 'text-slate-500 dark:text-slate-600 dark:text-slate-400 hover:text-slate-200'
                }`}
            >
              Root Cause Analysis (RCA)
            </button>
          </div>

          {/* Active Tab Panel */}
          <div className="bg-white/95 dark:bg-[#0f172a]/95 backdrop-blur border border-slate-750 rounded-xl p-7 shadow-2xl min-h-[600px]">
            <AnimatePresence mode="wait">
              {activeTab === 'remediation' && (
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  transition={{ duration: 0.2 }}
                  className="flex flex-col gap-4"
                  key="remediation-tab"
                >
                  <div className="flex justify-between items-center border-b border-slate-200 dark:border-slate-800 pb-4">
                    <div>
                      <h3 className="text-base font-bold text-white uppercase tracking-wide">
                        Remediation Directives: {selectedCve?.cveId || 'CVE-2026-1043'}
                      </h3>
                      <p className="text-xs text-slate-500 dark:text-slate-600 dark:text-slate-400 mt-1">
                        Rigorous RBI compliance & technical rollback strategy
                      </p>
                    </div>

                    {remediationPlaybook && (
                      <div className="flex gap-2">
                        <button
                          onClick={() => handleCopy(getRemediationMarkdown())}
                          className="px-3.5 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 text-slate-700 dark:text-slate-300 hover:text-white rounded-lg text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 transition-all"
                        >
                          {copied ? <Check size={14} className="text-green-400" /> : <Copy size={14} />}
                          {copied ? 'Copied' : 'Copy'}
                        </button>
                        <button
                          onClick={() => handleDownload(`${selectedCve?.cveId || 'CVE-2026-1043'}_Playbook.md`, getRemediationMarkdown())}
                          className="px-3.5 py-2 bg-cyan-100 dark:bg-cyan-500/10 hover:bg-cyan-200 dark:hover:bg-cyan-500/20 border border-cyan-200 dark:border-cyan-500/20 hover:border-cyan-500/40 text-cyan-600 dark:text-cyan-400 rounded-lg text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 transition-all"
                        >
                          <Download size={14} />
                          Download
                        </button>
                      </div>
                    )}
                  </div>

                  {remLoading ? (
                    <div className="py-32 flex flex-col items-center justify-center gap-4">
                      <div className="w-8 h-8 border-3 border-cyan-500 border-t-transparent rounded-full animate-spin"></div>
                      <div className="text-center">
                        <p className="text-xs text-slate-700 dark:text-slate-300 font-bold uppercase tracking-widest animate-pulse">
                          Gemini 1.5 Pro Orchestrating Remediation
                        </p>
                        <p className="text-[10px] text-slate-500 dark:text-slate-500 mt-1">
                          Drafting technical rollback sequences, RBI alignments, and network isolates...
                        </p>
                      </div>
                    </div>
                  ) : remediationPlaybook ? (
                    <div className="flex flex-col gap-4">
                      <div className="border border-slate-800/80 rounded-xl overflow-hidden bg-slate-50 dark:bg-slate-950/20">
                        <div className="p-6 text-[15px] md:text-base leading-relaxed text-slate-900 dark:text-slate-100 font-medium bg-white dark:bg-slate-950/70">
                          {(!remediationPlaybook.executiveSummary && !remediationPlaybook.containment) ? (
                            <div className="whitespace-pre-wrap">{remediationPlaybook.rawResponse}</div>
                          ) : (
                            [
                              { key: 'executiveSummary', label: '1. Executive Summary', icon: ShieldCheck, color: 'text-cyan-600 dark:text-cyan-400', borderStyle: 'border-cyan-300 dark:border-cyan-500/40' },
                              { key: 'validation', label: '2. Validation: Is this real?', icon: AlertCircle, color: 'text-rose-400', borderStyle: 'border-rose-500/40' },
                              { key: 'containment', label: '3. Containment: Stop the threat', icon: Server, color: 'text-amber-600 dark:text-amber-400', borderStyle: 'border-amber-300 dark:border-amber-500/40' },
                              { key: 'eradicationRemediation', label: '4. Eradication & Remediation', icon: Layers, color: 'text-blue-600 dark:text-blue-400', borderStyle: 'border-blue-500/40' },
                              { key: 'postIncidentHunting', label: '5. Post-Incident Hunting', icon: ShieldAlert, color: 'text-emerald-400', borderStyle: 'border-emerald-500/40' },
                            ].map((section, idx, arr) => {
                              const content = remediationPlaybook[section.key];
                              if (!content) return null;
                              return (
                                <div key={section.key}>
                                  <div className="mb-4">
                                    <h4 className={`text-lg font-bold flex items-center gap-2 ${section.color} mb-3`}>
                                      <section.icon size={22} />
                                      {section.label}
                                    </h4>
                                    <div className="mt-1 whitespace-pre-wrap text-slate-700 dark:text-slate-300">{content}</div>
                                  </div>
                                  {idx < arr.length - 1 && (
                                    <div className={`w-full border-b-[2px] ${section.borderStyle} my-8`}></div>
                                  )}
                                </div>
                              );
                            })
                          )}
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="py-24 text-center text-slate-500 dark:text-slate-500 flex flex-col items-center gap-2">
                      <span><span role="img" aria-label="shield">🛡️</span></span>
                      <p className="text-xs">Select a top-risk CVE on the left to review its mitigation playbook.</p>
                    </div>
                  )}
                </motion.div>
              )}

              {activeTab === 'rca' && (
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  transition={{ duration: 0.2 }}
                  className="flex flex-col gap-5"
                  key="rca-tab"
                >
                  <div className="border-b border-slate-200 dark:border-slate-800 pb-4 flex justify-between items-center">
                    <div>
                      <h3 className="text-base font-bold text-white uppercase tracking-wide">
                        Incident Forensic Root Cause Analysis (RCA)
                      </h3>
                      <p className="text-xs text-slate-500 dark:text-slate-600 dark:text-slate-400 mt-1">
                        Generate regulator-ready RCA reports mapped to ISO 27001 & CERT-In requirements
                      </p>
                    </div>

                    {rcaReport && (
                      <div className="flex gap-2">
                        <button
                          onClick={() => handleCopy(getRcaMarkdown())}
                          className="px-3.5 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 text-slate-700 dark:text-slate-300 hover:text-white rounded-lg text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 transition-all"
                        >
                          {copied ? <Check size={14} className="text-green-400" /> : <Copy size={14} />}
                          {copied ? 'Copied' : 'Copy'}
                        </button>
                        <button
                          onClick={() => handleDownload(`${rcaForm.incidentId}_RCA.md`, getRcaMarkdown())}
                          className="px-3.5 py-2 bg-cyan-100 dark:bg-cyan-500/10 hover:bg-cyan-200 dark:hover:bg-cyan-500/20 border border-cyan-200 dark:border-cyan-500/20 hover:border-cyan-500/40 text-cyan-600 dark:text-cyan-400 rounded-lg text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 transition-all"
                        >
                          <Download size={14} />
                          Download
                        </button>
                      </div>
                    )}
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {/* Left Column Form */}
                    <form onSubmit={handleGenerateRca} className="flex flex-col gap-5 bg-slate-950/40 p-7 rounded-xl border border-slate-800/80">
                      <h4 className="text-base font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider border-b border-slate-900 pb-2.5">
                        Forensic Parameters
                      </h4>

                      <div className="flex flex-col gap-2">
                        <label className="text-[12px] font-bold uppercase text-slate-500 dark:text-slate-600 dark:text-slate-400 font-mono">Incident Identifier</label>
                        <input
                          type="text"
                          required
                          value={rcaForm.incidentId}
                          onChange={(e) => setRcaForm(prev => ({ ...prev, incidentId: e.target.value }))}
                          className="px-4 py-3 bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg text-[15px] font-mono text-slate-800 dark:text-slate-200 focus:outline-none focus:border-cyan-500 transition-all"
                        />
                      </div>

                      <div className="flex flex-col gap-2">
                        <label className="text-[12px] font-bold uppercase text-slate-500 dark:text-slate-600 dark:text-slate-400 font-mono">Attack Class / Scenario</label>
                        <select
                          value={rcaForm.attackType}
                          onChange={(e) => setRcaForm(prev => ({ ...prev, attackType: e.target.value }))}
                          className="px-4 py-3 bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg text-[15px] text-slate-800 dark:text-slate-200 focus:outline-none focus:border-cyan-500 transition-all"
                        >
                          <option value="Lateral Movement">DMZ to Core Banking Lateral Movement</option>
                          <option value="Credential Stuffing">IAM Infrastructure Credential Stuffing</option>
                          <option value="SWIFT Gateway Compromise">SWIFT Gateway Exploitation</option>
                          <option value="Ransomware Propagation">Network-wide Ransomware Propagation</option>
                          <option value="Insider Abuse">Privileged Insider Abuse</option>
                        </select>
                      </div>

                      <div className="flex flex-col gap-2">
                        <label className="text-[12px] font-bold uppercase text-slate-500 dark:text-slate-600 dark:text-slate-400 font-mono">Affected Asset Keys (comma separated)</label>
                        <input
                          type="text"
                          required
                          value={rcaForm.affectedAssets}
                          onChange={(e) => setRcaForm(prev => ({ ...prev, affectedAssets: e.target.value }))}
                          className="px-4 py-3 bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg text-[15px] font-mono text-slate-800 dark:text-slate-200 focus:outline-none focus:border-cyan-500 transition-all"
                        />
                      </div>

                      <div className="flex flex-col gap-2">
                        <label className="text-[12px] font-bold uppercase text-slate-500 dark:text-slate-600 dark:text-slate-400 font-mono">Primary Intrusion Vector</label>
                        <input
                          type="text"
                          required
                          value={rcaForm.attackVector}
                          onChange={(e) => setRcaForm(prev => ({ ...prev, attackVector: e.target.value }))}
                          className="px-4 py-3 bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg text-[15px] font-mono text-slate-800 dark:text-slate-200 focus:outline-none focus:border-cyan-500 transition-all"
                        />
                      </div>

                      <div className="flex flex-col gap-2">
                        <label className="text-[12px] font-bold uppercase text-slate-500 dark:text-slate-600 dark:text-slate-400 font-mono">Detection Latency Gap</label>
                        <input
                          type="text"
                          required
                          value={rcaForm.detectionTime}
                          onChange={(e) => setRcaForm(prev => ({ ...prev, detectionTime: e.target.value }))}
                          className="px-4 py-3 bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg text-[15px] font-mono text-slate-800 dark:text-slate-200 focus:outline-none focus:border-cyan-500 transition-all"
                        />
                      </div>

                      <button
                        type="submit"
                        disabled={rcaLoading}
                        className="mt-3 py-3 bg-cyan-500 hover:bg-cyan-600 disabled:bg-cyan-500/20 text-slate-950 disabled:text-slate-500 font-extrabold rounded-lg text-sm tracking-wider uppercase transition-all shadow-[0_0_15px_rgba(6,182,212,0.15)] flex items-center justify-center gap-2"
                      >
                        {rcaLoading ? <RefreshCw size={14} className="animate-spin" /> : 'Orchestrate RCA Analysis'}
                      </button>
                    </form>

                    {/* Right Column Output */}
                    <div className="bg-slate-50 dark:bg-slate-950/20 border border-slate-200 dark:border-slate-800 rounded-xl p-6 flex flex-col min-h-[400px] relative max-h-[550px] overflow-y-auto custom-scrollbar">
                      {rcaLoading ? (
                        <div className="absolute inset-0 flex flex-col items-center justify-center gap-4 bg-slate-950/80 rounded-xl">
                          <div className="w-7 h-7 border-3 border-cyan-500 border-t-transparent rounded-full animate-spin"></div>
                          <div className="text-center px-4">
                            <p className="text-xs text-slate-700 dark:text-slate-300 font-bold uppercase tracking-widest animate-pulse">
                              Gemini Reconstructing Intrusion Chain
                            </p>
                            <p className="text-[9px] text-slate-500 dark:text-slate-500 mt-1">
                              Processing security logs, mapping lateral hops, and aligning regulatory compliance timelines...
                            </p>
                          </div>
                        </div>
                      ) : rcaReport ? (
                        <div className="flex flex-col gap-4">
                          {[
                            { title: 'Executive Summary', content: rcaReport.executiveSummary, color: 'text-cyan-600 dark:text-cyan-400' },
                            { title: 'Intrusion Timeline', content: rcaReport.timeline, color: 'text-rose-400' },
                            { title: 'Root Cause', content: rcaReport.rootCause, color: 'text-amber-600 dark:text-amber-400' },
                            { title: 'Contributing Factors', content: rcaReport.contributingFactors, color: 'text-blue-600 dark:text-blue-400' },
                            { title: 'Immediate Business Impact', content: rcaReport.immediateImpact, color: 'text-purple-400' },
                            { title: 'Lessons Learned', content: rcaReport.lessonLearned, color: 'text-emerald-400' },
                            { title: 'Prevention & Compliance Measures', content: rcaReport.preventionMeasures, color: 'text-slate-500 dark:text-slate-600 dark:text-slate-400' },
                          ].map((sec, idx) => (
                            <div key={idx} className="flex flex-col gap-2 text-sm">
                              <span className={`font-extrabold uppercase tracking-wider ${sec.color}`}>{sec.title}</span>
                              <p className="text-[15px] leading-relaxed text-slate-900 dark:text-slate-100 font-medium bg-white dark:bg-slate-950/70 p-4 rounded-lg border border-slate-900 whitespace-pre-wrap">
                                {sec.content}
                              </p>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="m-auto text-center text-slate-500 dark:text-slate-500 flex flex-col items-center gap-2">
                          <span>📊</span>
                          <p className="text-xs">Adjust incident parameters and trigger root cause calculation.</p>
                        </div>
                      )}
                    </div>
                  </div>
                </motion.div>
              )}


            </AnimatePresence>
          </div>
        </div>
      </div>
    </div>
  );
}
