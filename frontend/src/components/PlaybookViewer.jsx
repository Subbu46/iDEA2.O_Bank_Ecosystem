import React, { useState, useEffect } from 'react';
import { playbooksApi } from '../api/client';

export default function PlaybookViewer({ selectedItem, type }) {
  const [playbookContent, setPlaybookContent] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!selectedItem) {
      setPlaybookContent('');
      return;
    }

    setLoading(true);
    setPlaybookContent('');

    if (type === 'alert') {
      // Generate standard Playbook for the alert vulnerability configuration
      playbooksApi.generatePlaybook({
        cve_id: selectedItem.cve_id || 'CVE-2026-1043',
        asset_name: selectedItem.asset_id || 'Web Gateway Server',
        technique_name: selectedItem.technique_id || 'T1190 Exploit Public-Facing App'
      })
      .then(res => {
        setPlaybookContent(res.playbook);
        setLoading(false);
      })
      .catch(() => {
        setPlaybookContent('Failed to fetch playbook.');
        setLoading(false);
      });
    } else {
      // Node details
      const nodeProps = selectedItem.properties || {};
      playbooksApi.generatePlaybook({
        cve_id: nodeProps.cve_id || 'CVE-2026-1043',
        asset_name: nodeProps.name || selectedItem.name || 'System Gateway',
        technique_name: nodeProps.technique_id || 'T1190'
      })
      .then(res => {
        setPlaybookContent(res.playbook);
        setLoading(false);
      })
      .catch(() => {
        setPlaybookContent('Failed to fetch playbook.');
        setLoading(false);
      });
    }
  }, [selectedItem, type]);

  const handleCopy = () => {
    navigator.clipboard.writeText(playbookContent);
  };

  return (
    <div className="glass-panel rounded-xl flex flex-col h-[320px]">
      <div className="px-4 py-3 border-b border-cyber-border bg-slate-900/40 flex justify-between items-center">
        <div>
          <h2 className="text-xs font-bold uppercase tracking-wider text-slate-400">🛡️ GenAI Incident Response Playbook</h2>
          <p className="text-[10px] text-slate-500">Custom containment and remediation orchestrator</p>
        </div>
        {playbookContent && !loading && (
          <button
            onClick={handleCopy}
            className="px-2 py-0.5 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/20 hover:border-cyan-500/40 text-cyan-400 rounded transition-all text-[9px] font-bold"
          >
            COPY PLAYBOOK
          </button>
        )}
      </div>

      <div className="flex-1 p-4 overflow-y-auto min-h-[150px]">
        {!selectedItem ? (
          <div className="h-full flex flex-col items-center justify-center text-slate-500 text-xs gap-1.5 py-6">
            <span>🧙‍♂️</span>
            <span>Select an active alert or graph node to generate a response playbook.</span>
          </div>
        ) : loading ? (
          <div className="h-full flex flex-col items-center justify-center gap-3">
            <div className="w-6 h-6 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin"></div>
            <span className="text-[10px] text-slate-400 font-semibold uppercase tracking-widest animate-pulse">
              Gemini drafting security directives...
            </span>
          </div>
        ) : (
          <div className="text-xs leading-relaxed text-slate-300 font-mono whitespace-pre-wrap">
            {playbookContent}
          </div>
        )}
      </div>
    </div>
  );
}
