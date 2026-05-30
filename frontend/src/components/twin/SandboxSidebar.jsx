import React, { useState, useEffect } from 'react';
import { SCENARIOS } from './twinData';
import { Play, Shield, Target, BookOpen, CheckCircle } from 'lucide-react';

export default function SandboxSidebar({
  simState,
  selectedScenario,
  onSelectScenario,
  onStartSim,
  onResetSim,
  onStartPlaybook,
}) {
  const [activeTab, setActiveTab] = useState('simulation'); // 'simulation' or 'playbooks'
  const [cachedPlaybooks, setCachedPlaybooks] = useState([]);
  const [selectedPlaybook, setSelectedPlaybook] = useState(null);

  // Fetch playbooks from localStorage
  useEffect(() => {
    const playbooks = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && key.startsWith('playbook_cache_v2_')) {
        try {
          const pb = JSON.parse(localStorage.getItem(key));
          if (pb) {
            playbooks.push({ cveId: key.replace('playbook_cache_v2_', ''), data: pb });
          }
        } catch (e) {
          console.warn('Could not parse playbook from cache', key);
        }
      }
    }
    setCachedPlaybooks(playbooks);
  }, [activeTab]); // Refresh when tab changes

  const isRunning = simState === 'running' || simState === 'breach' || simState === 'remediating';

  return (
    <div className="twin-sidebar-left" style={{ width: 340, padding: 0, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>

      {/* ── Toggle Header ── */}
      <div style={{ padding: '20px', background: 'rgba(5, 13, 24, 0.95)', borderBottom: '1px solid rgba(6, 182, 212, 0.2)' }}>
        <h2 style={{ fontSize: 16, fontWeight: 800, color: '#fff', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
          <Target size={18} className="text-cyan-400" />
          Digital Twin Sandbox
        </h2>

        <div style={{ display: 'flex', background: 'rgba(0,0,0,0.4)', borderRadius: 8, padding: 4, border: '1px solid rgba(255,255,255,0.05)' }}>
          <button
            onClick={() => setActiveTab('simulation')}
            style={{
              flex: 1, padding: '8px 0', fontSize: 11, fontWeight: 800, borderRadius: 6, textTransform: 'uppercase', letterSpacing: 0.5,
              background: activeTab === 'simulation' ? 'rgba(239, 68, 68, 0.15)' : 'transparent',
              color: activeTab === 'simulation' ? '#f87171' : '#64748b',
              border: activeTab === 'simulation' ? '1px solid rgba(239, 68, 68, 0.3)' : '1px solid transparent',
              transition: 'all 0.2s'
            }}
          >
            Red Team
          </button>
          <button
            onClick={() => setActiveTab('playbooks')}
            style={{
              flex: 1, padding: '8px 0', fontSize: 11, fontWeight: 800, borderRadius: 6, textTransform: 'uppercase', letterSpacing: 0.5,
              background: activeTab === 'playbooks' ? 'rgba(16, 185, 129, 0.15)' : 'transparent',
              color: activeTab === 'playbooks' ? '#34d399' : '#64748b',
              border: activeTab === 'playbooks' ? '1px solid rgba(16, 185, 129, 0.3)' : '1px solid transparent',
              transition: 'all 0.2s'
            }}
          >
            Test Playbooks
          </button>
        </div>
      </div>

      {/* ── Tab Content ── */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '20px', display: 'flex', flexDirection: 'column', gap: 16 }}>

        {activeTab === 'simulation' && (
          <>
            <div style={{ fontSize: 11, color: '#94a3b8', fontWeight: 600, marginBottom: -4 }}>SELECT SCENARIO</div>
            {Object.entries(SCENARIOS).map(([id, s]) => (
              <div
                key={id}
                onClick={() => { if (!isRunning) onSelectScenario(id) }}
                style={{
                  padding: 14, borderRadius: 12, cursor: isRunning ? 'not-allowed' : 'pointer',
                  background: selectedScenario === id ? 'rgba(239, 68, 68, 0.08)' : 'rgba(15, 23, 42, 0.6)',
                  border: selectedScenario === id ? '1px solid rgba(239, 68, 68, 0.4)' : '1px solid rgba(30, 41, 59, 0.8)',
                  transition: 'all 0.2s'
                }}
              >
                <div style={{ fontSize: 13, fontWeight: 700, color: selectedScenario === id ? '#f87171' : '#e2e8f0', marginBottom: 4 }}>
                  {s.name}
                </div>
                <div style={{ fontSize: 11, color: '#94a3b8', marginBottom: 8, lineHeight: 1.4 }}>
                  {s.description}
                </div>
                <div style={{ fontSize: 10, color: '#64748b', fontFamily: 'monospace' }}>
                  {s.path.length} HOPS
                </div>
              </div>
            ))}

            <div style={{ marginTop: 'auto', paddingTop: 16 }}>
              <button
                onClick={onStartSim}
                disabled={isRunning}
                style={{
                  width: '100%', padding: '14px', borderRadius: 12, fontWeight: 800, fontSize: 13, textTransform: 'uppercase', letterSpacing: 1,
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
                  background: isRunning ? 'rgba(239, 68, 68, 0.1)' : 'linear-gradient(to right, #dc2626, #b91c1c)',
                  color: isRunning ? '#ef4444' : '#fff',
                  border: isRunning ? '1px solid rgba(239, 68, 68, 0.3)' : 'none',
                  opacity: isRunning ? 0.7 : 1,
                  cursor: isRunning ? 'not-allowed' : 'pointer',
                  boxShadow: isRunning ? 'none' : '0 4px 14px rgba(220, 38, 38, 0.4)'
                }}
              >
                {simState === 'running' || simState === 'breach' ? 'Simulating...' : 'Run Simulation'}
                {!isRunning && <Play size={16} fill="currentColor" />}
              </button>
            </div>
          </>
        )}

        {activeTab === 'playbooks' && (
          <>
            <div style={{ fontSize: 11, color: '#94a3b8', fontWeight: 600, marginBottom: -4 }}>GENERATED PLAYBOOKS</div>
            {cachedPlaybooks.length === 0 ? (
              <div style={{ padding: 20, textAlign: 'center', color: '#64748b', fontSize: 12, background: 'rgba(15,23,42,0.6)', borderRadius: 12, border: '1px solid rgba(30,41,59,0.8)' }}>
                No playbooks found. Run AI Analysis to generate playbooks.
              </div>
            ) : (
              cachedPlaybooks.map((pb) => (
                <div
                  key={pb.cveId}
                  onClick={() => { if (!isRunning) setSelectedPlaybook(pb) }}
                  style={{
                    padding: 14, borderRadius: 12, cursor: isRunning ? 'not-allowed' : 'pointer',
                    background: selectedPlaybook?.cveId === pb.cveId ? 'rgba(16, 185, 129, 0.08)' : 'rgba(15, 23, 42, 0.6)',
                    border: selectedPlaybook?.cveId === pb.cveId ? '1px solid rgba(16, 185, 129, 0.4)' : '1px solid rgba(30, 41, 59, 0.8)',
                    transition: 'all 0.2s'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                    <BookOpen size={14} className={selectedPlaybook?.cveId === pb.cveId ? 'text-emerald-400' : 'text-slate-400'} />
                    <div style={{ fontSize: 13, fontWeight: 700, color: selectedPlaybook?.cveId === pb.cveId ? '#34d399' : '#e2e8f0' }}>
                      {pb.cveId}
                    </div>
                  </div>
                  <div style={{ fontSize: 11, color: '#94a3b8', marginBottom: 8, lineHeight: 1.4 }}>
                    {pb.data.executiveSummary || 'Remediation Playbook'}
                  </div>
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                    <span style={{ fontSize: 9, padding: '2px 6px', background: 'rgba(239,68,68,0.1)', color: '#ef4444', borderRadius: 4 }}>
                      CVSS: {pb.data.cvssScore || '9.8'}
                    </span>
                    <span style={{ fontSize: 9, padding: '2px 6px', background: 'rgba(245,158,11,0.1)', color: '#f59e0b', borderRadius: 4 }}>
                      {pb.data.severity || 'CRITICAL'}
                    </span>
                    <span style={{ fontSize: 9, padding: '2px 6px', background: 'rgba(148,163,184,0.1)', color: '#cbd5e1', borderRadius: 4 }}>
                      {pb.data.assetName || 'Target Asset'}
                    </span>
                  </div>
                </div>
              ))
            )}

            <div style={{ marginTop: 'auto', paddingTop: 16 }}>
              <button
                onClick={() => { if (selectedPlaybook) onStartPlaybook(selectedPlaybook) }}
                disabled={isRunning || !selectedPlaybook}
                style={{
                  width: '100%', padding: '14px', borderRadius: 12, fontWeight: 800, fontSize: 13, textTransform: 'uppercase', letterSpacing: 1,
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
                  background: (isRunning || !selectedPlaybook) ? 'rgba(16, 185, 129, 0.1)' : 'linear-gradient(to right, #059669, #047857)',
                  color: (isRunning || !selectedPlaybook) ? '#34d399' : '#fff',
                  border: (isRunning || !selectedPlaybook) ? '1px solid rgba(16, 185, 129, 0.3)' : 'none',
                  opacity: (isRunning || !selectedPlaybook) ? 0.7 : 1,
                  cursor: (isRunning || !selectedPlaybook) ? 'not-allowed' : 'pointer',
                  boxShadow: (isRunning || !selectedPlaybook) ? 'none' : '0 4px 14px rgba(5, 150, 105, 0.4)'
                }}
              >
                {simState === 'remediating' ? 'Applying...' : 'Test Playbook'}
                {(!isRunning && selectedPlaybook) && <Shield size={16} />}
              </button>
            </div>
          </>
        )}
      </div>

      {/* ── Sandbox Status Area ── */}
      <div style={{ padding: '16px 20px', background: 'rgba(5, 13, 24, 0.95)', borderTop: '1px solid rgba(6, 182, 212, 0.2)', minHeight: 90 }}>
        <div style={{ fontSize: 10, color: '#64748b', fontWeight: 700, marginBottom: 8, textTransform: 'uppercase', letterSpacing: 0.5 }}>Sandbox Status</div>

        {simState === 'idle' && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#94a3b8', fontSize: 12 }}>
            <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#64748b' }} />
            Ready for execution
          </div>
        )}

        {(simState === 'running' || simState === 'breach') && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#f87171', fontSize: 12, fontWeight: 600 }}>
            <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#f87171', animation: 'pulse 1s infinite' }} />
            Attack Simulation In Progress...
          </div>
        )}

        {simState === 'remediating' && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#34d399', fontSize: 12, fontWeight: 600 }}>
            <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#34d399', animation: 'pulse 1s infinite' }} />
            Validating Playbook Remediation...
          </div>
        )}

        {simState === 'remediated' && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#10b981', fontSize: 12, fontWeight: 600 }}>
            <CheckCircle size={14} />
            Playbook Successful. Threat Blocked.
          </div>
        )}

        {simState !== 'idle' && (
          <button
            onClick={onResetSim}
            style={{ marginTop: 12, background: 'transparent', border: '1px solid #475569', color: '#94a3b8', padding: '4px 8px', borderRadius: 4, fontSize: 10, cursor: 'pointer', fontWeight: 600 }}
          >
            RESET SANDBOX
          </button>
        )}
      </div>
    </div>
  );
}
