// ─────────────────────────────────────────────────────────────────────────────
// twin/TwinHUD.jsx
// Dashboard overlay panels — top command bar, left simulation controls,
// right SOC log feed. All glassmorphism light-mode enterprise styling.
// ─────────────────────────────────────────────────────────────────────────────
import React from 'react';
import { SCENARIOS, STATE_COLORS, NORMAL_LOGS, nowStr } from './twinData';

// ── Top Command Bar ─────────────────────────────────────────────────────────
export function TopBar({ defcon, compromisedCount, liability, simState, nodes }) {
  const defconColor = defcon <= 1 ? '#dc2626' : defcon <= 2 ? '#ea580c' : defcon <= 3 ? '#d97706' : defcon <= 4 ? '#2563eb' : '#16a34a';
  const kevCount = nodes.filter(n => n.isKEV).length;
  const cveCount = nodes.length;
  const isNominal = simState === 'idle' || simState === 'remediated';

  return (
    <div className="twin-topbar">
      {/* Title */}
      <div className="twin-topbar-title">
        <div className="brand">SARATHI CYBERDEFENSE</div>
        <div className="subtitle">Banking Infrastructure Digital Twin — {nodes.length}-Node / 4-Zone</div>
      </div>

      {/* DEFCON */}
      <div className="twin-defcon" style={{ borderColor: `${defconColor}30`, border: `1px solid ${defconColor}25` }}>
        <div className="defcon-label">DEFCON</div>
        <div className="defcon-value" style={{ color: defconColor, textShadow: `0 0 12px ${defconColor}40` }}>{defcon}</div>
      </div>

      {/* Stats */}
      {[
        { label: 'TOTAL ASSETS', value: nodes.length, color: '#2563eb' },
        { label: 'ZONES', value: '4', color: '#7c3aed' },
        { label: 'ACTIVE CVEs', value: cveCount, color: '#d97706' },
        { label: 'KEV ENTRIES', value: kevCount, color: '#dc2626' },
        { label: 'COMPROMISED', value: compromisedCount, color: compromisedCount > 0 ? '#dc2626' : '#16a34a' },
        ...(liability > 0 ? [{ label: 'LIABILITY', value: `₹${(liability / 100000).toFixed(1)}L`, color: '#dc2626' }] : []),
      ].map(s => (
        <div key={s.label} className="twin-stat-badge">
          <div className="value" style={{ color: s.color }}>{s.value}</div>
          <div className="label">{s.label}</div>
        </div>
      ))}

      {/* Status */}
      <div className={`twin-status-badge ${isNominal ? 'nominal' : 'alert'}`}>
        <span style={{
          width: 7, height: 7, borderRadius: '50%',
          background: isNominal ? '#16a34a' : '#dc2626',
          display: 'inline-block',
          boxShadow: `0 0 6px ${isNominal ? '#16a34a' : '#dc2626'}`,
        }}
          className={!isNominal ? 'live-dot' : ''}
        />
        {isNominal ? 'NOMINAL' : 'ALERT'}
      </div>
    </div>
  );
}

// ── Status Banner ───────────────────────────────────────────────────────────
export function StatusBanner({ simState, selectedScenario, compromisedCount }) {
  if (simState === 'idle') return null;

  const cls = simState === 'remediated' ? 'remediated' : simState === 'breach' ? 'breach' : 'running';
  const messages = {
    running: `🔴 RED TEAM ACTIVE — Scenario: "${SCENARIOS[selectedScenario]?.name}" — Tracking ${compromisedCount} compromised node(s)`,
    breach: `💥 SECURITY BREACH CONFIRMED — ${compromisedCount} assets compromised — AI containment protocols executing...`,
    remediated: `✅ THREAT CONTAINED — AI Governance layer successfully quarantined attack vector — Systems returning to normal`,
  };

  return (
    <div className={`twin-banner ${cls}`}>
      <span style={{
        width: 8, height: 8, borderRadius: '50%',
        background: simState === 'remediated' ? '#16a34a' : '#dc2626',
        display: 'inline-block',
        boxShadow: `0 0 8px ${simState === 'remediated' ? '#16a34a' : '#dc2626'}`,
      }}
        className={simState !== 'remediated' ? 'live-dot' : ''}
      />
      {messages[simState]}
    </div>
  );
}

// ── Left Sidebar — Simulation Controls ──────────────────────────────────────
export function LeftSidebar({
  simState,
  selectedScenario,
  onSelectScenario,
  onStartSim,
  onResetSim,
}) {
  return (
    <div className="twin-sidebar-left">
      {/* Simulation Control */}
      <div className="twin-panel">
        <div className="twin-panel-header">
          <span className="icon">⚙️</span>
          <span className="title">Simulation</span>
        </div>

        <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
          <button
            className={`twin-btn twin-btn-run ${simState === 'running' || simState === 'breach' ? 'active' : ''}`}
            onClick={onStartSim}
            disabled={simState === 'running' || simState === 'breach'}
            style={{ flex: 1 }}
          >
            {simState === 'running' ? '⚡ SIMULATING...' :
              simState === 'breach' ? '💥 BREACHED' :
                simState === 'remediated' ? '🔄 RE-RUN' : '▶ RUN SIM'}
          </button>
          <button className="twin-btn twin-btn-reset" onClick={onResetSim} style={{ flex: 0.6 }}>
            RESET
          </button>
        </div>
      </div>

      {/* Scenario Selection */}
      <div className="twin-panel">
        <div className="twin-panel-header">
          <span className="icon">⚠️</span>
          <span className="title">Scenario Injection</span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {Object.entries(SCENARIOS).map(([id, s]) => (
            <button
              key={id}
              className={`twin-scenario-btn ${selectedScenario === id ? 'selected' : ''}`}
              onClick={() => onSelectScenario(id)}
              disabled={simState === 'running' || simState === 'breach'}
            >
              <span style={{ flex: 1 }}>{s.name}</span>
              <span style={{
                fontSize: 8,
                fontWeight: 800,
                padding: '2px 6px',
                borderRadius: 3,
                background: selectedScenario === id ? 'rgba(37,99,235,0.15)' : 'rgba(0,0,0,0.04)',
                color: selectedScenario === id ? '#2563eb' : '#94a3b8',
              }}>
                {selectedScenario === id ? 'ACTIVE' : 'OFF'}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Zone Health Summary */}
      <div className="twin-panel">
        <div className="twin-panel-header">
          <span className="icon">🏦</span>
          <span className="title">Zone Health</span>
        </div>

        {[
          { name: 'DMZ', color: '#ef4444', health: simState === 'idle' ? 92 : simState === 'remediated' ? 95 : 45 },
          { name: 'Middleware', color: '#f59e0b', health: simState === 'idle' ? 88 : simState === 'remediated' ? 90 : 60 },
          { name: 'Core', color: '#7c3aed', health: simState === 'idle' ? 95 : simState === 'remediated' ? 98 : 35 },
          { name: 'Mgmt', color: '#2563eb', health: simState === 'idle' ? 96 : simState === 'remediated' ? 97 : 80 },
        ].map(z => (
          <div key={z.name} style={{ marginBottom: 8 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9, fontWeight: 700, color: '#334155', marginBottom: 3 }}>
              <span>{z.name}</span>
              <span style={{ color: z.health > 80 ? '#16a34a' : z.health > 50 ? '#d97706' : '#dc2626', fontFamily: 'JetBrains Mono, monospace' }}>
                {z.health}%
              </span>
            </div>
            <div style={{ height: 4, borderRadius: 2, background: '#e2e8f0', overflow: 'hidden' }}>
              <div style={{
                height: '100%',
                width: `${z.health}%`,
                borderRadius: 2,
                background: z.health > 80 ? '#16a34a' : z.health > 50 ? '#d97706' : '#dc2626',
                transition: 'width 0.8s ease',
              }} />
            </div>
          </div>
        ))}
      </div>

      {/* Threat Legend */}
      <div className="twin-panel">
        <div className="twin-panel-header">
          <span className="icon">🎯</span>
          <span className="title">Threat Legend</span>
        </div>
        {Object.entries(STATE_COLORS).map(([k, v]) => (
          <div key={k} className="twin-legend-item">
            <div className="twin-legend-dot" style={{ background: v.color, boxShadow: `0 0 4px ${v.color}40` }} />
            <span className="twin-legend-label">{v.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Right Sidebar — SOC Log + AI Advisor ────────────────────────────────────
export function RightSidebar({ logLines, simState }) {
  const logTypeStyle = {
    NORMAL: { color: '#16a34a', prefix: '●', cls: 'normal' },
    ALERT: { color: '#d97706', prefix: '▲', cls: 'alert' },
    ATTACK: { color: '#dc2626', prefix: '✗', cls: 'attack' },
    BREACH: { color: '#dc2626', prefix: '💥', cls: 'breach' },
    REMEDIATE: { color: '#16a34a', prefix: '✓', cls: 'remediate' },
    SUSPICIOUS: { color: '#7c3aed', prefix: '?', cls: 'alert' },
  };

  return (
    <div className="twin-sidebar-right">
      {/* AI Operations Advisor */}
      <div className="twin-panel" style={{ flexShrink: 0 }}>
        <div className="twin-panel-header">
          <span className="icon">🤖</span>
          <span className="title">AI Ops Advisor</span>
          <span style={{
            marginLeft: 'auto',
            width: 7, height: 7, borderRadius: '50%',
            background: '#16a34a',
            boxShadow: '0 0 6px #16a34a',
            display: 'inline-block',
          }} />
        </div>
        <div style={{ fontSize: 11, color: '#475569', lineHeight: 1.5 }}>
          {simState === 'idle' && (
            <>
              <div style={{ fontSize: 12, fontWeight: 700, color: '#0f172a', marginBottom: 4 }}>System Nominal</div>
              <div>Monitoring grid telemetry for anomalies. All zones operational.</div>
            </>
          )}
          {simState === 'running' && (
            <>
              <div style={{ fontSize: 12, fontWeight: 700, color: '#dc2626', marginBottom: 4 }}>⚡ Threat Detected</div>
              <div>Analyzing lateral movement pattern. Preparing containment strategies.</div>
            </>
          )}
          {simState === 'breach' && (
            <>
              <div style={{ fontSize: 12, fontWeight: 700, color: '#dc2626', marginBottom: 4 }}>🚨 Active Breach</div>
              <div>Critical assets compromised. Initiating automated isolation protocols.</div>
            </>
          )}
          {simState === 'remediated' && (
            <>
              <div style={{ fontSize: 12, fontWeight: 700, color: '#16a34a', marginBottom: 4 }}>✅ Contained</div>
              <div>Threat neutralized. Post-incident analysis in progress.</div>
            </>
          )}
        </div>
      </div>

      {/* Live SOC Log */}
      <div className="twin-panel" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div className="twin-panel-header">
          <span className="icon">📡</span>
          <span className="title">Live SOC Log</span>
          <div style={{
            marginLeft: 'auto',
            display: 'flex', alignItems: 'center', gap: 5,
            fontSize: 9, fontWeight: 700,
            color: simState !== 'idle' ? '#dc2626' : '#16a34a',
          }}>
            <span style={{
              width: 6, height: 6, borderRadius: '50%',
              background: simState !== 'idle' ? '#dc2626' : '#16a34a',
              boxShadow: `0 0 6px ${simState !== 'idle' ? '#dc2626' : '#16a34a'}`,
              display: 'inline-block',
            }}
              className="live-dot"
            />
            LIVE
          </div>
        </div>

        <div className="twin-log-container">
          {logLines.map(line => {
            const style = logTypeStyle[line.type] || logTypeStyle.NORMAL;
            return (
              <div key={line.id} className={`twin-log-line ${style.cls}`}>
                <span className="time">{line.time}</span>
                <span>{style.prefix} {line.msg}</span>
              </div>
            );
          })}
          {logLines.length === 0 && (
            <div style={{ color: '#94a3b8', fontSize: 10, fontFamily: 'JetBrains Mono, monospace', padding: 8 }}>
              Initialising telemetry feed...
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
