// ─────────────────────────────────────────────────────────────────────────────
// twin/NodeDetailPanel.jsx
// Slide-in inspection panel when clicking a 3D entity.
// Shows full node metadata from the live pipeline data.
// ─────────────────────────────────────────────────────────────────────────────
import React from 'react';
import { STATE_COLORS, getThreatState, ZONE_MAP } from './twinData';

export default function NodeDetailPanel({ node, simState, attackPathSet, onClose }) {
  if (!node) return null;

  const state = getThreatState(node, attackPathSet, simState);
  const sc = STATE_COLORS[state] || STATE_COLORS.secure;
  const zoneInfo = ZONE_MAP[node.zone];

  const rows = [
    ['IP Address', node.ip],
    ['OS Version', node.os],
    ['Zone', node.zone],
    ['Type', node.type],
    ['Criticality', `${node.criticality}/10`],
    ['CVE', node.cve],
    ['CVSS Score', node.cvss],
    ['KEV Status', node.isKEV ? '⚠️ CISA KEV' : '✓ Not in KEV'],
  ];

  return (
    <div className="twin-detail-panel">
      {/* Header */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
        marginBottom: 16,
      }}>
        <div>
          <div style={{ fontSize: 13, fontWeight: 800, color: '#0f172a', lineHeight: 1.3 }}>
            {node.name}
          </div>
          <div style={{
            fontSize: 10, color: '#64748b', fontFamily: 'JetBrains Mono, monospace', marginTop: 2,
          }}>
            {node.id}
          </div>
          {/* Status badge */}
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 5,
            marginTop: 8,
            padding: '3px 10px',
            borderRadius: 5,
            background: `${sc.color}12`,
            border: `1px solid ${sc.color}30`,
            fontSize: 9,
            fontWeight: 800,
            color: sc.color,
            letterSpacing: 0.5,
          }}>
            <span style={{
              width: 6, height: 6, borderRadius: '50%',
              background: sc.color,
              boxShadow: `0 0 6px ${sc.color}`,
              display: 'inline-block',
            }} />
            {sc.label}
          </div>
        </div>
        <button
          onClick={onClose}
          style={{
            background: 'rgba(0,0,0,0.04)',
            border: '1px solid rgba(0,0,0,0.08)',
            color: '#64748b',
            borderRadius: 8,
            padding: '6px 10px',
            cursor: 'pointer',
            fontSize: 14,
            fontWeight: 600,
            lineHeight: 1,
            transition: 'all 0.2s ease',
          }}
        >
          ✕
        </button>
      </div>

      {/* Data rows */}
      {rows.map(([k, v]) => (
        <div key={k} className="twin-detail-row">
          <span className="key">{k}</span>
          <span className="val" style={{
            color: k === 'KEV Status'
              ? (node.isKEV ? '#dc2626' : '#16a34a')
              : k === 'CVSS Score'
                ? (node.cvss >= 9 ? '#dc2626' : node.cvss >= 7 ? '#d97706' : '#16a34a')
                : '#0f172a',
          }}>
            {String(v)}
          </span>
        </div>
      ))}

      {/* Zone indicator */}
      {zoneInfo && (
        <div style={{
          marginTop: 12,
          padding: '8px 10px',
          borderRadius: 8,
          background: `${zoneInfo.color}08`,
          border: `1px solid ${zoneInfo.color}20`,
          fontSize: 10,
          color: zoneInfo.color,
          fontWeight: 700,
          letterSpacing: 0.5,
        }}>
          {zoneInfo.label}
        </div>
      )}

      {/* KEV Warning */}
      {node.isKEV && (
        <div style={{
          marginTop: 10,
          padding: 10,
          borderRadius: 8,
          background: 'rgba(254,226,226,0.6)',
          border: '1px solid rgba(220,38,38,0.15)',
          fontSize: 10,
          color: '#991b1b',
          lineHeight: 1.5,
        }}>
          ⚠️ This CVE is listed in the CISA Known Exploited Vulnerabilities catalog. Immediate patching required.
        </div>
      )}

      {/* CVSS visual bar */}
      <div style={{ marginTop: 12 }}>
        <div style={{
          display: 'flex', justifyContent: 'space-between',
          fontSize: 9, fontWeight: 700, color: '#64748b', marginBottom: 4,
        }}>
          <span>CVSS SEVERITY</span>
          <span style={{
            color: node.cvss >= 9 ? '#dc2626' : node.cvss >= 7 ? '#d97706' : '#16a34a',
            fontFamily: 'JetBrains Mono, monospace',
          }}>
            {node.cvss} / 10.0
          </span>
        </div>
        <div style={{ height: 6, borderRadius: 3, background: '#e2e8f0', overflow: 'hidden' }}>
          <div style={{
            height: '100%',
            width: `${(node.cvss / 10) * 100}%`,
            borderRadius: 3,
            background: node.cvss >= 9 ? '#dc2626' : node.cvss >= 7 ? '#d97706' : '#16a34a',
            transition: 'width 0.5s ease',
          }} />
        </div>
      </div>

      {/* Criticality visual bar */}
      <div style={{ marginTop: 10 }}>
        <div style={{
          display: 'flex', justifyContent: 'space-between',
          fontSize: 9, fontWeight: 700, color: '#64748b', marginBottom: 4,
        }}>
          <span>ASSET CRITICALITY</span>
          <span style={{
            color: node.criticality >= 9 ? '#7c3aed' : '#2563eb',
            fontFamily: 'JetBrains Mono, monospace',
          }}>
            {node.criticality} / 10
          </span>
        </div>
        <div style={{ height: 6, borderRadius: 3, background: '#e2e8f0', overflow: 'hidden' }}>
          <div style={{
            height: '100%',
            width: `${(node.criticality / 10) * 100}%`,
            borderRadius: 3,
            background: node.criticality >= 9 ? '#7c3aed' : '#2563eb',
            transition: 'width 0.5s ease',
          }} />
        </div>
      </div>
    </div>
  );
}
