// ─────────────────────────────────────────────────────────────────────────────
// twin/twinData.js
// Shared constants, 3D layout positions (U-curve wavy), GLB model mapping,
// zone configuration, and utilities for the Banking Digital Twin 3D scene.
// All node/connection data is fetched live from the backend pipeline.
// This file only defines visual layout and presentation constants.
// ─────────────────────────────────────────────────────────────────────────────

// ── Security Zone Visual Config ──────────────────────────────────────────────
export const ZONES = [
  { id: 'DMZ', label: 'ZONE 1 — INTERNET-FACING DMZ', color: '#ef4444', accent: '#fca5a5', floorColor: '#fef2f2' },
  { id: 'Middleware', label: 'ZONE 2 — INTEGRATION MIDDLEWARE', color: '#f59e0b', accent: '#fcd34d', floorColor: '#fffbeb' },
  { id: 'Core', label: 'ZONE 3 — CORE BANKING ENCLAVE', color: '#7c3aed', accent: '#c4b5fd', floorColor: '#f5f3ff' },
  { id: 'Management', label: 'ZONE 4 — MANAGEMENT & CONTROL', color: '#2563eb', accent: '#93c5fd', floorColor: '#eff6ff' },
];

// Zone → ID lookup (backend returns zone as "DMZ", "Middleware", "Core", "Management")
export const ZONE_MAP = Object.fromEntries(ZONES.map(z => [z.id, z]));

// ── 3D World Positions — U-Shape Wavy Layout ────────────────────────────────
// Each row of 3 nodes follows a U-curve: the center node pushes forward (or
// backward) while the edge nodes sit at the base Z.  The direction alternates
// per row to create a sinusoidal "wavy" visual from the camera angle.
//
//  Row 1 (DMZ):       ∪  center forward   (toward camera)
//  Row 2 (Middleware): ∩  center backward  (away from camera)
//  Row 3 (Core):       ∪  center forward
//  Row 4 (Management): ∩  center backward
//
const CURVE_AMP = 5;  // Z-amplitude of each U-curve

export const NODE_POSITIONS = {
  // Zone 1: DMZ — front row, ∪ curve (center dips toward camera = higher Z)
  'SRV-DMZ-WEB-01': [-18, 0, 19],
  'SRV-DMZ-GW-02': [0, 0, 27],
  'SRV-DMZ-CMS-03': [18, 0, 19],

  // Zone 2: Middleware — middle row, ∪ curve (pointing forward = higher Z)
  'SRV-MID-ESB-01': [-18, 0, 2],
  'SRV-MID-IAM-02': [0, 0, 10],
  'SRV-MID-SWI-03': [18, 0, 2],

  // Zone 3: Core Banking — center-back, ∪ curve (pointing forward = higher Z)
  'SRV-CORE-CBS-01': [-18, 0, -14],
  'DB-CORE-LEDG-02': [0, 0, -6],
  'SRV-CORE-SWIFT-03': [18, 0, -14],

  // Zone 4: Management — far back, ∪ curve (pointing forward = higher Z)
  'SRV-MGMT-AD-01': [-18, 0, -30],
  'SRV-MGMT-JUMP-02': [0, 0, -22],
  'SRV-MGMT-SIEM-03': [18, 0, -30],
};

// ── GLB 3D Model Config per Node ─────────────────────────────────────────────
// Served by backend at /api/models/<filename>  (FastAPI StaticFiles mount).
// scale: uniform scale factor;  yOffset: shift model above platform;
// rotation: [x,y,z] radians;   labelHeight: height for the floating label.
export const GLB_MODELS = {
  'SRV-DMZ-WEB-01': { url: '/api/models/webserver.glb', scale: 1.55, yOffset: 0, rotation: [0, 0, 0], labelHeight: 5.5 },
  'SRV-DMZ-GW-02': { url: `/api/models/${encodeURIComponent('api gateway.glb')}`, scale: 2.80, yOffset: 0, rotation: [0, 0, 0], labelHeight: 5.0 },
  'SRV-DMZ-CMS-03': { url: '/api/models/CMS_portal.glb', scale: 1.00, yOffset: 0, rotation: [0, 0, 0], labelHeight: 5.0 },
  'SRV-MID-ESB-01': { url: '/api/models/service_bus.glb', scale: 3.50, yOffset: 0, rotation: [0, 0, 0], labelHeight: 7.0 },
  'SRV-MID-IAM-02': { url: '/api/models/IAM_manager.glb', scale: 3.25, yOffset: 2, rotation: [0, 0, 0], labelHeight: 5.5 },
  'SRV-MID-SWI-03': { url: '/api/models/payment_switch.glb', scale: 0.02, yOffset: 0, rotation: [0, 0, 0], labelHeight: 4.0 },
  'SRV-CORE-CBS-01': { url: '/api/models/service_bus.glb', scale: 3.50, yOffset: 0.0, rotation: [0, 0, 0], labelHeight: 7.0 },
  'DB-CORE-LEDG-02': { url: '/api/models/central_db.glb', scale: 0.25, yOffset: 0, rotation: [0, 0, 0], labelHeight: 5.5 },
  'SRV-CORE-SWIFT-03': { url: '/api/models/swift_node.glb', scale: 2.50, yOffset: 0, rotation: [0, 0, 0], labelHeight: 5.0 },
  'SRV-MGMT-AD-01': { url: '/api/models/AD_Controller.glb', scale: 0.02, yOffset: 0, rotation: [0, 0, 0], labelHeight: 5.5 },
  'SRV-MGMT-JUMP-02': { url: '/api/models/jumpserver.glb', scale: 0.45, yOffset: 0, rotation: [0, 0, 0], labelHeight: 5.0 },
  'SRV-MGMT-SIEM-03': { url: '/api/models/SIEM_Node.glb', scale: 1.35, yOffset: 0, rotation: [0, 0, 0], labelHeight: 5.5 },
};

// ── 3D Building Shapes per Node Type (kept as visual metadata) ───────────────
// Used for fallback rendering, platform sizing, and label colors.
export const ENTITY_VISUALS = {
  'SRV-DMZ-WEB-01': { shape: 'tower', height: 5.5, width: 2.5, color: '#3b82f6', emissive: '#1d4ed8', label: 'Web Server' },
  'SRV-DMZ-GW-02': { shape: 'gateway', height: 3.5, width: 3.5, color: '#0ea5e9', emissive: '#0284c7', label: 'API Gateway' },
  'SRV-DMZ-CMS-03': { shape: 'office', height: 3.0, width: 2.5, color: '#6366f1', emissive: '#4338ca', label: 'CMS Portal' },
  'SRV-MID-ESB-01': { shape: 'warehouse', height: 3.5, width: 4.0, color: '#f97316', emissive: '#c2410c', label: 'Service Bus' },
  'SRV-MID-IAM-02': { shape: 'cylinder', height: 5.0, width: 2.0, color: '#eab308', emissive: '#a16207', label: 'IAM Manager' },
  'SRV-MID-SWI-03': { shape: 'switch', height: 2.5, width: 3.0, color: '#f59e0b', emissive: '#b45309', label: 'Payment Switch' },
  'SRV-CORE-CBS-01': { shape: 'headquarters', height: 6.5, width: 4.0, color: '#7c3aed', emissive: '#5b21b6', label: 'Core Banking' },
  'DB-CORE-LEDG-02': { shape: 'vault', height: 4.0, width: 3.5, color: '#6d28d9', emissive: '#4c1d95', label: 'Central DB' },
  'SRV-CORE-SWIFT-03': { shape: 'globe', height: 4.5, width: 2.5, color: '#4f46e5', emissive: '#3730a3', label: 'SWIFT Node' },
  'SRV-MGMT-AD-01': { shape: 'government', height: 5.0, width: 3.5, color: '#2563eb', emissive: '#1e40af', label: 'AD Controller' },
  'SRV-MGMT-JUMP-02': { shape: 'fortress', height: 4.0, width: 2.5, color: '#475569', emissive: '#1e293b', label: 'Jump Server' },
  'SRV-MGMT-SIEM-03': { shape: 'radar', height: 4.5, width: 3.0, color: '#1e40af', emissive: '#1e3a5f', label: 'SIEM Node' },
};

// ── Topology Connections (matches backend graph_builder.py TOPOLOGY) ─────────
// Used as fallback when backend is unavailable.
export const FALLBACK_CONNECTIONS = [
  ['SRV-DMZ-WEB-01', 'SRV-MID-IAM-02'],
  ['SRV-DMZ-WEB-01', 'SRV-DMZ-GW-02'],
  ['SRV-DMZ-CMS-03', 'SRV-DMZ-GW-02'],
  ['SRV-DMZ-CMS-03', 'SRV-MID-ESB-01'],
  ['SRV-DMZ-GW-02', 'SRV-MID-SWI-03'],
  ['SRV-DMZ-GW-02', 'SRV-MID-ESB-01'],
  ['SRV-MID-ESB-01', 'SRV-CORE-CBS-01'],
  ['SRV-MID-ESB-01', 'DB-CORE-LEDG-02'],
  ['SRV-MID-IAM-02', 'SRV-MGMT-SIEM-03'],
  ['SRV-MID-SWI-03', 'DB-CORE-LEDG-02'],
  ['SRV-MID-SWI-03', 'SRV-CORE-CBS-01'],
  ['SRV-CORE-CBS-01', 'DB-CORE-LEDG-02'],
  ['SRV-CORE-CBS-01', 'SRV-MGMT-JUMP-02'],
  ['SRV-MGMT-AD-01', 'SRV-DMZ-WEB-01'],
  ['SRV-MGMT-AD-01', 'SRV-MID-ESB-01'],
  ['SRV-MGMT-AD-01', 'SRV-CORE-CBS-01'],
  ['SRV-MGMT-JUMP-02', 'SRV-CORE-CBS-01'],
  ['SRV-MGMT-JUMP-02', 'DB-CORE-LEDG-02'],
  ['SRV-MGMT-JUMP-02', 'SRV-CORE-SWIFT-03'],
  ['SRV-MGMT-SIEM-03', 'SRV-MGMT-AD-01'],
];

// ── Fallback Node Data (mirrors graph_builder.py ASSETS) ─────────────────────
export const FALLBACK_NODES = [
  { id: 'SRV-DMZ-WEB-01', name: 'Retail Internet Banking Web Server', type: 'Gateway', zone: 'DMZ', ip: '10.0.1.10', os: 'Ubuntu 22.04', cve: 'CVE-2023-25690', cvss: 9.8, isKEV: true, criticality: 8 },
  { id: 'SRV-DMZ-GW-02', name: 'Mobile Banking API Gateway', type: 'Gateway', zone: 'DMZ', ip: '10.0.1.20', os: 'RHEL 9.1', cve: 'CVE-2022-41915', cvss: 7.5, isKEV: false, criticality: 8 },
  { id: 'SRV-DMZ-CMS-03', name: 'Public CMS Portal', type: 'WebApp', zone: 'DMZ', ip: '10.0.2.10', os: 'Ubuntu 20.04', cve: 'CVE-2021-29447', cvss: 8.0, isKEV: true, criticality: 5 },
  { id: 'SRV-MID-ESB-01', name: 'Enterprise Service Bus', type: 'Middleware', zone: 'Middleware', ip: '10.1.1.10', os: 'Win Server 2022', cve: 'CVE-2021-44228', cvss: 10.0, isKEV: true, criticality: 8 },
  { id: 'SRV-MID-IAM-02', name: 'Customer Identity & Access Manager', type: 'IAM', zone: 'Middleware', ip: '10.1.1.20', os: 'RHEL 8.6', cve: 'CVE-2022-37434', cvss: 9.8, isKEV: true, criticality: 10 },
  { id: 'SRV-MID-SWI-03', name: 'Universal Payment Switch', type: 'PaymentSwitch', zone: 'Middleware', ip: '10.1.2.10', os: 'Ubuntu 22.04', cve: 'CVE-2023-28432', cvss: 7.5, isKEV: true, criticality: 10 },
  { id: 'SRV-CORE-CBS-01', name: 'Core Banking System App Server', type: 'AppServer', zone: 'Core', ip: '10.2.1.10', os: 'RHEL 9.0', cve: 'CVE-2023-21839', cvss: 7.5, isKEV: true, criticality: 10 },
  { id: 'DB-CORE-LEDG-02', name: 'Central Production Database', type: 'Database', zone: 'Core', ip: '10.2.2.10', os: 'Oracle Linux 8.5', cve: 'CVE-2022-21569', cvss: 7.5, isKEV: false, criticality: 10 },
  { id: 'SRV-CORE-SWIFT-03', name: 'SWIFT Transaction Appliance', type: 'SWIFT', zone: 'Core', ip: '10.2.3.10', os: 'Hardened Linux', cve: 'CVE-2023-38606', cvss: 7.8, isKEV: true, criticality: 10 },
  { id: 'SRV-MGMT-AD-01', name: 'Active Directory Domain Controller', type: 'AD', zone: 'Management', ip: '10.3.1.10', os: 'Win Server 2022', cve: 'CVE-2022-26925', cvss: 9.8, isKEV: true, criticality: 10 },
  { id: 'SRV-MGMT-JUMP-02', name: 'Enterprise Jump Server / Bastion', type: 'Bastion', zone: 'Management', ip: '10.3.1.20', os: 'RHEL 8.8 Hardened', cve: 'CVE-2023-30570', cvss: 8.1, isKEV: false, criticality: 8 },
  { id: 'SRV-MGMT-SIEM-03', name: 'SIEM & Log Aggregator Node', type: 'SIEM', zone: 'Management', ip: '10.3.2.10', os: 'Ubuntu 22.04', cve: 'CVE-2023-31414', cvss: 7.5, isKEV: false, criticality: 8 },
];

// ── Red Team Scenarios (from backend simulator.py) ───────────────────────────
export const SCENARIOS = {
  core_data_exfil: {
    name: 'Core Banking Data Exfiltration',
    description: 'Attack originates from a compromised internal Jump Server, pivots to the Core Banking System, and exfiltrates Ledger DB data.',
    path: ['SRV-MGMT-JUMP-02', 'SRV-CORE-CBS-01', 'DB-CORE-LEDG-02'],
    color: '#ef4444',
  },
  api_ssrf_pivot: {
    name: 'API Gateway SSRF Pivot',
    description: 'Attack hits the API Gateway via the public CMS portal, pivots to the Enterprise Service Bus, and exploits the Payment Switch.',
    path: ['SRV-DMZ-CMS-03', 'SRV-DMZ-GW-02', 'SRV-MID-SWI-03'],
    color: '#f59e0b',
  },
  idp_takeover: {
    name: 'Identity Provider Takeover',
    description: 'Credential stuffing on the Web Portal leads to IAM Manager compromise, giving access to the SIEM and AD Controller.',
    path: ['SRV-DMZ-WEB-01', 'SRV-MID-IAM-02', 'SRV-MGMT-SIEM-03', 'SRV-MGMT-AD-01'],
    color: '#a855f7',
  },
  swift_ransomware: {
    name: 'SWIFT Network Ransomware',
    description: 'Insider threat drops malware on the Jump Server, which laterally moves to encrypt the SWIFT Transaction Appliance.',
    path: ['SRV-MGMT-JUMP-02', 'SRV-CORE-SWIFT-03', 'SRV-CORE-CBS-01'],
    color: '#ef4444',
  },
};

// ── Threat State Utilities ───────────────────────────────────────────────────
export function getThreatState(node, attackPathSet, simState) {
  if (simState === 'remediated' && attackPathSet && attackPathSet.has(node.id)) return 'remediated';
  if (simState === 'remediated') return 'secure';
  if (simState === 'remediating' && attackPathSet && attackPathSet.has(node.id)) return 'remediating';
  if (!attackPathSet || !attackPathSet.has(node.id)) {
    if (node.isKEV && node.cvss >= 9.0) return 'critical';
    if (node.isKEV) return 'vulnerable';
    return 'secure';
  }
  if (simState === 'breach' || simState === 'running') return 'compromised';
  return 'attacking';
}

export const STATE_COLORS = {
  secure: { color: '#16a34a', glow: '#22c55e', label: 'SECURE', emissive: 0x16a34a },
  vulnerable: { color: '#d97706', glow: '#f59e0b', label: 'VULNERABLE', emissive: 0xd97706 },
  critical: { color: '#dc2626', glow: '#ef4444', label: 'CRITICAL', emissive: 0xdc2626 },
  attacking: { color: '#ea580c', glow: '#f97316', label: 'UNDER ATTACK', emissive: 0xea580c },
  compromised: { color: '#dc2626', glow: '#ef4444', label: '⚠ COMPROMISED', emissive: 0xdc2626 },
  remediating: { color: '#0ea5e9', glow: '#38bdf8', label: 'REMEDIATING...', emissive: 0x0ea5e9 },
  remediated: { color: '#10b981', glow: '#34d399', label: '🛡️ SECURED', emissive: 0x10b981 },
};

// ── Traffic Log Templates ────────────────────────────────────────────────────
export const NORMAL_LOGS = [
  'AUTH  10.0.1.10 → 10.1.1.20  GET /api/v2/session-token  200 OK',
  'TXN   10.1.2.10 → 10.2.2.10  INSERT ledger_entry amount=₹4,200  OK',
  'SYNC  10.1.1.10 → 10.2.1.10  CBS batch job reconciliation  OK',
  'AUDIT 10.1.1.20 → 10.3.2.10  Auth event stream flushed  200',
  'JUMP  10.3.1.20 → 10.2.1.10  Admin SSH session opened by ops@bank',
  'SIEM  10.3.2.10 → 10.3.1.10  Alert correlation batch complete',
  'DNS   10.0.1.10 → 8.8.8.8    Query cdn.bank.in  A 142.250.x.x',
  'UPI   10.1.2.10 → NPCI_GW    IMPS payment 0009XYZ queued  OK',
];

// ── Utilities ────────────────────────────────────────────────────────────────
export const pad2 = n => String(n).padStart(2, '0');
export const nowStr = () => {
  const d = new Date();
  return `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
};
