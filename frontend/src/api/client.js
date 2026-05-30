import axios from 'axios';

// Dynamically target backend URL (port 8000 in dev or mapped proxy)
const API_BASE = 'http://localhost:8000/api';

const client = axios.create({
  baseURL: API_BASE,
  timeout: 30000,   // 30s — attack-path analysis can take a moment
  headers: {
    'Content-Type': 'application/json',
  },
});

// ── Knowledge Graph ───────────────────────────────────────────────────────────
export const graphApi = {
  /** All nodes formatted for react-force-graph */
  getNodes: () =>
    client.get('/graph/nodes').then(r => {
      if (r.data && typeof r.data === 'object' && 'nodes' in r.data) {
        return r.data.nodes;
      }
      return r.data;
    }),

  /** All directed relationships */
  getLinks: () =>
    client.get('/graph/links').then(r => r.data),

  /**
   * Legacy: shortest unweighted hop path between two asset IDs.
   * @param {string} source  Asset ID (e.g. "Asset_1")
   * @param {string} target  Asset ID (e.g. "Asset_4")
   */
  getAttackPath: (source, target) =>
    client.get(`/graph/attack-path?source=${source}&target=${target}`).then(r => r.data),

  /**
   * Full ranked lateral attack-path analysis (top-5 paths, risk-scored).
   * @param {string} source  Entry-point asset ID (default "Asset_1")
   * @param {string} target  Target asset ID      (default "Asset_4")
   * @returns {Promise<AttackPath[]>}
   */
  getAttackPaths: (source = 'Asset_1', target = 'Asset_4') =>
    client.get(`/graph/attack-paths?source=${source}&target=${target}`).then(r => r.data),

  /**
   * Top composite-risk CVEs linked to assets (sorted by risk score).
   * @param {number} limit  Max records (1-100, default 20)
   * @returns {Promise<TopRisk[]>}
   */
  getTopRisks: (limit = 20) =>
    client.get(`/graph/top-risks?limit=${limit}`).then(r => r.data),

  /**
   * Assets with criticality >= minCriticality, enriched with CVE risk data.
   * @param {number} minCriticality  1-10, default 7
   * @returns {Promise<CriticalAsset[]>}
   */
  getCriticalAssets: (minCriticality = 7) =>
    client.get(`/graph/critical-assets?min_criticality=${minCriticality}`).then(r => r.data),

  /**
   * Hybrid risk predictor: composite formula + RandomForest tier prediction.
   * @param {{ cvss: number, epss: number, is_kev: boolean, asset_criticality: number }} payload
   */
  evaluateRisk: (payload) =>
    client.post('/graph/evaluate-risk', payload).then(r => r.data),

  /**
   * Trigger full threat-intel ingestion pipeline (NVD / MITRE / EPSS / KEV)
   * and rebuild the Neo4j Knowledge Graph.  Also invalidates ML caches.
   */
  syncThreatIntel: () =>
    client.post('/graph/sync').then(r => r.data),
};

// ── Alerts ────────────────────────────────────────────────────────────────────
export const alertsApi = {
  listAlerts:   () =>
    client.get('/alerts').then(r => r.data),
  resolveAlert: (alertId, status) =>
    client.post(`/alerts/${alertId}/resolve`, { status }).then(r => r.data),
};

// ── AI Playbooks ──────────────────────────────────────────────────────────────
export const playbooksApi = {
  /** Legacy: returns raw markdown string */
  generatePlaybook: (payload) =>
    client.post('/playbooks/generate', payload).then(r => r.data),

  /**
   * Structured 7-section remediation playbook (banking context).
   * @param {{ cve_data: object, affected_assets: string[] }} payload
   */
  generateRemediationPlaybook: (payload) =>
    client.post('/playbooks/remediation', payload).then(r => r.data),

  /**
   * 1-page security policy for a MITRE ATT&CK technique.
   * @param {{ technique_data: object }} payload
   */
  generateSecurityPolicy: (payload) =>
    client.post('/playbooks/security-policy', payload).then(r => r.data),

  /**
   * Structured RCA report (incident_data dict or legacy alert_sequence list).
   * @param {object} payload
   */
  generateRca: (payload) =>
    client.post('/playbooks/rca', payload).then(r => r.data),

  /**
   * Concise SOC IR draft for a single alert (fast-path, real-time).
   * @param {{ alert_data: object }} payload
   */
  generateIRDraft: (payload) =>
    client.post('/playbooks/incident-response', payload).then(r => r.data),
};

// ── Red Team Simulation ───────────────────────────────────────────────────────
export const redteamApi = {
  getScenarios:  () =>
    client.get('/redteam/scenarios').then(r => r.data),
  triggerBreach: (scenario) =>
    client.post('/redteam/trigger', { scenario }).then(r => r.data),
};

// ── Gen-AI Threat Intelligence ────────────────────────────────────────────────
export const genaiApi = {
  /**
   * Run Gen-AI analysis on the full CVE dataset (legacy non-streaming).
   * Returns { analysis: string, dataset_size: number, generated_at: string }
   */
  analyseThreats: () =>
    client.post('/genai/analyse-threats').then(r => r.data),

  /**
   * NEW: Full 7-step analysis pipeline via SSE streaming.
   * Returns an EventSource connected to /genai/run-full-analysis.
   * The caller receives events of type: step, playbook_progress, playbook_ready, complete.
   * @returns {EventSource}
   */
  runFullAnalysis: () => new EventSource(`${API_BASE}/genai/run-full-analysis`),

  /**
   * Generate a remediation playbook for a specific alert.
   * Accepts any alert object and maps to the legacy /playbooks/generate API.
   * @param {{ cve_id?: string, asset_id?: string, technique_id?: string, message?: string }} alert
   */
  generatePlaybookFromAlert: (alert) =>
    client.post('/playbooks/generate', {
      cve_id:         alert.cve_id || 'CVE-UNKNOWN',
      asset_name:     alert.asset_id || 'Unknown Asset',
      technique_name: alert.technique_id || 'T1190',
    }).then(r => r.data),
};

export default client;

/* ─────────────────────────────────────────────────────────────────────────────
   TypeScript-style JSDoc shapes for IDE intellisense
   ─────────────────────────────────────────────────────────────────────────────

   @typedef {Object} TopRisk
   @property {string}  cveId
   @property {number}  cvssScore
   @property {number}  epssScore
   @property {boolean} isKEV
   @property {string}  severity
   @property {string}  kevDueDate
   @property {string}  assetName
   @property {string}  assetId
   @property {number}  assetCriticality
   @property {number}  riskScore         0-100
   @property {string}  riskLevel         CRITICAL|HIGH|MEDIUM|LOW
   @property {Object}  breakdown         {cvssComponent, epssComponent, kevBonus, critComponent, rawTotal}
   @property {string}  explanation

   @typedef {Object} AttackPath
   @property {string[]}      path_nodes
   @property {Object[]}      node_details      [{assetId, name, criticality, nodeRiskScore, kevPresent, worstCveId}]
   @property {number}        total_risk_score
   @property {number}        hop_count
   @property {string|null}   highest_risk_cve
   @property {boolean}       contains_kev
   @property {string}        explanation

   @typedef {Object} CriticalAsset
   @property {string}   assetId
   @property {string}   name
   @property {string}   type
   @property {number}   criticality
   @property {string}   exposure
   @property {string}   owner
   @property {string}   environment
   @property {number}   vulnerabilityCount
   @property {number}   maxCvssScore
   @property {number}   maxCveRisk
   @property {string}   riskLevel
   @property {string[]} cveIds
*/
