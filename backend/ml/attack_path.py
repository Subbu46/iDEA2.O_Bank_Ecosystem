"""
ml/attack_path.py
-----------------
NetworkX-powered lateral attack-path analyser for the Sarathi Cyberdefense platform.

Algorithm overview
------------------
1. Fetch Asset nodes + CONNECTS_TO edges from Neo4j (or mock).
2. Load CVE risk data per asset (used to weight paths).
3. Build a directed NetworkX graph where edge weight = 1 / asset_criticality
   (lower criticality → higher traversal cost, so high-value assets are
   naturally preferred targets in shortest-path variants).
4. Enumerate all simple paths from source → target up to cutoff=6 hops.
5. Score each path using the sum of composite CVE risk scores across its nodes.
6. Return the top-5 paths with full explainability metadata.

Caching
-------
Asset topology and CVE-risk data are cached separately with a 90-second TTL
to avoid redundant Aura round-trips during repeated API calls in a session.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import networkx as nx

logger = logging.getLogger("sarathi.attack_path")

# ── Cache constants ────────────────────────────────────────────────────────────
_TOPOLOGY_TTL = 90      # seconds – asset topology cache
_RISK_TTL     = 90      # seconds – CVE risk-per-asset cache
_PATH_CUTOFF  = 6       # max hops for all_simple_paths
_TOP_N_PATHS  = 5       # paths returned to caller


class AttackPathAnalyzer:
    """
    Builds an in-memory directed graph of the asset topology and identifies
    the riskiest lateral movement paths an attacker could traverse.
    """

    def __init__(self, neo4j_client=None) -> None:
        """
        Parameters
        ----------
        neo4j_client : Neo4jClient | None
            Optional: pass a shared client so the existing /attack-path route
            keeps working with the singleton pattern in routes_graph.py.
        """
        self._db = neo4j_client             # legacy singleton compat
        self._nx_graph: nx.DiGraph = nx.DiGraph()

        # Separate TTL caches
        self._topo_cache: dict | None = None   # {"nodes": [...], "edges": [...]}
        self._topo_ts:    float = 0.0
        self._risk_cache: dict[str, dict] | None = None  # assetId → risk info
        self._risk_ts:    float = 0.0

    # ──────────────────────────────────────────────────────────────────────────
    # Public API – new full-featured methods
    # ──────────────────────────────────────────────────────────────────────────

    def find_attack_paths(
        self,
        neo4j_client,
        source: str = "SRV-DMZ-WEB-01",
        target: str = "DB-CORE-LEDG-02",
    ) -> list[dict[str, Any]]:
        """
        Find and score the top-N lateral attack paths from `source` to `target`.

        Parameters
        ----------
        neo4j_client : Neo4jClient
        source       : str   Asset id of the entry-point (e.g. public-facing)
        target       : str   Asset id of the high-value target

        Returns
        -------
        List of up to _TOP_N_PATHS dicts, each containing:
          path_nodes, total_risk_score, hop_count,
          highest_risk_cve, contains_kev, explanation
        """
        logger.info("find_attack_paths: %s → %s", source, target)

        # ── Load cached topology ──────────────────────────────────────────────
        topo  = self._get_topology(neo4j_client)
        risks = self._get_asset_risks(neo4j_client)

        graph = self._build_nx_graph(topo, risks)

        if source not in graph.nodes:
            logger.warning("Source node '%s' not in graph. Nodes: %s", source, list(graph.nodes))
            return [self._no_path_result(source, target, "source node not found in graph")]

        if target not in graph.nodes:
            logger.warning("Target node '%s' not in graph. Nodes: %s", target, list(graph.nodes))
            return [self._no_path_result(source, target, "target node not found in graph")]

        # ── Enumerate simple paths ────────────────────────────────────────────
        try:
            raw_paths = list(
                nx.all_simple_paths(graph, source=source, target=target, cutoff=_PATH_CUTOFF)
            )
        except nx.NetworkXNoPath:
            raw_paths = []
        except Exception as exc:
            logger.error("Path enumeration error: %s", exc)
            raw_paths = []

        if not raw_paths:
            logger.info("No paths found from %s to %s.", source, target)
            return [self._no_path_result(source, target, "no connected path within 6 hops")]

        # ── Score each path ───────────────────────────────────────────────────
        scored: list[dict] = []
        for path_nodes in raw_paths:
            scored.append(self._score_path(path_nodes, graph, risks))

        # Sort by total_risk_score descending
        scored.sort(key=lambda p: p["total_risk_score"], reverse=True)
        top = scored[:_TOP_N_PATHS]

        logger.info(
            "find_attack_paths: found %d paths, returning top %d. "
            "Highest risk score: %.1f",
            len(raw_paths), len(top),
            top[0]["total_risk_score"] if top else 0,
        )
        return top

    def get_critical_assets(
        self,
        neo4j_client,
        min_criticality: int = 7,
    ) -> list[dict[str, Any]]:
        """
        Return all assets with criticality >= min_criticality, enriched with
        their vulnerability count and max CVE risk score.

        Returns
        -------
        List of dicts sorted by criticality DESC, then maxCveRisk DESC:
          assetId, name, type, criticality, exposure, owner, environment,
          vulnerabilityCount, maxCveRisk, riskLevel, cveIds
        """
        logger.info("get_critical_assets: threshold=%d", min_criticality)

        query = """
        MATCH (a:Asset) WHERE a.criticality >= $min_crit
        OPTIONAL MATCH (a)-[:HAS_VULNERABILITY]->(v:Vulnerability)
        RETURN
            a.id            AS assetId,
            a.name          AS name,
            a.type          AS type,
            a.criticality   AS criticality,
            a.exposure      AS exposure,
            a.owner         AS owner,
            a.environment   AS environment,
            count(v)        AS vulnerabilityCount,
            max(v.cvss_score) AS maxCvssScore,
            collect(v.cve_id) AS cveIds
        ORDER BY a.criticality DESC, max(v.cvss_score) DESC
        """

        rows = neo4j_client.run_query(query, {"min_crit": min_criticality})

        if getattr(neo4j_client, "mock_mode", False) or not rows:
            logger.warning("get_critical_assets: using mock fallback.")
            rows = self._mock_critical_assets_rows(min_criticality)

        risks = self._get_asset_risks(neo4j_client)

        result: list[dict] = []
        for row in rows:
            asset_id    = row.get("assetId", "")
            crit        = int(row.get("criticality") or 5)
            max_cvss    = float(row.get("maxCvssScore") or 0.0)
            asset_risks = risks.get(asset_id, {})
            max_risk    = asset_risks.get("maxRiskScore", 0.0)

            # Derive risk level from the asset's worst CVE composite score
            from ml.risk_scorer import RiskScorer
            level = RiskScorer().classify_risk(max_risk)

            result.append({
                "assetId":            asset_id,
                "name":               row.get("name",  "Unknown"),
                "type":               row.get("type",  "Unknown"),
                "criticality":        crit,
                "exposure":           row.get("exposure",    "Unknown"),
                "owner":              row.get("owner",       "Unknown"),
                "environment":        row.get("environment", "Unknown"),
                "vulnerabilityCount": int(row.get("vulnerabilityCount") or 0),
                "maxCvssScore":       round(max_cvss, 2),
                "maxCveRisk":         round(max_risk, 2),
                "riskLevel":          level,
                "cveIds":             [c for c in (row.get("cveIds") or []) if c],
            })

        logger.info("get_critical_assets: returned %d assets.", len(result))
        return result

    # ──────────────────────────────────────────────────────────────────────────
    # Backward-compatible methods (used by existing /attack-path route)
    # ──────────────────────────────────────────────────────────────────────────

    def load_network_graph(self) -> None:
        """Legacy: populate self._nx_graph from the stored db client."""
        if self._db is None:
            return
        topo  = self._get_topology(self._db)
        risks = self._get_asset_risks(self._db)
        self._nx_graph = self._build_nx_graph(topo, risks)

    def find_shortest_attack_path(self, source_id: str, target_id: str) -> list[str]:
        """
        Legacy method: find the shortest hop path (unweighted) between two nodes.
        Used by GET /graph/attack-path.
        """
        self.load_network_graph()
        try:
            return nx.shortest_path(self._nx_graph, source=source_id, target=target_id)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def calculate_blast_radius(self, asset_id: str) -> int:
        """Legacy: count assets reachable downstream from asset_id."""
        self.load_network_graph()
        if asset_id not in self._nx_graph:
            return 0
        return len(nx.descendants(self._nx_graph, asset_id))

    def invalidate_cache(self) -> None:
        """Force-expire both topology and risk caches."""
        self._topo_cache  = None
        self._topo_ts     = 0.0
        self._risk_cache  = None
        self._risk_ts     = 0.0
        logger.info("AttackPathAnalyzer caches invalidated.")

    # ──────────────────────────────────────────────────────────────────────────
    # Cache-aware data fetchers
    # ──────────────────────────────────────────────────────────────────────────

    def _get_topology(self, neo4j_client) -> dict:
        """Return {nodes: [...], edges: [...]} with TTL caching."""
        now = time.monotonic()
        if self._topo_cache is not None and (now - self._topo_ts) < _TOPOLOGY_TTL:
            logger.debug("Topology cache HIT.")
            return self._topo_cache

        logger.info("Topology cache MISS — querying Neo4j …")

        # Asset nodes
        node_rows = neo4j_client.run_query(
            "MATCH (a:Asset) RETURN "
            "a.id AS id, a.name AS name, a.type AS type, "
            "a.criticality AS criticality, a.exposure AS exposure"
        )

        # Lateral edges
        edge_rows = neo4j_client.run_query(
            "MATCH (a:Asset)-[:CONNECTS_TO]->(b:Asset) "
            "RETURN a.id AS from_id, b.id AS to_id, "
            "a.criticality AS from_crit"
        )

        # Mock fallback
        if getattr(neo4j_client, "mock_mode", False) or not node_rows:
            node_rows, edge_rows = self._mock_topology()

        self._topo_cache = {"nodes": node_rows, "edges": edge_rows}
        self._topo_ts    = now
        logger.info("Topology loaded: %d nodes, %d edges.", len(node_rows), len(edge_rows))
        return self._topo_cache

    def _get_asset_risks(self, neo4j_client) -> dict[str, dict]:
        """
        Return {assetId: {maxRiskScore, kevPresent, worstCveId, cves: [...]}}
        with TTL caching.
        """
        now = time.monotonic()
        if self._risk_cache is not None and (now - self._risk_ts) < _RISK_TTL:
            logger.debug("Risk cache HIT.")
            return self._risk_cache

        logger.info("Risk cache MISS — querying Neo4j …")

        rows = neo4j_client.run_query(
            "MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability) "
            "RETURN a.id AS assetId, "
            "v.cve_id AS cveId, v.cvss_score AS cvssScore, "
            "v.epss_score AS epssScore, v.is_kev AS isKEV, "
            "a.criticality AS assetCriticality"
        )

        risk_map: dict[str, dict] = {}

        if not getattr(neo4j_client, "mock_mode", False) and rows:
            from ml.risk_scorer import RiskScorer
            scorer = RiskScorer()

            for row in rows:
                aid  = row.get("assetId", "")
                if not aid:
                    continue

                scored = scorer.score_cve({
                    "cvssScore":        row.get("cvssScore"),
                    "epssScore":        row.get("epssScore"),
                    "isKEV":            row.get("isKEV"),
                    "assetCriticality": row.get("assetCriticality"),
                })
                rs = scored["riskScore"]

                if aid not in risk_map:
                    risk_map[aid] = {
                        "maxRiskScore": 0.0,
                        "totalRiskScore": 0.0,
                        "kevPresent":   False,
                        "worstCveId":   None,
                        "cves":         [],
                    }

                risk_map[aid]["cves"].append({
                    "cveId":     row.get("cveId"),
                    "riskScore": rs,
                    "isKEV":     bool(row.get("isKEV", False)),
                })
                risk_map[aid]["totalRiskScore"] += rs
                if rs > risk_map[aid]["maxRiskScore"]:
                    risk_map[aid]["maxRiskScore"] = rs
                    risk_map[aid]["worstCveId"]   = row.get("cveId")
                if row.get("isKEV"):
                    risk_map[aid]["kevPresent"] = True
        else:
            risk_map = self._mock_asset_risks()

        self._risk_cache = risk_map
        self._risk_ts    = now
        logger.info("Asset risk map built for %d assets.", len(risk_map))
        return risk_map

    # ──────────────────────────────────────────────────────────────────────────
    # Graph construction
    # ──────────────────────────────────────────────────────────────────────────

    def _build_nx_graph(
        self,
        topo:  dict,
        risks: dict[str, dict],
    ) -> nx.DiGraph:
        """
        Build a weighted directed graph.
        Edge weight = 1 / from_node_criticality  (lower crit → harder to cross).
        """
        G = nx.DiGraph()

        for node in topo["nodes"]:
            nid  = node.get("id", "")
            crit = int(node.get("criticality") or 5)
            risk = risks.get(nid, {})
            G.add_node(
                nid,
                name          = node.get("name",     nid),
                type          = node.get("type",      "Asset"),
                criticality   = crit,
                exposure      = node.get("exposure",  "Unknown"),
                maxRiskScore  = risk.get("maxRiskScore",   0.0),
                totalRiskScore= risk.get("totalRiskScore", 0.0),
                kevPresent    = risk.get("kevPresent",     False),
                worstCveId    = risk.get("worstCveId",     None),
                cves          = risk.get("cves",           []),
            )

        for edge in topo["edges"]:
            from_id   = edge.get("from_id", "")
            to_id     = edge.get("to_id",   "")
            from_crit = int(edge.get("from_crit") or 5)
            if from_id and to_id:
                weight = round(1.0 / max(from_crit, 1), 4)
                G.add_edge(from_id, to_id, weight=weight)

        logger.debug("NX graph built: %d nodes, %d edges.", G.number_of_nodes(), G.number_of_edges())
        return G

    # ──────────────────────────────────────────────────────────────────────────
    # Path scoring & explanation
    # ──────────────────────────────────────────────────────────────────────────

    def _score_path(
        self,
        path_nodes: list[str],
        graph: nx.DiGraph,
        risks: dict[str, dict],
    ) -> dict[str, Any]:
        """Compute composite risk score for a single attack path."""
        total_risk    = 0.0
        contains_kev  = False
        worst_cve_id  = None
        worst_cve_risk = 0.0

        node_details: list[dict] = []

        for nid in path_nodes:
            nd          = graph.nodes.get(nid, {})
            asset_risk  = risks.get(nid, {})
            node_score  = asset_risk.get("totalRiskScore", 0.0)
            total_risk += node_score

            if asset_risk.get("kevPresent"):
                contains_kev = True

            cve_id = asset_risk.get("worstCveId")
            cve_rs = asset_risk.get("maxRiskScore", 0.0)
            if cve_rs > worst_cve_risk:
                worst_cve_risk = cve_rs
                worst_cve_id   = cve_id

            node_details.append({
                "assetId":      nid,
                "name":         nd.get("name", nid),
                "criticality":  nd.get("criticality", 5),
                "nodeRiskScore": round(node_score, 2),
                "kevPresent":   asset_risk.get("kevPresent", False),
                "worstCveId":   cve_id,
            })

        explanation = self._explain_path(path_nodes, node_details, total_risk, contains_kev)

        return {
            "path_nodes":       path_nodes,
            "node_details":     node_details,
            "total_risk_score": round(total_risk, 2),
            "hop_count":        len(path_nodes) - 1,
            "highest_risk_cve": worst_cve_id,
            "contains_kev":     contains_kev,
            "explanation":      explanation,
        }

    def _explain_path(
        self,
        path_nodes:   list[str],
        node_details: list[dict],
        total_risk:   float,
        contains_kev: bool,
    ) -> str:
        steps = " → ".join(nd["name"] for nd in node_details)
        lines = [
            f"Attack path ({len(path_nodes)-1} hops): {steps}.",
            f"Cumulative risk score: {total_risk:.1f}.",
        ]
        if contains_kev:
            kev_assets = [nd["name"] for nd in node_details if nd.get("kevPresent")]
            lines.append(
                f"Path traverses {len(kev_assets)} CISA KEV-confirmed asset(s): "
                f"{', '.join(kev_assets)}."
            )
        high_crit = [nd for nd in node_details if nd["criticality"] >= 9]
        if high_crit:
            lines.append(
                f"Passes through {len(high_crit)} critical asset(s) "
                f"(criticality ≥ 9): "
                f"{', '.join(nd['name'] for nd in high_crit)}."
            )
        lines.append("Immediate remediation is strongly recommended.")
        return " ".join(lines)

    def _no_path_result(self, source: str, target: str, reason: str) -> dict:
        return {
            "path_nodes":       [source, target],
            "node_details":     [],
            "total_risk_score": 0.0,
            "hop_count":        0,
            "highest_risk_cve": None,
            "contains_kev":     False,
            "explanation":      f"No attack path found from '{source}' to '{target}': {reason}.",
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Mock fallbacks
    # ──────────────────────────────────────────────────────────────────────────

    def _mock_topology(self) -> tuple[list, list]:
        """12-node banking topology fallback for mock / offline mode."""
        nodes = [
            # DMZ Zone
            {"id": "SRV-DMZ-WEB-01",  "name": "Retail Internet Banking Web Server", "type": "Gateway",       "criticality":  8, "exposure": "Public"},
            {"id": "SRV-DMZ-GW-02",   "name": "Mobile Banking API Gateway",         "type": "Gateway",       "criticality":  8, "exposure": "Public"},
            {"id": "SRV-DMZ-CMS-03",  "name": "Public CMS Portal",                  "type": "WebApp",        "criticality":  5, "exposure": "Public"},
            # Middleware Zone
            {"id": "SRV-MID-ESB-01",  "name": "Enterprise Service Bus",             "type": "Middleware",    "criticality":  8, "exposure": "Internal"},
            {"id": "SRV-MID-IAM-02",  "name": "Customer Identity & Access Manager", "type": "IAM",           "criticality": 10, "exposure": "Internal"},
            {"id": "SRV-MID-SWI-03",  "name": "Universal Payment Switch",           "type": "PaymentSwitch", "criticality": 10, "exposure": "Internal"},
            # Core Zone
            {"id": "SRV-CORE-CBS-01", "name": "Core Banking System App Server",     "type": "AppServer",     "criticality": 10, "exposure": "Private"},
            {"id": "DB-CORE-LEDG-02", "name": "Central Production Database",        "type": "Database",      "criticality": 10, "exposure": "Private"},
            {"id": "SRV-CORE-SWIFT-03","name": "SWIFT Transaction Appliance",       "type": "SWIFT",         "criticality": 10, "exposure": "Private"},
            # Management Zone
            {"id": "SRV-MGMT-AD-01",  "name": "Active Directory Domain Controller", "type": "AD",            "criticality": 10, "exposure": "Internal"},
            {"id": "SRV-MGMT-JUMP-02","name": "Enterprise Jump Server / Bastion",   "type": "Bastion",       "criticality":  8, "exposure": "Internal"},
            {"id": "SRV-MGMT-SIEM-03","name": "SIEM & Log Aggregator Node",         "type": "SIEM",          "criticality":  8, "exposure": "Internal"},
        ]
        edges = [
            # DMZ → Middleware
            {"from_id": "SRV-DMZ-WEB-01",   "to_id": "SRV-MID-IAM-02",    "from_crit":  8},
            {"from_id": "SRV-DMZ-WEB-01",   "to_id": "SRV-DMZ-GW-02",     "from_crit":  8},
            {"from_id": "SRV-DMZ-GW-02",    "to_id": "SRV-MID-SWI-03",    "from_crit":  8},
            {"from_id": "SRV-DMZ-GW-02",    "to_id": "SRV-MID-ESB-01",    "from_crit":  8},
            # Middleware → Core
            {"from_id": "SRV-MID-ESB-01",   "to_id": "SRV-CORE-CBS-01",   "from_crit":  8},
            {"from_id": "SRV-MID-ESB-01",   "to_id": "DB-CORE-LEDG-02",   "from_crit":  8},
            {"from_id": "SRV-MID-IAM-02",   "to_id": "SRV-MGMT-SIEM-03", "from_crit": 10},
            {"from_id": "SRV-MID-SWI-03",   "to_id": "DB-CORE-LEDG-02",   "from_crit": 10},
            {"from_id": "SRV-MID-SWI-03",   "to_id": "SRV-CORE-CBS-01",   "from_crit": 10},
            # Core internal
            {"from_id": "SRV-CORE-CBS-01",  "to_id": "DB-CORE-LEDG-02",   "from_crit": 10},
            {"from_id": "SRV-CORE-CBS-01",  "to_id": "SRV-MGMT-JUMP-02",  "from_crit": 10},
            # Management
            {"from_id": "SRV-MGMT-AD-01",   "to_id": "SRV-DMZ-WEB-01",    "from_crit": 10},
            {"from_id": "SRV-MGMT-AD-01",   "to_id": "SRV-MID-ESB-01",    "from_crit": 10},
            {"from_id": "SRV-MGMT-AD-01",   "to_id": "SRV-CORE-CBS-01",   "from_crit": 10},
            {"from_id": "SRV-MGMT-JUMP-02", "to_id": "SRV-CORE-CBS-01",   "from_crit":  8},
            {"from_id": "SRV-MGMT-JUMP-02", "to_id": "DB-CORE-LEDG-02",   "from_crit":  8},
            {"from_id": "SRV-MGMT-JUMP-02", "to_id": "SRV-CORE-SWIFT-03", "from_crit":  8},
            {"from_id": "SRV-MGMT-SIEM-03", "to_id": "SRV-MGMT-AD-01",    "from_crit":  8},
        ]
        return nodes, edges

    def _mock_asset_risks(self) -> dict[str, dict]:
        """12-asset CVE risk map fallback using real CVEs from the library."""
        from ml.risk_scorer import RiskScorer
        scorer = RiskScorer()
        # (assetId, cveId, cvss, epss, isKEV, criticality)
        mock_cves = [
            ("SRV-DMZ-WEB-01",   "CVE-2023-25690",  9.8, 0.9341, True,   8),
            ("SRV-DMZ-GW-02",    "CVE-2022-41915",  7.5, 0.6230, False,  8),
            ("SRV-DMZ-CMS-03",   "CVE-2021-29447",  8.0, 0.7812, True,   5),
            ("SRV-MID-ESB-01",   "CVE-2021-44228", 10.0, 0.9763, True,   8),
            ("SRV-MID-IAM-02",   "CVE-2022-37434",  9.8, 0.8912, True,  10),
            ("SRV-MID-SWI-03",   "CVE-2023-28432",  7.5, 0.6540, True,  10),
            ("SRV-CORE-CBS-01",  "CVE-2023-21839",  7.5, 0.7234, True,  10),
            ("DB-CORE-LEDG-02",  "CVE-2022-21569",  7.5, 0.5810, False, 10),
            ("SRV-CORE-SWIFT-03","CVE-2023-38606",  7.8, 0.6980, True,  10),
            ("SRV-MGMT-AD-01",   "CVE-2022-26925",  9.8, 0.9120, True,  10),
            ("SRV-MGMT-JUMP-02", "CVE-2023-30570",  8.1, 0.7456, False,  8),
            ("SRV-MGMT-SIEM-03", "CVE-2023-31414",  7.5, 0.5230, False,  8),
        ]
        risk_map: dict[str, dict] = {}
        for aid, cve_id, cvss, epss, kev, crit in mock_cves:
            scored = scorer.score_cve({
                "cvssScore": cvss, "epssScore": epss,
                "isKEV": kev, "assetCriticality": crit,
            })
            risk_map[aid] = {
                "maxRiskScore":   scored["riskScore"],
                "totalRiskScore": scored["riskScore"],
                "kevPresent":     kev,
                "worstCveId":     cve_id,
                "cves": [{"cveId": cve_id, "riskScore": scored["riskScore"], "isKEV": kev}],
            }
        return risk_map

    def _mock_critical_assets_rows(self, min_criticality: int) -> list[dict]:
        """12-asset fallback for get_critical_assets() in mock mode."""
        all_assets = [
            {"assetId": "SRV-DMZ-WEB-01",   "name": "Retail Internet Banking Web Server", "type": "Gateway",       "criticality":  8, "exposure": "Public",    "owner": "Digital Banking Team", "environment": "Production", "vulnerabilityCount": 1, "maxCvssScore": 9.8,  "cveIds": ["CVE-2023-25690"]},
            {"assetId": "SRV-DMZ-GW-02",    "name": "Mobile Banking API Gateway",         "type": "Gateway",       "criticality":  8, "exposure": "Public",    "owner": "Platform Engineering","environment": "Production", "vulnerabilityCount": 1, "maxCvssScore": 7.5,  "cveIds": ["CVE-2022-41915"]},
            {"assetId": "SRV-DMZ-CMS-03",   "name": "Public CMS Portal",                  "type": "WebApp",        "criticality":  5, "exposure": "Public",    "owner": "Marketing IT",        "environment": "Production", "vulnerabilityCount": 1, "maxCvssScore": 8.0,  "cveIds": ["CVE-2021-29447"]},
            {"assetId": "SRV-MID-ESB-01",   "name": "Enterprise Service Bus",             "type": "Middleware",    "criticality":  8, "exposure": "Internal",  "owner": "Integration Team",    "environment": "Production", "vulnerabilityCount": 1, "maxCvssScore": 10.0, "cveIds": ["CVE-2021-44228"]},
            {"assetId": "SRV-MID-IAM-02",   "name": "Customer Identity & Access Manager", "type": "IAM",           "criticality": 10, "exposure": "Internal",  "owner": "Identity Team",       "environment": "Production", "vulnerabilityCount": 1, "maxCvssScore": 9.8,  "cveIds": ["CVE-2022-37434"]},
            {"assetId": "SRV-MID-SWI-03",   "name": "Universal Payment Switch",           "type": "PaymentSwitch", "criticality": 10, "exposure": "Internal",  "owner": "Payments Team",       "environment": "Production", "vulnerabilityCount": 1, "maxCvssScore": 7.5,  "cveIds": ["CVE-2023-28432"]},
            {"assetId": "SRV-CORE-CBS-01",  "name": "Core Banking System App Server",     "type": "AppServer",     "criticality": 10, "exposure": "Private",   "owner": "CBS Team",            "environment": "Production", "vulnerabilityCount": 1, "maxCvssScore": 7.5,  "cveIds": ["CVE-2023-21839"]},
            {"assetId": "DB-CORE-LEDG-02",  "name": "Central Production Database",        "type": "Database",      "criticality": 10, "exposure": "Private",   "owner": "Data Platform Team",  "environment": "Production", "vulnerabilityCount": 1, "maxCvssScore": 7.5,  "cveIds": ["CVE-2022-21569"]},
            {"assetId": "SRV-CORE-SWIFT-03","name": "SWIFT Transaction Appliance",        "type": "SWIFT",         "criticality": 10, "exposure": "Private",   "owner": "Treasury Operations",  "environment": "Production", "vulnerabilityCount": 1, "maxCvssScore": 7.8,  "cveIds": ["CVE-2023-38606"]},
            {"assetId": "SRV-MGMT-AD-01",   "name": "Active Directory Domain Controller", "type": "AD",            "criticality": 10, "exposure": "Internal",  "owner": "IT Operations",       "environment": "Production", "vulnerabilityCount": 1, "maxCvssScore": 9.8,  "cveIds": ["CVE-2022-26925"]},
            {"assetId": "SRV-MGMT-JUMP-02", "name": "Enterprise Jump Server / Bastion",   "type": "Bastion",       "criticality":  8, "exposure": "Internal",  "owner": "IT Security",         "environment": "Production", "vulnerabilityCount": 1, "maxCvssScore": 8.1,  "cveIds": ["CVE-2023-30570"]},
            {"assetId": "SRV-MGMT-SIEM-03", "name": "SIEM & Log Aggregator Node",         "type": "SIEM",          "criticality":  8, "exposure": "Internal",  "owner": "SOC Team",            "environment": "Production", "vulnerabilityCount": 1, "maxCvssScore": 7.5,  "cveIds": ["CVE-2023-31414"]},
        ]
        return [a for a in all_assets if a["criticality"] >= min_criticality]


logger.info("AttackPathAnalyzer module loaded.")
