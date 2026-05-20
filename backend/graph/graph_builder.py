"""
graph_builder.py
----------------
Orchestrates the full Sarathi Cyberdefense Knowledge Graph construction:
  1. Schema constraints & indexes (delegated to Neo4jClient)
  2. Asset infrastructure nodes + lateral topology edges
  3. Threat intelligence ingestion (CVE / MITRE / EPSS / KEV)
  4. Graph statistics reporting & Cypher validation queries

Usage
-----
  # From the FastAPI startup event (main.py):
      db = Neo4jClient()
      GraphBuilder(db).build_full_graph()

  # From the standalone validation script (validate_graph.py):
      python validate_graph.py
"""

from __future__ import annotations

import logging
from typing import Any

from graph.neo4j_client import Neo4jClient
from ingestion.nvd_fetcher import NVDFetcher
from ingestion.mitre_fetcher import MitreFetcher
from ingestion.epss_fetcher import EPSSFetcher
from ingestion.kev_fetcher import KEVFetcher

logger = logging.getLogger("sarathi.graph_builder")


class GraphBuilder:
    """
    Constructs the Cyber Defense Knowledge Graph.
    Correlates vulnerabilities, assets, and attack tactics.
    """

    def __init__(self, neo4j_client: Neo4jClient):
        self.db = neo4j_client
        self.nvd = NVDFetcher()
        self.mitre = MitreFetcher()
        self.epss = EPSSFetcher()
        self.kev = KEVFetcher()

    # ------------------------------------------------------------------ #
    # Asset infrastructure seeding                                         #
    # ------------------------------------------------------------------ #

    def seed_assets(self):
        """
        Creates (or updates) the baseline Asset nodes representing the
        protected infrastructure and wires their lateral CONNECTS_TO edges.
        Uses MERGE so it is fully idempotent.
        """
        assets = [
            {
                "id": "Asset_1",
                "name": "Web Application Gateway",
                "type": "Gateway",
                "criticality": 10,
                "exposure": "Public",
                "owner": "Platform Team",
                "environment": "Production",
            },
            {
                "id": "Asset_2",
                "name": "Authentication Service",
                "type": "Microservice",
                "criticality": 9,
                "exposure": "Internal",
                "owner": "Identity Team",
                "environment": "Production",
            },
            {
                "id": "Asset_3",
                "name": "Admin Dashboard",
                "type": "WebApp",
                "criticality": 8,
                "exposure": "Internal",
                "owner": "Engineering",
                "environment": "Production",
            },
            {
                "id": "Asset_4",
                "name": "Core Database Cluster",
                "type": "Database",
                "criticality": 10,
                "exposure": "Private",
                "owner": "Data Platform Team",
                "environment": "Production",
            },
            {
                "id": "Asset_5",
                "name": "Edge Firewall Router",
                "type": "NetworkDevice",
                "criticality": 9,
                "exposure": "Public",
                "owner": "NetOps",
                "environment": "Production",
            },
        ]

        asset_query = """
        MERGE (a:Asset {id: $id})
        SET a.name        = $name,
            a.type        = $type,
            a.criticality = $criticality,
            a.exposure    = $exposure,
            a.owner       = $owner,
            a.environment = $environment
        """

        # Directed topology: (from) -[:CONNECTS_TO]-> (to)
        topology = [
            ("Asset_1", "Asset_2"),  # Gateway  → Auth Service
            ("Asset_1", "Asset_5"),  # Gateway  → Firewall
            ("Asset_2", "Asset_4"),  # Auth     → DB Cluster
            ("Asset_3", "Asset_4"),  # Admin UI → DB Cluster
            ("Asset_5", "Asset_1"),  # Firewall → Gateway  (bidirectional monitoring)
        ]

        connectivity_query = """
        MATCH (a:Asset {id: $from_id})
        MATCH (b:Asset {id: $to_id})
        MERGE (a)-[:CONNECTS_TO]->(b)
        """

        for asset in assets:
            self.db.execute_write(asset_query, asset)

        for from_id, to_id in topology:
            self.db.execute_write(connectivity_query, {"from_id": from_id, "to_id": to_id})

        logger.info("  ✓ Seeded %d asset nodes and %d topology edges.", len(assets), len(topology))
        print(f"  ✓ Seeded {len(assets)} asset nodes and {len(topology)} topology edges.")

    # ------------------------------------------------------------------ #
    # Threat intelligence ingestion                                        #
    # ------------------------------------------------------------------ #

    # ── Fixture CVEs: always ingested for demo coverage ──────────────────────
    _FIXTURE_CVES = [
        {"cve_id": "CVE-2026-1043", "severity": "CRITICAL", "cvss_score": 9.8,
         "description": "RCE in Web Gateway via crafted HTTP requests.",      "published_date": "2026-05-15"},
        {"cve_id": "CVE-2026-2090", "severity": "HIGH",     "cvss_score": 8.1,
         "description": "SQL Injection in Auth Module bypasses MFA.",           "published_date": "2026-05-18"},
        {"cve_id": "CVE-2026-3022", "severity": "MEDIUM",   "cvss_score": 6.5,
         "description": "XSS in Admin Dashboard allows priv escalation.",       "published_date": "2026-05-19"},
        {"cve_id": "CVE-2026-4401", "severity": "HIGH",     "cvss_score": 7.5,
         "description": "DoS via memory exhaustion in TLS handshake frames.",   "published_date": "2026-05-20"},
    ]

    # Explicit asset mapping for well-known CVEs
    _CVE_ASSET_MAP: dict = {
        "CVE-2026-1043": "Asset_1",   # Gateway
        "CVE-2026-4401": "Asset_5",   # Firewall
        "CVE-2026-2090": "Asset_2",   # Auth Service
        "CVE-2026-3022": "Asset_3",   # Admin Dashboard
    }

    # Fallback round-robin asset list for NVD-cache CVEs
    _ROUNDROBIN_ASSETS = ["Asset_1", "Asset_2", "Asset_3", "Asset_4", "Asset_5"]

    def build_threat_graph(self):
        """
        Fetches CVEs (NVD), EPSS scores, KEV status, and MITRE ATT&CK mappings,
        then writes Vulnerability and Technique nodes plus their relationships
        into the graph.

        Always ingests the four fixture CVEs first (full EPSS/KEV enrichment),
        then supplements with up to 6 additional CVEs from the NVD local cache,
        distributed across all assets via round-robin so every asset gets coverage.
        """
        # Always start with the fixture CVEs (they have explicit mappings)
        nvd_extra   = self.nvd.fetch_recent_cves(limit=6)
        fixture_ids = {c["cve_id"] for c in self._FIXTURE_CVES}
        # Remove any duplicates if NVD cache happens to contain them
        nvd_extra   = [c for c in nvd_extra if c["cve_id"] not in fixture_ids]
        recent_cves = self._FIXTURE_CVES + nvd_extra[:6]

        logger.info("  Processing %d CVE records …", len(recent_cves))
        rr_index = 0   # round-robin counter for unknown CVEs

        for cve in recent_cves:
            cve_id = cve["cve_id"]
            epss_data = self.epss.get_epss_score(cve_id)
            kev_data = self.kev.is_known_exploited(cve_id)
            attack_details = self.mitre.get_attack_details(cve_id)

            # ── 1. Vulnerability node ─────────────────────────────────
            self.db.execute_write(
                """
                MERGE (v:Vulnerability {cve_id: $cve_id})
                SET v.cvss_score      = $cvss_score,
                    v.severity        = $severity,
                    v.description     = $description,
                    v.epss_score      = $epss,
                    v.epss_percentile = $percentile,
                    v.is_kev          = $is_kev,
                    v.kev_due_date    = $due_date
                """,
                {
                    "cve_id":       cve_id,
                    "cvss_score":   cve["cvss_score"],
                    "severity":     cve["severity"],
                    "description":  cve["description"],
                    "epss":         epss_data["epss"],
                    "percentile":   epss_data["percentile"],
                    "is_kev":       kev_data["is_exploited"],
                    "due_date":     kev_data["due_date"],
                },
            )

            # ── 2. Technique node (MITRE ATT&CK) ─────────────────────
            self.db.execute_write(
                """
                MERGE (t:Technique {technique_id: $tech_id})
                SET t.name       = $name,
                    t.tactic     = $tactic,
                    t.capec_id   = $capec_id,
                    t.capec_name = $capec_name
                """,
                {
                    "tech_id":   attack_details["technique_id"],
                    "name":      attack_details["technique_name"],
                    "tactic":    attack_details["tactic"],
                    "capec_id":  attack_details["capec_id"],
                    "capec_name": attack_details["capec_name"],
                },
            )

            # ── 3. CVE → Technique relationship ──────────────────────
            self.db.execute_write(
                """
                MATCH (v:Vulnerability {cve_id: $cve_id})
                MATCH (t:Technique {technique_id: $tech_id})
                MERGE (v)-[:MAPS_TO_TECHNIQUE]->(t)
                """,
                {"cve_id": cve_id, "tech_id": attack_details["technique_id"]},
            )

            # ── 4. Asset → CVE exposure relationship ──────────────────
            # Explicit map for fixture CVEs; round-robin across all assets
            # for NVD-cache CVEs so every asset gets vulnerability coverage.
            if cve_id in self._CVE_ASSET_MAP:
                asset_target = self._CVE_ASSET_MAP[cve_id]
            else:
                asset_target = self._ROUNDROBIN_ASSETS[rr_index % len(self._ROUNDROBIN_ASSETS)]
                rr_index += 1

            self.db.execute_write(
                """
                MATCH (a:Asset {id: $asset_id})
                MATCH (v:Vulnerability {cve_id: $cve_id})
                MERGE (a)-[:HAS_VULNERABILITY]->(v)
                """,
                {"asset_id": asset_target, "cve_id": cve_id},
            )

        print(f"  ✓ Ingested {len(recent_cves)} CVE records into the graph.")

    # ------------------------------------------------------------------ #
    # Full graph orchestration                                             #
    # ------------------------------------------------------------------ #

    def build_full_graph(self):
        """
        Master entry point for the complete Knowledge Graph build pipeline:

          1. Schema  – constraints + indexes (idempotent)
          2. Assets  – infrastructure nodes + lateral topology edges
          3. Threats – CVE / Technique / EPSS / KEV ingestion
          4. Stats   – node/relationship counts + validation queries

        Safe to call on every startup (all writes use MERGE).
        """
        _sep = "=" * 62
        print(f"\n{_sep}")
        print("  Sarathi Cyberdefense — Knowledge Graph Build Pipeline")
        print(_sep)

        # ── Step 1: Schema ───────────────────────────────────────────
        print("\n[1/4] Setting up schema constraints and indexes …")
        self.db.setup_constraints_and_indexes()
        print("  ✓ Schema ready.")

        # ── Step 2: Assets ───────────────────────────────────────────
        print("\n[2/4] Seeding asset infrastructure nodes …")
        self.seed_assets()

        # ── Step 3: Threat intelligence ──────────────────────────────
        print("\n[3/4] Ingesting threat intelligence (CVE / MITRE / EPSS / KEV) …")
        self.build_threat_graph()

        # ── Step 4: Validate & stats ─────────────────────────────────
        print("\n[4/4] Validating graph — running statistics queries …")
        self._print_graph_statistics()
        self._run_validation_queries()

        print(f"\n{_sep}")
        print("  ✅  Knowledge Graph build complete.")
        print(f"{_sep}\n")

    # ------------------------------------------------------------------ #
    # Statistics                                                           #
    # ------------------------------------------------------------------ #

    def _print_graph_statistics(self):
        """Prints node and relationship counts for every label / type."""
        print("\n  ┌─ Node Counts ───────────────────────────────────────")
        node_counts = self.db.get_node_counts()
        if node_counts:
            for label, count in sorted(node_counts.items()):
                print(f"  │  {label:<22} {count:>5}  nodes")
        else:
            print("  │  (graph is empty – no nodes found)")
        print("  └─────────────────────────────────────────────────────")

        print("\n  ┌─ Relationship Counts ───────────────────────────────")
        rel_counts = self.db.get_relationship_counts()
        if rel_counts:
            for rel_type, count in sorted(rel_counts.items()):
                print(f"  │  {rel_type:<28} {count:>5}  relationships")
        else:
            print("  │  (no relationships found)")
        print("  └─────────────────────────────────────────────────────")

    # ------------------------------------------------------------------ #
    # Validation queries                                                   #
    # ------------------------------------------------------------------ #

    def _run_validation_queries(self):
        """
        Executes representative Cypher read queries that prove the graph is
        correctly structured and prints results for human review.
        """
        validations: list[dict[str, Any]] = [
            {
                "label": "Critical / High CVEs  (CVSS ≥ 7.0)",
                "query": (
                    "MATCH (v:Vulnerability) WHERE v.cvss_score >= 7.0 "
                    "RETURN v.cve_id AS cve_id, v.severity AS severity, "
                    "v.cvss_score AS cvss, v.is_kev AS kev "
                    "ORDER BY v.cvss_score DESC"
                ),
            },
            {
                "label": "CVEs in CISA KEV catalog",
                "query": (
                    "MATCH (v:Vulnerability {is_kev: true}) "
                    "RETURN v.cve_id AS cve_id, v.kev_due_date AS due_date, "
                    "v.cvss_score AS cvss ORDER BY v.cvss_score DESC"
                ),
            },
            {
                "label": "CVE → MITRE Technique mappings",
                "query": (
                    "MATCH (v:Vulnerability)-[:MAPS_TO_TECHNIQUE]->(t:Technique) "
                    "RETURN v.cve_id AS cve_id, t.technique_id AS technique_id, "
                    "t.name AS technique_name, t.tactic AS tactic "
                    "ORDER BY v.cve_id"
                ),
            },
            {
                "label": "Asset → Vulnerability exposure",
                "query": (
                    "MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability) "
                    "RETURN a.name AS asset, v.cve_id AS cve_id, "
                    "v.severity AS severity, v.cvss_score AS cvss "
                    "ORDER BY a.name, v.cvss_score DESC"
                ),
            },
            {
                "label": "Asset lateral movement topology",
                "query": (
                    "MATCH (a:Asset)-[:CONNECTS_TO]->(b:Asset) "
                    "RETURN a.name AS from_asset, b.name AS to_asset, "
                    "a.criticality AS from_crit "
                    "ORDER BY a.criticality DESC"
                ),
            },
            {
                "label": "High EPSS exploit probability  (≥ 0.5)",
                "query": (
                    "MATCH (v:Vulnerability) WHERE v.epss_score >= 0.5 "
                    "RETURN v.cve_id AS cve_id, v.epss_score AS epss, "
                    "v.epss_percentile AS pct "
                    "ORDER BY v.epss_score DESC"
                ),
            },
        ]

        for check in validations:
            print(f"\n  ── {check['label']} ──")
            try:
                rows = self.db.run_query(check["query"])
                if rows:
                    for row in rows:
                        line = "  |  " + "  ·  ".join(f"{k}: {v}" for k, v in row.items())
                        print(line)
                else:
                    print("  |  (no results)")
            except Exception as exc:
                print(f"  |  ⚠️  query error: {exc}")
