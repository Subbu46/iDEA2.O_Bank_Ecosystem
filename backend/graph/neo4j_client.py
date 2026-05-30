"""
neo4j_client.py
---------------
Manages Neo4j Aura driver lifecycle, session/transaction helpers,
constraint/index creation, and a graceful in-memory mock fallback.

Design decisions
----------------
- Uses the official `neo4j` Python driver (bolt+neo4j+s protocol).
- All write paths go through execute_write() which opens a write transaction.
- Batched write helper (execute_batch) groups parameter lists into chunks so
  Aura is never overwhelmed by huge single transactions.
- Mock mode is activated only when the real connection fails, so the frontend
  stays functional during local development without Aura access.
"""

from __future__ import annotations

import logging
from typing import Any

from neo4j import GraphDatabase, exceptions as neo4j_exc
from config import settings

logger = logging.getLogger("sarathi.neo4j")

# ──────────────────────────────────────────────
# Default batch size for Aura-safe bulk writes
# ──────────────────────────────────────────────
BATCH_SIZE = 250


class Neo4jClient:
    """
    Handles all Neo4j driver initialisation, session management and queries.
    Includes a graceful in-memory mock fallback to support standalone
    execution without a live Neo4j instance.
    """

    # ------------------------------------------------------------------ #
    # Construction / connection                                            #
    # ------------------------------------------------------------------ #

    def __init__(self):
        self.uri = settings.NEO4J_URI
        self.username = settings.NEO4J_USERNAME
        self.password = settings.NEO4J_PASSWORD
        self.driver = None
        self.mock_mode = False

        # Local mock state (populated only in fallback mode)
        self.mock_nodes: dict[str, dict] = {}
        self.mock_relationships: list[dict] = []

        self._connect()

    def _connect(self):
        """Attempt to open and verify the Aura driver connection."""
        try:
            self.driver = GraphDatabase.driver(
                self.uri,
                auth=(self.username, self.password),
                max_connection_lifetime=3600,   # 1 hour
                max_connection_pool_size=50,
                connection_timeout=30,
            )
            self.driver.verify_connectivity()
            logger.info("✅  Neo4j Aura: connected to %s", self.uri)
        except Exception as exc:
            logger.warning(
                "⚠️  Neo4j connection failed (%s). Activating in-memory mock mode.", exc
            )
            self.mock_mode = True
            self._init_mock_data()

    def close(self):
        """Cleanly close the driver connection pool."""
        if self.driver:
            self.driver.close()
            logger.info("Neo4j driver closed.")

    # ------------------------------------------------------------------ #
    # Schema setup                                                         #
    # ------------------------------------------------------------------ #

    def setup_constraints_and_indexes(self):
        """
        Creates uniqueness constraints for primary identifiers and indexes
        for frequently queried properties.  Safe to call multiple times –
        Neo4j silently ignores already-existing constraints/indexes.
        """
        if self.mock_mode:
            logger.info("[mock] Schema constraints skipped in mock mode.")
            return

        constraints = [
            # Uniqueness constraints (also auto-create a lookup index)
            "CREATE CONSTRAINT cve_id_unique IF NOT EXISTS FOR (c:CVE) REQUIRE c.cveId IS UNIQUE",
            "CREATE CONSTRAINT technique_id_unique IF NOT EXISTS FOR (t:Technique) REQUIRE t.techniqueId IS UNIQUE",
            "CREATE CONSTRAINT asset_id_unique IF NOT EXISTS FOR (a:Asset) REQUIRE a.assetId IS UNIQUE",
            "CREATE CONSTRAINT actor_name_unique IF NOT EXISTS FOR (ta:ThreatActor) REQUIRE ta.name IS UNIQUE",
            # Additional property indexes
            "CREATE INDEX cve_severity IF NOT EXISTS FOR (c:CVE) ON (c.severity)",
            "CREATE INDEX cve_is_kev IF NOT EXISTS FOR (c:CVE) ON (c.isKEV)",
            "CREATE INDEX asset_criticality IF NOT EXISTS FOR (a:Asset) ON (a.criticality)",
        ]

        with self.driver.session() as session:
            for stmt in constraints:
                try:
                    session.run(stmt)
                    logger.debug("Schema: %s", stmt)
                except Exception as exc:
                    # Already exists or minor syntax difference in older Neo4j
                    logger.debug("Schema note: %s → %s", stmt[:60], exc)

        logger.info("✅  Schema constraints and indexes verified.")

    # ------------------------------------------------------------------ #
    # Query helpers                                                        #
    # ------------------------------------------------------------------ #

    def run_query(self, query: str, parameters: dict | None = None) -> list[dict]:
        """
        Execute a read (or write) Cypher query and return all records as dicts.
        In mock mode, a very basic parser returns sample data so the frontend
        renders correctly.
        """
        if self.mock_mode:
            return self._mock_run_query(query)

        with self.driver.session() as session:
            result = session.run(query, parameters or {})
            return [record.data() for record in result]

    def execute_write(self, query: str, parameters: dict | None = None):
        """
        Execute a single write Cypher statement inside a write transaction.
        """
        if self.mock_mode:
            logger.debug("[mock] write skipped: %s", query[:80])
            return

        def _work(tx):
            tx.run(query, parameters or {})

        with self.driver.session() as session:
            session.execute_write(_work)

    def execute_batch(self, query: str, param_list: list[dict], batch_size: int = BATCH_SIZE):
        """
        Execute a Cypher query that accepts an `$items` list parameter
        (UNWIND $items AS row …) in chunks of `batch_size`.

        This is the preferred path for bulk node/relationship ingestion because
        it limits individual transaction size for Aura compatibility.
        """
        if self.mock_mode:
            logger.debug("[mock] batch write skipped (%d items).", len(param_list))
            return

        total = len(param_list)
        ingested = 0

        for start in range(0, total, batch_size):
            chunk = param_list[start: start + batch_size]

            def _work(tx, items=chunk):
                tx.run(query, {"items": items})

            with self.driver.session() as session:
                session.execute_write(_work)

            ingested += len(chunk)
            logger.debug("  batch progress: %d / %d", ingested, total)

        logger.info("  ✓ batch complete: %d records.", total)

    # ------------------------------------------------------------------ #
    # Convenience statistics                                               #
    # ------------------------------------------------------------------ #

    def get_node_counts(self) -> dict[str, int]:
        """Return {label: count} for every node label in the graph."""
        if self.mock_mode:
            counts: dict[str, int] = {}
            for node in self.mock_nodes.values():
                lbl = node.get("label", "Unknown")
                counts[lbl] = counts.get(lbl, 0) + 1
            return counts

        rows = self.run_query(
            "CALL db.labels() YIELD label "
            "CALL apoc.cypher.run('MATCH (n:`' + label + '`) RETURN count(n) AS cnt', {}) YIELD value "
            "RETURN label, value.cnt AS count"
        )
        # apoc may not be available on all Aura tiers – fall back to per-label queries
        if not rows:
            rows = self.run_query(
                "MATCH (n) RETURN labels(n)[0] AS label, count(n) AS count"
            )
        return {r["label"]: r["count"] for r in rows if r.get("label")}

    def get_relationship_counts(self) -> dict[str, int]:
        """Return {rel_type: count} for every relationship type in the graph."""
        if self.mock_mode:
            counts: dict[str, int] = {}
            for rel in self.mock_relationships:
                t = rel.get("type", "UNKNOWN")
                counts[t] = counts.get(t, 0) + 1
            return counts

        rows = self.run_query(
            "MATCH ()-[r]->() RETURN type(r) AS rel_type, count(r) AS count"
        )
        return {r["rel_type"]: r["count"] for r in rows if r.get("rel_type")}

    # ------------------------------------------------------------------ #
    # Cleanup / dev-mode reset                                            #
    # ------------------------------------------------------------------ #

    def reset_graph(self, confirm: bool = False):
        """
        DEVELOPMENT UTILITY – deletes ALL nodes and relationships.
        Requires confirm=True to prevent accidental calls.
        """
        if not confirm:
            logger.warning("reset_graph() called without confirm=True. Skipping.")
            return

        if self.mock_mode:
            self.mock_nodes.clear()
            self.mock_relationships.clear()
            logger.info("[mock] in-memory graph cleared.")
            return

        logger.warning("🗑️  Resetting graph – MATCH (n) DETACH DELETE n")
        with self.driver.session() as session:
            # Delete in batches to avoid timeout on large graphs
            while True:
                result = session.run(
                    "MATCH (n) WITH n LIMIT 10000 DETACH DELETE n RETURN count(n) AS deleted"
                )
                deleted = result.single()["deleted"]
                logger.info("  deleted %d nodes …", deleted)
                if deleted == 0:
                    break
        logger.info("✅  Graph reset complete.")

    def drop_constraints_and_indexes(self):
        """
        DEVELOPMENT UTILITY – removes all user-created constraints and indexes.
        Useful when you want a completely clean slate.
        """
        if self.mock_mode:
            return

        rows = self.run_query("SHOW CONSTRAINTS YIELD name")
        for row in rows:
            name = row.get("name")
            if name:
                try:
                    self.execute_write(f"DROP CONSTRAINT {name} IF EXISTS")
                    logger.debug("Dropped constraint: %s", name)
                except Exception:
                    pass

        rows2 = self.run_query("SHOW INDEXES YIELD name, type WHERE type <> 'LOOKUP'")
        for row in rows2:
            name = row.get("name")
            if name:
                try:
                    self.execute_write(f"DROP INDEX {name} IF EXISTS")
                    logger.debug("Dropped index: %s", name)
                except Exception:
                    pass

        logger.info("✅  All constraints and indexes dropped.")

    # ------------------------------------------------------------------ #
    # Mock fallback data                                                   #
    # ------------------------------------------------------------------ #

    def _mock_run_query(self, query: str) -> list[dict]:
        """Minimal mock query dispatcher for the frontend."""
        q = query.upper()
        if "HAS_VULNERABILITY" in q:
            rows = []
            for rel in self.mock_relationships:
                if rel["type"] == "HAS_VULNERABILITY":
                    asset = self.mock_nodes.get(rel["from"])
                    cve = self.mock_nodes.get(rel["to"])
                    if asset and cve:
                        # Find mapped MITRE technique
                        tech_id = ""
                        tech_name = ""
                        for t_rel in self.mock_relationships:
                            if t_rel["from"] == cve["id"] and t_rel["type"] == "MAPS_TO_TECHNIQUE":
                                tech_id = t_rel["to"]
                                tech_node = self.mock_nodes.get(tech_id)
                                if tech_node:
                                    tech_name = tech_node.get("name", "")
                                break
                        
                        rows.append({
                            "assetName": asset.get("name", "Unknown Asset"),
                            "assetId": asset.get("id", ""),
                            "assetCriticality": asset.get("criticality", 5),
                            "assetType": asset.get("type", "Server"),
                            "cveId": cve.get("cveId") or cve.get("id") or "UNKNOWN",
                            "cvssScore": cve.get("cvssScore") or cve.get("cvss_score") or 5.0,
                            "epssScore": cve.get("epssScore") or cve.get("epss_score") or 0.015,
                            "isKEV": bool(cve.get("isKEV") or cve.get("is_kev") or False),
                            "severity": cve.get("severity", "MEDIUM"),
                            "kevDueDate": cve.get("kevDueDate", "N/A"),
                            "description": cve.get("description", ""),
                            "techniqueId": tech_id,
                            "techniqueName": tech_name
                        })
            # Sort mock data by cvssScore DESC just like the Cypher query does
            rows.sort(key=lambda x: x.get("cvssScore", 0.0), reverse=True)
            return rows

        if "MATCH (N)" in q or "MATCH (N:" in q:
            return [{"n": v} for v in self.mock_nodes.values()]
        if "MATCH (A)-[R]->(B)" in q or "MATCH ()-[R]->()" in q:
            return [
                {"source": r["from"], "target": r["to"], "type": r["type"]}
                for r in self.mock_relationships
            ]
        # Default: return nodes
        return [{"n": v} for v in self.mock_nodes.values()]

    def _init_mock_data(self):
        """Seed the in-memory mock store with representative graph data."""
        self.mock_nodes = {}
        self.mock_relationships = []

        try:
            from graph.graph_builder import ASSETS, TOPOLOGY, CVE_LIBRARY
            from ingestion.mitre_fetcher import MitreFetcher
            mitre = MitreFetcher()

            # Add Asset nodes
            for asset in ASSETS:
                self.mock_nodes[asset["id"]] = {
                    "id": asset["id"],
                    "label": "Asset",
                    "name": asset["name"],
                    "type": asset["type"],
                    "zone": asset["zone"],
                    "criticality": asset["criticality"],
                    "exposure": asset["exposure"],
                    "ip_address": asset["ip_address"],
                    "os_version": asset["os_version"],
                    "owner": asset["owner"],
                    "environment": asset["environment"],
                    "software_stack": ",".join(asset["software_stack"]),
                    "assetId": asset["id"]
                }

            # Add lateral connection relationships (Asset connects to Asset)
            for src_id, tgt_id in TOPOLOGY:
                self.mock_relationships.append({
                    "from": src_id,
                    "to": tgt_id,
                    "type": "CONNECTS_TO"
                })

            # Add Vulnerability nodes and their relationship to Assets (software-stack based)
            for cve in CVE_LIBRARY:
                cve_id = cve["cve_id"]
                self.mock_nodes[cve_id] = {
                    "id": cve_id,
                    "label": "CVE",
                    "name": cve_id,
                    "cveId": cve_id,
                    "cvssScore": cve["cvss_score"],
                    "severity": cve["severity"],
                    "description": cve["description"],
                    "affected_product": cve["affected_product"],
                    "published_date": cve["published_date"],
                    "isKEV": cve_id in ["CVE-2021-44228", "CVE-2023-25690", "CVE-2022-26925"],
                    "epssScore": 0.85 if cve["cvss_score"] > 9.0 else 0.45
                }
                
                # Map CVE to Asset based on software stack
                affected_product = cve["affected_product"]
                for asset in ASSETS:
                    if affected_product in asset["software_stack"]:
                        self.mock_relationships.append({
                            "from": asset["id"],
                            "to": cve_id,
                            "type": "HAS_VULNERABILITY"
                        })

                # Map Technique details
                attack_details = mitre.get_attack_details(cve_id)
                tech_id = attack_details["technique_id"]
                
                # Add Technique node
                if tech_id not in self.mock_nodes:
                    self.mock_nodes[tech_id] = {
                        "id": tech_id,
                        "label": "Technique",
                        "name": attack_details["technique_name"],
                        "techniqueId": tech_id,
                        "tactic": attack_details["tactic"],
                        "capec_id": attack_details["capec_id"],
                        "capec_name": attack_details["capec_name"]
                    }
                
                # Map CVE -> Technique relationship
                self.mock_relationships.append({
                    "from": cve_id,
                    "to": tech_id,
                    "type": "MAPS_TO_TECHNIQUE"
                })

            # Add Threat Actors
            threat_actors = [
                {"id": "apt29", "name": "APT29", "motivation": "espionage", "origin": "Russia"},
                {"id": "lazarus", "name": "Lazarus Group", "motivation": "financial", "origin": "North Korea"},
                {"id": "lockbit", "name": "LockBit Ransomware", "motivation": "financial", "origin": "Cybercrime Syndicate"}
            ]
            
            for ta in threat_actors:
                self.mock_nodes[ta["id"]] = {
                    "id": ta["id"],
                    "label": "ThreatActor",
                    "name": ta["name"],
                    "motivation": ta["motivation"],
                    "origin": ta["origin"]
                }
                
            # Map Threat Actors to Techniques
            self.mock_relationships.append({"from": "apt29", "to": "T1203", "type": "USES_TECHNIQUE"})
            self.mock_relationships.append({"from": "lazarus", "to": "T1203", "type": "USES_TECHNIQUE"})
            self.mock_relationships.append({"from": "lockbit", "to": "T1203", "type": "USES_TECHNIQUE"})

        except Exception as e:
            logger.error("Failed to populate 12-node topology mock data: %s. Using basic default mock data.", e)
            self.mock_nodes = {
                "asset-web-gw": {
                    "id": "asset-web-gw", "label": "Asset",
                    "name": "Web Gateway", "type": "Server",
                    "criticality": 10, "assetId": "asset-web-gw"
                },
                "asset-db-cluster": {
                    "id": "asset-db-cluster", "label": "Asset",
                    "name": "Core DB Cluster", "type": "Database",
                    "criticality": 9, "assetId": "asset-db-cluster"
                },
                "asset-auth-api": {
                    "id": "asset-auth-api", "label": "Asset",
                    "name": "Auth API", "type": "Microservice",
                    "criticality": 8, "assetId": "asset-auth-api"
                },
                "CVE-2021-44228": {
                    "id": "CVE-2021-44228", "label": "CVE",
                    "name": "CVE-2021-44228", "cveId": "CVE-2021-44228",
                    "severity": "CRITICAL", "cvssScore": 10.0,
                    "isKEV": True, "epssScore": 0.97
                },
                "T1190": {
                    "id": "T1190", "label": "Technique",
                    "name": "Exploit Public-Facing Application",
                    "techniqueId": "T1190", "tactics": ["initial-access"]
                },
                "apt29": {
                    "id": "apt29", "label": "ThreatActor",
                    "name": "APT29", "motivation": "espionage"
                },
            }
            self.mock_relationships = [
                {"from": "CVE-2021-44228", "to": "T1190",         "type": "EXPLOITED_BY"},
                {"from": "CVE-2021-44228", "to": "asset-web-gw",  "type": "AFFECTS"},
                {"from": "T1190",          "to": "apt29",          "type": "USED_BY"},
                {"from": "asset-web-gw",   "to": "asset-auth-api", "type": "CONNECTS_TO"},
                {"from": "asset-auth-api", "to": "asset-db-cluster", "type": "CONNECTS_TO"},
            ]
