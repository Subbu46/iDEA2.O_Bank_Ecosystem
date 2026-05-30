"""
graph_builder.py
----------------
Orchestrates the full Sarathi Cyberdefense Knowledge Graph construction:
  1. Schema constraints & indexes (delegated to Neo4jClient)
  2. Asset infrastructure nodes + lateral topology edges
  3. Threat intelligence ingestion (CVE / MITRE / EPSS / KEV)
  4. Graph statistics reporting & Cypher validation queries

Architecture: Software-Stack-Driven CVE Mapping
------------------------------------------------
Instead of hardcoding CVE IDs directly to asset IDs, each Asset declares
a `software_stack` (list of product tags), and the CVE_LIBRARY tags each
CVE with the `affected_product` it exploits.  The graph builder auto-maps:
  for each Asset:
      for each CVE in library:
          if CVE.affected_product in Asset.software_stack → HAS_VULNERABILITY

This mirrors how real vulnerability scanners (Qualys, Nessus, Tenable)
fingerprint hosts and match CVEs — intuitive, extensible, and architecturally
honest for the MVP demonstration.

Usage
-----
  # From the FastAPI startup event (main.py):
      db = Neo4jClient()
      GraphBuilder(db).build_full_graph()
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


# ──────────────────────────────────────────────────────────────────────────────
# CVE Library — tagged by affected_product
# Each entry is a curated, realistic CVE aligned to the banking software stack.
# The affected_product tag drives automatic Asset→CVE mapping.
# ──────────────────────────────────────────────────────────────────────────────
CVE_LIBRARY: list[dict] = [
    {
        "cve_id":           "CVE-2023-25690",
        "affected_product": "apache_httpd",
        "cvss_score":       9.8,
        "severity":         "CRITICAL",
        "description":      "HTTP request smuggling in Apache HTTP Server 2.4.0-2.4.55 allows "
                            "attackers to bypass access controls, hijack sessions, or mount "
                            "cross-site scripting attacks via malformed HTTP/1.1 request sequences.",
        "published_date":   "2023-03-07",
    },
    {
        "cve_id":           "CVE-2022-41915",
        "affected_product": "nginx",
        "cvss_score":       7.5,
        "severity":         "HIGH",
        "description":      "Integer overflow in NGINX Plus under heavy HTTP/2 load allows "
                            "crafted requests to cause memory corruption or potential sandbox "
                            "escape via malformed header frames.",
        "published_date":   "2022-12-13",
    },
    {
        "cve_id":           "CVE-2021-29447",
        "affected_product": "wordpress",
        "cvss_score":       8.0,
        "severity":         "HIGH",
        "description":      "XML External Entity (XXE) injection in WordPress 5.6-5.7 via "
                            "crafted media file upload, allowing arbitrary server-side file "
                            "reads and potential SSRF against internal services.",
        "published_date":   "2021-04-15",
    },
    {
        "cve_id":           "CVE-2021-44228",
        "affected_product": "log4j",
        "cvss_score":       10.0,
        "severity":         "CRITICAL",
        "description":      "Log4Shell: Remote code execution in Apache Log4j2 JNDI lookup "
                            "feature. Unauthenticated attackers can execute arbitrary code on "
                            "servers processing attacker-controlled log messages via LDAP/RMI.",
        "published_date":   "2021-12-10",
    },
    {
        "cve_id":           "CVE-2022-37434",
        "affected_product": "zlib",
        "cvss_score":       9.8,
        "severity":         "CRITICAL",
        "description":      "Heap-based buffer overflow in zlib inflate operation allows "
                            "attackers to trigger memory corruption, crash, or arbitrary "
                            "code execution via crafted gzip data streams.",
        "published_date":   "2022-08-05",
    },
    {
        "cve_id":           "CVE-2023-28432",
        "affected_product": "minio",
        "cvss_score":       7.5,
        "severity":         "HIGH",
        "description":      "Information disclosure in MinIO cluster-mode exposes sensitive "
                            "environment variables (MINIO_SECRET_KEY, MINIO_ROOT_PASSWORD) "
                            "via the /minio/health/cluster endpoint without authentication.",
        "published_date":   "2023-03-22",
    },
    {
        "cve_id":           "CVE-2023-21839",
        "affected_product": "oracle_weblogic",
        "cvss_score":       7.5,
        "severity":         "HIGH",
        "description":      "Unauthenticated remote vulnerability in Oracle WebLogic Server "
                            "T3/IIOP protocol handlers allowing unauthorized data access or "
                            "control plane manipulation without credentials.",
        "published_date":   "2023-01-17",
    },
    {
        "cve_id":           "CVE-2022-21569",
        "affected_product": "oracle_db",
        "cvss_score":       7.5,
        "severity":         "HIGH",
        "description":      "Vulnerability in Oracle Database Server core network layer "
                            "processing allows unauthenticated read/write access via "
                            "specially crafted TNS network packets.",
        "published_date":   "2022-07-19",
    },
    {
        "cve_id":           "CVE-2023-38606",
        "affected_product": "swift_alliance",
        "cvss_score":       7.8,
        "severity":         "HIGH",
        "description":      "Privilege escalation in SWIFT Alliance Access platform kernel "
                            "subsystem allows local attackers to gain elevated OS-level "
                            "privileges via memory-mapped register manipulation.",
        "published_date":   "2023-07-26",
    },
    {
        "cve_id":           "CVE-2022-26925",
        "affected_product": "windows_lsa",
        "cvss_score":       9.8,
        "severity":         "CRITICAL",
        "description":      "Windows LSA (Local Security Authority) spoofing vulnerability "
                            "enabling Man-in-the-Middle credential theft or domain controller "
                            "privilege escalation via crafted NTLM authentication requests.",
        "published_date":   "2022-05-10",
    },
    {
        "cve_id":           "CVE-2023-30570",
        "affected_product": "apache_guacamole",
        "cvss_score":       8.1,
        "severity":         "HIGH",
        "description":      "Remote code execution flaw in Apache Guacamole protocol handling; "
                            "under specific conditions allows privilege bypass and unauthorized "
                            "command execution on the Guacamole server host.",
        "published_date":   "2023-05-19",
    },
    {
        "cve_id":           "CVE-2023-31414",
        "affected_product": "elasticsearch",
        "cvss_score":       7.5,
        "severity":         "HIGH",
        "description":      "Denial-of-service vulnerability in Elasticsearch audit logging "
                            "via resource exhaustion; specially crafted malformed audit log "
                            "packages cause the node to become unresponsive.",
        "published_date":   "2023-05-31",
    },
]

# Build a quick lookup: product_tag → CVE record
_PRODUCT_TO_CVE: dict[str, dict] = {
    cve["affected_product"]: cve for cve in CVE_LIBRARY
}


# ──────────────────────────────────────────────────────────────────────────────
# Banking Infrastructure Asset Definitions — 12-node topology across 4 zones
# ──────────────────────────────────────────────────────────────────────────────
ASSETS: list[dict] = [
    # ── Zone 1: Internet-Facing DMZ ──────────────────────────────────────────
    {
        "id":             "SRV-DMZ-WEB-01",
        "name":           "Retail Internet Banking Web Server",
        "type":           "Gateway",
        "zone":           "DMZ",
        "criticality":    8,
        "exposure":       "Public",
        "ip_address":     "10.0.1.10",
        "os_version":     "Ubuntu Server 22.04 LTS",
        "owner":          "Digital Banking Team",
        "environment":    "Production",
        "software_stack": ["apache_httpd", "openssl", "php"],
    },
    {
        "id":             "SRV-DMZ-GW-02",
        "name":           "Mobile Banking API Gateway",
        "type":           "Gateway",
        "zone":           "DMZ",
        "criticality":    8,
        "exposure":       "Public",
        "ip_address":     "10.0.1.20",
        "os_version":     "Red Hat Enterprise Linux 9.1",
        "owner":          "Platform Engineering",
        "environment":    "Production",
        "software_stack": ["nginx", "kong_gateway"],
    },
    {
        "id":             "SRV-DMZ-CMS-03",
        "name":           "Public CMS Portal",
        "type":           "WebApp",
        "zone":           "DMZ",
        "criticality":    5,
        "exposure":       "Public",
        "ip_address":     "10.0.2.10",
        "os_version":     "Ubuntu Server 20.04 LTS",
        "owner":          "Marketing IT",
        "environment":    "Production",
        "software_stack": ["wordpress", "nginx", "mysql"],
    },
    # ── Zone 2: Integration & Middleware ─────────────────────────────────────
    {
        "id":             "SRV-MID-ESB-01",
        "name":           "Enterprise Service Bus",
        "type":           "Middleware",
        "zone":           "Middleware",
        "criticality":    8,
        "exposure":       "Internal",
        "ip_address":     "10.1.1.10",
        "os_version":     "Windows Server 2022 Datacenter",
        "owner":          "Integration Team",
        "environment":    "Production",
        "software_stack": ["log4j", "apache_camel", "java"],
    },
    {
        "id":             "SRV-MID-IAM-02",
        "name":           "Customer Identity & Access Manager",
        "type":           "IAM",
        "zone":           "Middleware",
        "criticality":    10,
        "exposure":       "Internal",
        "ip_address":     "10.1.1.20",
        "os_version":     "Red Hat Enterprise Linux 8.6",
        "owner":          "Identity Team",
        "environment":    "Production",
        "software_stack": ["keycloak", "wildfly", "zlib"],
    },
    {
        "id":             "SRV-MID-SWI-03",
        "name":           "Universal Payment Switch",
        "type":           "PaymentSwitch",
        "zone":           "Middleware",
        "criticality":    10,
        "exposure":       "Internal",
        "ip_address":     "10.1.2.10",
        "os_version":     "Ubuntu Server 22.04 LTS",
        "owner":          "Payments Team",
        "environment":    "Production",
        "software_stack": ["nodejs", "redis", "minio"],
    },
    # ── Zone 3: Core Banking Enclave ─────────────────────────────────────────
    {
        "id":             "SRV-CORE-CBS-01",
        "name":           "Core Banking System App Server",
        "type":           "AppServer",
        "zone":           "Core",
        "criticality":    10,
        "exposure":       "Private",
        "ip_address":     "10.2.1.10",
        "os_version":     "Red Hat Enterprise Linux 9.0",
        "owner":          "CBS Team",
        "environment":    "Production",
        "software_stack": ["oracle_weblogic", "java"],
    },
    {
        "id":             "DB-CORE-LEDG-02",
        "name":           "Central Production Database",
        "type":           "Database",
        "zone":           "Core",
        "criticality":    10,
        "exposure":       "Private",
        "ip_address":     "10.2.2.10",
        "os_version":     "Oracle Linux 8.5",
        "owner":          "Data Platform Team",
        "environment":    "Production",
        "software_stack": ["oracle_db"],
    },
    {
        "id":             "SRV-CORE-SWIFT-03",
        "name":           "SWIFT Transaction Appliance",
        "type":           "SWIFT",
        "zone":           "Core",
        "criticality":    10,
        "exposure":       "Private",
        "ip_address":     "10.2.3.10",
        "os_version":     "Hardened Linux (SWIFT Alliance-certified)",
        "owner":          "Treasury Operations",
        "environment":    "Production",
        "software_stack": ["swift_alliance"],
    },
    # ── Zone 4: Management & Control ─────────────────────────────────────────
    {
        "id":             "SRV-MGMT-AD-01",
        "name":           "Active Directory Domain Controller",
        "type":           "AD",
        "zone":           "Management",
        "criticality":    10,
        "exposure":       "Internal",
        "ip_address":     "10.3.1.10",
        "os_version":     "Windows Server 2022 Datacenter",
        "owner":          "IT Operations",
        "environment":    "Production",
        "software_stack": ["windows_lsa", "active_directory"],
    },
    {
        "id":             "SRV-MGMT-JUMP-02",
        "name":           "Enterprise Jump Server / Bastion Host",
        "type":           "Bastion",
        "zone":           "Management",
        "criticality":    8,
        "exposure":       "Internal",
        "ip_address":     "10.3.1.20",
        "os_version":     "Red Hat Enterprise Linux 8.8 (Hardened)",
        "owner":          "IT Security",
        "environment":    "Production",
        "software_stack": ["apache_guacamole", "openssh"],
    },
    {
        "id":             "SRV-MGMT-SIEM-03",
        "name":           "SIEM & Log Aggregator Node",
        "type":           "SIEM",
        "zone":           "Management",
        "criticality":    8,
        "exposure":       "Internal",
        "ip_address":     "10.3.2.10",
        "os_version":     "Ubuntu Server 22.04 LTS",
        "owner":          "SOC Team",
        "environment":    "Production",
        "software_stack": ["elasticsearch", "logstash", "kibana"],
    },
]

# ── Network Topology: directed lateral movement edges ──────────────────────
TOPOLOGY: list[tuple[str, str]] = [
    # DMZ → Middleware
    ("SRV-DMZ-WEB-01",  "SRV-MID-IAM-02"),    # Web portal → IAM (auth sessions)
    ("SRV-DMZ-WEB-01",  "SRV-DMZ-GW-02"),     # Web portal → API Gateway
    ("SRV-DMZ-CMS-03",  "SRV-DMZ-GW-02"),     # CMS Portal → API Gateway
    ("SRV-DMZ-CMS-03",  "SRV-MID-ESB-01"),    # CMS Portal → ESB (SSRF pivot target)
    ("SRV-DMZ-GW-02",   "SRV-MID-SWI-03"),    # API Gateway → Payment Switch
    ("SRV-DMZ-GW-02",   "SRV-MID-ESB-01"),    # API Gateway → ESB
    # Middleware → Core
    ("SRV-MID-ESB-01",  "SRV-CORE-CBS-01"),   # ESB → CBS App Server
    ("SRV-MID-ESB-01",  "DB-CORE-LEDG-02"),   # ESB → Central DB (direct writes)
    ("SRV-MID-IAM-02",  "SRV-MGMT-SIEM-03"),  # IAM → SIEM (audit log stream)
    ("SRV-MID-SWI-03",  "DB-CORE-LEDG-02"),   # Payment Switch → Central DB
    ("SRV-MID-SWI-03",  "SRV-CORE-CBS-01"),   # Payment Switch → CBS
    # Core Banking internal
    ("SRV-CORE-CBS-01", "DB-CORE-LEDG-02"),   # CBS → Central DB (primary access)
    ("SRV-CORE-CBS-01", "SRV-MGMT-JUMP-02"),  # CBS → Jump Server (admin sessions)
    # Management → Infrastructure
    ("SRV-MGMT-AD-01",  "SRV-DMZ-WEB-01"),    # AD → Web (Group Policy push)
    ("SRV-MGMT-AD-01",  "SRV-MID-ESB-01"),    # AD → ESB (Kerberos auth)
    ("SRV-MGMT-AD-01",  "SRV-CORE-CBS-01"),   # AD → CBS (domain authentication)
    ("SRV-MGMT-JUMP-02","SRV-CORE-CBS-01"),   # Jump → CBS (admin sessions)
    ("SRV-MGMT-JUMP-02","DB-CORE-LEDG-02"),   # Jump → Central DB (DBA access)
    ("SRV-MGMT-JUMP-02","SRV-CORE-SWIFT-03"), # Jump → SWIFT Appliance (mgmt)
    ("SRV-MGMT-SIEM-03","SRV-MGMT-AD-01"),    # SIEM → AD (alert correlation)
]


class GraphBuilder:
    """
    Constructs the Cyber Defense Knowledge Graph.
    Correlates vulnerabilities, assets, and attack tactics using
    software-stack-based CVE mapping instead of hardcoded ID bindings.
    """

    def __init__(self, neo4j_client: Neo4jClient):
        self.db    = neo4j_client
        self.nvd   = NVDFetcher()
        self.mitre = MitreFetcher()
        self.epss  = EPSSFetcher()
        self.kev   = KEVFetcher()

    # ──────────────────────────────────────────────────────────────────────────
    # Asset infrastructure seeding
    # ──────────────────────────────────────────────────────────────────────────

    def seed_assets(self):
        """
        Creates (or updates) the 12 banking Asset nodes and wires their
        lateral CONNECTS_TO topology edges.  All fields from the ASSETS
        registry are persisted, including ip_address, os_version, zone,
        and software_stack (stored as a comma-joined string for Neo4j compat).
        Uses MERGE so the operation is fully idempotent.
        """
        asset_query = """
        MERGE (a:Asset {id: $id})
        SET a.name           = $name,
            a.type           = $type,
            a.zone           = $zone,
            a.criticality    = $criticality,
            a.exposure       = $exposure,
            a.ip_address     = $ip_address,
            a.os_version     = $os_version,
            a.owner          = $owner,
            a.environment    = $environment,
            a.software_stack = $software_stack
        """

        connectivity_query = """
        MATCH (a:Asset {id: $from_id})
        MATCH (b:Asset {id: $to_id})
        MERGE (a)-[:CONNECTS_TO]->(b)
        """

        for asset in ASSETS:
            params = dict(asset)
            # Store software_stack as comma-separated string for Neo4j
            params["software_stack"] = ",".join(asset["software_stack"])
            self.db.execute_write(asset_query, params)

        for from_id, to_id in TOPOLOGY:
            self.db.execute_write(connectivity_query, {"from_id": from_id, "to_id": to_id})

        logger.info(
            "  ✓ Seeded %d asset nodes and %d topology edges.",
            len(ASSETS), len(TOPOLOGY)
        )
        print(f"  ✓ Seeded {len(ASSETS)} asset nodes and {len(TOPOLOGY)} topology edges.")

    # ──────────────────────────────────────────────────────────────────────────
    # Threat intelligence ingestion — software-stack-driven CVE mapping
    # ──────────────────────────────────────────────────────────────────────────

    def build_threat_graph(self):
        """
        Builds Vulnerability and Technique nodes and their relationships.

        Mapping Strategy (software-stack-driven):
        ------------------------------------------
        For every CVE in CVE_LIBRARY, the builder:
          1. Writes/updates the Vulnerability node (enriched with live EPSS + KEV)
          2. Writes/updates the MITRE ATT&CK Technique node
          3. Creates CVE -[:MAPS_TO_TECHNIQUE]-> Technique edge
          4. Scans every Asset's software_stack — if the CVE's affected_product
             matches any tag in the stack → creates Asset -[:HAS_VULNERABILITY]-> CVE

        This means adding a new server automatically inherits matching CVEs
        based on its declared software, with no hardcoded ID mapping required.
        """
        logger.info("  Processing %d CVE records from library …", len(CVE_LIBRARY))

        for cve in CVE_LIBRARY:
            cve_id = cve["cve_id"]

            # Live enrichment from real EPSS / KEV APIs
            epss_data      = self.epss.get_epss_score(cve_id)
            kev_data       = self.kev.is_known_exploited(cve_id)
            attack_details = self.mitre.get_attack_details(cve_id)

            # ── 1. Vulnerability node ─────────────────────────────────────
            self.db.execute_write(
                """
                MERGE (v:Vulnerability {cve_id: $cve_id})
                SET v.cvss_score      = $cvss_score,
                    v.severity        = $severity,
                    v.description     = $description,
                    v.affected_product= $affected_product,
                    v.published_date  = $published_date,
                    v.epss_score      = $epss,
                    v.epss_percentile = $percentile,
                    v.is_kev          = $is_kev,
                    v.kev_due_date    = $due_date
                """,
                {
                    "cve_id":           cve_id,
                    "cvss_score":       cve["cvss_score"],
                    "severity":         cve["severity"],
                    "description":      cve["description"],
                    "affected_product": cve["affected_product"],
                    "published_date":   cve["published_date"],
                    "epss":             epss_data["epss"],
                    "percentile":       epss_data["percentile"],
                    "is_kev":           kev_data["is_exploited"],
                    "due_date":         kev_data["due_date"],
                },
            )

            # ── 2. Technique node (MITRE ATT&CK) ─────────────────────────
            self.db.execute_write(
                """
                MERGE (t:Technique {technique_id: $tech_id})
                SET t.name       = $name,
                    t.tactic     = $tactic,
                    t.capec_id   = $capec_id,
                    t.capec_name = $capec_name
                """,
                {
                    "tech_id":    attack_details["technique_id"],
                    "name":       attack_details["technique_name"],
                    "tactic":     attack_details["tactic"],
                    "capec_id":   attack_details["capec_id"],
                    "capec_name": attack_details["capec_name"],
                },
            )

            # ── 3. CVE → Technique relationship ──────────────────────────
            self.db.execute_write(
                """
                MATCH (v:Vulnerability {cve_id: $cve_id})
                MATCH (t:Technique {technique_id: $tech_id})
                MERGE (v)-[:MAPS_TO_TECHNIQUE]->(t)
                """,
                {"cve_id": cve_id, "tech_id": attack_details["technique_id"]},
            )

            # ── 4. Software-stack-driven Asset → CVE mapping ─────────────
            affected_product = cve["affected_product"]
            matched_assets = [
                a for a in ASSETS
                if affected_product in a["software_stack"]
            ]

            for asset in matched_assets:
                self.db.execute_write(
                    """
                    MATCH (a:Asset {id: $asset_id})
                    MATCH (v:Vulnerability {cve_id: $cve_id})
                    MERGE (a)-[:HAS_VULNERABILITY]->(v)
                    """,
                    {"asset_id": asset["id"], "cve_id": cve_id},
                )

            logger.debug(
                "  CVE %s (%s) → matched %d asset(s): %s",
                cve_id, affected_product, len(matched_assets),
                [a["id"] for a in matched_assets]
            )

        print(f"  ✓ Ingested {len(CVE_LIBRARY)} CVE records with software-stack-driven mapping.")

    # ──────────────────────────────────────────────────────────────────────────
    # Full graph orchestration
    # ──────────────────────────────────────────────────────────────────────────

    def build_full_graph(self):
        """
        Master entry point for the complete Knowledge Graph build pipeline:

          1. Schema  – constraints + indexes (idempotent)
          2. Assets  – 12-node infrastructure + 17 lateral topology edges
          3. Threats – CVE / Technique / EPSS / KEV ingestion (stack-driven)
          4. Stats   – node/relationship counts + validation queries

        Safe to call on every startup (all writes use MERGE).
        """
        _sep = "=" * 66
        print(f"\n{_sep}")
        print("  Sarathi Cyberdefense — Knowledge Graph Build Pipeline")
        print("  Banking Infrastructure: 12-node, 4-zone topology")
        print(_sep)

        # ── Step 1: Schema ────────────────────────────────────────────────
        print("\n[1/4] Setting up schema constraints and indexes …")
        self.db.setup_constraints_and_indexes()
        print("  ✓ Schema ready.")

        # ── Step 2: Assets ────────────────────────────────────────────────
        print(f"\n[2/4] Seeding {len(ASSETS)} asset nodes across 4 security zones …")
        self.seed_assets()

        # ── Step 3: Threat intelligence ───────────────────────────────────
        print("\n[3/4] Ingesting threat intelligence (CVE / MITRE / EPSS / KEV) …")
        print("      Strategy: software-stack-based CVE auto-mapping")
        self.build_threat_graph()

        # ── Step 4: Validate & stats ──────────────────────────────────────
        print("\n[4/4] Validating graph — running statistics queries …")
        self._print_graph_statistics()
        self._run_validation_queries()

        print(f"\n{_sep}")
        print("  ✅  Knowledge Graph build complete.")
        print(f"{_sep}\n")

    # ──────────────────────────────────────────────────────────────────────────
    # Statistics
    # ──────────────────────────────────────────────────────────────────────────

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

    # ──────────────────────────────────────────────────────────────────────────
    # Validation queries
    # ──────────────────────────────────────────────────────────────────────────

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
                "label": "Asset → Vulnerability (software-stack mapping)",
                "query": (
                    "MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability) "
                    "RETURN a.name AS asset, a.zone AS zone, "
                    "v.cve_id AS cve_id, v.affected_product AS product, "
                    "v.severity AS severity, v.cvss_score AS cvss "
                    "ORDER BY a.zone, v.cvss_score DESC"
                ),
            },
            {
                "label": "Asset lateral movement topology (per zone)",
                "query": (
                    "MATCH (a:Asset)-[:CONNECTS_TO]->(b:Asset) "
                    "RETURN a.name AS from_asset, a.zone AS from_zone, "
                    "b.name AS to_asset, b.zone AS to_zone "
                    "ORDER BY a.zone, b.zone"
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
