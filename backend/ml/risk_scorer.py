"""
ml/risk_scorer.py
-----------------
Composite cyber-risk scoring engine for the Sarathi Cyberdefense platform.

Scoring formula (0-100 scale)
------------------------------
  composite = min(100,
      cvss_score   * 0.30 * 10   +   # max 30  — exploitability severity
      epss_score   * 0.40 * 100  +   # max 40  — real-world exploit probability
      kev_bonus                  +   # +20     — CISA confirmed exploitation
      criticality  * 0.30 * 10       # max 30  — asset business impact
  )

Classification thresholds
--------------------------
  CRITICAL  > 80
  HIGH      60 – 80
  MEDIUM    40 – 60
  LOW       < 40

The module also preserves `predict_risk()` so the existing /evaluate-risk
FastAPI route continues to work unchanged.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

logger = logging.getLogger("sarathi.risk_scorer")

# ── Cache constants ────────────────────────────────────────────────────────────
_CACHE_TTL_SECONDS = 120          # top-risk result TTL (2 min)

_CVE_DESCRIPTIONS = {
    "CVE-2023-25690": "HTTP request smuggling in Apache HTTP Server 2.4.0-2.4.55 allows attackers to bypass access controls, hijack sessions, or mount cross-site scripting attacks via malformed HTTP/1.1 request sequences.",
    "CVE-2022-41915": "Integer overflow in NGINX Plus under heavy HTTP/2 load allows crafted requests to cause memory corruption or potential sandbox escape via malformed header frames.",
    "CVE-2021-29447": "XML External Entity (XXE) injection in WordPress 5.6-5.7 via crafted media file upload, allowing arbitrary server-side file reads and potential SSRF against internal services.",
    "CVE-2021-44228": "Log4Shell: Remote code execution in Apache Log4j2 JNDI lookup feature. Unauthenticated attackers can execute arbitrary code on servers processing attacker-controlled log messages via LDAP/RMI.",
    "CVE-2022-37434": "Heap-based buffer overflow in zlib inflate operation allows attackers to trigger memory corruption, crash, or arbitrary code execution via crafted gzip data streams.",
    "CVE-2023-28432": "Information disclosure in MinIO cluster-mode exposes sensitive environment variables (MINIO_SECRET_KEY, MINIO_ROOT_PASSWORD) via the /minio/health/cluster endpoint without authentication.",
    "CVE-2023-21839": "Unauthenticated remote vulnerability in Oracle WebLogic Server T3/IIOP protocol handlers allowing unauthorized data access or control plane manipulation without credentials.",
    "CVE-2022-21569": "Vulnerability in Oracle Database Server core network layer processing allows unauthenticated read/write access via specially crafted TNS network packets.",
    "CVE-2023-38606": "Privilege escalation in SWIFT Alliance Access platform kernel subsystem allows local attackers to gain elevated OS-level privileges via memory-mapped register manipulation.",
    "CVE-2022-26925": "Windows LSA (Local Security Authority) spoofing vulnerability enabling Man-in-the-Middle credential theft or domain controller privilege escalation via crafted NTLM authentication requests.",
    "CVE-2023-30570": "Remote code execution flaw in Apache Guacamole protocol handling; under specific conditions allows privilege bypass and unauthorized command execution on the Guacamole server host.",
    "CVE-2023-31414": "Denial-of-service vulnerability in Elasticsearch audit logging via resource exhaustion; specially crafted malformed audit log packages cause the node to become unresponsive."
}

_EXPLOIT_SCENARIOS = {
    "CVE-2023-25690": "Attackers smuggle HTTP request payloads past the WAF, hijacking active sessions of customers using retail internet banking, allowing unauthorized transfers and credentials compromise.",
    "CVE-2022-41915": "Attackers send malformed HTTP/2 header frames causing NGINX processes to crash (DoS) or trigger heap corruption, potentially bypassing reverse-proxy boundaries to access internal banking endpoints.",
    "CVE-2021-29447": "Attackers upload a crafted XML-based media file to the public CMS. The server parses external entities, allowing the attacker to read arbitrary server configuration files (like wp-config.php) or launch SSRF attacks against internal hosts.",
    "CVE-2021-44228": "Attackers inject malicious JNDI lookup strings into log fields (e.g. User-Agent). The Log4j library fetches and executes external Java classes, giving attackers full remote command-line access to the host, facilitating lateral network movement.",
    "CVE-2022-37434": "Attackers send compression streams with malformed headers to the identity manager session decoder, corrupting heap memory to cause authentication bypass and operator session spoofing.",
    "CVE-2023-28432": "Attackers query the unauthenticated cluster health endpoint, extracting the root administrator password and API secret keys, granting full read/write access to bank storage buckets.",
    "CVE-2023-21839": "Attackers bypass security checks via serialized T3/IIOP network packets, allowing unauthorized remote execution of management commands or full control of the application server.",
    "CVE-2022-21569": "Attackers send malformed TNS network packets to the database listener, bypassing DB authentication to read, modify, or delete central transaction ledgers and customer tables.",
    "CVE-2023-38606": "Attackers execute local code and abuse memory-mapped kernel registers to gain root privileges on the SWIFT system, allowing them to manipulate transaction messaging logs and inject fraudulent transfer files.",
    "CVE-2022-26925": "Attackers spoof NTLM security negotiations, forcing the Domain Controller to authenticate to an attacker-controlled listener, capturing administrative credentials to compromise the entire corporate Active Directory domain.",
    "CVE-2023-30570": "Attackers exploit Guacamole remote protocol handling flaws to execute commands on the jump server, bypassing session monitoring and auditing to gain direct SSH/RDP access to internal enclaves.",
    "CVE-2023-31414": "Attackers flood the SIEM index with malformed audit packets, crashing Elasticsearch services to blind the security operations center (SOC) to ongoing hacker activities."
}

# Safe defaults for missing numeric fields
_DEFAULT_CVSS          = 5.0
_DEFAULT_EPSS          = 0.015
_DEFAULT_CRITICALITY   = 5
_KEV_BONUS             = 20.0


class RiskScorer:
    """
    Composite risk-scoring engine combining deterministic formula scoring
    with an optional RandomForest classifier for tier prediction.

    The deterministic `score_cve()` / `classify_risk()` methods are the
    primary interface.  `predict_risk()` is kept for API backwards-compat.
    """

    def __init__(self) -> None:
        # RandomForest kept for the existing /evaluate-risk endpoint
        self._rf_model = RandomForestClassifier(n_estimators=10, random_state=42)
        self._train_rf_model()

        # In-memory cache for get_top_risks()
        self._cache_data: list[dict] | None = None
        self._cache_ts: float = 0.0

    # ──────────────────────────────────────────────────────────────────────────
    # Public API — deterministic scoring
    # ──────────────────────────────────────────────────────────────────────────

    def score_cve(self, cve_data: dict[str, Any]) -> dict[str, Any]:
        """
        Compute the composite risk score (0-100) for a single CVE record.

        Parameters
        ----------
        cve_data : dict
            Must contain any subset of:
              cvssScore / cvss_score      float  0-10
              epssScore / epss_score      float  0-1
              isKEV     / is_kev         bool
              assetCriticality / asset_criticality  int  1-10

        Returns
        -------
        dict with keys:
          riskScore, riskLevel, breakdown, explanation
        """
        cvss        = self._safe_float(
            cve_data, ("cvssScore", "cvss_score"), _DEFAULT_CVSS
        )
        epss        = self._safe_float(
            cve_data, ("epssScore", "epss_score"), _DEFAULT_EPSS
        )
        is_kev      = bool(cve_data.get("isKEV") or cve_data.get("is_kev", False))
        criticality = int(
            cve_data.get("assetCriticality")
            or cve_data.get("asset_criticality")
            or _DEFAULT_CRITICALITY
        )

        # ── Component scores ──────────────────────────────────────────────────
        cvss_component   = round(cvss        * 0.30 * 10,  2)   # 0-30
        epss_component   = round(epss        * 0.40 * 100, 2)   # 0-40
        kev_component    = _KEV_BONUS if is_kev else 0.0         # 0 or 20
        crit_component   = round(criticality * 0.30 * 10,  2)   # 0-30

        raw_score  = cvss_component + epss_component + kev_component + crit_component
        risk_score = round(min(100.0, raw_score), 2)
        risk_level = self.classify_risk(risk_score)

        breakdown = {
            "cvssComponent":   cvss_component,
            "epssComponent":   epss_component,
            "kevBonus":        kev_component,
            "critComponent":   crit_component,
            "rawTotal":        round(raw_score, 2),
        }

        cve_id = cve_data.get("cveId") or cve_data.get("cve_id") or "UNKNOWN"
        explanation = _EXPLOIT_SCENARIOS.get(
            cve_id,
            f"Vulnerability in banking infrastructure asset. Allows unauthorized access or privilege escalation under specific network configurations. CVSS score: {cvss:.1f}."
        )

        logger.debug(
            "score_cve | score=%.1f level=%s cvss=%.1f epss=%.3f kev=%s crit=%d",
            risk_score, risk_level, cvss, epss, is_kev, criticality
        )

        return {
            "riskScore":  risk_score,
            "riskLevel":  risk_level,
            "breakdown":  breakdown,
            "explanation": explanation,
        }

    def classify_risk(self, score: float) -> str:
        """
        Map a 0-100 numeric risk score to a severity label.

        Thresholds
        ----------
        CRITICAL > 80 | HIGH 60-80 | MEDIUM 40-60 | LOW < 40
        """
        if score > 80:
            return "CRITICAL"
        if score > 60:
            return "HIGH"
        if score > 40:
            return "MEDIUM"
        return "LOW"

    def get_top_risks(
        self,
        neo4j_client,
        limit: int = 20
    ) -> list[dict[str, Any]]:
        """
        Query Neo4j for CVEs linked to assets, compute composite risk scores,
        and return a list sorted by riskScore descending.

        Results are cached for _CACHE_TTL_SECONDS to reduce Aura round-trips.

        Returns
        -------
        List of dicts:
          cveId, cvssScore, epssScore, isKEV,
          assetName, assetCriticality,
          riskScore, riskLevel, breakdown, explanation
        """
        now = time.monotonic()
        if self._cache_data is not None and (now - self._cache_ts) < _CACHE_TTL_SECONDS:
            logger.debug("get_top_risks: returning cached result (%d items)", len(self._cache_data))
            return self._cache_data[:limit]

        logger.info("get_top_risks: querying Neo4j (cache miss) …")

        query = """
        MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability)
        RETURN
            a.name          AS assetName,
            a.id            AS assetId,
            a.criticality   AS assetCriticality,
            v.cve_id        AS cveId,
            v.cvss_score    AS cvssScore,
            v.epss_score    AS epssScore,
            v.is_kev        AS isKEV,
            v.severity      AS severity,
            v.description   AS description,
            v.kev_due_date  AS kevDueDate
        ORDER BY v.cvss_score DESC
        LIMIT $limit
        """

        rows = neo4j_client.run_query(query, {"limit": max(limit, 100)})

        if not rows:
            logger.warning("get_top_risks: no rows returned from Neo4j; using mock fallback.")
            rows = self._mock_top_risks_rows()

        results: list[dict] = []
        for row in rows:
            # Deterministic formula commented out per user request
            # scored = self.score_cve({
            #     "cveId":            row.get("cveId"),
            #     "cvssScore":        row.get("cvssScore"),
            #     "epssScore":        row.get("epssScore"),
            #     "isKEV":            row.get("isKEV"),
            #     "assetCriticality": row.get("assetCriticality"),
            # })
            
            # --- ML Based Scoring ---
            cvss_val = self._safe_float(row, ("cvssScore",), _DEFAULT_CVSS)
            epss_val = self._safe_float(row, ("epssScore",), _DEFAULT_EPSS)
            is_kev_val = bool(row.get("isKEV", False))
            crit_val = int(row.get("assetCriticality") or _DEFAULT_CRITICALITY)
            
            input_df = pd.DataFrame([[cvss_val, epss_val, 1 if is_kev_val else 0, crit_val]], columns=["cvss", "epss", "is_kev", "asset_criticality"])
            proba = self._rf_model.predict_proba(input_df)[0]
            
            # Create a continuous score from the ML model by computing the expected tier
            expected_tier = sum(i * p for i, p in enumerate(proba))
            risk_score = round((expected_tier / 3.0) * 100, 2)
            
            tier_idx = int(self._rf_model.predict(input_df)[0])
            tiers = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            risk_level = tiers[min(tier_idx, 3)]
            
            breakdown = {
                "rfConfidence": round(float(np.max(proba)) * 100, 2),
                "rfExpectedTier": round(expected_tier, 2)
            }
            cve_id = row.get("cveId", "UNKNOWN")
            explanation = _EXPLOIT_SCENARIOS.get(
                cve_id,
                f"Vulnerability in banking infrastructure asset. ML model predicts {risk_level} risk with {breakdown['rfConfidence']}% confidence."
            )

            results.append({
                "cveId":            row.get("cveId",         "UNKNOWN"),
                "cvssScore":        row.get("cvssScore",     _DEFAULT_CVSS),
                "epssScore":        row.get("epssScore",     _DEFAULT_EPSS),
                "isKEV":            bool(row.get("isKEV",    False)),
                "severity":         row.get("severity",      "UNKNOWN"),
                "kevDueDate":       row.get("kevDueDate",    "N/A"),
                "assetName":        row.get("assetName",     "Unknown Asset"),
                "assetId":          row.get("assetId",       ""),
                "assetCriticality": row.get("assetCriticality", _DEFAULT_CRITICALITY),
                "riskScore":        risk_score,
                "riskLevel":        risk_level,
                "breakdown":        breakdown,
                "description":      row.get("description") or _CVE_DESCRIPTIONS.get(row.get("cveId"), "No description available."),
                "explanation":      explanation,
            })

        # Sort by riskScore descending, then CVSS as tiebreaker
        results.sort(key=lambda r: (r["riskScore"], r["cvssScore"]), reverse=True)

        # Cache and return
        self._cache_data = results
        self._cache_ts   = now
        logger.info("get_top_risks: scored %d CVE-asset pairs.", len(results))
        return results[:limit]

    def invalidate_cache(self) -> None:
        """Force-expire the get_top_risks cache (call after a graph sync)."""
        self._cache_data = None
        self._cache_ts   = 0.0
        logger.info("RiskScorer cache invalidated.")

    # ──────────────────────────────────────────────────────────────────────────
    # Backward-compatible RandomForest predictor (used by /evaluate-risk route)
    # ──────────────────────────────────────────────────────────────────────────

    def predict_risk(
        self,
        cvss: float,
        epss: float,
        is_kev: bool,
        asset_criticality: int,
    ) -> dict[str, Any]:
        """
        Hybrid predictor: deterministic composite score + RF tier prediction.
        Kept for backwards compatibility with the /evaluate-risk API endpoint.
        """
        # Clamp / default guard
        cvss             = max(0.0, min(10.0, cvss or _DEFAULT_CVSS))
        epss             = max(0.0, min(1.0,  epss or _DEFAULT_EPSS))
        asset_criticality = max(1,  min(10,   int(asset_criticality or _DEFAULT_CRITICALITY)))
        kev_binary       = 1 if is_kev else 0

        # Deterministic composite score (Commented out per user request)
        # scored = self.score_cve({
        #     "cvssScore": cvss, "epssScore": epss,
        #     "isKEV": is_kev, "assetCriticality": asset_criticality,
        # })

        # RF tier prediction
        input_df = pd.DataFrame([[cvss, epss, kev_binary, asset_criticality]], columns=["cvss", "epss", "is_kev", "asset_criticality"])
        tier_idx    = int(self._rf_model.predict(input_df)[0])
        proba       = self._rf_model.predict_proba(input_df)[0]
        confidence  = float(np.max(proba))
        tiers       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        rf_tier     = tiers[min(tier_idx, 3)]
        
        expected_tier = sum(i * p for i, p in enumerate(proba))
        risk_score = round((expected_tier / 3.0) * 100, 2)
        
        breakdown = {
            "rfConfidence": round(confidence * 100, 2),
            "rfExpectedTier": round(expected_tier, 2)
        }
        
        explanation = f"ML model predicts {rf_tier} risk with {breakdown['rfConfidence']}% confidence based on provided metrics."

        return {
            "riskScore":          risk_score,
            "riskLevel":          rf_tier,
            "rfPredictedTier":    rf_tier,
            "rfConfidence":       round(confidence * 100, 2),
            "breakdown":          breakdown,
            "explanation":        explanation,
            # Legacy keys kept for any older consumers
            "predicted_tier":     rf_tier,
            "prediction_confidence": round(confidence * 100, 2),
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Private helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _safe_float(
        self,
        data: dict,
        keys: tuple[str, ...],
        default: float,
    ) -> float:
        """Return the first truthy numeric value found among `keys`, else default."""
        for k in keys:
            v = data.get(k)
            if v is not None:
                try:
                    fv = float(v)
                    if 0.0 <= fv:          # reject negatives
                        return fv
                except (TypeError, ValueError):
                    pass
        return default

    def _build_explanation(
        self,
        cvss: float, epss: float, is_kev: bool, criticality: int,
        cvss_c: float, epss_c: float, kev_c: float, crit_c: float,
        score: float, level: str,
    ) -> str:
        parts = [
            f"CVSS {cvss:.1f} contributes {cvss_c:.1f} pts (weight 0.30)",
            f"EPSS {epss:.3f} contributes {epss_c:.1f} pts (weight 0.40)",
        ]
        if is_kev:
            parts.append(f"CISA KEV status adds {int(kev_c)} pts bonus")
        parts.append(
            f"Asset criticality {criticality}/10 contributes {crit_c:.1f} pts (weight 0.30)"
        )
        parts.append(
            f"Composite risk score: {score:.1f}/100 → classified as {level}"
        )
        return ". ".join(parts) + "."

    def _train_rf_model(self) -> None:
        """
        Train a small RandomForest on representative cyber-risk records.
        Features: [cvss, epss, is_kev, asset_criticality]
        Labels  : 0=LOW, 1=MEDIUM, 2=HIGH, 3=CRITICAL
        """
        records = [
            # cvss, epss, kev, crit, label
            [9.8, 0.95, 1, 10, 3],
            [9.0, 0.88, 1,  8, 3],
            [8.5, 0.72, 1,  9, 3],
            [8.1, 0.75, 0,  8, 2],
            [7.5, 0.60, 1,  6, 2],
            [7.2, 0.45, 0,  7, 2],
            [6.5, 0.08, 0,  5, 1],
            [5.0, 0.12, 0,  9, 1],
            [5.5, 0.20, 0,  4, 1],
            [4.0, 0.04, 0,  3, 0],
            [3.2, 0.01, 0,  2, 0],
            [2.5, 0.01, 0,  1, 0],
        ]
        df = pd.DataFrame(
            records,
            columns=["cvss", "epss", "is_kev", "asset_criticality", "risk_tier"]
        )
        X = df[["cvss", "epss", "is_kev", "asset_criticality"]]
        y = df["risk_tier"]
        self._rf_model.fit(X, y)
        logger.debug("RandomForest risk model trained on %d records.", len(records))

    def _mock_top_risks_rows(self) -> list[dict]:
        """Fallback mock data using the 12-node banking infrastructure and real CVEs."""
        return [
            {"assetName": "Active Directory Domain Controller", "assetId": "SRV-MGMT-AD-01",
             "assetCriticality": 10, "cveId": "CVE-2022-26925",
             "cvssScore": 9.8, "epssScore": 0.9120, "isKEV": True,
             "severity": "CRITICAL", "kevDueDate": "2022-06-22"},
            {"assetName": "Customer Identity & Access Manager",  "assetId": "SRV-MID-IAM-02",
             "assetCriticality": 10, "cveId": "CVE-2022-37434",
             "cvssScore": 9.8, "epssScore": 0.8912, "isKEV": True,
             "severity": "CRITICAL", "kevDueDate": "2022-09-15"},
            {"assetName": "Retail Internet Banking Web Server", "assetId": "SRV-DMZ-WEB-01",
             "assetCriticality": 8,  "cveId": "CVE-2023-25690",
             "cvssScore": 9.8, "epssScore": 0.9341, "isKEV": True,
             "severity": "CRITICAL", "kevDueDate": "2023-05-01"},
            {"assetName": "Enterprise Service Bus",             "assetId": "SRV-MID-ESB-01",
             "assetCriticality": 8,  "cveId": "CVE-2021-44228",
             "cvssScore": 10.0, "epssScore": 0.9763, "isKEV": True,
             "severity": "CRITICAL", "kevDueDate": "2021-12-24"},
            {"assetName": "Enterprise Jump Server / Bastion",   "assetId": "SRV-MGMT-JUMP-02",
             "assetCriticality": 8,  "cveId": "CVE-2023-30570",
             "cvssScore": 8.1, "epssScore": 0.7456, "isKEV": False,
             "severity": "HIGH",     "kevDueDate": "N/A"},
            {"assetName": "Public CMS Portal",                  "assetId": "SRV-DMZ-CMS-03",
             "assetCriticality": 5,  "cveId": "CVE-2021-29447",
             "cvssScore": 8.0, "epssScore": 0.7812, "isKEV": True,
             "severity": "HIGH",     "kevDueDate": "2022-05-25"},
            {"assetName": "SWIFT Transaction Appliance",        "assetId": "SRV-CORE-SWIFT-03",
             "assetCriticality": 10, "cveId": "CVE-2023-38606",
             "cvssScore": 7.8, "epssScore": 0.6980, "isKEV": True,
             "severity": "HIGH",     "kevDueDate": "2023-09-14"},
            {"assetName": "Mobile Banking API Gateway",         "assetId": "SRV-DMZ-GW-02",
             "assetCriticality": 8,  "cveId": "CVE-2022-41915",
             "cvssScore": 7.5, "epssScore": 0.6230, "isKEV": False,
             "severity": "HIGH",     "kevDueDate": "N/A"},
            {"assetName": "Universal Payment Switch",           "assetId": "SRV-MID-SWI-03",
             "assetCriticality": 10, "cveId": "CVE-2023-28432",
             "cvssScore": 7.5, "epssScore": 0.6540, "isKEV": True,
             "severity": "HIGH",     "kevDueDate": "2023-04-21"},
            {"assetName": "Core Banking System App Server",     "assetId": "SRV-CORE-CBS-01",
             "assetCriticality": 10, "cveId": "CVE-2023-21839",
             "cvssScore": 7.5, "epssScore": 0.7234, "isKEV": True,
             "severity": "HIGH",     "kevDueDate": "2023-04-18"},
            {"assetName": "Central Production Database",        "assetId": "DB-CORE-LEDG-02",
             "assetCriticality": 10, "cveId": "CVE-2022-21569",
             "cvssScore": 7.5, "epssScore": 0.5810, "isKEV": False,
             "severity": "HIGH",     "kevDueDate": "N/A"},
            {"assetName": "SIEM & Log Aggregator Node",         "assetId": "SRV-MGMT-SIEM-03",
             "assetCriticality": 8,  "cveId": "CVE-2023-31414",
             "cvssScore": 7.5, "epssScore": 0.5230, "isKEV": False,
             "severity": "HIGH",     "kevDueDate": "N/A"},
        ]


logger.info("RiskScorer module loaded.")
