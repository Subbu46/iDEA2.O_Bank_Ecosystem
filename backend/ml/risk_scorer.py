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

        explanation = self._build_explanation(
            cvss, epss, is_kev, criticality,
            cvss_component, epss_component, kev_component, crit_component,
            risk_score, risk_level
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
            scored = self.score_cve({
                "cvssScore":        row.get("cvssScore"),
                "epssScore":        row.get("epssScore"),
                "isKEV":            row.get("isKEV"),
                "assetCriticality": row.get("assetCriticality"),
            })

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
                "riskScore":        scored["riskScore"],
                "riskLevel":        scored["riskLevel"],
                "breakdown":        scored["breakdown"],
                "explanation":      scored["explanation"],
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

        # Deterministic composite score
        scored = self.score_cve({
            "cvssScore": cvss, "epssScore": epss,
            "isKEV": is_kev, "assetCriticality": asset_criticality,
        })

        # RF tier prediction
        input_vec   = np.array([[cvss, epss, kev_binary, asset_criticality]])
        tier_idx    = int(self._rf_model.predict(input_vec)[0])
        proba       = self._rf_model.predict_proba(input_vec)[0]
        confidence  = float(np.max(proba))
        tiers       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        rf_tier     = tiers[min(tier_idx, 3)]

        return {
            "riskScore":          scored["riskScore"],
            "riskLevel":          scored["riskLevel"],
            "rfPredictedTier":    rf_tier,
            "rfConfidence":       round(confidence * 100, 2),
            "breakdown":          scored["breakdown"],
            "explanation":        scored["explanation"],
            # Legacy keys kept for any older consumers
            "predicted_tier":     scored["riskLevel"],
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
        """Fallback mock data when Neo4j returns nothing (mock mode)."""
        return [
            {"assetName": "Web Application Gateway", "assetId": "Asset_1",
             "assetCriticality": 10, "cveId": "CVE-2026-1043",
             "cvssScore": 9.8, "epssScore": 0.9452, "isKEV": True,
             "severity": "CRITICAL", "kevDueDate": "2026-06-05"},
            {"assetName": "Authentication Service",  "assetId": "Asset_2",
             "assetCriticality": 9,  "cveId": "CVE-2026-2090",
             "cvssScore": 8.1, "epssScore": 0.7812, "isKEV": False,
             "severity": "HIGH",     "kevDueDate": "N/A"},
            {"assetName": "Edge Firewall Router",    "assetId": "Asset_5",
             "assetCriticality": 9,  "cveId": "CVE-2026-4401",
             "cvssScore": 7.5, "epssScore": 0.6120, "isKEV": True,
             "severity": "HIGH",     "kevDueDate": "2026-06-10"},
            {"assetName": "Admin Dashboard",         "assetId": "Asset_3",
             "assetCriticality": 8,  "cveId": "CVE-2026-3022",
             "cvssScore": 6.5, "epssScore": 0.0841, "isKEV": False,
             "severity": "MEDIUM",   "kevDueDate": "N/A"},
        ]


logger.info("RiskScorer module loaded.")
