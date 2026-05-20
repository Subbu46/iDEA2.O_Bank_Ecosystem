"""
run_ml_demo.py
--------------
Standalone demo: connects to Neo4j Aura, runs both ML modules against
live graph data, and prints formatted results for human review.

Run from backend/ directory:
    python -X utf8 run_ml_demo.py
"""

import sys
import os
import io
import logging

# Force UTF-8 so box-drawing characters work on Windows
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

logging.basicConfig(
    level=logging.WARNING,  # suppress verbose DEBUG during demo
    format="%(levelname)s %(name)s — %(message)s",
)

# ─────────────────────────────────────────────────────────────────────────────
SEP  = "=" * 66
SEP2 = "-" * 66
TICK = "[OK]"
WARN = "[!!]"

RISK_COLORS = {
    "CRITICAL": "*** CRITICAL ***",
    "HIGH":     "**  HIGH       **",
    "MEDIUM":   "*   MEDIUM      *",
    "LOW":      "    LOW          ",
}


def banner(title: str) -> None:
    print(f"\n{SEP}")
    print(f"  {title}")
    print(SEP)


def section(title: str) -> None:
    print(f"\n  {SEP2}")
    print(f"  {title}")
    print(f"  {SEP2}")


def main() -> None:
    from graph.neo4j_client import Neo4jClient
    from ml.risk_scorer import RiskScorer
    from ml.attack_path import AttackPathAnalyzer

    # ── Connect ───────────────────────────────────────────────────────────────
    banner("Sarathi Cyberdefense — ML Module Live Demo")
    print(f"\n  Connecting to Neo4j Aura …")
    db = Neo4jClient()

    if db.mock_mode:
        print(f"\n  {WARN}  MOCK MODE — Neo4j Aura unavailable. Using in-memory data.\n")
    else:
        print(f"\n  {TICK}  Connected: {db.uri}\n")

    scorer        = RiskScorer()
    path_analyzer = AttackPathAnalyzer()

    # ═══════════════════════════════════════════════════════════════════════════
    # PART 1 — RiskScorer
    # ═══════════════════════════════════════════════════════════════════════════
    banner("PART 1 — RiskScorer")

    # 1a. score_cve demo
    section("1a. score_cve() — spot-checks with known CVEs")
    spot_checks = [
        {"label": "CVE-2026-1043 (KEV, CRITICAL, high-crit asset)",
         "data":  {"cvssScore": 9.8, "epssScore": 0.9452, "isKEV": True,  "assetCriticality": 10}},
        {"label": "CVE-2026-2090 (HIGH, no KEV)",
         "data":  {"cvssScore": 8.1, "epssScore": 0.7812, "isKEV": False, "assetCriticality": 9}},
        {"label": "CVE-2026-4401 (KEV, HIGH, high-crit firewall)",
         "data":  {"cvssScore": 7.5, "epssScore": 0.6120, "isKEV": True,  "assetCriticality": 9}},
        {"label": "CVE-2026-3022 (MEDIUM, no KEV, internal dashboard)",
         "data":  {"cvssScore": 6.5, "epssScore": 0.0841, "isKEV": False, "assetCriticality": 8}},
        {"label": "Unknown CVE (all defaults / missing values)",
         "data":  {"cvssScore": None, "epssScore": None, "isKEV": None,   "assetCriticality": None}},
    ]

    for chk in spot_checks:
        result = scorer.score_cve(chk["data"])
        tag    = RISK_COLORS.get(result["riskLevel"], result["riskLevel"])
        bd     = result["breakdown"]
        print(f"\n  [{tag}]  {chk['label']}")
        print(f"    Score : {result['riskScore']:.1f}/100")
        print(f"    Breakdown → CVSS:{bd['cvssComponent']}  "
              f"EPSS:{bd['epssComponent']}  "
              f"KEV:{bd['kevBonus']}  "
              f"Crit:{bd['critComponent']}")
        print(f"    Explain: {result['explanation']}")

    # 1b. classify_risk demo
    section("1b. classify_risk() — threshold verification")
    test_scores = [100, 90, 81, 80, 70, 61, 60, 50, 41, 40, 20, 0]
    for s in test_scores:
        print(f"    score={s:>3}  →  {scorer.classify_risk(s)}")

    # 1c. predict_risk (hybrid RF + formula)
    section("1c. predict_risk() — hybrid RF + formula (backward-compat API)")
    hybrid = scorer.predict_risk(cvss=9.8, epss=0.9452, is_kev=True, asset_criticality=10)
    print(f"    riskScore      : {hybrid['riskScore']}")
    print(f"    riskLevel      : {hybrid['riskLevel']}")
    print(f"    rfPredictedTier: {hybrid['rfPredictedTier']}")
    print(f"    rfConfidence   : {hybrid['rfConfidence']}%")
    print(f"    Breakdown      : {hybrid['breakdown']}")

    # 1d. get_top_risks from live Neo4j
    section("1d. get_top_risks() — top 10 scored CVE-asset pairs from Neo4j")
    top_risks = scorer.get_top_risks(neo4j_client=db, limit=10)
    print(f"\n  {'#':<3}  {'CVE ID':<18}  {'Asset':<26}  "
          f"{'CVSS':>5}  {'EPSS':>6}  {'KEV':>4}  {'Score':>6}  {'Level'}")
    print(f"  {'─'*3}  {'─'*18}  {'─'*26}  "
          f"{'─'*5}  {'─'*6}  {'─'*4}  {'─'*6}  {'─'*8}")
    for i, r in enumerate(top_risks, 1):
        kev = "YES" if r["isKEV"] else "no"
        print(f"  {i:<3}  {r['cveId']:<18}  {r['assetName']:<26}  "
              f"{r['cvssScore']:>5.1f}  {r['epssScore']:>6.4f}  {kev:>4}  "
              f"{r['riskScore']:>6.1f}  {r['riskLevel']}")

    # ═══════════════════════════════════════════════════════════════════════════
    # PART 2 — AttackPathAnalyzer
    # ═══════════════════════════════════════════════════════════════════════════
    banner("PART 2 — AttackPathAnalyzer")

    # 2a. find_attack_paths
    section("2a. find_attack_paths() — Asset_1 (Gateway) → Asset_4 (DB Cluster)")
    paths = path_analyzer.find_attack_paths(
        neo4j_client=db,
        source="Asset_1",
        target="Asset_4",
    )
    for rank, path in enumerate(paths, 1):
        kev_flag = " [KEV CONFIRMED]" if path["contains_kev"] else ""
        print(f"\n  Rank #{rank}{kev_flag}")
        print(f"    Hops        : {path['hop_count']}")
        print(f"    Risk Score  : {path['total_risk_score']:.1f}")
        print(f"    Worst CVE   : {path['highest_risk_cve'] or 'N/A'}")
        print(f"    Path        : {' → '.join(path['path_nodes'])}")
        print(f"    Explanation : {path['explanation']}")

    # 2b. find_attack_paths — alternate route
    section("2b. find_attack_paths() — Asset_5 (Firewall) → Asset_4 (DB Cluster)")
    paths2 = path_analyzer.find_attack_paths(
        neo4j_client=db,
        source="Asset_5",
        target="Asset_4",
    )
    for rank, path in enumerate(paths2, 1):
        kev_flag = " [KEV CONFIRMED]" if path["contains_kev"] else ""
        print(f"\n  Rank #{rank}{kev_flag}")
        print(f"    Hops        : {path['hop_count']}")
        print(f"    Risk Score  : {path['total_risk_score']:.1f}")
        print(f"    Path        : {' → '.join(path['path_nodes'])}")

    # 2c. get_critical_assets
    section("2c. get_critical_assets() — criticality >= 7")
    assets = path_analyzer.get_critical_assets(neo4j_client=db, min_criticality=7)
    print(f"\n  {'Asset':<28}  {'Type':<14}  {'Crit':>4}  "
          f"{'CVEs':>4}  {'MaxCVSS':>7}  {'RiskScore':>9}  {'Level'}")
    print(f"  {'─'*28}  {'─'*14}  {'─'*4}  "
          f"{'─'*4}  {'─'*7}  {'─'*9}  {'─'*8}")
    for a in assets:
        print(f"  {a['name']:<28}  {a['type']:<14}  {a['criticality']:>4}  "
              f"{a['vulnerabilityCount']:>4}  {a['maxCvssScore']:>7.1f}  "
              f"{a['maxCveRisk']:>9.1f}  {a['riskLevel']}")
        if a["cveIds"]:
            print(f"    CVEs: {', '.join(a['cveIds'][:5])}"
                  + (" …" if len(a["cveIds"]) > 5 else ""))

    # ═══════════════════════════════════════════════════════════════════════════
    # PART 3 — Sample frontend API payloads
    # ═══════════════════════════════════════════════════════════════════════════
    banner("PART 3 — Sample API Response Shapes (for frontend integration)")

    section("GET /api/graph/top-risks?limit=3  →  first 3 records")
    import json
    sample_risks = top_risks[:3]
    # Trim explanation for readability
    for r in sample_risks:
        r["explanation"] = r["explanation"][:120] + "…"
    print(json.dumps(sample_risks, indent=4))

    section("GET /api/graph/attack-paths?source=Asset_1&target=Asset_4  →  first path")
    if paths and paths[0]["hop_count"] > 0:
        p = dict(paths[0])
        p["explanation"] = p["explanation"][:160] + "…"
        print(json.dumps(p, indent=4))

    section("GET /api/graph/critical-assets?min_criticality=7  →  first 2 records")
    print(json.dumps(assets[:2], indent=4))

    # ── Teardown ──────────────────────────────────────────────────────────────
    db.close()
    print(f"\n{SEP}")
    print("  Demo complete. Neo4j driver closed.")
    print(SEP + "\n")


if __name__ == "__main__":
    main()
