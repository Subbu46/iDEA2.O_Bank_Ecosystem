"""
api/routes_graph.py
-------------------
FastAPI router for all Knowledge Graph operations:

  GET  /graph/nodes              – all nodes (react-force-graph format)
  GET  /graph/links              – all relationships
  GET  /graph/top-risks          – composite-scored CVE+asset risk list
  GET  /graph/attack-path        – shortest hop path (legacy)
  GET  /graph/attack-paths       – ranked lateral movement paths (full analysis)
  GET  /graph/critical-assets    – assets with criticality >= threshold
  POST /graph/evaluate-risk      – single-CVE risk prediction (RF + formula)
  POST /graph/sync               – trigger full threat-intel ingestion pipeline
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import List, Dict, Any, Optional

from graph.neo4j_client import Neo4jClient
from ml.attack_path import AttackPathAnalyzer
from ml.risk_scorer import RiskScorer
from ingestion.threat_intel_orchestrator import ThreatIntelOrchestrator

router = APIRouter(prefix="/graph", tags=["Threat Knowledge Graph"])

# ── Module-level singletons ───────────────────────────────────────────────────
# One shared Neo4j connection per worker process (FastAPI is async-safe here
# because all DB calls are synchronous bolt driver calls).
db_client     = Neo4jClient()
path_analyzer = AttackPathAnalyzer(db_client)   # legacy compat
scorer        = RiskScorer()


# ── Request / Response models ─────────────────────────────────────────────────

class RiskQuery(BaseModel):
    cvss:             float
    epss:             float
    is_kev:           bool
    asset_criticality: int


# ─────────────────────────────────────────────────────────────────────────────
# Existing endpoints (kept intact for frontend compatibility)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/nodes", summary="All graph nodes & links (visualization format)")
def get_graph_nodes():
    """
    Returns unified graph payload containing both nodes and links formatted
    for react-force-graph and standard visualization tools.
    """
    try:
        # Get nodes
        results = db_client.run_query("MATCH (n) RETURN n")
        nodes = []
        for record in results:
            node = record.get("n", {})
            if not node:
                continue
            
            # Infer label (class type)
            label = (
                node.get("label")
                or ("Vulnerability" if "cve_id" in node else
                    "Technique" if "technique_id" in node else
                    "Asset")
            )
            node_id = node.get("id") or node.get("cve_id") or node.get("technique_id")
            
            nodes.append({
                "id": node_id,
                "label": label,
                "type": node.get("type") or label,
                "name": node.get("name") or node_id,
                "properties": node,
            })
            
        # Get links
        if db_client.mock_mode:
            links = [
                {"source": r["from"], "target": r["to"], "type": r["type"]}
                for r in db_client.mock_relationships
            ]
        else:
            link_results = db_client.run_query(
                "MATCH (a)-[r]->(b) "
                "RETURN a.id AS src_id, a.cve_id AS src_cve, a.technique_id AS src_tech, "
                "       b.id AS tgt_id, b.cve_id AS tgt_cve, b.technique_id AS tgt_tech, "
                "       type(r) AS rel"
            )
            links = []
            for rec in link_results:
                src = rec.get("src_id") or rec.get("src_cve") or rec.get("src_tech")
                tgt = rec.get("tgt_id") or rec.get("tgt_cve") or rec.get("tgt_tech")
                if src and tgt:
                    links.append({
                        "source": src,
                        "target": tgt,
                        "type": rec.get("rel"),
                    })
            
        return {
            "nodes": nodes,
            "links": links
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/links", summary="All graph relationships")
def get_graph_links():
    """Returns all directed edges in the Knowledge Graph (kept for backward compatibility)."""
    try:
        if db_client.mock_mode:
            return [
                {"source": r["from"], "target": r["to"], "type": r["type"]}
                for r in db_client.mock_relationships
            ]
        link_results = db_client.run_query(
            "MATCH (a)-[r]->(b) "
            "RETURN a.id AS src_id, a.cve_id AS src_cve, a.technique_id AS src_tech, "
            "       b.id AS tgt_id, b.cve_id AS tgt_cve, b.technique_id AS tgt_tech, "
            "       type(r) AS rel"
        )
        links = []
        for rec in link_results:
            src = rec.get("src_id") or rec.get("src_cve") or rec.get("src_tech")
            tgt = rec.get("tgt_id") or rec.get("tgt_cve") or rec.get("tgt_tech")
            if src and tgt:
                links.append({
                    "source": src,
                    "target": tgt,
                    "type": rec.get("rel"),
                })
        return links
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/attack-path",
    summary="Shortest hop path between two assets (legacy)",
)
def compute_attack_path(source: str, target: str):
    """
    Legacy endpoint: returns the shortest unweighted hop path.
    For full ranked-path analysis, use GET /graph/attack-paths instead.
    """
    path = path_analyzer.find_shortest_attack_path(source, target)
    if not path:
        return {"status": "No path found", "path": []}
    return {"status": "Critical attack path identified", "path": path}


@router.post("/evaluate-risk", summary="Single-CVE risk prediction")
def evaluate_cyber_risk(query: RiskQuery):
    """
    Hybrid risk evaluator: deterministic composite formula +
    RandomForest tier prediction, with full breakdown and explanation.
    """
    prediction = scorer.predict_risk(
        cvss=query.cvss,
        epss=query.epss,
        is_kev=query.is_kev,
        asset_criticality=query.asset_criticality,
    )
    return prediction


@router.post("/sync", summary="Trigger threat-intel ingestion + graph rebuild")
def sync_threat_intel():
    """
    Runs all four ingestion pipelines (NVD, MITRE, EPSS, KEV) in parallel,
    then rebuilds the Neo4j Knowledge Graph.  Also invalidates ML caches so
    the next /top-risks or /attack-paths call reflects fresh data.
    """
    try:
        orchestrator = ThreatIntelOrchestrator()
        result = orchestrator.run_sync_pipeline()

        # Invalidate stale ML caches after a sync
        scorer.invalidate_cache()
        path_analyzer.invalidate_cache()

        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# New ML-powered endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/top-risks",
    summary="Top composite-risk CVEs linked to assets",
)
def get_top_risks(
    limit: int = Query(default=20, ge=1, le=100, description="Max results to return"),
):
    """
    Queries Neo4j for CVE-Asset pairs, computes composite risk scores using
    the weighted formula (CVSS 30% + EPSS 40% + KEV bonus + criticality 30%),
    and returns results sorted by risk score descending.

    Results are cached for 2 minutes to reduce Aura reads.

    Response schema per item
    ------------------------
    cveId, cvssScore, epssScore, isKEV, severity, kevDueDate,
    assetName, assetId, assetCriticality,
    riskScore, riskLevel, breakdown, explanation
    """
    try:
        return scorer.get_top_risks(neo4j_client=db_client, limit=limit)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/attack-paths",
    summary="Ranked lateral movement paths with risk scoring",
)
def get_attack_paths(
    source: str = Query(default="SRV-DMZ-WEB-01", description="Entry-point asset ID (DMZ web server)"),
    target: str = Query(default="DB-CORE-LEDG-02", description="Target asset ID (Central Production DB)"),
):
    """
    Enumerates all simple paths (up to 6 hops) from source to target in the
    asset topology graph, scores each path using cumulative CVE risk scores,
    and returns the top-5 ranked by total risk score.

    Edge weights: 1 / asset_criticality  (prefers traversal through critical assets).

    Response schema per path
    ------------------------
    path_nodes, node_details, total_risk_score, hop_count,
    highest_risk_cve, contains_kev, explanation
    """
    try:
        return path_analyzer.find_attack_paths(
            neo4j_client=db_client,
            source=source,
            target=target,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/critical-assets",
    summary="Assets with criticality >= threshold, enriched with CVE risk",
)
def get_critical_assets(
    min_criticality: int = Query(
        default=7, ge=1, le=10,
        description="Minimum asset criticality score (1-10)"
    ),
):
    """
    Returns all assets meeting the criticality threshold, enriched with:
    - Vulnerability count and max CVSS score
    - Composite max CVE risk score
    - Risk classification (CRITICAL / HIGH / MEDIUM / LOW)
    - List of associated CVE IDs

    Results are sorted by criticality DESC, then maxCveRisk DESC.
    """
    try:
        return path_analyzer.get_critical_assets(
            neo4j_client=db_client,
            min_criticality=min_criticality,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
