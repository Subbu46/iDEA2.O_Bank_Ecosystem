"""
api/routes_playbook.py
----------------------
FastAPI router for GenAI-powered playbook and RCA endpoints.

  POST /playbooks/generate             – legacy string playbook (backwards compat)
  POST /playbooks/remediation          – structured 7-section remediation playbook
  POST /playbooks/security-policy      – 1-page MITRE technique security policy
  POST /playbooks/rca                  – structured 7-section RCA report
  POST /playbooks/incident-response    – concise SOC IR draft for a single alert
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional

from genai.playbook_gen import PlaybookGenerator
from genai.rca_gen import RCAGenerator

router = APIRouter(prefix="/playbooks", tags=["GenAI Orchestration Playbooks"])

# Module-level singletons — one Gemini client per worker
playbook_engine = PlaybookGenerator()
rca_engine      = RCAGenerator()


# ── Request models ─────────────────────────────────────────────────────────────

class LegacyPlaybookRequest(BaseModel):
    """Legacy request shape kept for backwards compatibility."""
    cve_id:         str
    asset_name:     str
    technique_name: str


class RemediationRequest(BaseModel):
    """Full structured playbook request."""
    cve_data: Dict[str, Any] = Field(
        ...,
        example={
            "cveId":       "CVE-2026-1043",
            "description": "RCE in web gateway via crafted HTTP requests.",
            "cvssScore":   9.8,
            "severity":    "CRITICAL",
            "epssScore":   0.9452,
            "isKEV":       True,
        }
    )
    affected_assets: List[str] = Field(
        default_factory=list,
        example=["Web Application Gateway", "Edge Firewall Router"],
    )


class SecurityPolicyRequest(BaseModel):
    technique_data: Dict[str, Any] = Field(
        ...,
        example={
            "techniqueId": "T1190",
            "name":        "Exploit Public-Facing Application",
            "tactic":      "Initial Access",
            "capecId":     "CAPEC-242",
        }
    )


class IncidentDataRequest(BaseModel):
    """Structured incident data for the new RCA API."""
    incidentId:     str               = "INC-UNKNOWN"
    attackType:     str               = "Unknown Attack"
    affectedAssets: List[str]         = Field(default_factory=list)
    attackVector:   str               = "Unknown Vector"
    timestamp:      str               = "N/A"
    detectionTime:  str               = "N/A"


class LegacyRCARequest(BaseModel):
    """Legacy alert-sequence list kept for backwards compatibility."""
    alert_sequence: List[Dict[str, Any]]


class IRDraftRequest(BaseModel):
    """Single alert dict for SOC IR draft generation."""
    alert_data: Dict[str, Any] = Field(
        ...,
        example={
            "id":          "alert_01",
            "severity":    "CRITICAL",
            "asset_id":    "Asset_1",
            "message":     "External port sweep on Edge Router Gateway",
            "cve_id":      "CVE-2026-1043",
            "technique_id":"T1190",
            "timestamp":   "2026-05-20T17:00:00",
        }
    )


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post(
    "/generate",
    summary="Legacy: generate playbook (returns raw markdown string)",
)
def create_playbook(request: LegacyPlaybookRequest):
    """
    Backwards-compatible endpoint that returns a raw markdown string.
    Delegates to generate_mitigation_playbook() → rawResponse.
    """
    try:
        playbook = playbook_engine.generate_mitigation_playbook(
            cve_id=request.cve_id,
            asset_name=request.asset_name,
            technique_name=request.technique_name,
        )
        return {"playbook": playbook}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post(
    "/remediation",
    summary="Generate structured 7-section remediation playbook (banking context)",
)
def create_remediation_playbook(request: RemediationRequest):
    """
    Generates a structured playbook with sections:
    executiveSummary, immediateActions, shortTermRemediation, longTermHardening,
    verificationSteps, rollbackPlan, complianceNotes.

    Includes the raw LLM response alongside parsed sections.
    Falls back gracefully if Gemini API is unavailable.
    """
    try:
        return playbook_engine.generate_remediation_playbook(
            cve_data=request.cve_data,
            affected_assets=request.affected_assets,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post(
    "/security-policy",
    summary="Generate 1-page security policy for a MITRE ATT&CK technique",
)
def create_security_policy(request: SecurityPolicyRequest):
    """
    Generates a 1-page policy document (RBI/ISO 27001/DPDP compliant)
    for the specified MITRE ATT&CK technique.
    """
    try:
        policy = playbook_engine.generate_security_policy(request.technique_data)
        return {"policy": policy}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post(
    "/rca",
    summary="Generate structured RCA report (incident_data or legacy alert list)",
)
def generate_rca(request: IncidentDataRequest | LegacyRCARequest):
    """
    Accepts either:
    - `IncidentDataRequest` — structured incident dict (new API)
    - `LegacyRCARequest`   — `alert_sequence` list (backwards compat)

    Returns structured sections:
    incidentId, timeline, rootCause, contributingFactors,
    immediateImpact, lessonLearned, preventionMeasures, executiveSummary.
    """
    try:
        if isinstance(request, LegacyRCARequest):
            rca_report = rca_engine.generate_rca_report(request.alert_sequence)
        else:
            rca_report = rca_engine.generate_rca_report(request.model_dump())
        return {"rca_report": rca_report}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post(
    "/incident-response",
    summary="Generate concise SOC incident response draft for a single alert",
)
def create_ir_draft(request: IRDraftRequest):
    """
    Fast-path endpoint for real-time dashboard use.
    Returns a concise (< 250 word) incident response draft.
    """
    try:
        draft = rca_engine.generate_incident_response_draft(request.alert_data)
        return {"ir_draft": draft}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
