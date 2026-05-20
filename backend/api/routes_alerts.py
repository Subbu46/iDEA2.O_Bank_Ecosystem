from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Dict, Any
from datetime import datetime

router = APIRouter(prefix="/alerts", tags=["Threat Alerts Panel"])

# In-memory session database for tracking alerts
alerts_store = [
    {
        "id": "alert_01",
        "timestamp": datetime.now().isoformat()[:19],
        "severity": "CRITICAL",
        "asset_id": "Asset_1",
        "message": "Reconnaissance scan: External port sweep detected targeting Edge Router Gateway",
        "status": "UNRESOLVED",
        "cve_id": "CVE-2026-1043",
        "technique_id": "T1190"
    },
    {
        "id": "alert_02",
        "timestamp": datetime.now().isoformat()[:19],
        "severity": "HIGH",
        "asset_id": "Asset_3",
        "message": "API Abuse: Unexpected brute force authorization requests against /api/v1/auth",
        "status": "UNRESOLVED",
        "cve_id": "CVE-2026-2090",
        "technique_id": "T1110"
    }
]

class AlertUpdate(BaseModel):
    status: str

@router.get("")
def list_alerts():
    """
    Returns active security incident alerts.
    """
    return alerts_store

@router.post("/{alert_id}/resolve")
def resolve_alert(alert_id: str, payload: AlertUpdate):
    """
    Acknowledge or resolve an active alert.
    """
    for alert in alerts_store:
        if alert["id"] == alert_id:
            alert["status"] = payload.status
            return {"status": "Success", "alert": alert}
    return {"status": "Error", "message": "Alert not found"}
