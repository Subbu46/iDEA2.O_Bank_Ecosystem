from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
from datetime import datetime

router = APIRouter(prefix="/alerts", tags=["Threat Alerts Panel"])

# Realistic simulated banking SOC alerts — 12 entries, one per asset
# Using real CVE IDs from CVE_LIBRARY and authentic MITRE technique codes
alerts_store = [
    {
        "id": "alert_01",
        "timestamp": datetime.now().isoformat()[:19],
        "severity": "CRITICAL",
        "asset_id": "SRV-DMZ-WEB-01",
        "message": "CVE-2023-25690 Exploit: HTTP request smuggling on Apache 2.4.52 — attacker bypassing WAF rules on internet banking portal",
        "status": "UNRESOLVED",
        "cve_id": "CVE-2023-25690",
        "technique_id": "T1190"
    },
    {
        "id": "alert_02",
        "timestamp": datetime.now().isoformat()[:19],
        "severity": "HIGH",
        "asset_id": "SRV-DMZ-GW-02",
        "message": "Anomalous API traffic spike: 14,200 req/sec via NGINX Plus — HTTP/2 integer overflow probe on mobile banking gateway",
        "status": "UNRESOLVED",
        "cve_id": "CVE-2022-41915",
        "technique_id": "T1498"
    },
    {
        "id": "alert_03",
        "timestamp": datetime.now().isoformat()[:19],
        "severity": "HIGH",
        "asset_id": "SRV-DMZ-CMS-03",
        "message": "XXE Injection attempt: Malformed XML media upload to WordPress 6.1 attempting SSRF probe into internal banking subnet",
        "status": "ACKNOWLEDGED",
        "cve_id": "CVE-2021-29447",
        "technique_id": "T1059"
    },
    {
        "id": "alert_04",
        "timestamp": datetime.now().isoformat()[:19],
        "severity": "CRITICAL",
        "asset_id": "SRV-MID-ESB-01",
        "message": "LOG4SHELL ACTIVE — CVE-2021-44228 confirmed: JNDI LDAP callback to 185.220.x.x detected on ESB, reverse shell spawned",
        "status": "UNRESOLVED",
        "cve_id": "CVE-2021-44228",
        "technique_id": "T1190"
    },
    {
        "id": "alert_05",
        "timestamp": datetime.now().isoformat()[:19],
        "severity": "CRITICAL",
        "asset_id": "SRV-MID-IAM-02",
        "message": "Zlib heap overflow on Keycloak 20.0.1 session decoder — potential auth bypass to impersonate privileged banking operator",
        "status": "UNRESOLVED",
        "cve_id": "CVE-2022-37434",
        "technique_id": "T1068"
    },
    {
        "id": "alert_06",
        "timestamp": datetime.now().isoformat()[:19],
        "severity": "HIGH",
        "asset_id": "SRV-MID-SWI-03",
        "message": "MinIO credential disclosure: Unauthenticated probe exposed MINIO_SECRET_KEY on payment switch — immediate rotation required",
        "status": "UNRESOLVED",
        "cve_id": "CVE-2023-28432",
        "technique_id": "T1552"
    },
    {
        "id": "alert_07",
        "timestamp": datetime.now().isoformat()[:19],
        "severity": "HIGH",
        "asset_id": "SRV-CORE-CBS-01",
        "message": "Oracle WebLogic T3 anomaly: Unauthenticated IIOP bind from 10.1.1.10 attempting CBS control plane access",
        "status": "UNRESOLVED",
        "cve_id": "CVE-2023-21839",
        "technique_id": "T1210"
    },
    {
        "id": "alert_08",
        "timestamp": datetime.now().isoformat()[:19],
        "severity": "CRITICAL",
        "asset_id": "DB-CORE-LEDG-02",
        "message": "TNS packet flood on Oracle DB 19c port 1521 — CVE-2022-21569 unauthenticated read probe targeting customer ledger tables",
        "status": "UNRESOLVED",
        "cve_id": "CVE-2022-21569",
        "technique_id": "T1190"
    },
    {
        "id": "alert_09",
        "timestamp": datetime.now().isoformat()[:19],
        "severity": "HIGH",
        "asset_id": "SRV-CORE-SWIFT-03",
        "message": "Privilege escalation on SWIFT Alliance v7.6: kernel register manipulation detected — MT103 message tampering risk",
        "status": "ACKNOWLEDGED",
        "cve_id": "CVE-2023-38606",
        "technique_id": "T1068"
    },
    {
        "id": "alert_10",
        "timestamp": datetime.now().isoformat()[:19],
        "severity": "CRITICAL",
        "asset_id": "SRV-MGMT-AD-01",
        "message": "LSA SPOOFING ACTIVE — CVE-2022-26925: MitM intercepting NTLM handshakes on domain auth, targeting DC elevation",
        "status": "UNRESOLVED",
        "cve_id": "CVE-2022-26925",
        "technique_id": "T1557"
    },
    {
        "id": "alert_11",
        "timestamp": datetime.now().isoformat()[:19],
        "severity": "HIGH",
        "asset_id": "SRV-MGMT-JUMP-02",
        "message": "Guacamole protocol anomaly: Unexpected RDP re-init from 10.2.1.10 — potential privilege bypass on bastion admin session",
        "status": "UNRESOLVED",
        "cve_id": "CVE-2023-30570",
        "technique_id": "T1021"
    },
    {
        "id": "alert_12",
        "timestamp": datetime.now().isoformat()[:19],
        "severity": "MEDIUM",
        "asset_id": "SRV-MGMT-SIEM-03",
        "message": "Elasticsearch DoS probe: Crafted malformed audit packages causing 94% CPU spike — SIEM visibility degradation (CVE-2023-31414)",
        "status": "RESOLVED",
        "cve_id": "CVE-2023-31414",
        "technique_id": "T1499"
    },
]


class AlertUpdate(BaseModel):
    status: str

@router.get("", summary="List all security alerts")
def list_alerts():
    """
    Returns active security incident alerts.
    """
    return alerts_store

@router.post("/{alert_id}/acknowledge", summary="Acknowledge alert")
def acknowledge_alert(alert_id: str):
    """
    Mark an active alert's status as ACKNOWLEDGED.
    """
    for alert in alerts_store:
        if alert["id"] == alert_id:
            alert["status"] = "ACKNOWLEDGED"
            return {"status": "Success", "alert": alert}
    raise HTTPException(status_code=404, detail="Alert not found")

@router.post("/{alert_id}/resolve", summary="Resolve alert (frontend compatible)")
def resolve_alert(alert_id: str, payload: AlertUpdate = None):
    """
    Acknowledge or resolve an active alert with custom payload status (supporting frontend calls).
    """
    status = payload.status if payload else "RESOLVED"
    for alert in alerts_store:
        if alert["id"] == alert_id:
            alert["status"] = status
            return {"status": "Success", "alert": alert}
    raise HTTPException(status_code=404, detail="Alert not found")

@router.get("/stats", summary="Alert metrics and counts")
def get_alerts_stats():
    """
    Compiles stats for the alerts dashboard grouped by severity and status.
    """
    total = len(alerts_store)
    severities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    statuses = {"UNRESOLVED": 0, "ACKNOWLEDGED": 0, "RESOLVED": 0}
    
    for alert in alerts_store:
        sev = alert.get("severity", "MEDIUM").upper()
        stat = alert.get("status", "UNRESOLVED").upper()
        
        if sev in severities:
            severities[sev] += 1
        else:
            severities["MEDIUM"] += 1
            
        if stat in statuses:
            statuses[stat] += 1
        else:
            statuses["UNRESOLVED"] += 1
            
    return {
        "total": total,
        "severities": severities,
        "statuses": statuses
    }
