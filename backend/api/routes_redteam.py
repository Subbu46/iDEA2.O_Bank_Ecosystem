from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
from redteam.simulator import RedTeamSimulator
from api.routes_alerts import alerts_store
import uuid

router = APIRouter(prefix="/redteam", tags=["Red Team Attack Simulator"])
simulator = RedTeamSimulator()

class SimulationRequest(BaseModel):
    scenario: str

@router.get("/scenarios")
def get_scenarios():
    """
    Lists available pre-defined breach simulation scenarios.
    """
    return {"scenarios": simulator.get_available_scenarios()}

@router.post("/trigger")
def trigger_breach(request: SimulationRequest):
    """
    Triggers the selected red team simulation and streams the events into the SOC logs dashboard.
    """
    scenarios = simulator.get_available_scenarios()
    if request.scenario not in scenarios:
        raise HTTPException(status_code=400, detail="Scenario not supported.")
        
    simulated_events = simulator.start_simulation(request.scenario)
    
    # Map simulated events into active alert panel storage
    added_alerts = []
    for idx, event in enumerate(simulated_events):
        alert_item = {
            "id": f"sim_{str(uuid.uuid4())[:8]}",
            "timestamp": event["timestamp"],
            "severity": event["severity"],
            "asset_id": event["asset_id"],
            "message": event["message"],
            "status": "UNRESOLVED",
            # Standardize linkages
            "cve_id": "CVE-2026-1043" if "Asset_1" in event["asset_id"] else "CVE-2026-2090",
            "technique_id": "T1190" if "Asset_1" in event["asset_id"] else "T1110"
        }
        alerts_store.insert(0, alert_item) # Insert at front
        added_alerts.append(alert_item)
        
    return {
        "status": "Breach campaign initiated",
        "scenario": request.scenario,
        "alerts_injected": len(added_alerts),
        "injected_details": added_alerts
    }
