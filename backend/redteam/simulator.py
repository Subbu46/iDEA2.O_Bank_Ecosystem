from typing import List, Dict, Any
from datetime import datetime

class RedTeamSimulator:
    """
    Simulates automated red team scenarios (e.g. ransomware propagation, lateral movement).
    Generates realistic multi-stage alerts to feed the SOC dashboard.
    """
    def __init__(self):
        self.scenarios = {
            "web_compromise": [
                {
                    "stage": 1,
                    "timestamp": "2026-05-20T20:00:00",
                    "severity": "HIGH",
                    "asset_id": "Asset_1",
                    "message": "Web Exploitation: CVE-2026-1043 Exploit detected targeting /api/v1/gateway",
                    "status": "TRIGGERED"
                },
                {
                    "stage": 2,
                    "timestamp": "2026-05-20T20:05:00",
                    "severity": "CRITICAL",
                    "asset_id": "Asset_1",
                    "message": "Command Shell Spawn: Unauthorized interactive cmd.exe/bash started by system profile",
                    "status": "TRIGGERED"
                },
                {
                    "stage": 3,
                    "timestamp": "2026-05-20T20:10:00",
                    "severity": "HIGH",
                    "asset_id": "Asset_3",
                    "message": "Lateral Movement: Unauthorized TCP port scanning from 192.168.1.10 to auth service at 192.168.1.12",
                    "status": "TRIGGERED"
                },
                {
                    "stage": 4,
                    "timestamp": "2026-05-20T20:15:00",
                    "severity": "CRITICAL",
                    "asset_id": "Asset_3",
                    "message": "Credential Dumping: Access to /etc/shadow or SAM registry simulated via CVE-2026-2090",
                    "status": "TRIGGERED"
                }
            ],
            "database_exfil": [
                {
                    "stage": 1,
                    "timestamp": "2026-05-20T20:10:00",
                    "severity": "HIGH",
                    "asset_id": "Asset_3",
                    "message": "Privilege Escalation: Administrator account accessed from new session",
                    "status": "TRIGGERED"
                },
                {
                    "stage": 2,
                    "timestamp": "2026-05-20T20:12:00",
                    "severity": "CRITICAL",
                    "asset_id": "Asset_2",
                    "message": "Database Ingress: SQL Injection exploit attempted on crown-jewel database cluster",
                    "status": "TRIGGERED"
                },
                {
                    "stage": 3,
                    "timestamp": "2026-05-20T20:14:00",
                    "severity": "CRITICAL",
                    "asset_id": "Asset_2",
                    "message": "Exfiltration Alert: Unexpected large-volume data transfer from database cluster to external host 45.12.33.2",
                    "status": "TRIGGERED"
                }
            ]
        }

    def start_simulation(self, scenario_name: str) -> List[Dict[str, Any]]:
        """
        Launches a simulated threat scenario, returning its structured alert timeline.
        """
        if scenario_name in self.scenarios:
            events = self.scenarios[scenario_name]
            # Update timestamps to be relative to active execution
            now = datetime.now().isoformat()[:19]
            for i, event in enumerate(events):
                event["timestamp"] = now
            return events
        return []
        
    def get_available_scenarios(self) -> List[str]:
        return list(self.scenarios.keys())
print("Red Team Breach Simulator compiled.")
