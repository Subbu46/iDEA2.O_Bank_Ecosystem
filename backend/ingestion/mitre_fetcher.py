import requests
import json
import logging
from pathlib import Path
from typing import List, Dict, Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sarathi.mitre_fetcher")

class MitreFetcher:
    """
    Fetcher and mapper for MITRE ATT&CK Techniques.
    Fetches the official enterprise-attack.json feed and correlates techniques.
    """
    def __init__(self):
        self.api_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        self.data_dir = Path(__file__).resolve().parent.parent / "data"
        self.output_file = self.data_dir / "mitre_techniques.json"
        
        # Original static high-fidelity correlation map
        self.cve_to_technique_map = {
            "CVE-2026-1043": {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "capec_id": "CAPEC-242",
                "capec_name": "Connection Reset"
            },
            "CVE-2026-2090": {
                "technique_id": "T1110",
                "technique_name": "Brute Force / Auth Bypass",
                "tactic": "Credential Access",
                "capec_id": "CAPEC-109",
                "capec_name": "SQL Injection"
            },
            "CVE-2026-3022": {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "capec_id": "CAPEC-588",
                "capec_name": "DOM-Based XSS"
            },
            "CVE-2026-4401": {
                "technique_id": "T1499",
                "technique_name": "Endpoint Denial of Service",
                "tactic": "Impact",
                "capec_id": "CAPEC-125",
                "capec_name": "Flooding"
            }
        }

    def get_attack_details(self, cve_id: str) -> Dict[str, Any]:
        """
        Maps a CVE ID to its associated MITRE ATT&CK Technique and CAPEC pattern.
        Pulls updated name and details from mitre_techniques.json if cached.
        """
        base_mapping = self.cve_to_technique_map.get(
            cve_id,
            {
                "technique_id": "T1203",
                "technique_name": "Exploitation for Client Execution",
                "tactic": "Execution",
                "capec_id": "CAPEC-63",
                "capec_name": "Cross-Site Scripting (XSS)"
            }
        )
        
        # Enriched from cached mitre_techniques.json if possible
        if self.output_file.exists():
            try:
                with open(self.output_file, "r", encoding="utf-8") as f:
                    techniques = json.load(f)
                
                tech_dict = {t.get("techniqueId"): t for t in techniques if t.get("techniqueId")}
                tech_id = base_mapping.get("technique_id")
                
                if tech_id in tech_dict:
                    tech_data = tech_dict[tech_id]
                    # Update technique_name and tactic with live data if available
                    base_mapping["technique_name"] = tech_data.get("name", base_mapping["technique_name"])
                    tactics = tech_data.get("tactics", [])
                    if tactics:
                        # Convert to title case/readable format for tactics
                        base_mapping["tactic"] = ", ".join(tactics).title()
            except Exception as e:
                logger.error(f"Error enriching MITRE attack details: {e}")
                
        return base_mapping

    def run_ingestion(self) -> int:
        """
        Downloads the MITRE ATT&CK Enterprise dataset and parses out all active techniques.
        """
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Downloading MITRE ATT&CK Enterprise STIX feed from {self.api_url}")
        
        try:
            response = requests.get(self.api_url, timeout=30)
            if response.status_code != 200:
                logger.error(f"MITRE STIX feed returned status code {response.status_code}: {response.text}")
                return 0
                
            data = response.json()
            objects = data.get("objects", [])
            techniques_list = []
            
            for obj in objects:
                # We only want attack-patterns (Techniques) that are not deprecated or revoked
                if obj.get("type") == "attack-pattern" and not obj.get("x_mitre_deprecated") and not obj.get("revoked"):
                    name = obj.get("name")
                    description = obj.get("description", "")
                    platforms = obj.get("x_mitre_platforms", [])
                    
                    # Extract external ID (Txxxx)
                    external_references = obj.get("external_references", [])
                    technique_id = None
                    for ref in external_references:
                        if ref.get("source_name") == "mitre-attack":
                            technique_id = ref.get("external_id")
                            break
                            
                    # Extract tactics
                    tactics = []
                    for phase in obj.get("kill_chain_phases", []):
                        if phase.get("kill_chain_name") == "mitre-attack":
                            tactics.append(phase.get("phase_name"))
                            
                    if technique_id:
                        techniques_list.append({
                            "techniqueId": technique_id,
                            "name": name,
                            "description": description,
                            "tactics": tactics,
                            "platforms": platforms
                        })
            
            # Save techniques
            if techniques_list:
                with open(self.output_file, "w", encoding="utf-8") as f:
                    json.dump(techniques_list, f, indent=4)
                logger.info(f"Successfully saved {len(techniques_list)} MITRE techniques to {self.output_file}")
                return len(techniques_list)
            else:
                logger.warning("No MITRE techniques were parsed.")
                
        except Exception as e:
            logger.error(f"Exception during MITRE fetch: {e}")
            
        return 0

if __name__ == "__main__":
    fetcher = MitreFetcher()
    fetcher.run_ingestion()
