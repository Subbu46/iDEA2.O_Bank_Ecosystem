import requests
import time
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Dict, Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sarathi.nvd_fetcher")

class NVDFetcher:
    """
    Fetcher for National Vulnerability Database (NVD) CVE entries.
    Supports live fetching of the last 90 days of CVEs or falling back to saved/mock data.
    """
    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.data_dir = Path(__file__).resolve().parent.parent / "data"
        self.output_file = self.data_dir / "nvd_cves.json"

    def fetch_recent_cves(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Loads cached CVE data from nvd_cves.json if available.
        Otherwise, falls back to pre-defined mock threat intelligence.
        """
        if self.output_file.exists():
            try:
                with open(self.output_file, "r", encoding="utf-8") as f:
                    cached_data = json.load(f)
                
                logger.info(f"Loaded {len(cached_data)} CVE records from local cache.")
                
                mapped_cves = []
                for item in cached_data[:limit]:
                    mapped_cves.append({
                        "cve_id": item.get("cveId"),
                        "severity": item.get("cvssV3Severity", "MEDIUM") or "MEDIUM",
                        "cvss_score": item.get("cvssV3Score", 5.0) or 5.0,
                        "description": item.get("description", "No description available."),
                        "published_date": item.get("publishedDate")
                    })
                return mapped_cves
            except Exception as e:
                logger.error(f"Error reading cached NVD CVEs: {e}. Falling back to mock data.")

        # Hardcoded high-fidelity mock data fallback
        mock_cves = [
            {
                "cve_id": "CVE-2026-1043",
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "description": "Remote Code Execution vulnerability in Sarathi Web Core allows unauthenticated attackers to execute arbitrary shell commands via crafted HTTP requests.",
                "affected_component": "Web Application Gateway",
                "published_date": "2026-05-15"
            },
            {
                "cve_id": "CVE-2026-2090",
                "severity": "HIGH",
                "cvss_score": 8.1,
                "description": "SQL Injection vulnerability in Sarathi Authentication Module allows remote authenticated attackers to bypass standard multi-factor authorization parameters.",
                "affected_component": "Auth Service",
                "published_date": "2026-05-18"
            },
            {
                "cve_id": "CVE-2026-3022",
                "severity": "MEDIUM",
                "cvss_score": 6.5,
                "description": "Cross-Site Scripting (XSS) in Dashboard UI allows privilege escalation to Administrator role if a victim visits the logs audit trail.",
                "affected_component": "Admin Dashboard",
                "published_date": "2026-05-19"
            },
            {
                "cve_id": "CVE-2026-4401",
                "severity": "HIGH",
                "cvss_score": 7.5,
                "description": "Denial of Service (DoS) vulnerability in Sarathi Packet Inspector via memory exhaustion from specially crafted TLS handshake frames.",
                "affected_component": "Edge Firewall Router",
                "published_date": "2026-05-20"
            }
        ]
        return mock_cves[:limit]

    def run_ingestion(self) -> int:
        """
        Connects to NVD API and fetches CVEs published in the last 90 days.
        """
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Calculate start and end date for past 90 days
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=90)
        
        pub_start_str = start_date.strftime("%Y-%m-%dT00:00:00.000")
        pub_end_str = end_date.strftime("%Y-%m-%dT00:00:00.000")
        
        logger.info(f"Initiating NVD API fetch from {pub_start_str} to {pub_end_str}")
        
        results_per_page = 2000
        start_index = 0
        all_cves = []
        
        headers = {
            "User-Agent": "Sarathi Cyberdefense Agent (banu.cyberdefense@gmail.com)"
        }
        
        while True:
            params = {
                "pubStartDate": pub_start_str,
                "pubEndDate": pub_end_str,
                "resultsPerPage": results_per_page,
                "startIndex": start_index
            }
            
            try:
                response = requests.get(self.base_url, params=params, headers=headers, timeout=15)
                if response.status_code != 200:
                    logger.error(f"NVD API returned error code {response.status_code}: {response.text}")
                    break
                
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                
                for item in vulnerabilities:
                    cve_data = item.get("cve", {})
                    cve_id = cve_data.get("id")
                    
                    # Parse English description
                    descriptions = cve_data.get("descriptions", [])
                    description_val = ""
                    for desc in descriptions:
                        if desc.get("lang") == "en":
                            description_val = desc.get("value", "")
                            break
                    
                    # Parse CVSS score and severity
                    metrics = cve_data.get("metrics", {})
                    cvss_score = None
                    cvss_severity = None
                    
                    # Look for v3.1 or v3.0 metrics
                    v31_metrics = metrics.get("cvssMetricV31", [])
                    v30_metrics = metrics.get("cvssMetricV30", [])
                    v3_metric = v31_metrics or v30_metrics
                    
                    if v3_metric:
                        cvss_data = v3_metric[0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        cvss_severity = cvss_data.get("baseSeverity")
                    
                    published_date = cve_data.get("published")
                    
                    all_cves.append({
                        "cveId": cve_id,
                        "description": description_val,
                        "cvssV3Score": cvss_score,
                        "cvssV3Severity": cvss_severity,
                        "publishedDate": published_date
                    })
                
                total_results = data.get("totalResults", 0)
                logger.info(f"Fetched {len(vulnerabilities)} records. Total accumulated so far: {len(all_cves)}/{total_results}")
                
                start_index += results_per_page
                if start_index >= total_results or len(vulnerabilities) == 0:
                    break
                
                # 1 second rate limiting delay
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Exception during NVD fetch: {e}")
                break
        
        # Save to file
        if all_cves:
            try:
                with open(self.output_file, "w", encoding="utf-8") as f:
                    json.dump(all_cves, f, indent=4)
                logger.info(f"Successfully saved {len(all_cves)} NVD CVE records to {self.output_file}")
                return len(all_cves)
            except Exception as e:
                logger.error(f"Failed to write NVD CVE file: {e}")
        else:
            logger.warning("No CVE records were fetched. File was not updated.")
            
        return 0

if __name__ == "__main__":
    fetcher = NVDFetcher()
    fetcher.run_ingestion()
