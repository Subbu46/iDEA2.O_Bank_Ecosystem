import requests
import json
import logging
from pathlib import Path
from typing import Dict, Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sarathi.epss_fetcher")

class EPSSFetcher:
    """
    Fetcher for Exploit Prediction Scoring System (EPSS) scores.
    Loads live 30-day scores or queries FIRST's public API.
    """
    def __init__(self):
        self.api_url = "https://api.first.org/data/v1/epss"
        self.data_dir = Path(__file__).resolve().parent.parent / "data"
        self.output_file = self.data_dir / "epss_scores.json"

    def get_epss_score(self, cve_id: str) -> Dict[str, Any]:
        """
        Retrieves EPSS probability and percentile for a given CVE from cached json.
        Falls back to high-fidelity mock scores if not cached or missing.
        """
        # High-fidelity mock fallback scores
        scores_db = {
            "CVE-2026-1043": {"epss": 0.9452, "percentile": 0.9984},
            "CVE-2026-2090": {"epss": 0.7812, "percentile": 0.9234},
            "CVE-2026-3022": {"epss": 0.0841, "percentile": 0.4512},
            "CVE-2026-4401": {"epss": 0.6120, "percentile": 0.8120}
        }
        
        if self.output_file.exists():
            try:
                with open(self.output_file, "r", encoding="utf-8") as f:
                    scores_list = json.load(f)
                
                # Check for matching CVE in loaded list
                for item in scores_list:
                    if item.get("cve") == cve_id:
                        return {
                            "epss": item.get("epss", 0.0150),
                            "percentile": item.get("percentile", 0.1200)
                        }
            except Exception as e:
                logger.error(f"Error reading EPSS local cache: {e}")
                
        return scores_db.get(cve_id, {"epss": 0.0150, "percentile": 0.1200})

    def run_ingestion(self) -> int:
        """
        Fetches EPSS scores for the last 30 days from FIRST API with proper pagination.
        """
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Initiating EPSS fetch from {self.api_url}?days=30")
        
        offset = 0
        limit = 10000
        all_scores = []
        
        while True:
            params = {
                "days": 30,
                "limit": limit,
                "offset": offset
            }
            
            try:
                response = requests.get(self.api_url, params=params, timeout=15)
                if response.status_code != 200:
                    logger.error(f"EPSS API returned status code {response.status_code}: {response.text}")
                    break
                    
                data = response.json()
                scores_data = data.get("data", [])
                
                for item in scores_data:
                    cve = item.get("cve")
                    epss_val = item.get("epss")
                    percentile_val = item.get("percentile")
                    
                    all_scores.append({
                        "cve": cve,
                        "epss": float(epss_val) if epss_val else 0.0,
                        "percentile": float(percentile_val) if percentile_val else 0.0
                    })
                
                total = int(data.get("total", 0))
                logger.info(f"Fetched {len(scores_data)} scores. Total accumulated: {len(all_scores)}/{total}")
                
                offset += limit
                if offset >= total or len(scores_data) == 0:
                    break
                    
            except Exception as e:
                logger.error(f"Exception during EPSS fetch: {e}")
                break
                
        # Save to file
        if all_scores:
            try:
                with open(self.output_file, "w", encoding="utf-8") as f:
                    json.dump(all_scores, f, indent=4)
                logger.info(f"Successfully saved {len(all_scores)} EPSS scores to {self.output_file}")
                return len(all_scores)
            except Exception as e:
                logger.error(f"Failed to write EPSS scores file: {e}")
        else:
            logger.warning("No EPSS scores were fetched. File was not updated.")
            
        return 0

if __name__ == "__main__":
    fetcher = EPSSFetcher()
    fetcher.run_ingestion()
