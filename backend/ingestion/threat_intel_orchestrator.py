import time
import logging
import threading
import concurrent.futures
from typing import Dict, Any

# Ingestion Fetchers
from ingestion.nvd_fetcher import NVDFetcher
from ingestion.mitre_fetcher import MitreFetcher
from ingestion.epss_fetcher import EPSSFetcher
from ingestion.kev_fetcher import KEVFetcher

# Graph builder
from graph.neo4j_client import Neo4jClient
from graph.graph_builder import GraphBuilder

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sarathi.threat_intel_orchestrator")

class ThreatIntelOrchestrator:
    """
    Coordinates multi-feed threat intelligence ingestion pipelines concurrently.
    Synchronizes results to the Neo4j Knowledge Graph.
    """
    def __init__(self):
        self.nvd = NVDFetcher()
        self.mitre = MitreFetcher()
        self.epss = EPSSFetcher()
        self.kev = KEVFetcher()
        self._scheduler_thread = None
        self._stop_scheduler = threading.Event()

    def run_sync_pipeline(self) -> Dict[str, Any]:
        """
        Executes all threat intelligence download pipelines in parallel.
        Then, synchronizes data into the Neo4j Knowledge Graph.
        """
        logger.info("Starting consolidated Threat Intelligence Sync Pipeline...")
        start_time = time.time()
        
        # Parallel ingestion execution dictionary map
        pipelines = {
            "nvd": self.nvd.run_ingestion,
            "mitre": self.mitre.run_ingestion,
            "epss": self.epss.run_ingestion,
            "kev": self.kev.run_ingestion
        }
        
        results = {}
        
        # Run downloads in parallel using ThreadPoolExecutor
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            future_to_name = {
                executor.submit(run_fn): name 
                for name, run_fn in pipelines.items()
            }
            
            for future in concurrent.futures.as_completed(future_to_name):
                name = future_to_name[future]
                try:
                    count = future.result()
                    results[name] = count
                    logger.info(f"Ingestion pipeline '{name}' completed successfully with {count} records.")
                except Exception as e:
                    logger.error(f"Ingestion pipeline '{name}' failed with error: {e}")
                    results[name] = 0

        # Post-download: Rebuild the Neo4j knowledge graph using builder
        logger.info("Ingestion completed. Synchronizing Neo4j Knowledge Graph...")
        graph_sync_success = True
        try:
            db_client = Neo4jClient()
            builder = GraphBuilder(db_client)
            builder.build_full_graph()
            db_client.close()
            logger.info("Neo4j Threat Knowledge Graph successfully synchronized.")
        except Exception as e:
            logger.error(f"Failed to synchronize Neo4j Threat Knowledge Graph: {e}")
            graph_sync_success = False

        duration = time.time() - start_time
        logger.info(f"Threat Intelligence Ingestion Sync completed in {duration:.2f} seconds.")
        
        return {
            "status": "Success" if graph_sync_success else "Partial Success (Database Graph Sync Failed)",
            "duration_seconds": round(duration, 2),
            "metrics": {
                "nvd_cves": results.get("nvd", 0),
                "mitre_techniques": results.get("mitre", 0),
                "epss_scores": results.get("epss", 0),
                "cisa_kev": results.get("kev", 0)
            }
        }

    def _scheduler_loop(self, interval_hours: int = 24):
        """
        Background scheduler daemon process loop.
        """
        logger.info(f"Threat Intelligence scheduler loop started. Interval: {interval_hours} hours.")
        
        # Initial delay before checking
        while not self._stop_scheduler.is_set():
            # Wait with sub-second polling checks so the thread terminates rapidly on shutdown
            for _ in range(interval_hours * 3600):
                if self._stop_scheduler.is_set():
                    break
                time.sleep(1)
            
            if self._stop_scheduler.is_set():
                break
                
            try:
                logger.info("Scheduled trigger firing for Threat Intelligence update...")
                self.run_sync_pipeline()
            except Exception as e:
                logger.error(f"Error during scheduled sync: {e}")

    def start_scheduler(self, interval_hours: int = 24):
        """
        Launches the background updater thread.
        """
        if self._scheduler_thread and self._scheduler_thread.is_alive():
            logger.warning("Threat Intelligence scheduler is already running.")
            return

        self._stop_scheduler.clear()
        self._scheduler_thread = threading.Thread(
            target=self._scheduler_loop,
            args=(interval_hours,),
            daemon=True,
            name="SarathiThreatIntelScheduler"
        )
        self._scheduler_thread.start()
        logger.info("Threat Intelligence scheduler successfully started in background.")

    def stop_scheduler(self):
        """
        Stops the running scheduler thread gracefully.
        """
        if not self._scheduler_thread or not self._scheduler_thread.is_alive():
            return

        logger.info("Stopping Threat Intelligence scheduler...")
        self._stop_scheduler.set()
        self._scheduler_thread.join(timeout=5)
        logger.info("Threat Intelligence scheduler stopped successfully.")

if __name__ == "__main__":
    orchestrator = ThreatIntelOrchestrator()
    print("Testing orchestrator sync pipeline:")
    res = orchestrator.run_sync_pipeline()
    print(res)
