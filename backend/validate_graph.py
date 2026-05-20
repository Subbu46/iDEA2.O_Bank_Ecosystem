"""
validate_graph.py
-----------------
Standalone script to:
  1. Connect to Neo4j Aura (or fall back to mock mode)
  2. Execute build_full_graph() -- schema + assets + threat intel
  3. Print graph statistics and validation query results

Run from the backend/ directory:
    python validate_graph.py

Or with a custom env file:
    NEO4J_URI=neo4j+s://... python validate_graph.py
"""

import sys
import os
import logging
import io

# Force UTF-8 on Windows so Unicode box-drawing / tick chars print safely
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Ensure backend/ is on the Python path when called from the repo root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("sarathi.validate_graph")


def main():
    from graph.neo4j_client import Neo4jClient
    from graph.graph_builder import GraphBuilder

    logger.info("Connecting to Neo4j …")
    db = Neo4jClient()

    if db.mock_mode:
        print("\n[MOCK MODE] Neo4j Aura is not reachable.")
        print("  Graph writes are no-ops; validation queries return in-memory data.\n")
    else:
        print(f"\n[OK] Connected to Neo4j Aura: {db.uri}\n")

    builder = GraphBuilder(db)

    try:
        builder.build_full_graph()
    finally:
        db.close()
        logger.info("Neo4j driver closed.")


if __name__ == "__main__":
    main()
