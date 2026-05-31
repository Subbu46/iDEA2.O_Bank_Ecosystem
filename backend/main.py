import uvicorn
import logging
from datetime import datetime

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from config import settings

# Local imports
from api import routes_graph, routes_alerts, routes_playbook, routes_redteam, routes_genai
from graph.neo4j_client import Neo4jClient
from graph.graph_builder import GraphBuilder
from fastapi.staticfiles import StaticFiles
from pathlib import Path 
# Configure logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sarathi.main")

app = FastAPI(
    title="🛡️ Sarathi Cyberdefense API Gate",
    description="Full-stack Intelligent Cybersecurity Graph Analytics & Incident Containment System",
    version="1.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routes
app.include_router(routes_graph.router, prefix="/api")
app.include_router(routes_alerts.router, prefix="/api")

# Support both /api/playbook and /api/playbooks for perfect client/spec compatibility
app.include_router(routes_playbook.router, prefix="/api/playbook")
app.include_router(routes_playbook.router, prefix="/api/playbooks")

app.include_router(routes_redteam.router, prefix="/api")

# Gen-AI Threat Intelligence
app.include_router(routes_genai.router, prefix="/api")

# Serve 3D GLB models for the Digital Twin frontend
# Serve 3D GLB models for Digital Twin
BASE_DIR = Path(__file__).resolve().parent
GLB_DIR = BASE_DIR / "glb_files"

print(f"GLB_DIR = {GLB_DIR}")

app.mount(
    "/api/models",
    StaticFiles(directory=str(GLB_DIR)),
    name="3d_models"
)
@app.get("/api/models-test")
def models_test():
    import os
    return {
        "exists": os.path.exists(GLB_DIR),
        "files": os.listdir(GLB_DIR) if os.path.exists(GLB_DIR) else []
    }

@app.on_event("startup")
def startup_event():
    logger.info("Initializing Sarathi Cyberdefense backend services...")

    try:
        db = Neo4jClient()
        db.setup_constraints_and_indexes()
        
        # Check node counts to verify if the graph is empty
        counts = db.get_node_counts()
        total_nodes = sum(counts.values()) if counts else 0
        logger.info(f"Current graph node counts: {counts} (Total: {total_nodes} nodes)")

        if total_nodes == 0:
            logger.info("Graph is empty. Running build_full_graph() to seed initial data...")
            builder = GraphBuilder(db)
            builder.build_full_graph()
        else:
            logger.info("Graph is already populated. Skipping automatic rebuild pipeline.")

    except Exception as e:
        logger.error(f"Failed to initialize or synchronize Knowledge Graph: {e}")


@app.get("/")
def read_root():
    return {
        "project": "Sarathi Cyberdefense Ecosystem",
        "status": "Online",
        "genai_enabled": bool(settings.GEMINI_API_KEY),
        "docs_url": "/docs"
    }


@app.get("/health")
@app.get("/api/health")
def health_check():
    """
    Returns API health and Neo4j database state.
    """
    db_status = "unknown"
    try:
        db = Neo4jClient()
        db_status = "mock" if db.mock_mode else "connected"
    except Exception as exc:
        db_status = f"error: {str(exc)}"

    return {
        "status": "Healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "neo4j": db_status,
        "genai_enabled": bool(settings.GEMINI_API_KEY)
    }


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=settings.PORT,
        reload=True
    )