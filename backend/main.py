import uvicorn
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import settings

# Local imports
from api import routes_graph, routes_alerts, routes_playbook, routes_redteam
from graph.neo4j_client import Neo4jClient
from graph.graph_builder import GraphBuilder

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
app.include_router(routes_playbook.router, prefix="/api")
app.include_router(routes_redteam.router, prefix="/api")


@app.on_event("startup")
def startup_event():
    logger.info("Initializing Sarathi Cyberdefense backend services...")

    try:
        db = Neo4jClient()
        builder = GraphBuilder(db)
        builder.build_full_graph()

    except Exception as e:
        logger.error(f"Failed to synchronize Knowledge Graph: {e}")


@app.get("/")
def read_root():
    return {
        "project": "Sarathi Cyberdefense Ecosystem",
        "status": "Online",
        "genai_enabled": bool(settings.GEMINI_API_KEY),
        "docs_url": "/docs"
    }


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=settings.PORT,
        reload=True
    )