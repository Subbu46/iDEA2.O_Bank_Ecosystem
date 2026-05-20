import os
from pathlib import Path
from dotenv import load_dotenv

# Locate and load the env file (look in parent directory since we are in backend/)
env_path = Path(__file__).resolve().parent.parent / '.env'
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
else:
    load_dotenv()  # Fallback to local or system environment

class Settings:
    # Neo4j Configurations
    NEO4J_URI: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USERNAME: str = os.getenv("NEO4J_USERNAME", "neo4j")
    NEO4J_PASSWORD: str = os.getenv("NEO4J_PASSWORD", "password")

    # GenAI Configurations
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")

    # Server Configurations
    PORT: int = int(os.getenv("PORT", 8000))
    HOST: str = "0.0.0.0"

settings = Settings()
