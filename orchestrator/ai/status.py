"""Local AI (Ollama) health check for the dashboard."""
import ollama

from orchestrator.config import OLLAMA_HOST, OLLAMA_MODEL


def check_ollama_status() -> dict:
    try:
        client = ollama.Client(host=OLLAMA_HOST)
        resp = client.list()
        models = [m.model for m in resp.models]
        model_loaded = any(OLLAMA_MODEL in m for m in models)
        return {
            "online": True,
            "model": OLLAMA_MODEL,
            "model_loaded": model_loaded,
            "available_models": models,
            "host": OLLAMA_HOST,
            "error": None,
        }
    except Exception as e:
        return {
            "online": False,
            "model": OLLAMA_MODEL,
            "model_loaded": False,
            "available_models": [],
            "host": OLLAMA_HOST,
            "error": str(e),
        }
