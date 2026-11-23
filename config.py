"""Central configuration. All tunables come from environment variables (see .env.example)."""
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


class Config:
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-only-change-me")
    DB_PATH = str((BASE_DIR / os.getenv("DB_PATH", "reconai.db")).resolve())
    SCHEMA_PATH = BASE_DIR / "database" / "schema.sql"

    # Network timeouts (seconds)
    HTTP_TIMEOUT = _int("HTTP_TIMEOUT", 10)
    DNS_TIMEOUT = _int("DNS_TIMEOUT", 3)
    WHOIS_TIMEOUT = _int("WHOIS_TIMEOUT", 15)
    LLM_TIMEOUT = _int("LLM_TIMEOUT", 60)

    # Concurrency and rate limits
    SCAN_WORKERS = _int("SCAN_WORKERS", 2)
    MAX_SUBDOMAIN_WORKERS = _int("MAX_SUBDOMAIN_WORKERS", 8)
    RATE_LIMIT_PER_MINUTE = _int("RATE_LIMIT_PER_MINUTE", 10)

    # Safety: refuse targets that resolve to private/loopback/reserved space unless explicitly allowed
    ALLOW_PRIVATE_TARGETS = _bool("ALLOW_PRIVATE_TARGETS", False)

    USER_AGENT = os.getenv("RECON_USER_AGENT", "ReconAI/1.0 (authorized security assessment)")

    # Bounded, fixed wordlist: never brute-force
    SUBDOMAIN_WORDLIST = ("www", "api", "mail", "dev", "staging", "admin", "cdn", "blog")

    # LLM backend: none | ollama | openai (any OpenAI-compatible endpoint, e.g. OpenRouter)
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "none").strip().lower()
    LLM_MODEL = os.getenv("LLM_MODEL", "")
    LLM_API_KEY = os.getenv("LLM_API_KEY", "")
    LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://openrouter.ai/api/v1")
    OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
