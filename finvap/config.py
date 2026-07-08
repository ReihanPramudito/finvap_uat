"""Central configuration: filesystem paths, database URL, and GVM connection.

All values can be overridden with environment variables so that sensitive data
(e.g. the GVM password) never has to live in the codebase.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

# Load a local .env (gitignored) if present, so secrets like the GVM password
# live outside the codebase. Variables already exported in the shell take
# precedence (load_dotenv's override defaults to False).
load_dotenv(BASE_DIR / ".env")
DATA_DIR = BASE_DIR / "data"
REGULATIONS_DIR = BASE_DIR / "regulations"
TEMPLATES_DIR = BASE_DIR / "templates"
EXPORTS_DIR = DATA_DIR / "exports"
UPLOADS_DIR = DATA_DIR / "uploads"  # human-uploaded report screenshots (S5.5b, web UI)
BACKUPS_DIR = DATA_DIR / "backups"  # client-state snapshots (finvap backup/restore)
CHROMA_DIR = DATA_DIR / ".chroma"  # persistent vector store for regulatory RAG (Obj 1)
LOGS_DIR = DATA_DIR / "logs"        # audit trail + AI activity log (the "history tab")
AI_LOGS_DIR = LOGS_DIR / "ai"       # full per-call LLM prompt/response artifacts

DB_PATH = Path(os.environ.get("FINVAP_DB", str(DATA_DIR / "finvap.db")))
DATABASE_URL = f"sqlite:///{DB_PATH}"

# Operator preferences for the one-shot orchestrator (`finvap <target>`), edited
# interactively via `finvap config`. Lives at the project root so it survives
# `db reset` (it's a preference, not client data). Override with FINVAP_CONFIG.
USER_CONFIG_PATH = Path(os.environ.get("FINVAP_CONFIG", str(BASE_DIR / "finvap.config.json")))

# Engagement metadata for custom `.docx` report templates (S3): the client/company
# identity behind the template's Word Document Properties, collected via `finvap
# meta` and reused across runs. Gitignored — it carries client identifiers.
# Override with FINVAP_ENGAGEMENT (tests redirect it to a tmp path).
ENGAGEMENT_PATH = Path(os.environ.get("FINVAP_ENGAGEMENT", str(BASE_DIR / "finvap.engagement.json")))

# GVM / Greenbone connection (Objective 2). Defaults match a standard Kali
# `gvm-setup`. Set FINVAP_GVM_USER / FINVAP_GVM_PASS in .env (or the shell).
GVM_SOCKET = os.environ.get("FINVAP_GVM_SOCKET", "/run/gvmd/gvmd.sock")
GVM_USERNAME = os.environ.get("FINVAP_GVM_USER", "admin")
GVM_PASSWORD = os.environ.get("FINVAP_GVM_PASS", "")

# LLM / report generation (Objective 4). Provider-agnostic: local Ollama by
# default (privacy NFR — data never leaves the host), with opt-in cloud
# (OpenAI-compatible endpoint or native Claude) for users who accept the
# trade-off. `template` is a no-LLM fallback that still produces a grounded
# report. All values overridable via env / .env.
LLM_PROVIDER = os.environ.get("FINVAP_LLM_PROVIDER", "ollama")  # ollama|openai|anthropic|template
LLM_MODEL = os.environ.get("FINVAP_LLM_MODEL", "")             # blank -> provider default
OLLAMA_HOST = os.environ.get("FINVAP_OLLAMA_HOST", "http://localhost:11434")
# Default local model — IBM Granite (Apache-2.0, tuned for enterprise summaries).
# `ollama pull` the current tag; override with FINVAP_LLM_MODEL if yours differs.
OLLAMA_DEFAULT_MODEL = os.environ.get("FINVAP_OLLAMA_MODEL", "granite3.3:8b")
# Every N chat calls, unload the model so Ollama's server-side prompt cache is
# freed. The server keeps the KV state of every distinct prompt (~150 MiB each
# for an 8B model at 4k ctx) with no reachable cap, so a long per-finding run
# grows it until the kernel OOM-kills `ollama serve`. 0 disables the flush.
OLLAMA_FLUSH_EVERY = int(os.environ.get("FINVAP_OLLAMA_FLUSH_EVERY", "15") or 0)
LLM_BASE_URL = os.environ.get("FINVAP_LLM_BASE_URL", "")       # OpenAI-compatible base URL
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

# Cloud-provider API keys entered through the web UI live here — a gitignored,
# 0600 JSON file separate from client data (so `db reset`/backups don't carry a
# key). Read at call time (not import) so a key saved in the UI takes effect
# without a restart. A UI-saved key takes precedence over the env var so the
# field the operator just set always wins. Override the path with FINVAP_SECRETS.
SECRETS_PATH = Path(os.environ.get("FINVAP_SECRETS", str(BASE_DIR / "finvap.secrets.json")))
_ENV_KEY = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}


def _load_secrets() -> dict:
    try:
        data = json.loads(SECRETS_PATH.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def get_api_key(provider: str) -> str:
    """API key for a cloud provider: UI-saved secret first, then the env var."""
    saved = (_load_secrets().get(f"{provider}_api_key") or "").strip()
    if saved:
        return saved
    env = _ENV_KEY.get(provider)
    return os.environ.get(env, "").strip() if env else ""


def set_api_key(provider: str, key: str) -> None:
    """Persist (or, with a blank key, remove) a cloud provider's API key."""
    if provider not in _ENV_KEY:
        return
    data = _load_secrets()
    field = f"{provider}_api_key"
    if key.strip():
        data[field] = key.strip()
    else:
        data.pop(field, None)
    SECRETS_PATH.write_text(json.dumps(data, indent=2))
    try:
        os.chmod(SECRETS_PATH, 0o600)
    except OSError:
        pass


def api_key_source(provider: str) -> str | None:
    """Where the provider's key comes from — 'saved', 'env', or None if unset."""
    if (_load_secrets().get(f"{provider}_api_key") or "").strip():
        return "saved"
    env = _ENV_KEY.get(provider)
    if env and os.environ.get(env, "").strip():
        return "env"
    return None


DATA_DIR.mkdir(parents=True, exist_ok=True)
EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
