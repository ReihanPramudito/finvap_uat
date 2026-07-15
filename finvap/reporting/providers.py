"""Provider-agnostic LLM access for report generation (Objective 4).

Local-first (privacy NFR): the default is **Ollama** on localhost — data never
leaves the host. Opt-in cloud providers (any **OpenAI-compatible** endpoint, e.g.
a company's own LLM, or **native Claude**) are available for users who accept the
trade-off and set an API key. ``template`` is a no-LLM fallback so a grounded
report still generates with no model at all. Both cloud providers work over
plain HTTP (``httpx``) with just an API key — no extra SDK required; the
optional ``anthropic`` package is used opportunistically when present.

Every provider implements ``available()`` (actionable reachability check, like
``finvap doctor``) and ``complete(system, user)``. PII is already masked by the
caller before any text reaches a provider.
"""
from __future__ import annotations

import time

from .. import config


class LLMError(RuntimeError):
    """An LLM call failed — carries an actionable, human-readable message."""


class TemplateProvider:
    """No LLM. Signals callers to fall back to their deterministic prose."""
    name = "template"

    def available(self) -> tuple[bool, str]:
        return True, "no-LLM template mode (deterministic prose)"

    def complete(self, system: str, user: str, max_tokens: int = 4000,
                 temperature: float = 0.2) -> str:  # pragma: no cover
        raise LLMError("template provider does not call an LLM")


class OllamaProvider:
    """Local Ollama over HTTP (no Python dep — just httpx + a running `ollama`)."""
    name = "ollama"

    def __init__(self, model: str, host: str | None = None):
        self.model = model
        self.host = (host or config.OLLAMA_HOST).rstrip("/")
        self._calls = 0  # chat calls since the last prompt-cache flush

    def available(self) -> tuple[bool, str]:
        import httpx
        try:
            r = httpx.get(f"{self.host}/api/tags", timeout=5)
            r.raise_for_status()
            tags = [m.get("name", "") for m in r.json().get("models", [])]
        except Exception:
            return False, (f"Ollama not reachable at {self.host} — install it, run "
                           f"`ollama serve`, then `ollama pull {self.model}`.")
        # Match with or without an explicit :tag.
        base = self.model.split(":")[0]
        if not any(t == self.model or t.split(":")[0] == base for t in tags):
            return False, f"model {self.model!r} not pulled — run `ollama pull {self.model}`."
        return True, f"ollama:{self.model} @ {self.host}"

    def complete(self, system: str, user: str, max_tokens: int = 4000,
                 temperature: float = 0.2) -> str:
        import httpx
        payload = {
            "model": self.model, "stream": False,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        # A per-finding run makes dozens of sequential calls over minutes; if the
        # server dies mid-call (systemd restarts an OOM-killed `ollama serve` in
        # seconds), retry rather than losing the whole run. Timeouts and 4xx are
        # not retried — those won't heal by asking again.
        for attempt in (1, 2, 3):
            try:
                r = httpx.post(f"{self.host}/api/chat", json=payload,
                               timeout=600)  # CPU generation can take minutes
                r.raise_for_status()
                out = (r.json().get("message", {}).get("content") or "").strip()
                self._maybe_flush()
                return out
            except (httpx.RemoteProtocolError, httpx.ConnectError, httpx.ReadError,
                    httpx.WriteError, httpx.HTTPStatusError) as e:
                crashed = (not isinstance(e, httpx.HTTPStatusError)
                           or e.response.status_code >= 500)
                if not crashed or attempt == 3:
                    raise LLMError(f"Ollama generation failed: {e}") from e
                if not self._wait_ready():
                    raise LLMError(
                        f"Ollama dropped the connection mid-generation and did not "
                        f"come back within 120s ({e}) — check `journalctl -u ollama` "
                        f"(commonly the kernel OOM killer; give the machine more "
                        f"memory or keep FINVAP_OLLAMA_FLUSH_EVERY low).") from e
            except Exception as e:
                raise LLMError(f"Ollama generation failed: {e}") from e
        raise LLMError("Ollama generation failed")  # pragma: no cover — loop always exits above

    def _wait_ready(self, wait_s: int = 120) -> bool:
        """After a dropped connection, poll until the server answers again (the
        retried call then reloads the model itself). False if it stays down."""
        import httpx
        deadline = time.monotonic() + wait_s
        while time.monotonic() < deadline:
            time.sleep(3)
            try:
                httpx.get(f"{self.host}/api/tags", timeout=5).raise_for_status()
                return True
            except Exception:
                continue
        return False

    def _maybe_flush(self):
        """Every OLLAMA_FLUSH_EVERY successful calls, unload the model so the
        server's prompt cache is freed (see config.OLLAMA_FLUSH_EVERY — it grows
        per distinct prompt until the kernel OOM-kills the server). The next call
        reloads the model transparently. Best-effort."""
        import httpx
        self._calls += 1
        every = config.OLLAMA_FLUSH_EVERY
        if not every or self._calls % every:
            return
        try:
            httpx.post(f"{self.host}/api/chat",
                       json={"model": self.model, "messages": [], "keep_alive": 0},
                       timeout=30)
        except Exception:
            pass


class OpenAICompatProvider:
    """Any OpenAI-compatible /chat/completions endpoint (OpenAI, a company's own
    gateway, a self-hosted vLLM, …). Configured by base URL + API key."""
    name = "openai"

    def __init__(self, model: str, base_url: str | None = None, api_key: str | None = None):
        self.model = model or "gpt-4o-mini"
        self.base_url = (base_url or config.LLM_BASE_URL or "https://api.openai.com/v1").rstrip("/")
        self.api_key = api_key or config.get_api_key("openai")

    def available(self) -> tuple[bool, str]:
        if not self.api_key:
            return False, "no API key — set it on the Setup page (or OPENAI_API_KEY / FINVAP_LLM_BASE_URL for a custom endpoint)."
        return True, f"openai-compatible:{self.model} @ {self.base_url}"

    def complete(self, system: str, user: str, max_tokens: int = 4000,
                 temperature: float = 0.2) -> str:
        import httpx
        try:
            r = httpx.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={"model": self.model, "max_tokens": max_tokens, "temperature": temperature,
                      "messages": [{"role": "system", "content": system},
                                   {"role": "user", "content": user}]},
                timeout=120,
            )
            r.raise_for_status()
            return (r.json()["choices"][0]["message"]["content"] or "").strip()
        except Exception as e:
            raise LLMError(f"OpenAI-compatible generation failed: {e}") from e


class AnthropicProvider:
    """Native Claude. Prefers the official SDK (optional `cloud` extra) but
    falls back to the raw HTTP Messages API when it's not installed — the
    same fallback `_anthropic_models()` already uses for model discovery, so
    a model picked there doesn't go on to fail here with an SDK error."""
    name = "anthropic"

    def __init__(self, model: str, api_key: str | None = None):
        self.model = model or "claude-opus-4-8"
        self.api_key = api_key or config.get_api_key("anthropic")

    def available(self) -> tuple[bool, str]:
        if not self.api_key:
            return False, "no API key — set it on the Setup page (or the ANTHROPIC_API_KEY env var)."
        return True, f"anthropic:{self.model}"

    def complete(self, system: str, user: str, max_tokens: int = 4000,
                 temperature: float = 0.2) -> str:
        try:
            import anthropic
        except ImportError:
            return self._complete_http(system, user, max_tokens, temperature)
        try:
            client = anthropic.Anthropic(api_key=self.api_key)
            msg = client.messages.create(
                model=self.model, max_tokens=max_tokens, temperature=temperature,
                system=system, messages=[{"role": "user", "content": user}],
            )
            return "".join(b.text for b in msg.content if b.type == "text").strip()
        except Exception as e:
            raise LLMError(f"Anthropic generation failed: {e}") from e

    def _complete_http(self, system: str, user: str, max_tokens: int, temperature: float) -> str:
        import httpx
        try:
            r = httpx.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01",
                         "content-type": "application/json"},
                json={"model": self.model, "max_tokens": max_tokens, "temperature": temperature,
                      "system": system, "messages": [{"role": "user", "content": user}]},
                timeout=120,
            )
            r.raise_for_status()
            blocks = r.json().get("content", [])
            return "".join(b.get("text", "") for b in blocks if b.get("type") == "text").strip()
        except Exception as e:
            raise LLMError(f"Anthropic generation failed: {e}") from e


# --------------------------------------------------------------------------- #
# Live model discovery — list the ids a backend actually offers *right now*,
# so `finvap config` shows real choices (only-pulled Ollama tags, key-authorised
# cloud models) instead of a static guess. Each returns (ids, status):
#   * ids is a list -> discovery ran (may be empty: reachable but nothing to use)
#   * ids is None    -> discovery couldn't run; status says why + how to fix it
# Never raises — the config picker degrades to curated defaults + custom entry.
# --------------------------------------------------------------------------- #

def _ollama_models() -> tuple[list[str] | None, str]:
    import httpx
    host = (config.OLLAMA_HOST or "http://localhost:11434").rstrip("/")
    try:
        r = httpx.get(f"{host}/api/tags", timeout=5)
        r.raise_for_status()
    except Exception:
        return None, (f"Ollama not reachable at {host} — install it and run "
                      f"`ollama serve`, then `ollama pull {config.OLLAMA_DEFAULT_MODEL}`.")
    ids = sorted({m.get("name", "") for m in r.json().get("models", []) if m.get("name")})
    if not ids:
        return [], f"Ollama is up but no models are pulled — run `ollama pull {config.OLLAMA_DEFAULT_MODEL}`."
    return ids, f"{len(ids)} local model(s) @ {host}"


def _openai_models() -> tuple[list[str] | None, str]:
    import httpx
    key = config.get_api_key("openai")
    base = (config.LLM_BASE_URL or "https://api.openai.com/v1").rstrip("/")
    if not key:
        return None, "no API key — set it on the Setup page (or OPENAI_API_KEY / FINVAP_LLM_BASE_URL for a custom endpoint)."
    try:
        r = httpx.get(f"{base}/models", headers={"Authorization": f"Bearer {key}"}, timeout=10)
        r.raise_for_status()
        ids = sorted({m.get("id", "") for m in r.json().get("data", []) if m.get("id")})
    except Exception as e:
        return None, f"couldn't list models at {base} — {e}"
    # Real OpenAI returns embeddings/tts/whisper/etc.; keep only chat-capable ids.
    # A custom OpenAI-compatible endpoint serves arbitrary names, so list them all.
    if "api.openai.com" in base:
        ids = [m for m in ids if m.startswith(("gpt-", "o1", "o3", "o4", "chatgpt-"))] or ids
    return ids, f"{len(ids)} model(s) @ {base}"


def _anthropic_models() -> tuple[list[str] | None, str]:
    key = config.get_api_key("anthropic")
    if not key:
        return None, "no API key — set it on the Setup page (or the ANTHROPIC_API_KEY env var)."
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=key)
        ids = [m.id for m in client.models.list(limit=100).data]  # newest first
        return ids, f"{len(ids)} model(s)"
    except ImportError:
        pass  # SDK not installed — fall back to the raw HTTP endpoint
    except Exception as e:
        return None, f"couldn't list models — {e}"
    import httpx
    try:
        r = httpx.get("https://api.anthropic.com/v1/models",
                      headers={"x-api-key": key, "anthropic-version": "2023-06-01"}, timeout=10)
        r.raise_for_status()
        ids = [m.get("id", "") for m in r.json().get("data", []) if m.get("id")]
    except Exception as e:
        return None, f"couldn't list models — {e}"
    return ids, f"{len(ids)} model(s)"


def discover_models(provider: str) -> tuple[list[str] | None, str]:
    """Model ids `provider` offers now, or (None, why) if discovery can't run."""
    provider = (provider or "").lower()
    if provider == "ollama":
        return _ollama_models()
    if provider in ("openai", "openai-compatible", "compat"):
        return _openai_models()
    if provider in ("anthropic", "claude"):
        return _anthropic_models()
    return None, f"no live model list for provider {provider!r}."


# Curated fallback model ids per provider, shown only when live discovery can't
# run (backend down / no API key) so a picker still offers provider-specific
# choices. Shared by `finvap config` and the web Setup page.
MODEL_SUGGESTIONS = {
    "ollama": ["granite3.3:8b", "llama3.1:8b", "qwen2.5:7b"],
    "openai": ["gpt-4o-mini", "gpt-4o"],
    "anthropic": ["claude-opus-4-8", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"],
    "template": [],
}


def model_choices(provider: str) -> tuple[list[str], str, bool]:
    """Options for a model picker: the live-discovered ids when the backend
    answers, else the curated per-provider suggestions. Returns
    ``(ids, status, live)`` — ``live`` False means ids are suggestions only."""
    provider = (provider or "").lower()
    if provider == "template":
        return [], "template mode writes deterministic prose — no LLM/model used", True
    ids, status = discover_models(provider)
    if ids is not None:
        return ids, status, True
    return list(MODEL_SUGGESTIONS.get(provider, [])), status, False


def get_provider(provider: str | None = None, model: str | None = None):
    """Build a provider from explicit args or config defaults."""
    provider = (provider or config.LLM_PROVIDER or "ollama").lower()
    model = model or config.LLM_MODEL or None
    if provider == "template":
        return TemplateProvider()
    if provider == "ollama":
        return OllamaProvider(model or config.OLLAMA_DEFAULT_MODEL)
    if provider in ("openai", "openai-compatible", "compat"):
        return OpenAICompatProvider(model)
    if provider in ("anthropic", "claude"):
        return AnthropicProvider(model)
    raise LLMError(f"unknown LLM provider {provider!r} (use ollama|openai|anthropic|template)")
