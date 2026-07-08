"""Unit tests for Objective 4 building blocks — PII masking, the two-tier
remediation SLA, and the LLM providers. Fully offline (no Ollama, no cloud, no
network): providers are exercised via the `template` provider and monkeypatched
HTTP. The docx template fill itself is covered in test_templates.py."""
import pytest

from finvap import config
from finvap.reporting import Masker, get_provider
from finvap.reporting.deadlines import clause_for, deadline_for
from finvap.reporting.providers import (AnthropicProvider, LLMError,
                                        OllamaProvider, OpenAICompatProvider,
                                        TemplateProvider, discover_models)


# --- masking ----------------------------------------------------------------
def test_mask_and_unmask_roundtrip():
    m = Masker()
    m.register_asset("192.168.44.128", "paygw01")
    masked = m.mask("Host paygw01 at 192.168.44.128 is vulnerable")
    assert "192.168.44.128" not in masked and "paygw01" not in masked
    assert "ASSET-1" in masked and "HOST-1" in masked
    assert m.unmask(masked) == "Host paygw01 at 192.168.44.128 is vulnerable"


def test_mask_catches_unregistered_ip():
    m = Masker()
    masked = m.mask("connect to 10.0.0.5 now")
    assert "10.0.0.5" not in masked and "ASSET-" in masked


def test_unmask_longest_placeholder_first():
    m = Masker()
    for i in range(11):
        m.register_asset(f"10.0.0.{i}")
    masked = m.mask("10.0.0.10 and 10.0.0.1")  # ASSET-11 and ASSET-2
    assert m.unmask(masked) == "10.0.0.10 and 10.0.0.1"


def test_map_holds_placeholder_to_real():
    m = Masker()
    m.register_asset("192.168.1.1")
    assert m.map["ASSET-1"] == "192.168.1.1"


# --- deadlines --------------------------------------------------------------
def test_deadline_critical_rmit_cites_clause():
    d = deadline_for("Critical", framework="rmit")
    assert d["days"] == 7 and "RMiT S 10.18(b)" in d["basis"] and d["due"]


def test_deadline_trm_clause():
    assert clause_for("trm") == "TRM 7.4.1"
    assert "TRM 7.4.1" in deadline_for("High", framework="trm")["basis"]


def test_deadline_unknown_severity_is_none():
    assert deadline_for(None) is None and deadline_for("Bogus") is None


def test_deadline_sla_override():
    sla = {"Critical": {"ext": 3, "int": 9}}
    assert deadline_for("Critical", exposure="external", framework="rmit", sla=sla)["days"] == 3
    assert deadline_for("Critical", exposure="internal", framework="rmit", sla=sla)["days"] == 9


def test_deadline_exposure_tiers_default():
    # internet-facing gets the shorter turnaround; unknown exposure -> stricter (ext)
    assert deadline_for("High", exposure="external")["days"] == 30
    assert deadline_for("High", exposure="internal")["days"] == 60
    assert deadline_for("High")["days"] == 30  # unknown -> ext


# --- providers --------------------------------------------------------------
def test_get_provider_template():
    p = get_provider("template")
    assert isinstance(p, TemplateProvider) and p.available()[0] is True


def test_get_provider_ollama_default_model():
    p = get_provider("ollama")
    assert isinstance(p, OllamaProvider) and "granite" in p.model


def test_get_provider_unknown_raises():
    with pytest.raises(LLMError):
        get_provider("bogus")


def test_ollama_unreachable_is_actionable():
    ok, reason = OllamaProvider("granite3.3:8b", host="http://127.0.0.1:1").available()
    assert ok is False and "ollama" in reason.lower()


def test_cloud_providers_need_keys():
    assert OpenAICompatProvider("gpt-4o-mini", api_key="").available()[0] is False
    assert AnthropicProvider("claude-opus-4-8", api_key="").available()[0] is False


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def test_ollama_complete_request_and_parse(monkeypatch):
    """Verify the /api/chat payload shape and response parsing without a model."""
    captured = {}

    def fake_post(url, json=None, timeout=None, **kw):
        captured["url"] = url
        captured["json"] = json
        return _FakeResp({"message": {"role": "assistant", "content": "GRANITE OUTPUT"}})

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)
    out = OllamaProvider("granite3.3:8b").complete("SYS", "USER")
    assert out == "GRANITE OUTPUT"
    assert captured["url"].endswith("/api/chat")
    roles = [m["role"] for m in captured["json"]["messages"]]
    assert roles == ["system", "user"] and captured["json"]["stream"] is False
    assert captured["json"]["model"] == "granite3.3:8b"


def test_ollama_complete_retries_after_server_crash(monkeypatch):
    """A dropped connection (Ollama OOM-killed mid-call, restarted by systemd)
    is retried once the server answers again — one crash must not fail a run."""
    import time as _time

    import httpx
    calls = {"post": 0}

    def fake_post(url, json=None, timeout=None, **kw):
        calls["post"] += 1
        if calls["post"] == 1:
            raise httpx.RemoteProtocolError("Server disconnected without sending a response.")
        return _FakeResp({"message": {"content": "recovered"}})

    monkeypatch.setattr(httpx, "post", fake_post)
    monkeypatch.setattr(httpx, "get", lambda url, timeout=None: _FakeResp({}))  # server back up
    monkeypatch.setattr(_time, "sleep", lambda s: None)
    assert OllamaProvider("granite3.3:8b").complete("SYS", "USER") == "recovered"
    assert calls["post"] == 2


def test_ollama_complete_timeout_is_not_retried(monkeypatch):
    """A 600s read timeout means the box is genuinely stuck — retrying doubles
    the pain, so it must surface immediately (exactly one attempt)."""
    import httpx
    calls = {"post": 0}

    def fake_post(url, json=None, timeout=None, **kw):
        calls["post"] += 1
        raise httpx.ReadTimeout("timed out")

    monkeypatch.setattr(httpx, "post", fake_post)
    with pytest.raises(LLMError):
        OllamaProvider("granite3.3:8b").complete("SYS", "USER")
    assert calls["post"] == 1


def test_ollama_flushes_prompt_cache_every_n_calls(monkeypatch):
    """Every OLLAMA_FLUSH_EVERY calls the model is unloaded (keep_alive=0, empty
    messages) so the server-side prompt cache can't grow until the OOM killer."""
    import httpx
    chat, unload = [], []

    def fake_post(url, json=None, timeout=None, **kw):
        (unload if json.get("keep_alive") == 0 else chat).append(json)
        return _FakeResp({"message": {"content": "ok"}})

    monkeypatch.setattr(httpx, "post", fake_post)
    monkeypatch.setattr(config, "OLLAMA_FLUSH_EVERY", 2)
    p = OllamaProvider("granite3.3:8b")
    for _ in range(4):
        p.complete("SYS", "USER")
    assert len(chat) == 4 and len(unload) == 2
    assert all(u["messages"] == [] for u in unload)


def test_openai_complete_request_and_parse(monkeypatch):
    captured = {}

    def fake_post(url, headers=None, json=None, timeout=None, **kw):
        captured["url"] = url
        captured["headers"] = headers
        captured["json"] = json
        return _FakeResp({"choices": [{"message": {"content": "GPT OUTPUT"}}]})

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)
    out = OpenAICompatProvider("gpt-4o-mini", base_url="https://api.example/v1",
                               api_key="sk-test").complete("SYS", "USER")
    assert out == "GPT OUTPUT"
    assert captured["url"] == "https://api.example/v1/chat/completions"
    assert captured["headers"]["Authorization"] == "Bearer sk-test"


# --- live model discovery (finvap config picker) ----------------------------

def _fake_get(monkeypatch, payload):
    import httpx

    def fake_get(url, headers=None, timeout=None, **kw):
        return _FakeResp(payload)
    monkeypatch.setattr(httpx, "get", fake_get)


def test_discover_ollama_lists_only_pulled_tags(monkeypatch):
    _fake_get(monkeypatch, {"models": [{"name": "llama3.1:8b"}, {"name": "granite3.3:8b"}]})
    ids, status = discover_models("ollama")
    assert ids == ["granite3.3:8b", "llama3.1:8b"]      # sorted, exactly what's pulled
    assert "local model" in status


def test_discover_ollama_up_but_empty_is_actionable(monkeypatch):
    _fake_get(monkeypatch, {"models": []})
    ids, status = discover_models("ollama")
    assert ids == [] and "ollama pull" in status.lower()


def test_discover_ollama_unreachable_returns_none(monkeypatch):
    # Point at a dead port so the (real) httpx call fails fast and deterministically.
    monkeypatch.setattr(config, "OLLAMA_HOST", "http://127.0.0.1:1")
    ids, status = discover_models("ollama")
    assert ids is None and "ollama serve" in status.lower()


def test_discover_openai_filters_non_chat_for_openai_com(monkeypatch):
    monkeypatch.setattr(config, "get_api_key", lambda provider: "sk-test")
    monkeypatch.setattr(config, "LLM_BASE_URL", "")     # -> api.openai.com default
    _fake_get(monkeypatch, {"data": [{"id": "gpt-4o"}, {"id": "o3-mini"},
                                     {"id": "text-embedding-3-small"}, {"id": "tts-1"}]})
    ids, _ = discover_models("openai")
    assert "gpt-4o" in ids and "o3-mini" in ids
    assert "text-embedding-3-small" not in ids and "tts-1" not in ids


def test_discover_openai_custom_endpoint_unfiltered(monkeypatch):
    monkeypatch.setattr(config, "get_api_key", lambda provider: "sk-test")
    monkeypatch.setattr(config, "LLM_BASE_URL", "https://vllm.local/v1")
    _fake_get(monkeypatch, {"data": [{"id": "my-model"}, {"id": "text-embedding-3-small"}]})
    ids, _ = discover_models("openai")
    assert ids == ["my-model", "text-embedding-3-small"]   # nothing filtered off


def test_discover_cloud_without_key_is_actionable(monkeypatch):
    monkeypatch.setattr(config, "get_api_key", lambda provider: "")
    oid, ostatus = discover_models("openai")
    aid, astatus = discover_models("anthropic")
    assert oid is None and "OPENAI_API_KEY" in ostatus
    assert aid is None and "ANTHROPIC_API_KEY" in astatus
