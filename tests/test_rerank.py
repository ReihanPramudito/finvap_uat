"""Tests for the LLM clause re-ranker (Obj 1). Uses a fake provider — no real LLM,
no network — so it's fast and deterministic.
"""
from types import SimpleNamespace

from finvap.compliance import rerank


class FakeProvider:
    name = "fake"
    model = "fake-model"

    def __init__(self, reply):
        self.reply = reply
        self.calls = 0

    def complete(self, system, user, max_tokens=300, temperature=0.0):
        self.calls += 1
        return self.reply


CANDS = [
    {"citation": "RMIT S 10.20", "section": "Cryptography", "text": "strong crypto", "binding": "S"},
    {"citation": "RMIT S 10.39", "section": "Network Resilience", "text": "bandwidth", "binding": "S"},
]
F = SimpleNamespace(name="Weak SSH MAC", summary="weak mac", solution="disable", impact=None)


def test_selects_only_listed_candidate(tmp_path, monkeypatch):
    monkeypatch.setattr(rerank, "CACHE_DIR", tmp_path)
    prov = FakeProvider('{"selected": ["RMIT S 10.20"], "reason": "weak crypto"}')
    sel, reason = rerank.select_clauses(F, CANDS, framework="rmit", provider=prov)
    assert [c["citation"] for c in sel] == ["RMIT S 10.20"]
    assert reason == "weak crypto"


def test_none_selected(tmp_path, monkeypatch):
    monkeypatch.setattr(rerank, "CACHE_DIR", tmp_path)
    prov = FakeProvider('{"selected": [], "reason": "informational"}')
    sel, reason = rerank.select_clauses(F, CANDS, framework="rmit", provider=prov)
    assert sel == [] and reason == "informational"


def test_flexible_match_when_model_echoes_section_label(tmp_path, monkeypatch):
    monkeypatch.setattr(rerank, "CACHE_DIR", tmp_path)
    prov = FakeProvider('{"selected": ["RMIT S 10.20 (Cryptography)"], "reason": "x"}')
    sel, _ = rerank.select_clauses(F, CANDS, framework="rmit", provider=prov)
    assert [c["citation"] for c in sel] == ["RMIT S 10.20"]


def test_hallucinated_id_is_dropped(tmp_path, monkeypatch):
    # The model can only ever return real candidates — an invented clause is ignored.
    monkeypatch.setattr(rerank, "CACHE_DIR", tmp_path)
    prov = FakeProvider('{"selected": ["RMIT S 99.99"], "reason": "x"}')
    sel, _ = rerank.select_clauses(F, CANDS, framework="rmit", provider=prov)
    assert sel == []


def test_verdict_is_cached(tmp_path, monkeypatch):
    monkeypatch.setattr(rerank, "CACHE_DIR", tmp_path)
    prov = FakeProvider('{"selected": ["RMIT S 10.20"], "reason": "r"}')
    rerank.select_clauses(F, CANDS, framework="rmit", provider=prov)
    rerank.select_clauses(F, CANDS, framework="rmit", provider=prov)  # served from cache
    assert prov.calls == 1


def test_empty_candidates_skip_llm(tmp_path, monkeypatch):
    monkeypatch.setattr(rerank, "CACHE_DIR", tmp_path)
    prov = FakeProvider("{}")
    sel, _ = rerank.select_clauses(F, [], framework="rmit", provider=prov)
    assert sel == [] and prov.calls == 0


def test_malformed_json_yields_no_selection(tmp_path, monkeypatch):
    monkeypatch.setattr(rerank, "CACHE_DIR", tmp_path)
    prov = FakeProvider("the model rambled without any json")
    sel, reason = rerank.select_clauses(F, CANDS, framework="rmit", provider=prov)
    assert sel == [] and "no parsable" in reason
