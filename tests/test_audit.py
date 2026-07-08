"""Tests for the audit trail + AI activity log (Step 1).

Covers: event record/read, run-scope start/outcome classification, the automated
PII leak-check, the AI-call masking-proof artifact, and masking on the map
re-rank path. The `logs` viewer is now the web History page (see test_web.py).

``conftest._isolate_audit_logs`` redirects ``config.LOGS_DIR`` to a temp dir per
test, so these never touch the real ``data/logs/``.
"""
import json
import types

import pytest

from finvap import audit
from finvap.reporting.masking import Masker


# --------------------------------------------------------------------------- #
# leak-check
# --------------------------------------------------------------------------- #

def test_leak_check_passes_on_masked_text():
    r = audit.leak_check("ASSET-1 runs an old TLS stack", {"ASSET-1": "10.0.0.5"})
    assert r["result"] == "pass" and r["leaked"] == [] and r["checked"] == 1


def test_leak_check_flags_a_real_identifier():
    r = audit.leak_check("problem found on 10.0.0.5", {"ASSET-1": "10.0.0.5"})
    assert r["result"] == "leak" and "10.0.0.5" in r["leaked"]


# --------------------------------------------------------------------------- #
# record / read
# --------------------------------------------------------------------------- #

def test_record_and_read_back():
    audit.record("test.event", command="x", target="t", summary="hi", detail={"a": 1})
    rows = audit.recent()
    assert rows and rows[0]["action"] == "test.event"
    e = audit.get(rows[0]["id"])
    assert e["summary"] == "hi" and json.loads(e["detail"])["a"] == 1


def test_disabled_audit_writes_nothing(monkeypatch):
    monkeypatch.setenv("FINVAP_AUDIT", "0")
    audit.record("should.not.persist", summary="nope")
    assert audit.recent() == []


# --------------------------------------------------------------------------- #
# run() scope + status classification
# --------------------------------------------------------------------------- #

def test_run_records_start_end_and_propagates_run_id():
    with audit.run("scan", target="1.2.3.4"):
        audit.event("nmap.scan", summary="ran nmap")
    rows = {r["action"]: r for r in audit.recent()}
    assert {"run.start", "run.end", "nmap.scan"} <= set(rows)
    end = rows["run.end"]
    assert end["status"] == "ok" and end["command"] == "scan"
    assert end["duration_ms"] is not None
    # the sub-event inherits the run id + command without being passed them
    assert rows["nmap.scan"]["command"] == "scan"
    assert rows["nmap.scan"]["run_id"] == end["run_id"]


def test_run_marks_error_on_exception():
    with pytest.raises(RuntimeError):
        with audit.run("score"):
            raise RuntimeError("boom")
    assert audit.recent()[0]["action"] == "run.end"
    assert audit.recent()[0]["status"] == "error"


def test_run_classifies_typer_exit_and_abort():
    import typer
    with pytest.raises(typer.Exit):
        with audit.run("map"):
            raise typer.Exit(1)
    assert audit.recent()[0]["status"] == "error"  # handled Exit(1) -> error

    with pytest.raises(typer.Abort):
        with audit.run("db reset"):
            raise typer.Abort()
    assert audit.recent()[0]["status"] == "aborted"  # user-cancelled confirm


# --------------------------------------------------------------------------- #
# ai_call — the masking proof
# --------------------------------------------------------------------------- #

def test_ai_call_writes_masking_proof_artifact():
    m = Masker()
    m.register_asset("10.0.0.9", "db01")
    sent = m.mask("findings on 10.0.0.9 (host db01)")
    leak = audit.ai_call(
        stage="exec_summary", provider="ollama", model="granite",
        system="be brief", user_sent=sent, response_raw="ASSET-1 is exposed",
        placeholder_map=m.map, response_unmasked=m.unmask("ASSET-1 is exposed"),
    )
    assert leak["result"] == "pass"

    ev = audit.recent()[0]
    assert ev["action"] == "llm.call" and ev["status"] == "ok" and ev["artifact_path"]
    art = json.loads(open(ev["artifact_path"]).read())
    # what was sent is masked; the map is kept locally; the output is restored
    assert "10.0.0.9" not in art["user_prompt_sent"] and "db01" not in art["user_prompt_sent"]
    assert art["placeholder_map"]["ASSET-1"] == "10.0.0.9"
    assert "10.0.0.9" in art["response_unmasked"]
    assert art["leak_check"]["result"] == "pass"


def test_ai_call_flags_a_leak_and_warns():
    leak = audit.ai_call(
        stage="x", provider="p", model="m", system="s",
        user_sent="please review 10.0.0.9", response_raw="",
        placeholder_map={"ASSET-1": "10.0.0.9"},
    )
    assert leak["result"] == "leak"
    assert audit.recent()[0]["status"] == "warn"


# --------------------------------------------------------------------------- #
# the map re-rank AI path is masked + logged
# --------------------------------------------------------------------------- #

def test_rerank_masks_finding_text_before_the_llm():
    from finvap.compliance import rerank

    seen = {}

    class FakeProv:
        name, model = "ollama", "granite"

        def complete(self, system, user, **k):
            seen["user"] = user
            return '{"selected": ["RMiT S 1.1"], "reason": "weak crypto on ASSET-1"}'

    finding = types.SimpleNamespace(
        name="Weak TLS on 10.0.0.9", summary="host 10.0.0.9 negotiates weak ciphers",
        solution=None, impact=None,
    )
    cands = [{"citation": "RMiT S 1.1", "section": "S 1.1", "text": "encryption controls",
              "clause_id": "1.1", "binding": "S", "score": 0.3}]
    m = Masker()
    m.register_asset("10.0.0.9")

    sel, reason = rerank.select_clauses(
        finding, cands, framework="rmit", provider=FakeProv(), use_cache=False, masker=m,
    )
    # the finding's real IP never reached the model
    assert "10.0.0.9" not in seen["user"] and "ASSET-1" in seen["user"]
    assert sel and sel[0]["citation"] == "RMiT S 1.1"
    # a placeholder the model echoed in its reason is restored before storage
    assert "10.0.0.9" in reason
    ev = audit.recent()[0]
    assert ev["action"] == "llm.call" and ev["status"] == "ok"
