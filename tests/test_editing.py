"""Tests for human-in-the-loop editing + override durability (Phase 5, NFR).

The headline behaviour: a manual override survives a later `finvap score` / `map`
(the engine/mapping skip overridden findings), and `--clear-override` re-enables
recomputation.
"""
import pytest
from sqlmodel import Session, SQLModel, create_engine, select

from finvap import db
from finvap.editing import EditError, edit_finding
from finvap.models import Asset, Finding, FindingScore
from finvap.risk import score_findings

_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # base 9.8


def _db(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path/'t.db'}")
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(db, "engine", engine)
    return engine


def _seed(engine) -> int:
    with Session(engine) as s:
        a = Asset(ip_address="10.0.0.1")
        s.add(a); s.commit(); s.refresh(a)
        f = Finding(asset_id=a.id, tool="gvm", name="Orig", cve="CVE-2021-9999",
                    cvss_vector=_VECTOR, cvss_version="3.1",
                    cvss_adjusted=7.0, severity_adjusted="High")
        s.add(f); s.commit(); s.refresh(f)
        for v in ("3.1", "4.0"):
            s.add(FindingScore(
                finding_id=f.id, cvss_version=v, base_vector=_VECTOR, base_score=9.8,
                base_severity="Critical", source="scan", adj_vector=_VECTOR,
                adj_score=7.0, adj_severity="High"))
        s.commit()
        return f.id


def test_edit_text_fields_no_override(tmp_path, monkeypatch):
    engine = _db(tmp_path, monkeypatch)
    fid = _seed(engine)
    edit_finding(fid, name="New name", solution="Patch it")
    with Session(engine) as s:
        f = s.get(Finding, fid)
        assert f.name == "New name" and f.solution == "Patch it"
        assert f.score_overridden is False  # text edits aren't an override


def test_score_override_propagates_to_all_layers(tmp_path, monkeypatch):
    engine = _db(tmp_path, monkeypatch)
    fid = _seed(engine)
    edit_finding(fid, score=2.0, severity="Low")
    with Session(engine) as s:
        f = s.get(Finding, fid)
        assert f.score_overridden is True
        assert f.cvss_adjusted == 2.0 and f.severity_adjusted == "Low"
        for fs in s.exec(select(FindingScore).where(FindingScore.finding_id == fid)).all():
            # both adj_* (mapping/score view) and fw_adj_* (report view) updated
            assert fs.adj_score == 2.0 and fs.adj_severity == "Low"
            assert fs.fw_adj_score == 2.0 and fs.fw_adj_severity == "Low"


def test_override_survives_rescore(tmp_path, monkeypatch):
    engine = _db(tmp_path, monkeypatch)
    fid = _seed(engine)
    edit_finding(fid, score=2.0, severity="Low")
    _, stats = score_findings(offline=True)
    assert stats["overridden"] == 1 and stats["scored"] == 0
    with Session(engine) as s:
        f = s.get(Finding, fid)
        assert f.cvss_adjusted == 2.0 and f.severity_adjusted == "Low"  # untouched


def test_clear_override_allows_rescore(tmp_path, monkeypatch):
    engine = _db(tmp_path, monkeypatch)
    fid = _seed(engine)
    edit_finding(fid, score=2.0, severity="Low")
    edit_finding(fid, clear_override=True)
    _, stats = score_findings(offline=True)
    assert stats["scored"] == 1 and stats["overridden"] == 0
    with Session(engine) as s:
        fs = s.exec(select(FindingScore).where(
            FindingScore.finding_id == fid, FindingScore.cvss_version == "3.1")).first()
        assert fs.adj_score != 2.0  # recomputed from the vector + asset tags


def test_severity_only_snaps_to_band_floor(tmp_path, monkeypatch):
    engine = _db(tmp_path, monkeypatch)
    fid = _seed(engine)
    edit_finding(fid, severity="Critical")
    with Session(engine) as s:
        f = s.get(Finding, fid)
        assert f.severity_adjusted == "Critical" and f.cvss_adjusted == 9.0


def test_clause_override_survives_remap(tmp_path, monkeypatch):
    engine = _db(tmp_path, monkeypatch)
    fid = _seed(engine)
    edit_finding(fid, add_clause="RMiT S 10.20")
    with Session(engine) as s:
        f = s.get(Finding, fid)
        assert f.clauses_overridden is True and "10.20" in f.regulatory_clauses

    # Stub the vector store so map runs without the real Chroma index.
    from finvap.compliance import mapping, store
    monkeypatch.setattr(store, "query", lambda *a, **k: [])
    stats = mapping.map_findings(framework="rmit", k=3, floor=0.2)
    assert stats["overridden"] == 1
    with Session(engine) as s:
        f = s.get(Finding, fid)
        assert "10.20" in (f.regulatory_clauses or "")  # curation not wiped


def test_map_skips_info_findings_without_calling_llm(tmp_path, monkeypatch):
    from finvap.compliance import mapping

    engine = _db(tmp_path, monkeypatch)
    with Session(engine) as s:
        a = Asset(ip_address="10.0.0.9")
        s.add(a); s.commit(); s.refresh(a)
        s.add(Finding(asset_id=a.id, tool="gvm", name="Info note", cvss_vector=None))  # no CVSS
        s.commit()

    class _NoLLM:  # fails the test if mapping tries to call the model
        name = "x"
        model = "x"
        def complete(self, *a, **k):
            raise AssertionError("LLM must not be called for an info-only finding")

    stats = mapping.map_findings(framework="rmit", provider=_NoLLM())
    assert stats["info_skipped"] == 1 and stats["mapped"] == 0


def test_map_commits_each_finding_before_a_mid_run_crash(tmp_path, monkeypatch):
    """`map` commits per finding, so verdicts reached before the LLM dies mid-run
    (e.g. Ollama OOM-killed and never restarted) survive the aborted run."""
    from finvap.compliance import mapping, rerank, store
    from finvap.reporting.providers import LLMError

    engine = _db(tmp_path, monkeypatch)
    fid1 = _seed(engine)
    with Session(engine) as s:
        a = Asset(ip_address="10.0.0.2")
        s.add(a); s.commit(); s.refresh(a)
        f2 = Finding(asset_id=a.id, tool="gvm", name="Second", cve="CVE-2021-8888",
                     cvss_vector=_VECTOR, cvss_version="3.1")
        s.add(f2); s.commit(); s.refresh(f2)
        fid2 = f2.id

    clause = {"citation": "RMiT S 10.55", "clause_id": "10.55", "section": "Cryptography",
              "binding": True, "score": 0.9, "text": "must encrypt", "reason": "matches"}
    calls = {"n": 0}

    def fake_select(f, candidates, *, framework, provider, masker):
        calls["n"] += 1
        if calls["n"] == 2:
            raise LLMError("Ollama generation failed: Server disconnected")
        return [clause], "selected"

    monkeypatch.setattr(store, "query", lambda *a, **k: [dict(clause)])
    monkeypatch.setattr(rerank, "select_clauses", fake_select)

    with pytest.raises(LLMError):
        mapping.map_findings(framework="rmit", provider=object())

    with Session(engine) as s:
        assert "10.55" in (s.get(Finding, fid1).regulatory_clauses or "")  # kept
        assert s.get(Finding, fid2).regulatory_clauses is None             # not reached


def test_invalid_severity_and_empty_and_missing(tmp_path, monkeypatch):
    engine = _db(tmp_path, monkeypatch)
    fid = _seed(engine)
    with pytest.raises(EditError):
        edit_finding(fid, severity="Spicy")
    with pytest.raises(EditError):
        edit_finding(fid)  # nothing to change
    with pytest.raises(EditError):
        edit_finding(999999, name="x")  # no such finding
