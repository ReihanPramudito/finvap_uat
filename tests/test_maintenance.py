"""Test for the one data-lifecycle operation FinVAP still owns: cascade delete of
a single finding (used by the web UI's per-finding Delete button)."""
from sqlmodel import Session, SQLModel, create_engine, select

import pytest

from finvap import db, maintenance
from finvap.models import Asset, Finding, FindingScore


def _make_db(path, monkeypatch):
    engine = create_engine(f"sqlite:///{path}")
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(db, "engine", engine)  # get_session() reads db.engine at call time
    return engine


def _score(finding_id: int) -> FindingScore:
    return FindingScore(
        finding_id=finding_id, cvss_version="3.1", base_vector="v", base_score=5.0,
        base_severity="Medium", source="scan", adj_vector="v", adj_score=5.0,
        adj_severity="Medium",
    )


def test_delete_finding_cascades_scores_and_leaves_others(tmp_path, monkeypatch):
    engine = _make_db(tmp_path / "t.db", monkeypatch)
    with Session(engine) as s:
        a = Asset(ip_address="10.0.0.1"); s.add(a); s.commit(); s.refresh(a)
        f = Finding(asset_id=a.id, tool="gvm", name="Target")
        keep = Finding(asset_id=a.id, tool="gvm", name="Keep")
        s.add(f); s.add(keep); s.commit(); s.refresh(f)
        s.add(_score(f.id)); s.commit()
        fid = f.id

    assert maintenance.delete_finding(fid, dry_run=True) == {
        "finding": fid, "name": "Target", "scores": 1}
    maintenance.delete_finding(fid)

    with Session(engine) as s:
        assert [x.name for x in s.exec(select(Finding)).all()] == ["Keep"]
        assert s.exec(select(FindingScore)).all() == []     # scores cascaded


def test_delete_finding_unknown_id_raises(tmp_path, monkeypatch):
    _make_db(tmp_path / "t.db", monkeypatch)
    with pytest.raises(LookupError):
        maintenance.delete_finding(9999)
