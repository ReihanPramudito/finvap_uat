"""Projects — one SQLite DB per client engagement, switchable at runtime."""
import pytest
from sqlmodel import Session, select

from finvap import db, engagement, projects
from finvap.models import Asset


@pytest.fixture
def proj_dir(tmp_path, monkeypatch):
    # isolate the projects dir + restore the global engine (create/activate rebind it)
    import finvap.db as _db
    saved = _db.engine
    d = tmp_path / "projects"
    monkeypatch.setattr(projects, "PROJECTS_DIR", d)
    monkeypatch.setattr(projects, "ACTIVE_FILE", d / ".active")
    yield d
    _db.engine = saved


def test_create_activate_and_isolation(proj_dir):
    a = projects.create("Client A", targets="10.0.0.1")
    assert projects.active() == a
    with Session(db.engine) as s:           # DB is bound to project A
        s.add(Asset(ip_address="10.0.0.1")); s.commit()

    b = projects.create("Client B", targets="10.0.0.2")
    assert projects.active() == b
    with Session(db.engine) as s:           # B is a fresh, separate DB
        assert s.exec(select(Asset)).all() == []

    projects.activate(a)                     # switch back — A's data is intact
    with Session(db.engine) as s:
        assert len(s.exec(select(Asset)).all()) == 1


def test_list_rename_delete(proj_dir):
    slug = projects.create("My Client", targets="10.0.0.0/24")
    lst = projects.list_projects()
    assert len(lst) == 1
    assert lst[0]["name"] == "My Client" and lst[0]["active"] and lst[0]["targets"] == "10.0.0.0/24"

    assert projects.rename(slug, "Renamed Co")
    assert projects.list_projects()[0]["name"] == "Renamed Co"

    assert projects.delete(slug)
    assert projects.list_projects() == []


def test_engagement_is_per_project(proj_dir):
    a = projects.create("A")
    engagement.save({"Client_Full_Name": "Acme Bank"})
    projects.create("B")                     # B has its own (empty) engagement
    assert engagement.load() == {}
    projects.activate(a)
    assert engagement.load().get("Client_Full_Name") == "Acme Bank"


def test_load_active_binds_on_startup(proj_dir):
    a = projects.create("A")
    with Session(db.engine) as s:
        s.add(Asset(ip_address="10.0.0.7")); s.commit()
    db.bind(proj_dir / "nowhere.db")         # simulate a fresh process (unbound)
    assert projects.load_active() == a       # marker restores project A
    with Session(db.engine) as s:
        assert len(s.exec(select(Asset)).all()) == 1


def test_default_name(proj_dir):
    assert "assessment" in projects.default_name("")
    assert "+1 more" in projects.default_name("10.0.0.1, 10.0.0.2")
    assert projects.default_name("10.0.0.5").startswith("10.0.0.5")


def test_assess_creates_project_and_normalizes_target(proj_dir, monkeypatch):
    import finvap.orchestrator as orch
    from typer.testing import CliRunner

    from finvap.cli import app
    captured = {}

    def fake_pipeline(source, **kw):
        captured["source"], captured["gvm"] = source, kw.get("gvm")
        return None
    monkeypatch.setattr(orch, "run_pipeline", fake_pipeline)

    r = CliRunner().invoke(app, ["10.0.0.1,10.0.0.2", "--no-gvm"])
    assert r.exit_code == 0, r.output
    assert captured["source"] == "10.0.0.1 10.0.0.2"   # comma -> space for the scanners
    assert captured["gvm"] is False
    assert projects.active() is not None                # a project was created + activated
    assert projects.list_projects()[0]["targets"] == "10.0.0.1,10.0.0.2"
