"""Tests for the one-shot entry point (`finvap <target>` / `finvap <file.nessus>`).

The orchestrator now only scans/imports and then hands off to the web UI; the old
headless tag→score→map→report pipeline was removed. Covers input detection, the
scan/import→launch hand-off, the missing-file abort, and the bare-command routing.
"""
import pytest
from sqlmodel import Session, create_engine
from typer.testing import CliRunner

from finvap import config, db, orchestrator
from finvap.models import Asset, Finding
from finvap.orchestrator import PipelineError, _is_nessus, run_pipeline


class FakeConsole:
    """Console double: captures `print`, no-op everything else."""
    def __init__(self):
        self.lines = []

    def print(self, *a, **k):
        self.lines.append(" ".join(str(x) for x in a))

    @property
    def text(self):
        return "\n".join(self.lines)


def _seed(monkeypatch, tmp_path):
    """Temp DB with one asset + finding; returns the engine."""
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "t.db")
    engine = create_engine(f"sqlite:///{config.DB_PATH}")
    monkeypatch.setattr(db, "engine", engine)
    db.init_db()
    with Session(engine) as s:
        a = Asset(ip_address="10.0.0.1")
        s.add(a); s.commit(); s.refresh(a)
        s.add(Finding(asset_id=a.id, tool="gvm", name="vuln", cvss_vector="x"))
        s.commit()
    return engine


def _stub_launch(monkeypatch, sink: dict):
    import finvap.web.server as server
    monkeypatch.setattr(server, "launch", lambda **k: sink.setdefault("launch", k))


# --- input detection --------------------------------------------------------

def test_is_nessus_detects_file_vs_target(tmp_path):
    f = tmp_path / "scan.nessus"
    f.write_text("x")
    assert _is_nessus(str(f)) is True
    assert _is_nessus("scan.nessus") is True           # by extension, even if absent
    assert _is_nessus("192.168.1.10") is False
    assert _is_nessus("192.168.1.0/24") is False


# --- scan/import → web hand-off ---------------------------------------------

def test_run_pipeline_scans_then_opens_web(tmp_path, monkeypatch):
    _seed(monkeypatch, tmp_path)
    calls: dict = {}
    monkeypatch.setattr(orchestrator, "_scan",
                        lambda console, target, gvm: calls.setdefault("scan", (target, gvm)))
    _stub_launch(monkeypatch, calls)

    run_pipeline("10.0.0.1", console=FakeConsole(), gvm=True, open_browser=False, port=8123)

    assert calls["scan"] == ("10.0.0.1", True)          # nmap+GVM ran
    assert calls["launch"]["path"] == "/setup"          # UI opened at the setup page
    assert calls["launch"]["open_browser"] is False and calls["launch"]["port"] == 8123


def test_run_pipeline_imports_nessus_then_opens_web(tmp_path, monkeypatch):
    _seed(monkeypatch, tmp_path)
    f = tmp_path / "s.nessus"; f.write_text("x")
    calls: dict = {}
    monkeypatch.setattr(orchestrator, "_import",
                        lambda console, file: calls.setdefault("import", file))
    _stub_launch(monkeypatch, calls)

    run_pipeline(str(f), console=FakeConsole())

    assert calls["import"] == str(f)                    # importer ran, not the scanner
    assert calls["launch"]["path"] == "/setup"


def test_no_gvm_does_nmap_only(tmp_path, monkeypatch):
    _seed(monkeypatch, tmp_path)
    calls: dict = {}
    monkeypatch.setattr(orchestrator, "_scan",
                        lambda console, target, gvm: calls.setdefault("scan", (target, gvm)))
    _stub_launch(monkeypatch, calls)
    run_pipeline("10.0.0.1", console=FakeConsole(), gvm=False)
    assert calls["scan"] == ("10.0.0.1", False)


def test_missing_nessus_file_aborts(tmp_path, monkeypatch):
    _seed(monkeypatch, tmp_path)
    with pytest.raises(PipelineError, match="file not found"):
        run_pipeline(str(tmp_path / "absent.nessus"), console=FakeConsole())


# --- bare-command routing ---------------------------------------------------

def test_bare_target_routes_to_assess_and_assess_is_hidden():
    import re

    from finvap.cli import app

    r = CliRunner()
    help_out = r.invoke(app, ["--help"]).output
    assert not re.search(r"\bassess\b", help_out)         # `assess` is hidden
    assert "web" in help_out and "doctor" in help_out      # the visible commands

    # A bare target routes to assess: its --help (routed, no scan) shows assess options.
    routed = r.invoke(app, ["10.0.0.1", "--help"])
    assert routed.exit_code == 0 and "--no-gvm" in routed.output
    # Real subcommands are not hijacked.
    assert r.invoke(app, ["web", "--help"]).exit_code == 0
    assert r.invoke(app, ["doctor", "--help"]).exit_code == 0
