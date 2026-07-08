"""Tests for `finvap doctor` readiness checks that don't need a live GVM/DB —
specifically the PostgreSQL-cluster check that explains the #1 recurring
`gvm-start` failure (a down cluster while the wrapper unit reads active)."""
from finvap.doctor import FAIL, OK, _postgres_check


class _Run:
    def __init__(self, stdout):
        self.stdout = stdout


def test_postgres_down_cluster_flags_the_fix(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/pg_lsclusters")
    monkeypatch.setattr("subprocess.run", lambda *a, **k: _Run(
        "18  main    5432 down   postgres /var/lib/postgresql/18/main /var/log/x"))
    c = _postgres_check()
    assert c.status == FAIL
    assert "18/main" in c.detail and "postgresql@18-main" in c.detail


def test_postgres_up_cluster_is_ok(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/pg_lsclusters")
    monkeypatch.setattr("subprocess.run", lambda *a, **k: _Run(
        "18  main    5432 online postgres /var/lib/postgresql/18/main /var/log/x"))
    c = _postgres_check()
    assert c.status == OK and "1 cluster(s) up" in c.detail


def test_postgres_check_skipped_without_pg_lsclusters(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert _postgres_check() is None
