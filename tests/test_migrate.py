"""Auto-migration (`ensure_schema`) runs on every web / orchestrator launch, so a
tester who updated FinVAP since their last scan is not blocked by a missing
column. The key regression guarded here: migration must run against the
*currently bound* engine — activating a project rebinds ``db.engine``, and a
captured reference would silently migrate the wrong database."""
from sqlalchemy import create_engine, inspect, text

from finvap import db
from finvap.migrate import ensure_schema, migrate


def test_migrate_adds_column_on_the_rebound_engine(tmp_path, monkeypatch):
    # A pre-'environment' asset table, bound as the active engine the way
    # projects.activate() rebinds it after the tool was updated.
    path = tmp_path / "old.db"
    eng = create_engine(f"sqlite:///{path}")
    with eng.begin() as c:
        c.execute(text("CREATE TABLE asset (id INTEGER PRIMARY KEY, ip_address VARCHAR)"))
    monkeypatch.setattr(db, "engine", eng)

    migrate()
    cols = {c["name"] for c in inspect(db.engine).get_columns("asset")}
    assert "environment" in cols                       # migrated the rebound DB, not a stale one
    assert not any("environment" in a for a in migrate())  # idempotent second run


def test_ensure_schema_on_fresh_db_is_valid_and_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "engine", create_engine(f"sqlite:///{tmp_path/'fresh.db'}"))
    ensure_schema()
    ensure_schema()                                    # safe to call again
    tables = set(inspect(db.engine).get_table_names())
    assert {"asset", "finding", "findingscore"} <= tables
