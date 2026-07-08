"""Lightweight, idempotent schema migration for the SQLite store.

SQLModel's ``create_all`` only creates *missing tables* — it never alters an
existing one. Phase 2 changes the shape of ``asset`` and ``finding`` and adds the
``findingscore`` table, so existing databases (built in Phase 1) need a one-off
migration. This module applies only the deltas and is safe to run repeatedly.

It also backfills ``finding.cvss_vector`` for rows scanned before the column
existed, by re-parsing the raw GVM XML saved under ``data/`` — no GVM needed.
"""
from __future__ import annotations

from sqlalchemy import inspect, text

from . import db
from .config import DATA_DIR

# Read ``db.engine`` at call time (not ``from .db import engine``): activating a
# project rebinds ``db.engine``, so a captured reference would migrate the wrong
# database.


def _asset_columns() -> set[str]:
    return {c["name"] for c in inspect(db.engine).get_columns("asset")}


def _finding_columns() -> set[str]:
    return {c["name"] for c in inspect(db.engine).get_columns("finding")}


def migrate() -> list[str]:
    """Bring an existing database up to the Phase 2 schema. Returns a log of
    the actions taken (empty entries are skipped) for the CLI to print."""
    log: list[str] = []

    # New table(s) first — create_all adds findingscore without touching others.
    existing_tables = set(inspect(db.engine).get_table_names())
    db.init_db()
    new_tables = set(inspect(db.engine).get_table_names()) - existing_tables
    for t in sorted(new_tables):
        log.append(f"created table {t}")

    with db.engine.begin() as conn:
        acols = _asset_columns()
        fcols = _finding_columns()

        # asset.environment (new context tag) — default to production so existing
        # assets keep full Security-Requirement weight until re-tagged.
        if "environment" not in acols:
            conn.execute(text(
                "ALTER TABLE asset ADD COLUMN environment VARCHAR "
                "NOT NULL DEFAULT 'production'"
            ))
            log.append("asset += environment (default 'production')")

        # finding.cvss_vector (native base vector — the risk engine's input)
        if "cvss_vector" not in fcols:
            conn.execute(text("ALTER TABLE finding ADD COLUMN cvss_vector VARCHAR"))
            log.append("finding += cvss_vector")

        # Richer NVT context for regulatory mapping (Obj 1) + reporting (Obj 4).
        for col in ("summary", "impact", "affected"):
            if col not in fcols:
                conn.execute(text(f"ALTER TABLE finding ADD COLUMN {col} VARCHAR"))
                log.append(f"finding += {col}")

        # Phase 5: human-in-the-loop override flags (SQLite stores bool as 0/1).
        # text_overridden (added with the WebUI's upfront AI-prose step) protects a
        # finalised description/solution from re-generation.
        for col in ("score_overridden", "clauses_overridden", "text_overridden"):
            if col not in fcols:
                conn.execute(text(
                    f"ALTER TABLE finding ADD COLUMN {col} BOOLEAN NOT NULL DEFAULT 0"
                ))
                log.append(f"finding += {col}")

        # Drop the removed, hard-to-defend modifier. SQLite >= 3.35 supports
        # DROP COLUMN; guard for older builds where it must be left in place.
        if "compensating_controls" in acols:
            try:
                conn.execute(text("ALTER TABLE asset DROP COLUMN compensating_controls"))
                log.append("asset -= compensating_controls")
            except Exception as e:  # pragma: no cover - old sqlite only
                log.append(f"could not drop asset.compensating_controls ({e}); leaving it")

    return log


def backfill_finding_context() -> int:
    """Fill NVT-derived fields (cvss_vector, summary, impact, affected) for rows
    scanned before those columns existed, by re-parsing the raw GVM XML in
    ``data/``. Returns the number of rows updated.

    Matching mirrors how the rows were ingested — by (asset IP, finding name,
    port, protocol). These fields are properties of the NVT, so every result
    sharing a name carries the same values; collisions are therefore harmless.
    """
    from lxml import etree
    from sqlmodel import select

    from .db import get_session
    from .models import Asset, Finding
    from .scanners.gvm_scanner import GvmScanner

    FIELDS = ("cvss_vector", "summary", "impact", "affected")
    parsed_by_key: dict[tuple, object] = {}
    for xml_path in sorted(DATA_DIR.glob("gvm-*.xml")):
        try:
            tree = etree.parse(str(xml_path))
        except etree.XMLSyntaxError:
            continue
        parsed = GvmScanner._parse(tree.getroot(), target=xml_path.stem)
        for f in parsed.findings:
            parsed_by_key[(f.ip_address, f.name, f.port, f.protocol)] = f

    if not parsed_by_key:
        return 0

    updated = 0
    with get_session() as session:
        ip_by_id = {a.id: a.ip_address for a in session.exec(select(Asset)).all()}
        for f in session.exec(select(Finding)).all():
            src = parsed_by_key.get((ip_by_id.get(f.asset_id), f.name, f.port, f.protocol))
            if src is None:
                continue
            changed = False
            for attr in FIELDS:
                if getattr(f, attr) is None and getattr(src, attr) is not None:
                    setattr(f, attr, getattr(src, attr))
                    changed = True
            if changed:
                session.add(f)
                updated += 1
        session.commit()
    return updated


def ensure_schema() -> None:
    """Idempotently bring the active database up to date — create tables, apply
    pending column migrations, backfill NVT context. Silent and safe to call on
    every launch, so a tester who updates FinVAP mid-engagement keeps working
    without running a manual migration. Never raises on a fresh/empty DB."""
    migrate()
    backfill_finding_context()
