"""Projects — one SQLite database per client engagement.

Each scan/import creates a **project**: its own DB (assets/findings/scans/report)
and its own engagement identity, under ``data/projects/``. Run settings + the SLA
stay global (``finvap.config.json``). An ``.active`` marker names the current
project so the CLI and the long-running web server agree on which DB is live —
:func:`activate` rebinds :data:`finvap.db.engine` and the engagement path.
"""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone

from . import config, db

PROJECTS_DIR = config.DATA_DIR / "projects"
ACTIVE_FILE = PROJECTS_DIR / ".active"


def _slugify(text: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "-", (text or "").strip().lower()).strip("-")
    return s[:40] or "project"


def db_path(slug: str):
    return PROJECTS_DIR / f"{slug}.db"


def engagement_path(slug: str):
    return PROJECTS_DIR / f"{slug}.engagement.json"


def meta_path(slug: str):
    return PROJECTS_DIR / f"{slug}.meta.json"


def _read_meta(slug: str) -> dict | None:
    p = meta_path(slug)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return None


def create(name: str, targets: str = "") -> str:
    """Create a new project (unique slug from ``name``), init its DB, activate it,
    and return the slug. ``name`` is the display label; ``targets`` is informational."""
    PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
    base = _slugify(name)
    slug, n = base, 1
    while meta_path(slug).exists() or db_path(slug).exists():
        n += 1
        slug = f"{base}-{n}"
    meta_path(slug).write_text(json.dumps({
        "slug": slug, "name": name.strip() or slug, "targets": targets,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }, indent=2))
    activate(slug)          # binds db + engagement path
    db.init_db()            # create tables in the new project DB
    return slug


def active() -> str | None:
    """The active project's slug, or None (legacy default DB)."""
    if not ACTIVE_FILE.exists():
        return None
    slug = ACTIVE_FILE.read_text().strip()
    return slug if slug and meta_path(slug).exists() else None


def exists(slug: str) -> bool:
    return meta_path(slug).exists()


def active_meta() -> dict | None:
    """Meta of the active project (name/targets/created), or None."""
    slug = active()
    return _read_meta(slug) if slug else None


def activate(slug: str) -> None:
    """Make ``slug`` the active project: rebind the DB engine + engagement path,
    and persist the marker so later CLI runs use the same project."""
    PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
    ACTIVE_FILE.write_text(slug)
    db.bind(db_path(slug))
    config.ENGAGEMENT_PATH = engagement_path(slug)


def load_active() -> str | None:
    """On startup: bind to the marked project if one exists. Returns its slug."""
    slug = active()
    if slug:
        activate(slug)
    return slug


def rename(slug: str, name: str) -> bool:
    meta = _read_meta(slug)
    if meta is None:
        return False
    meta["name"] = name.strip() or slug
    meta_path(slug).write_text(json.dumps(meta, indent=2))
    return True


def delete(slug: str) -> bool:
    """Remove a project's DB, engagement and meta files. Clears the active marker
    if it pointed here (the caller should then activate another / fall back)."""
    if _read_meta(slug) is None:
        return False
    for p in (db_path(slug), engagement_path(slug), meta_path(slug)):
        if p.exists():
            p.unlink()
    if active() is None and ACTIVE_FILE.exists() and ACTIVE_FILE.read_text().strip() == slug:
        ACTIVE_FILE.unlink()
    return True


def _counts(slug: str) -> tuple[int, int]:
    """(assets, findings) for a project without disturbing the active engine."""
    from sqlalchemy import func
    from sqlmodel import Session, create_engine, select

    from .models import Asset, Finding
    p = db_path(slug)
    if not p.exists():
        return (0, 0)
    try:
        # timeout=30: this reader opens its own connection to the project file; if
        # that file is the active project mid-analysis, wait out a brief write lock
        # rather than failing the projects list with "database is locked".
        eng = create_engine(f"sqlite:///{p}", connect_args={"timeout": 30})
        with Session(eng) as s:
            a = s.exec(select(func.count()).select_from(Asset)).one()
            f = s.exec(select(func.count()).select_from(Finding)).one()
        eng.dispose()
        return (a, f)
    except Exception:       # missing tables / unreadable — treat as empty
        return (0, 0)


def list_projects() -> list[dict]:
    """All projects, newest first, with asset/finding counts and the active flag."""
    if not PROJECTS_DIR.exists():
        return []
    cur = active()
    out = []
    for mp in PROJECTS_DIR.glob("*.meta.json"):
        meta = _read_meta(mp.name[: -len(".meta.json")])
        if not meta:
            continue
        n_assets, n_findings = _counts(meta["slug"])
        out.append({**meta, "n_assets": n_assets, "n_findings": n_findings,
                    "active": meta["slug"] == cur})
    out.sort(key=lambda m: m.get("created_at", ""), reverse=True)
    return out


def default_name(targets: str) -> str:
    """A readable auto-name for a new project from its scan targets + today."""
    day = datetime.now().strftime("%d %b %Y")
    t = (targets or "").strip()
    parts = [p for p in re.split(r"[,\s]+", t) if p]
    if not parts:
        label = "assessment"
    elif len(parts) == 1:
        label = parts[0]
    else:
        label = f"{parts[0]} +{len(parts) - 1} more"
    return f"{label} · {day}"
