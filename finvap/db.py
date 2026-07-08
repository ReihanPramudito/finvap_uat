"""Database engine and session helpers (SQLite via SQLModel).

The engine is rebindable so the app can switch between per-client **projects**
(one SQLite file each — see :mod:`finvap.projects`). ``get_session`` / ``init_db``
read the module-level ``engine`` at call time, so a ``bind`` takes effect for
every later query.
"""
from __future__ import annotations

from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine

from . import models  # noqa: F401  (registers tables on SQLModel.metadata)
from .config import DATABASE_URL

# check_same_thread=False: the web UI runs long operations (analysis, report) in
# background threads, so a session may be created off the main thread. Each session
# gets its own connection and we never share one concurrently.
# timeout=30: SQLite's busy-timeout. When a write meets a lock held by another
# connection (e.g. a short finding edit while a background job commits) it waits up
# to 30s instead of pysqlite's 5s default before raising "database is locked".
_CONNECT_ARGS = {"check_same_thread": False, "timeout": 30}

engine = create_engine(DATABASE_URL, echo=False, connect_args=_CONNECT_ARGS)


def bind(db_path) -> None:
    """Point the active engine at ``db_path`` (a project's SQLite file)."""
    global engine
    engine = create_engine(f"sqlite:///{Path(db_path)}", echo=False, connect_args=_CONNECT_ARGS)


def init_db() -> None:
    """Create all tables if they do not yet exist."""
    SQLModel.metadata.create_all(engine)


def get_session() -> Session:
    return Session(engine)
