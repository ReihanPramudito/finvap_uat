"""Tiny in-memory background-job registry for the local UI.

Long operations (analysis, report generation) run in a daemon thread and report
progress via a callback; the browser polls ``/progress/{id}`` and shows a real
progress bar. Single operator, single process — a plain dict + lock is plenty.
Each job stores the name of the result template + the context to render when done.

The heavy jobs (analysis, recompute, report) all write the one per-project SQLite
file. Running two at once makes SQLite deadlock ("database is locked"), so only
**one** job may run at a time — :func:`start` refuses to launch a second and the
caller shows the operator a "wait for it to finish" banner.
"""
from __future__ import annotations

import threading
import uuid

_jobs: dict[str, dict] = {}
_lock = threading.Lock()
_active: str | None = None      # id of the running job, or None when idle


class JobBusy(RuntimeError):
    """Raised by :func:`start` when a background job is already running."""


def is_running() -> bool:
    """True if a heavy job is currently in flight (writes the DB)."""
    with _lock:
        j = _jobs.get(_active) if _active else None
        return j is not None and not j["done"]


def start(work, result_template: str) -> str:
    """Run ``work(progress)`` in a thread. ``progress(percent, label)`` updates the
    job; ``work`` returns the context dict to render with ``result_template``.

    Raises :class:`JobBusy` if a job is already running — the heavy jobs share one
    SQLite file and must not overlap.
    """
    global _active
    with _lock:
        prev = _jobs.get(_active) if _active else None
        if prev is not None and not prev["done"]:
            raise JobBusy()
        jid = uuid.uuid4().hex[:12]
        _jobs[jid] = {"percent": 0, "label": "starting…", "detail": "", "done": False,
                      "result": None, "error": None, "result_template": result_template}
        _active = jid

    def _progress(percent, label, detail=""):
        with _lock:
            j = _jobs.get(jid)
            if j and not j["done"]:
                j["percent"] = max(0, min(100, int(percent)))
                j["label"] = str(label)
                j["detail"] = str(detail or "")

    def _run():
        global _active
        try:
            result = work(_progress)
            with _lock:
                _jobs[jid].update(percent=100, label="done", done=True, result=result)
        except Exception as e:  # noqa: BLE001 — surfaced to the UI, never crashes the server
            with _lock:
                _jobs[jid].update(done=True, label="failed", error=f"{type(e).__name__}: {e}")
        finally:
            with _lock:
                if _active == jid:
                    _active = None

    threading.Thread(target=_run, daemon=True).start()
    return jid


def get(jid: str) -> dict | None:
    with _lock:
        j = _jobs.get(jid)
        return dict(j) if j else None


def discard(jid: str) -> None:
    with _lock:
        _jobs.pop(jid, None)
