"""Audit trail + AI activity log — the tool's "history tab".

Every state-changing / external action FinVAP takes is recorded as an audit
event so an operator (or the client, after a pentest) can review exactly what the
tool did: which command ran, when, against what, with what result — and crucially
*what it actually executed* (the literal nmap argv, the GVM task, each LLM call).

Design (the hybrid agreed in Step 1):
  * A dedicated SQLite store at ``data/logs/audit.db`` — its own file, separate
    from the client database — holds one compact, queryable row per event.
    Keeping it out of the client DB means ``finvap db reset`` / ``restore`` never
    disturb the audit trail (it is preserved unless explicitly cleared) and the
    client DB stays lean. Bulky LLM payloads spill to per-call JSON files under
    ``data/logs/ai/``, referenced by ``artifact_path`` — mirroring how a scan row
    points to its raw XML.
  * Every LLM call (report prose *and* clause re-rank) is masked before it leaves
    the process; :func:`ai_call` stores the masked text actually sent, the local
    placeholder->real map, the restored output, and an automated **leak-check**
    asserting no real identifier appears in the outbound payload. That is the
    evidence that PII masking works, not merely a claim.

Paths are read from :mod:`finvap.config` at call time so tests can redirect them.
Auditing is best-effort: a logging failure must never break the real operation.
Set ``FINVAP_AUDIT=0`` to disable.
"""
from __future__ import annotations

import contextlib
import contextvars
import json
import os
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from . import config

# The run a deep module's event belongs to is carried implicitly so callers like
# ingest / mapping / the report generator can emit events without threading a
# run id through every signature.
_run_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("finvap_run_id", default=None)
_run_cmd: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("finvap_run_cmd", default=None)


def enabled() -> bool:
    return os.environ.get("FINVAP_AUDIT", "1") != "0"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _db_path():
    return config.LOGS_DIR / "audit.db"


def _ai_dir():
    return config.AI_LOGS_DIR


_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_event (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        TEXT,
    ts            TEXT NOT NULL,
    command       TEXT,
    action        TEXT NOT NULL,
    target        TEXT,
    status        TEXT NOT NULL DEFAULT 'ok',
    duration_ms   INTEGER,
    summary       TEXT,
    detail        TEXT,
    artifact_path TEXT
)
"""


def _connect() -> sqlite3.Connection:
    config.LOGS_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_db_path()))
    conn.row_factory = sqlite3.Row
    conn.execute(_SCHEMA)
    return conn


def record(action: str, *, command: str | None = None, target: str | None = None,
           status: str = "ok", summary: str | None = None, detail: dict | None = None,
           artifact_path=None, duration_ms: int | None = None) -> None:
    """Write one audit row. Best-effort — auditing never breaks the operation."""
    if not enabled():
        return
    try:
        conn = _connect()
        with conn:
            conn.execute(
                "INSERT INTO audit_event "
                "(run_id, ts, command, action, target, status, duration_ms, "
                " summary, detail, artifact_path) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (_run_id.get(), _now(), command or _run_cmd.get(), action, target,
                 status, duration_ms, summary,
                 json.dumps(detail) if detail is not None else None,
                 str(artifact_path) if artifact_path else None),
            )
        conn.close()
    except Exception:
        pass  # logging must never crash the actual command


# Sub-events within a run read the current command/run id implicitly.
event = record


@contextlib.contextmanager
def run(command: str, *, target: str | None = None):
    """Wrap a command invocation: assign a run id, record start + outcome+duration.

    Classifies Typer/Click control-flow (Abort / Exit) without importing typer so
    a user-cancelled confirm reads as ``aborted`` and a handled ``Exit(1)`` as
    ``error``, while still re-raising so the CLI behaves exactly as before.

    **Reentrant:** if a run is already active (e.g. the orchestrator opened one and
    is calling into sub-steps), nested ``run()`` calls join the parent rather than
    starting a fresh run — so a whole `finvap <target>` pipeline groups under one
    run id in `finvap logs`.
    """
    if _run_id.get() is not None:
        yield _run_id.get()
        return
    rid = uuid.uuid4().hex[:12]
    tok_id = _run_id.set(rid)
    tok_cmd = _run_cmd.set(command)
    t0 = time.time()
    record("run.start", command=command, target=target, summary=f"{command} started")
    status, summary = "ok", f"{command} completed"
    try:
        yield rid
    except BaseException as e:
        name = type(e).__name__
        if name == "Abort":
            status, summary = "aborted", f"{command} aborted by user"
        elif name in ("Exit", "SystemExit"):
            code = getattr(e, "exit_code", getattr(e, "code", 0)) or 0
            status = "ok" if code == 0 else "error"
            summary = f"{command} exited (code {code})"
        else:
            status, summary = "error", f"{command} failed: {type(e).__name__}: {e}"
        raise
    finally:
        record("run.end", command=command, target=target, status=status,
               summary=summary, duration_ms=int((time.time() - t0) * 1000))
        _run_id.reset(tok_id)
        _run_cmd.reset(tok_cmd)


def leak_check(outbound_text: str, placeholder_map: dict) -> dict:
    """Assert no real identifier leaked into the text actually sent to the LLM.

    ``placeholder_map`` is placeholder->real (e.g. ``{"ASSET-1": "10.0.0.5"}``);
    we check that none of the *real* values appears in the outbound payload.
    Returns ``{result: pass|leak, checked: int, leaked: [...]}``.
    """
    reals = sorted({v for v in (placeholder_map or {}).values() if v}, key=len, reverse=True)
    found = [r for r in reals if r and r in (outbound_text or "")]
    return {"result": "leak" if found else "pass", "checked": len(reals), "leaked": found}


def ai_call(*, stage: str, provider: str, model: str, system: str, user_sent: str,
            response_raw: str, placeholder_map: dict | None = None,
            response_unmasked: str | None = None, command: str | None = None,
            duration_ms: int | None = None, extra: dict | None = None) -> dict:
    """Record one LLM call and persist the full prompt/response artifact.

    ``user_sent`` MUST be the *masked* text actually sent. The artifact stores the
    masked input, the local placeholder->real map, the restored output and the
    leak-check verdict — the evidence that masking worked. Returns the leak dict.
    """
    placeholder_map = placeholder_map or {}
    leak = leak_check((system or "") + "\n" + (user_sent or ""), placeholder_map)
    artifact_path = None
    rid = _run_id.get() or "adhoc"
    if enabled():
        try:
            _ai_dir().mkdir(parents=True, exist_ok=True)
            artifact_path = _ai_dir() / f"{rid}-{stage}-{int(time.time() * 1000)}.json"
            payload = {
                "run_id": rid, "ts": _now(), "command": command or _run_cmd.get(),
                "stage": stage, "provider": provider, "model": model, "masked": True,
                "system_prompt": system,
                "user_prompt_sent": user_sent,           # masked — what left the process
                "placeholder_map": placeholder_map,      # local only, never transmitted
                "response_raw": response_raw,             # model output (still masked)
                "response_unmasked": response_unmasked,   # restored locally for the report
                "leak_check": leak,
            }
            if extra:
                payload.update(extra)
            artifact_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
        except Exception:
            artifact_path = None
    words = len((response_raw or "").split())
    record("llm.call", command=command, target=stage,
           status="ok" if leak["result"] == "pass" else "warn",
           summary=(f"{provider}:{model} {stage} — masking {leak['result']}"
                    + (f" ({leak['checked']} id(s) checked)" if leak["checked"] else "")
                    + (f", {words} words out" if words else "")),
           detail={"provider": provider, "model": model, "stage": stage,
                   "leak_check": leak["result"], "ids_checked": leak["checked"],
                   "leaked": leak["leaked"]},
           artifact_path=str(artifact_path) if artifact_path else None,
           duration_ms=duration_ms)
    return leak


# --------------------------------------------------------------------------- #
# Read side (the `finvap logs` / `finvap logs show` views)
# --------------------------------------------------------------------------- #

def recent(limit: int = 60) -> list[dict]:
    """Most-recent events first (newest at the top, Burp-history style)."""
    if not _db_path().exists():
        return []
    conn = _connect()
    rows = conn.execute(
        "SELECT * FROM audit_event ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get(event_id: int) -> dict | None:
    if not _db_path().exists():
        return None
    conn = _connect()
    row = conn.execute("SELECT * FROM audit_event WHERE id = ?", (event_id,)).fetchone()
    conn.close()
    return dict(row) if row else None
