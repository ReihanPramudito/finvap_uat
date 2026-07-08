"""Finding deletion (cascade).

SQLite doesn't enforce foreign-key cascades for us, so a finding's ``FindingScore``
children are removed explicitly. Used by the web UI's per-finding Delete control.
Paths/engine are read at call time so tests can point at a temp DB.
"""
from __future__ import annotations

from sqlmodel import select

from .db import get_session
from .models import Finding, FindingScore


def _count_scores(session, finding_id: int) -> int:
    return len(
        session.exec(
            select(FindingScore).where(FindingScore.finding_id == finding_id)
        ).all()
    )


def _delete_findings(session, findings) -> int:
    """Delete the given findings and their FindingScore children; return #scores."""
    n_scores = 0
    for f in findings:
        for s in session.exec(
            select(FindingScore).where(FindingScore.finding_id == f.id)
        ).all():
            session.delete(s)
            n_scores += 1
        session.delete(f)
    return n_scores


def delete_finding(finding_id: int, *, dry_run: bool = False) -> dict:
    """Delete a single finding and its scores. ``dry_run`` returns the counts it
    would remove without deleting. Raises ``LookupError`` if the id is unknown."""
    with get_session() as session:
        f = session.get(Finding, finding_id)
        if f is None:
            raise LookupError(f"No finding #{finding_id}")
        counts = {"finding": finding_id, "name": f.name,
                  "scores": _count_scores(session, finding_id)}
        if dry_run:
            return counts
        _delete_findings(session, [f])
        session.commit()
        return counts
