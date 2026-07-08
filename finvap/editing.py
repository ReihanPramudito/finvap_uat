"""Human-in-the-loop edits to a finding (NFR: override an AI-generated risk
score, finding, or written text before finalising a report).

An edit sets an override flag so a later ``finvap score`` / ``map`` won't clobber
the manual value (see ``risk.engine.score_findings`` / ``compliance.mapping``).
A score/severity override is propagated to **all** of a finding's score layers —
both the environmental (``adj_*``) and regulatory (``fw_adj_*``) fields — so the
override shows consistently in the findings table, the mapping view and the
generated report (the report reads ``fw_adj_severity or adj_severity``).
"""
from __future__ import annotations

import json

from sqlmodel import select

from .db import get_session
from .models import Finding, FindingScore
from .risk import band

# Floor score for a severity-only override (snap to the bottom of the band so the
# number and label stay consistent). Matches risk.metrics banding.
_SEV_FLOOR = {"Critical": 9.0, "High": 7.0, "Medium": 4.0, "Low": 0.1, "None": 0.0}
VALID_SEVERITIES = tuple(_SEV_FLOOR)


class EditError(RuntimeError):
    """An edit could not be applied (no such finding, or bad input)."""


def _resolve_override(score: float | None, severity: str | None) -> tuple[float, str]:
    if score is not None and severity is not None:
        return float(score), severity
    if score is not None:
        return float(score), band(float(score))
    return _SEV_FLOOR[severity], severity  # severity-only -> snap to band floor


def edit_finding(
    finding_id: int, *,
    name: str | None = None,
    description: str | None = None,
    solution: str | None = None,
    score: float | None = None,
    severity: str | None = None,
    add_clause: str | None = None,
    remove_clause: str | None = None,
    clear_override: bool = False,
) -> dict:
    """Apply edits to a finding. Returns a summary dict of what changed."""
    with get_session() as session:
        f = session.get(Finding, finding_id)
        if f is None:
            raise EditError(f"No finding #{finding_id}")
        changed: list[str] = []

        # --- free-text edits (durable: ingest never rewrites an existing finding) ---
        if name is not None:
            f.name = name
            changed.append("name")
        if description is not None:
            f.description = description
            changed.append("description")
        if solution is not None:
            f.solution = solution
            changed.append("solution")
        # A human-finalised description/solution must survive the AI prose step.
        if description is not None or solution is not None:
            f.text_overridden = True

        # --- score / severity override ---
        if score is not None or severity is not None:
            if severity is not None and severity not in _SEV_FLOOR:
                raise EditError(f"--severity must be one of {list(VALID_SEVERITIES)}")
            new_score, new_sev = _resolve_override(score, severity)
            f.cvss_adjusted = new_score
            f.severity_adjusted = new_sev
            for fs in session.exec(
                select(FindingScore).where(FindingScore.finding_id == f.id)
            ).all():
                fs.adj_score = fs.fw_adj_score = new_score
                fs.adj_severity = fs.fw_adj_severity = new_sev
                session.add(fs)
            f.score_overridden = True
            changed.append(f"score={new_score} {new_sev} (overridden)")

        # --- cited-clause edits ---
        if add_clause or remove_clause:
            clauses = json.loads(f.regulatory_clauses) if f.regulatory_clauses else []
            if remove_clause:
                kept = [c for c in clauses
                        if remove_clause.lower() not in (c.get("citation") or "").lower()]
                if len(kept) < len(clauses):
                    changed.append(f"-clause {remove_clause}")
                clauses = kept
            if add_clause:
                clauses.append({
                    "citation": add_clause, "clause_id": add_clause,
                    "section": "(manually added)", "binding": None,
                    "score": None, "excerpt": "", "manual": True,
                })
                changed.append(f"+clause {add_clause}")
            f.regulatory_clauses = json.dumps(clauses) if clauses else None
            f.clauses_overridden = True

        # --- clear overrides (processed last so it wins if combined) ---
        if clear_override:
            f.score_overridden = False
            f.clauses_overridden = False
            f.text_overridden = False
            changed.append("cleared overrides")

        if not changed:
            raise EditError("nothing to change — pass at least one field to edit")
        session.add(f)
        session.commit()
        return {"finding": finding_id, "name": f.name, "changed": changed}
