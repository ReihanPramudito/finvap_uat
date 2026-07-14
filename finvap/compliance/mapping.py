"""Map findings to regulatory clauses and compute the framework-adjusted score.

Two outputs per `finvap map --framework X`:
  1. ``Finding.regulatory_clauses`` — the cited clauses (IDs + verbatim text),
     retrieved by semantic similarity. Anti-hallucination: only real, retrieved
     clauses are stored; nothing is model-generated.
  2. ``FindingScore.fw_adj_*`` — a **regulatory-priority** band (the Phase-2 slot),
     layered on top of the environmental score. It can raise OR lower, under the
     locked guardrails (see compute_fw_adj).
"""
from __future__ import annotations

import json

from .. import audit
from ..models import Criticality, DataSensitivity
from . import store

# Uniform band ladder (matches risk.metrics banding).
_ORDER = ["None", "Low", "Medium", "High", "Critical"]
_FLOOR = {"None": 0.0, "Low": 0.1, "Medium": 4.0, "High": 7.0, "Critical": 9.0}
_CEIL = {"None": 0.0, "Low": 3.9, "Medium": 6.9, "High": 8.9, "Critical": 10.0}

_HIGH_VALUE_CRIT = {Criticality.high, Criticality.critical}
_SENSITIVE_DATA = {DataSensitivity.financial, DataSensitivity.pii}


def _idx(sev: str) -> int:
    return _ORDER.index(sev) if sev in _ORDER else 1


def _step(sev: str, n: int) -> str:
    return _ORDER[max(0, min(len(_ORDER) - 1, _idx(sev) + n))]


def _higher(a: str, b: str) -> str:
    return a if _idx(a) >= _idx(b) else b


def _lower(a: str, b: str) -> str:
    return a if _idx(a) <= _idx(b) else b


def finding_query(f) -> str:
    """Enriched semantic query for a finding (bridges the technical->governance gap)."""
    return " ".join(p for p in (f.name, f.summary, f.impact, f.solution) if p).strip()


def compute_fw_adj(base_severity: str, adj_severity: str, adj_score: float,
                   mappings: list[dict], asset, framework: str) -> tuple[str, float, str]:
    """Deterministic regulatory-priority band on top of the environmental score.
    Returns (severity, score, reason).

    Model 1: the *number* stays standards-based (CVSS-environmental); clause
    *relevance* is judged upstream by the LLM re-ranker (a mapping here means the
    LLM confirmed the clause applies). Isolated in this one function so switching
    to an LLM-driven severity decision later is a single-place change.

    Rules:
      * RAISE one band only when the finding maps to a **binding** clause, is
        already a real vulnerability (**base >= Medium**), and sits on a high-value
        asset (critical/high criticality, or financial/pii data). High -> Critical
        only under the strict gate (criticality=critical AND data in
        {financial,pii}). Gating on the *base* severity keeps a low-impact mapped
        finding (e.g. weak SSH MAC, base Low) at its environmental band instead of
        inflating it to High.
      * DROP to Low when no clause applies and the finding is only Low/Medium
        (de-prioritise framework-irrelevant noise) — never a High/Critical finding.
      * HOLD the environmental severity otherwise.
    """
    if adj_severity is None:
        return adj_severity, adj_score, "not scored"
    mapped = len(mappings) > 0
    binding = (any(m.get("binding") == "S" for m in mappings)
               if framework == "rmit" else mapped)
    high_value = (asset.criticality in _HIGH_VALUE_CRIT
                  or asset.data_sensitivity in _SENSITIVE_DATA)
    base_is_real = _idx(base_severity or "None") >= _idx("Medium")

    if mapped and binding and base_is_real and high_value:
        strict_gate = (asset.criticality == Criticality.critical
                       and asset.data_sensitivity in _SENSITIVE_DATA)
        target = _step(adj_severity, +1)              # at most one band up
        if not strict_gate:
            target = _lower(target, "High")           # High -> Critical only on strict gate
        new = _higher(target, adj_severity)           # raise branch never lowers
        if _idx(new) > _idx(adj_severity):
            why = ("binding clause on a critical %s asset" % asset.data_sensitivity.value
                   if new == "Critical" else
                   "maps to a binding clause on a high-value asset")
            return new, round(max(adj_score, _FLOOR[new]), 1), f"raised: {why}"
        return adj_severity, adj_score, "held (already at/above regulatory band)"

    if not mapped and adj_severity in ("Low", "Medium"):
        new = _higher(_step(adj_severity, -1), "Low")  # -1, floored at Low
        if _idx(new) < _idx(adj_severity):
            return new, round(min(adj_score, _CEIL[new]), 1), \
                f"lowered: no {framework.upper()} clause addresses this finding"
        return adj_severity, adj_score, "held"

    return adj_severity, adj_score, "held"


def _clause_brief(m: dict) -> dict:
    d = {
        "citation": m["citation"], "clause_id": m["clause_id"],
        "section": m["section"], "binding": m["binding"],
        "score": m["score"], "excerpt": (m.get("text") or "")[:300],
    }
    if m.get("reason"):
        d["reason"] = m["reason"]  # the LLM's rationale for selecting *this* clause
    return d


def map_findings(*, framework: str, k: int = 8, floor: float = 0.0, progress=None,
                 provider=None):
    """Map every finding to clauses and recompute fw_adj. Returns a stats dict.

    Mapping is RAG-retrieve (top-``k`` candidates) + LLM re-rank: the LLM selects
    the applicable clause(s) from the real candidates (or none). ``provider``
    defaults to the configured LLM (Granite local by default).
    """
    from sqlmodel import select

    from ..db import get_session
    from ..models import Asset, Finding, FindingScore
    from ..reporting.masking import Masker
    from ..reporting.providers import get_provider
    from . import rerank

    prov = provider or get_provider()
    # Build the clause vector index on first use (missing on a fresh install —
    # it's client-scoped data, not shipped). Deterministic from the reg PDFs.
    store.ensure_index(framework,
                       progress=(lambda s: progress(0, 1, s)) if progress else None)
    stats = {"mapped": 0, "no_match": 0, "raised": 0, "lowered": 0,
             "unscored": 0, "overridden": 0, "info_skipped": 0}
    with get_session() as session:
        assets = {a.id: a for a in session.exec(select(Asset)).all()}
        findings = session.exec(select(Finding)).all()
        total = len(findings)

        for idx, f in enumerate(findings, 1):
            if progress:
                progress(idx, total, f.name or f.cve or "")
            # Preserve manually curated clauses (Phase 5): skip re-mapping.
            if f.clauses_overridden:
                stats["overridden"] += 1
                audit.event("clause.verdict", command="map", target=f"finding#{f.id}",
                            status="skipped",
                            summary=f"#{f.id} {(f.name or '')[:50]} — kept manual clause override",
                            detail={"finding_id": f.id, "reason": "clauses_overridden"})
                continue
            # Info-only findings (no CVSS score) aren't vulnerabilities — don't spend
            # an LLM call citing a clause for them. Keeps `map` proportional to real
            # findings, not the full info-noise count (a Nessus scan can be mostly info).
            if not f.cvss_vector:
                if f.regulatory_clauses is not None:
                    f.regulatory_clauses = None
                    session.add(f)
                stats["info_skipped"] += 1
                audit.event("clause.verdict", command="map", target=f"finding#{f.id}",
                            status="skipped",
                            summary=f"#{f.id} {(f.name or '')[:50]} — info-only, not mapped",
                            detail={"finding_id": f.id, "reason": "no CVSS vector"})
                continue
            asset = assets.get(f.asset_id)
            q = finding_query(f)
            candidates = store.query(framework, q, k=k, floor=floor) if q else []
            # Mask the finding text before it reaches the LLM (same privacy
            # treatment as the report path), keyed to this finding's asset.
            masker = Masker()
            if asset is not None:
                masker.register_asset(asset.ip_address, asset.hostname)
            if progress:  # second, finer update right before the slow LLM re-rank
                progress(idx, total, f"{(f.name or 'finding')[:60]} — re-ranking clauses (LLM)")
            selected, why = rerank.select_clauses(
                f, candidates, framework=framework, provider=prov, masker=masker
            )
            f.regulatory_clauses = (
                json.dumps([_clause_brief(m) for m in selected]) if selected else None
            )
            session.add(f)
            stats["mapped" if selected else "no_match"] += 1
            cites = [m["citation"] for m in selected]
            audit.event("clause.verdict", command="map", target=f"finding#{f.id}",
                        summary=f"#{f.id} {(f.name or '')[:50]} → "
                                + (", ".join(cites) if cites else "no clause")
                                + (f" — {why}" if why else ""),
                        detail={"finding_id": f.id, "selected": cites,
                                "candidates": len(candidates), "reason": why})

            fs_rows = session.exec(
                select(FindingScore).where(FindingScore.finding_id == f.id)
            ).all()
            if not fs_rows:
                stats["unscored"] += 1
            for fs in fs_rows:
                new_sev, new_score, _ = compute_fw_adj(
                    fs.base_severity, fs.adj_severity, fs.adj_score, selected, asset, framework
                )
                if fs.cvss_version == "3.1":  # count once per finding, on the default layer
                    if _idx(new_sev) > _idx(fs.adj_severity):
                        stats["raised"] += 1
                    elif _idx(new_sev) < _idx(fs.adj_severity):
                        stats["lowered"] += 1
                fs.fw_adj_severity = new_sev
                fs.fw_adj_score = new_score
                session.add(fs)
            # Commit per finding: each LLM re-rank takes seconds-to-minutes, so a
            # crash mid-run (LLM down, power, …) must not roll back the hours of
            # verdicts already reached.
            session.commit()

        session.commit()
    return stats


def refresh_fw_adj(*, framework: str, progress=None) -> dict:
    """Recompute the regulatory (fw_adj) severity for every scored finding from the
    clauses ALREADY stored on it — **no LLM, no re-mapping**.

    Used after the tag-effect weights change (the Risk-model page): the environmental
    score has been re-derived, so the deterministic fw_adj band on top of it must be
    refreshed, but the clause *selection* (the LLM's job) hasn't changed. Reads the
    persisted ``regulatory_clauses`` JSON and re-runs :func:`compute_fw_adj`.
    """
    from sqlmodel import select

    from ..db import get_session
    from ..models import Asset, Finding, FindingScore

    stats = {"raised": 0, "lowered": 0, "unchanged": 0}
    with get_session() as session:
        assets = {a.id: a for a in session.exec(select(Asset)).all()}
        findings = session.exec(select(Finding)).all()
        total = len(findings)
        for idx, f in enumerate(findings, 1):
            if progress:
                progress(idx, total, f.name or f.cve or "")
            try:
                selected = json.loads(f.regulatory_clauses) if f.regulatory_clauses else []
            except (ValueError, TypeError):
                selected = []
            if not isinstance(selected, list):
                selected = []
            asset = assets.get(f.asset_id)
            for fs in session.exec(
                select(FindingScore).where(FindingScore.finding_id == f.id)
            ).all():
                new_sev, new_score, _ = compute_fw_adj(
                    fs.base_severity, fs.adj_severity, fs.adj_score, selected, asset, framework
                )
                if fs.cvss_version == "3.1":  # count once per finding, on the default layer
                    prev = fs.fw_adj_severity or fs.adj_severity
                    if _idx(new_sev) > _idx(prev):
                        stats["raised"] += 1
                    elif _idx(new_sev) < _idx(prev):
                        stats["lowered"] += 1
                    else:
                        stats["unchanged"] += 1
                fs.fw_adj_severity = new_sev
                fs.fw_adj_score = new_score
                session.add(fs)
        session.commit()
    return stats
