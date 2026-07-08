"""LLM rewrite of each finding's description + recommendation, **persisted** to
the DB (a pipeline step, not a report-time transform).

Running this before the UI/report means the AI prose is stored on the finding, so
the operator can review and edit it and the report renders the final text. Grounded
on the scanner text, masked + audited (S1). Findings whose text has been finalised
(``text_overridden`` — a manual edit) are left untouched so an edit isn't clobbered;
the report reads the stored ``description``/``solution`` verbatim.
"""
from __future__ import annotations

import json
import re
import time

from sqlmodel import select

from .. import audit
from ..db import get_session
from ..models import Asset, Finding
from .docx_template import _SYS_FINDING  # reuse the same finding-prose system prompt
from .masking import Masker
from .providers import LLMError, get_provider


def rewrite_findings(provider: str | None = None, model: str | None = None,
                     progress=None) -> dict:
    """Rewrite + save description/recommendation for every finding (grouped by name,
    one LLM call per distinct vuln, applied to all its instances). Returns a stats
    dict. No-op without an LLM (keeps the scanner text)."""
    prov = get_provider(provider, model)
    stats = {"rewritten": 0, "skipped_override": 0, "skipped_empty": 0, "no_llm": 0}
    ok, _ = prov.available()
    if not ok or prov.name == "template":
        stats["no_llm"] = 1
        audit.record("report.prose", target="finding_prose",
                     summary="per-finding prose: kept scanner text (no LLM)")
        return stats

    with get_session() as s:
        masker = Masker()
        for a in s.exec(select(Asset)).all():
            masker.register_asset(a.ip_address, a.hostname)

        by_name: dict[str, list[Finding]] = {}
        for f in s.exec(select(Finding)).all():
            by_name.setdefault(f.name, []).append(f)

        total = len(by_name)
        for i, (name, group) in enumerate(by_name.items(), 1):
            if any(f.text_overridden for f in group):    # a human finalised it
                stats["skipped_override"] += 1
                continue
            rep = group[0]
            if not (rep.description or rep.solution):
                stats["skipped_empty"] += 1
                continue
            if progress:
                progress(i, total, (name or "")[:60])
            user = (f"DESCRIPTION:\n{masker.mask(rep.description or '(none)')}\n\n"
                    f"REMEDIATION:\n{masker.mask(rep.solution or '(none)')}")
            t0 = time.time()
            try:
                out = prov.complete(_SYS_FINDING, user, max_tokens=500)
            except LLMError as e:
                audit.record("llm.call", target=f"finding:{name[:40]}", status="error",
                             summary=f"{prov.name} finding rewrite failed: {e}",
                             duration_ms=int((time.time() - t0) * 1000))
                continue  # keep the raw scanner text
            audit.ai_call(stage="finding_prose", provider=prov.name,
                          model=getattr(prov, "model", ""), system=_SYS_FINDING,
                          user_sent=user, response_raw=out or "",
                          placeholder_map=masker.map, response_unmasked=masker.unmask(out or ""),
                          duration_ms=int((time.time() - t0) * 1000))
            try:
                m = re.search(r"\{.*\}", out or "", re.S)
                data = json.loads(m.group(0)) if m else {}
            except (ValueError, TypeError):
                continue
            desc = masker.unmask(str(data.get("description") or "")).strip()
            rec = masker.unmask(str(data.get("recommendation") or "")).strip()
            if not (desc or rec):
                continue
            for f in group:
                if desc:
                    f.description = desc
                if rec:
                    f.solution = rec
                s.add(f)
            stats["rewritten"] += 1
        s.commit()
    return stats
