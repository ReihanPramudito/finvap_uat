"""LLM re-ranking over RAG-retrieved candidate clauses (Objective 1).

Embedding similarity alone couldn't bridge the technical->governance gap (scores
clustered 0.15-0.33 and mis-ranked relevant clauses below irrelevant ones). So
RAG now retrieves a *candidate set* of real clauses and a local LLM (Granite by
default) selects the one(s) a finding genuinely implicates, or none.

Anti-hallucination is preserved: the model may only choose from the supplied
candidates, so every citation is a real, verifiable clause id — it can never
invent regulation. Verdicts are cached per (framework, finding, candidate set,
model) so re-runs are instant and reproducible, and the call uses temperature 0.
"""
from __future__ import annotations

import hashlib
import json
import re
import time

from .. import audit, config
from ..reporting.providers import get_provider

CACHE_DIR = config.DATA_DIR / "map_cache"

# Bump when the prompt/logic changes so cached verdicts are recomputed.
# v3: finding text is masked before the call (same masking as the report path)
# and the call is logged with a leak-check.
# v4: the model gives a per-clause reason (why *that* clause applies), not one
# shared reason across all cited clauses.
_PROMPT_VERSION = "4"

_SYSTEM = (
    "You are a senior financial-sector cybersecurity compliance analyst. You map a "
    "technical vulnerability finding to the specific regulatory clause(s) it directly "
    "implicates. Be strict and conservative: select a clause ONLY if the finding is an "
    "actual control FAILURE that the clause governs - e.g. missing or weak encryption, "
    "cleartext credentials, weak cryptographic algorithms, default/weak credentials, "
    "missing security patches, or missing access control. "
    "Distinguish such control failures from mere reconnaissance or information "
    "disclosure: findings like ICMP/TCP timestamps, traceroute, open-port or service "
    "banners, or 'supported protocol/version' disclosures merely reveal configuration "
    "and do NOT themselves breach a specific regulatory control - select none for these. "
    "You may ONLY choose from the numbered candidate clauses provided; never invent or "
    "cite anything else. Respond with JSON only."
)


def _finding_detail(finding) -> str:
    parts = [finding.summary, finding.solution, finding.impact]
    return " ".join(p for p in parts if p).strip()[:400]


def _build_prompt(finding, candidates, mask=lambda s: s) -> str:
    # Candidate clauses are public regulation text (no client data), so they are
    # not masked; the finding's name/detail are masked (``mask``) before sending.
    lines = [
        f"[{i}] {c['citation']} ({c['section']}): {(c.get('text') or '')[:200].strip()}"
        for i, c in enumerate(candidates, 1)
    ]
    return (
        f"FINDING: {mask(finding.name)}\n"
        f"DETAIL: {mask(_finding_detail(finding))}\n\n"
        "CANDIDATE CLAUSES (choose only from these, by exact id):\n"
        + "\n".join(lines)
        + "\n\nReturn ONLY JSON: {\"selected\": [{\"id\": \"<exact clause id>\", "
        "\"reason\": \"<one short sentence on why THIS clause specifically applies to "
        "the finding>\"}, ...]}. Give a distinct reason per clause. "
        "If none directly applies, return {\"selected\": [], \"reason\": \"<why none applies>\"}."
    )


def _parse(resp: str, candidate_ids: list[str]) -> tuple[list[str], dict[str, str], str]:
    """Map the model's reply onto real candidate ids, with a per-clause reason.

    Accepts both the current shape (``selected`` = list of {id, reason}) and the
    older shape (``selected`` = list of id strings + a single top-level ``reason``).
    Returns (chosen ids in order, {id: reason}, overall-reason)."""
    m = re.search(r"\{.*\}", resp or "", re.DOTALL)
    if not m:
        return [], {}, "model returned no parsable selection"
    try:
        data = json.loads(m.group(0))
    except json.JSONDecodeError:
        return [], {}, "model returned malformed JSON"
    raw = data.get("selected") or []
    if isinstance(raw, (str, dict)):
        raw = [raw]
    overall = str(data.get("reason") or "").strip()  # top-level / no-match reason
    chosen: list[str] = []
    reasons: dict[str, str] = {}
    for item in raw:
        if isinstance(item, dict):
            rid = str(item.get("id", "")).lower()
            rreason = str(item.get("reason") or "").strip()
        else:
            rid, rreason = str(item).lower(), ""
        # Flexible match: the model may echo an id with or without its section label.
        for cid in candidate_ids:
            if cid.lower() in rid or rid in cid.lower():
                if cid not in chosen:
                    chosen.append(cid)
                reasons[cid] = rreason or overall
                break
    return chosen, reasons, overall


def _cache_key(framework: str, finding, candidate_ids: list[str], model: str):
    raw = "|".join([_PROMPT_VERSION, framework, model, finding.name or ""] + sorted(candidate_ids))
    return CACHE_DIR / (hashlib.sha1(raw.encode()).hexdigest()[:16] + ".json")


def select_clauses(finding, candidates, *, framework: str, provider=None,
                   use_cache: bool = True, masker=None) -> tuple[list[dict], str]:
    """Pick the applicable clauses from the RAG candidates. Returns (clauses, reason).

    If a ``masker`` is given, the finding text is masked before it reaches the LLM
    (identical privacy treatment to the report path) and the call is logged with a
    leak-check. Raises whatever the provider raises (e.g. LLMError) if the model is
    unreachable — mapping now depends on the LLM, so the caller surfaces it.
    """
    if not candidates:
        return [], "no candidate clauses retrieved"
    prov = provider or get_provider()
    model = getattr(prov, "model", prov.name)
    ids = [c["citation"] for c in candidates]
    key = _cache_key(framework, finding, ids, model)
    if use_cache and key.exists():
        try:
            cached = json.loads(key.read_text())
            reasons = cached.get("reasons", {})
            sel = [dict(c, reason=reasons.get(c["citation"], cached.get("reason", "")))
                   for c in candidates if c["citation"] in cached.get("selected", [])]
            return sel, cached.get("reason", "")
        except json.JSONDecodeError:
            pass  # corrupt cache entry -> recompute

    mask = masker.mask if masker is not None else (lambda s: s)
    prompt = _build_prompt(finding, candidates, mask)
    t0 = time.time()
    resp = prov.complete(_SYSTEM, prompt, max_tokens=400, temperature=0.0)
    chosen_ids, reasons, overall = _parse(resp, ids)
    if masker is not None:
        reasons = {cid: masker.unmask(r) for cid, r in reasons.items()}  # restore placeholders
        overall = masker.unmask(overall)
        audit.ai_call(
            stage="clause_rerank", provider=prov.name, model=model,
            system=_SYSTEM, user_sent=prompt, response_raw=resp,
            placeholder_map=masker.map, response_unmasked=masker.unmask(resp),
            command="map", duration_ms=int((time.time() - t0) * 1000),
            extra={"selected": chosen_ids, "candidates": len(candidates)},
        )
    # Each cited clause carries its own reason; `overall` is for the audit summary/CLI.
    sel = [dict(c, reason=reasons.get(c["citation"], "")) for c in candidates
           if c["citation"] in chosen_ids]
    combined = "; ".join(dict.fromkeys(r for r in reasons.values() if r)) or overall
    if use_cache:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        key.write_text(json.dumps(
            {"selected": chosen_ids, "reasons": reasons, "reason": combined}))
    return sel, combined
