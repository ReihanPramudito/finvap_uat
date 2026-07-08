"""Objective 1: RAG-based mapping of findings to regulatory clauses.

Public API:
  load_clauses(framework)         -- parse a regulation PDF into Clause objects.
  store.build_index / store.query -- persist/search the clause vector store.
  map_findings(...)               -- map findings to clauses + compute fw_adj.
  compute_fw_adj(...)             -- pure framework-adjusted banding (for tests).
  normalize_citation(text)        -- consistent clause-reference casing (RMIT -> RMiT).
"""
import re

from . import store
from .mapping import compute_fw_adj, finding_query, map_findings
from .regulations import FRAMEWORKS, Clause, load_clauses

_CITE_CASE = re.compile(r"\bRMIT\b")


def normalize_citation(text: str) -> str:
    """Normalise clause-reference casing for display (source data has 'RMIT'; the
    house style is 'RMiT'). TRM is already correct."""
    return _CITE_CASE.sub("RMiT", text or "")


__all__ = [
    "store",
    "map_findings",
    "compute_fw_adj",
    "finding_query",
    "load_clauses",
    "normalize_citation",
    "Clause",
    "FRAMEWORKS",
]
