"""Objective 3: context-based risk scoring (CVSS adjusted by asset tags).

Public API:
  score_findings(...)  -- score the whole DB, persist FindingScore rows.
  score_one(...)       -- pure per-finding scoring (no DB), for tests/reuse.
  band(score)          -- uniform severity banding for any score layer.
"""
from .engine import SUPPORTED_VERSIONS, Layer, Scored, score_findings, score_one
from .metrics import band

__all__ = [
    "score_findings",
    "score_one",
    "band",
    "Layer",
    "Scored",
    "SUPPORTED_VERSIONS",
]
