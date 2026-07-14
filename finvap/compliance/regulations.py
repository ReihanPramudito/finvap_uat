"""Parse the regulation PDFs into citable clauses (Objective 1 RAG corpus).

Each framework has a different layout, confirmed against the real documents:

  * MAS TRM (mas-trm-2021.pdf): numbered clauses ``3.1.1`` under ``3``/``3.1``
    headings; every page repeats a "Monetary Authority of Singapore" footer.
    Guidelines use "should" — no binding marker.

  * BNM RMiT (pd-rmit-nov25.pdf): each paragraph is prefixed ``S`` (Standard =
    binding "must") or ``G`` (Guidance), e.g. ``S 10.57 ...``; bare Title-Case
    lines (e.g. "Access Control") act as section headings; pages repeat a
    "Risk Management in Technology ... of 80" / "Issued on:" header.

We keep one chunk per clause so every retrieval cites a real, verifiable clause
ID. The clause text is the clause line plus its continuation/sub-bullet lines.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import pypdf

from ..config import REGULATIONS_DIR

FRAMEWORKS = ("rmit", "trm")
_FILENAMES = {"rmit": "pd-rmit-nov25.pdf", "trm": "mas-trm-2021.pdf"}


@dataclass
class Clause:
    framework: str          # "rmit" | "trm"
    clause_id: str          # "3.1.1" | "10.57"
    section: str            # section heading (best-effort)
    binding: str            # "S" | "G" | ""  (RMiT only)
    text: str               # clause line + continuations, whitespace-collapsed

    @property
    def citation(self) -> str:
        tag = f"{self.binding} " if self.binding else ""
        return f"{self.framework.upper()} {tag}{self.clause_id}".strip()


def regulation_path(framework: str) -> Path:
    return REGULATIONS_DIR / _FILENAMES[framework]


def _pages_text(path: Path) -> list[str]:
    reader = pypdf.PdfReader(str(path))
    return [(p.extract_text() or "") for p in reader.pages]


def _norm(lines: list[str]) -> str:
    return re.sub(r"\s+", " ", " ".join(lines)).strip()


# --- MAS TRM ---------------------------------------------------------------
_TRM_DROP = re.compile(r"^(technology risk management guidelines|monetary authority of singapore)", re.I)
_TRM_CLAUSE = re.compile(r"^(\d+\.\d+\.\d+)\s+(.*)")
# A heading is a short Title-Case line standing alone — not a wrapped clause
# sentence that happens to begin "6.1 ...". Bound the length and forbid the
# mid-sentence punctuation (".", ":", ";") that marks running prose.
_TRM_SUBSEC = re.compile(r"^\d+\.\d+\s+([A-Z][A-Za-z0-9 &/,'()-]{1,58})$")
_TRM_SECTION = re.compile(r"^\d+\s+([A-Z][A-Za-z0-9 &/,'()-]{1,58})$")


def parse_trm(path: Path) -> list[Clause]:
    clauses: list[Clause] = []
    section = ""
    cur_id: str | None = None
    buf: list[str] = []

    def flush():
        nonlocal cur_id
        if cur_id and buf:
            text = _norm(buf)
            if len(text) > 15:  # drop TOC stubs / page-number fragments
                clauses.append(Clause("trm", cur_id, section, "", text))
        cur_id = None
        buf.clear()

    for page in _pages_text(path):
        for raw in page.split("\n"):
            line = raw.strip()
            if not line or _TRM_DROP.match(line):
                continue
            m = _TRM_CLAUSE.match(line)
            if m:
                flush()
                cur_id, _ = m.group(1), buf.append(m.group(2))
                continue
            # A section/subsection heading ends the current clause and renames
            # the section. These appear between clauses throughout the document,
            # so we must detect them even while a clause is open — otherwise the
            # section stays frozen at the first heading for every clause.
            sub = _TRM_SUBSEC.match(line)
            sec = _TRM_SECTION.match(line)
            if sub:
                flush()
                section = sub.group(1).strip()
                continue
            if sec:
                flush()
                section = sec.group(1).strip()
                continue
            if cur_id is not None:
                buf.append(line)
    flush()
    return clauses


# --- BNM RMiT --------------------------------------------------------------
_RMIT_DROP = re.compile(r"^(risk management in technology|issued on:|the rest of the page)", re.I)
_RMIT_CLAUSE = re.compile(r"^([SG])\s+(\d+\.\d+[a-z]?)\s+(.*)")
_RMIT_HEADING = re.compile(r"^[A-Z][A-Za-z][A-Za-z &/,'-]{1,48}$")  # short Title-Case line


def parse_rmit(path: Path) -> list[Clause]:
    clauses: list[Clause] = []
    section = ""
    cur: tuple[str, str] | None = None  # (binding, id)
    buf: list[str] = []
    prev_blank = True

    def flush():
        nonlocal cur
        if cur and buf:
            clauses.append(Clause("rmit", cur[1], section, cur[0], _norm(buf)))
        cur = None
        buf.clear()

    for page in _pages_text(path):
        for raw in page.split("\n"):
            line = raw.strip()
            if not line:
                prev_blank = True
                continue
            if _RMIT_DROP.match(line):
                continue
            m = _RMIT_CLAUSE.match(line)
            if m:
                flush()
                cur = (m.group(1), m.group(2))
                buf.append(m.group(3))
                prev_blank = False
                continue
            # A heading is a short Title-Case line standing alone (blank before),
            # not a sub-bullet "(a)"; it ends the current clause and renames the section.
            if prev_blank and not line.startswith("(") and _RMIT_HEADING.match(line):
                flush()
                section = line
            elif cur:
                buf.append(line)
            prev_blank = False
    flush()
    return clauses


def load_clauses(framework: str) -> list[Clause]:
    path = regulation_path(framework)
    if not path.exists():
        raise FileNotFoundError(
            f"{framework.upper()} document not found at {path}. "
            "Place the regulation PDF there (see README)."
        )
    return parse_rmit(path) if framework == "rmit" else parse_trm(path)
