"""Objective 4: report generation + export.

Fills an operator-authored Word (`.docx`) template with the assessment — grouped
by vulnerability, regulatory-adjusted severity, cited clauses and the two-tier
remediation SLA. Identifiers are masked before any LLM call (S1); scores, CVEs,
clauses and deadlines are rendered verbatim, and the LLM writes only prose
(executive summary + per-finding description/recommendation), grounded on the
facts. Output is the filled DOCX (the editable artifact) plus a PDF.

Public API:
  fill_template(...)    -- fill a template from the DB -> DOCX + PDF.
  resolve_template(...) -- locate the template (explicit -> config -> bundled default).
  get_provider(...)     -- build an LLMProvider (ollama|openai|anthropic|template).
  Masker                -- PII masking with a local placeholder->real map.
"""
from .docx_template import TemplateError
from .docx_template import fill as fill_template
from .docx_template import resolve_template
from .masking import Masker
from .prose import rewrite_findings
from .providers import LLMError, get_provider

__all__ = [
    "fill_template",
    "resolve_template",
    "rewrite_findings",
    "TemplateError",
    "get_provider",
    "Masker",
    "LLMError",
]
