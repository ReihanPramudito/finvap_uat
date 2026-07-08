"""Engagement metadata — the people/organisation details a report template needs
that FinVAP cannot derive from a scan (Objective 4, custom `.docx` templates / S3).

These are the values behind the template's built-in Word **Document Properties**
(client/company names, author, reviewer, client PIC). The store is a tiny JSON
file at the project root (`finvap.engagement.json`, gitignored — it carries
client identifiers), read at report-fill time.

Only the **identity** fields live here. The assessment/draft dates change every
report, and the post-verification / final dates stay as template placeholders
until the verification round. The web Report page writes this store directly via
:func:`load`/:func:`save` — there is no CLI prompt flow.
"""
from __future__ import annotations

import json

from . import config

# Each key IS the template's Word Document Property name, so filling is a direct
# map (no translation table). Order = prompt order, grouped client → us → signoff.
KEYS: list[dict] = [
    {"key": "Client_Full_Name", "label": "Client full legal name",
     "help": "The assessed organisation's full name as it should appear on the cover."},
    {"key": "Client_Short_Name", "label": "Client short name",
     "help": "Abbreviation used throughout the report, e.g. the acronym."},
    {"key": "Company_Full_Name", "label": "Your company full name",
     "help": "The assessing firm's full name (appears as the report author org)."},
    {"key": "Company_Short_Name", "label": "Your company short name",
     "help": "Abbreviation for the assessing firm."},
    {"key": "Author_Name", "label": "Author name",
     "help": "Who performed the assessment and wrote the report."},
    {"key": "Author_Title", "label": "Author title",
     "help": "The author's role, e.g. Security Consultant."},
    {"key": "Reviewer_Name", "label": "Reviewer name",
     "help": "Who QA'd / approved the report."},
    {"key": "Reviewer_Title", "label": "Reviewer title",
     "help": "The reviewer's role, e.g. Lead Consultant."},
    {"key": "Client_PIC_Name", "label": "Client contact (PIC) name",
     "help": "The client's person-in-charge who receives and accepts the report."},
    {"key": "Client_PIC_Title", "label": "Client contact (PIC) title",
     "help": "The client PIC's role, e.g. Head of IT Security."},
]

FIELDS = [k["key"] for k in KEYS]


def path():
    return config.ENGAGEMENT_PATH


def load() -> dict:
    """Saved identity values (only recognised keys); {} if none saved yet."""
    p = path()
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text())
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in data.items() if k in FIELDS and isinstance(v, str)}


def save(values: dict) -> None:
    """Persist the identity fields present in `values` (ignores unknown keys)."""
    path().write_text(json.dumps({k: values[k] for k in FIELDS if k in values}, indent=2))


def clear() -> bool:
    """Delete the saved metadata so the next run prompts afresh. True if removed."""
    p = path()
    if p.exists():
        p.unlink()
        return True
    return False


# --- Interactive collection (the CLI path; the Web UI will write load/save directly) ---

# Date properties prompted every run (they change each report), not stored.
DATE_KEYS: list[dict] = [
    {"key": "Date_Assessment", "label": "Assessment window (e.g. 01 Jun 2026 - 05 Jun 2026)"},
    {"key": "Date_DraftReport", "label": "Draft report date (e.g. 10 Jun 2026)"},
]


# Engagement identity + dates are collected on the web Report page, which writes
# this store directly via load()/save(); there is no CLI prompt flow.
