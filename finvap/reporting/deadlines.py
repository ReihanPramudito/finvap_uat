"""Remediation-deadline policy (Objective 4).

RMiT **S 10.18(b)** and MAS TRM **7.4.1** *require* a severity-based patch
turnaround but **prescribe no numbers** — the timeframe is the institution's
risk-based policy. So FinVAP ships a sensible **default SLA** that is fully
user-editable (`finvap config sla`) and can be switched off entirely
(`--no-deadlines`). Deadlines are computed from the regulatory-adjusted severity
and the asset's exposure, and each cites the clause that mandates *having* such a
policy — never presented as "the law says N days" (see docs/SCORING.md). All
values here are defaults, not law.

Two tiers per severity: internet-facing / critical assets get the shorter
turnaround, internal assets the longer one (the split RMiT/TRM expect when an
institution prioritises externally-reachable exposure).
"""
from __future__ import annotations

from datetime import date, timedelta

# Default SLA (days from assessment), per severity and exposure tier:
#   ext = internet-facing / critical assets (faster);  int = internal (slower).
# `ext` equals FinVAP's original single-tier defaults so unknown-exposure
# findings keep the stricter, safer turnaround. All user-editable, NOT law.
DEFAULT_SLA: dict[str, dict[str, int]] = {
    "Critical": {"ext": 7, "int": 14},
    "High": {"ext": 30, "int": 60},
    "Medium": {"ext": 90, "int": 180},
    "Low": {"ext": 180, "int": 365},
}
SEVERITIES = ["Critical", "High", "Medium", "Low"]  # Info has no hard number

# The clause that mandates a severity-based turnaround, per framework.
MANDATING_CLAUSE: dict[str, str] = {
    "rmit": "RMiT S 10.18(b)",
    "trm": "TRM 7.4.1",
}


def clause_for(framework: str | None) -> str:
    return MANDATING_CLAUSE.get((framework or "").lower(), "")


def merged_sla(overrides: dict | None = None) -> dict[str, dict[str, int]]:
    """Built-in two-tier SLA with any user overrides applied (deep copy — safe to mutate)."""
    out = {sev: dict(tiers) for sev, tiers in DEFAULT_SLA.items()}
    for sev, tiers in (overrides or {}).items():
        if sev in out and isinstance(tiers, dict):
            for tier in ("ext", "int"):
                v = tiers.get(tier)
                if isinstance(v, int) and v > 0:
                    out[sev][tier] = v
    return out


def _tier_for_exposure(exposure: str | None) -> str:
    """Map an asset's exposure to an SLA tier. Unknown -> ext (stricter, safer)."""
    return "int" if (exposure or "").lower() == "internal" else "ext"


def deadline_for(severity: str | None, *, exposure: str | None = None,
                 framework: str | None = None, assessed: date | None = None,
                 sla: dict | None = None) -> dict | None:
    """Return {days, due, basis, tier} for a severity+exposure, or None if unknown.

    `due` is ISO; `basis` cites the mandating clause + notes the SLA is a
    configurable policy default. `sla` is the two-tier table from :func:`merged_sla`.
    """
    sla = sla or merged_sla()
    if not severity or severity not in sla:
        return None
    tier = _tier_for_exposure(exposure)
    days = sla[severity][tier]
    assessed = assessed or date.today()
    clause = clause_for(framework)
    where = "internet-facing/critical" if tier == "ext" else "internal"
    basis = (f"{clause} requires a severity-based turnaround; "
             f"policy default for {severity} ({where}) = {days} days") if clause else \
            f"policy default for {severity} ({where}) = {days} days"
    return {"days": days, "due": (assessed + timedelta(days=days)).isoformat(),
            "basis": basis, "tier": tier}
