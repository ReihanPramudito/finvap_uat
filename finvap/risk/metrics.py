"""Asset context tags -> CVSS environmental metrics (the defensible core of Obj 3).

Each mapping is grounded in a published standard so the scoring can be justified
(viva / audit), not hand-waved:

  * data_sensitivity -> Confidentiality/Integrity Requirement (CR/IR)
        FIPS 199 / NIST SP 800-60 information-impact levels.
  * criticality      -> Availability Requirement (AR), and raises the CR/IR floor
        FIPS 199 availability impact; a mission-critical host can't be "low".
  * exposure         -> Modified Attack Vector (MAV)
        CVSS v3.1/v4.0 spec: an internal-only host is less reachable, so the
        attack vector is stepped down one level; we never inflate it above base.
  * environment      -> ceiling on CR/IR/AR
        a non-production tier can't carry full real-world requirements, which also
        stops it double-counting with criticality.

The *same* explicit CR/IR/AR values are emitted for both CVSS versions; each
spec then interprets them natively (3.1 default = Medium, so High amplifies above
base; 4.0 default = High, so the tags can only hold-at-base or de-amplify). See
docs/SCORING.md.
"""
from __future__ import annotations

from ..models import Asset, Exposure

# Ordered low -> high so we can take floors (max) and ceilings (min) on levels.
_ORDER = {"L": 0, "M": 1, "H": 2}
_LEVEL = {0: "L", 1: "M", 2: "H"}

# data_sensitivity -> (CR, IR). Confidentiality dominates for sensitive data;
# The grounded NIST defaults for every tag option, as plain strings so they
# round-trip through finvap.config.json. This is the single source of truth for
# the tag -> CVSS effect; the web Risk-model page overrides individual leaves and
# settings.effective_tag_effects() merges the overrides back over these defaults.
#   data_sensitivity option -> {CR, IR}   (confidentiality/integrity requirement)
#   criticality      option -> {AR, floor} (availability req + a CR/IR floor)
#   environment      option -> ceiling level on CR/IR/AR
#   exposure                -> internal_av_steps (how far to step the AV down)
DEFAULT_TAG_EFFECTS: dict = {
    "data_sensitivity": {
        "public":       {"CR": "L", "IR": "L"},
        "internal":     {"CR": "L", "IR": "M"},
        "confidential": {"CR": "M", "IR": "M"},
        "pii":          {"CR": "H", "IR": "M"},
        "financial":    {"CR": "H", "IR": "H"},
    },
    "criticality": {
        "low":      {"AR": "L", "floor": "L"},
        "medium":   {"AR": "M", "floor": "M"},
        "high":     {"AR": "H", "floor": "H"},
        "critical": {"AR": "H", "floor": "H"},
    },
    "environment": {
        "production": "H", "staging": "M", "uat": "M", "development": "L",
    },
    "exposure": {"internal_av_steps": 1},
}

# Modified Attack Vector, stepped one level *down* in reachability (N>A>L>P).
_AV_REDUCE_ONE = {"N": "A", "A": "L", "L": "P", "P": "P"}


def _effective_tag_effects() -> dict:
    """The merged (defaults + operator overrides) tag-effect table. Lazily pulls
    the merge from :mod:`finvap.settings` so metrics.py stays import-cycle free
    and still works if settings is unavailable (falls back to the defaults)."""
    try:
        from .. import settings
        return settings.effective_tag_effects()
    except Exception:      # never let a config problem break scoring
        return DEFAULT_TAG_EFFECTS

_SEVERITY_BANDS = [(9.0, "Critical"), (7.0, "High"), (4.0, "Medium"), (0.1, "Low")]


def band(score: float | None) -> str | None:
    """Uniform severity band used for every score layer (base and adjusted)."""
    if score is None:
        return None
    for threshold, label in _SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "None"


def _max(a: str, b: str) -> str:
    return _LEVEL[max(_ORDER[a], _ORDER[b])]


def _min(a: str, b: str) -> str:
    return _LEVEL[min(_ORDER[a], _ORDER[b])]


def environmental_metrics(asset: Asset, base_av: str) -> tuple[dict[str, str], list[str]]:
    """Build the {CR, IR, AR[, MAV]} environmental metrics for an asset.

    Returns (metrics, reasons) where reasons is a cited, plain-English list for
    ``--explain``. ``base_av`` is the Attack Vector of the (target-version) base
    vector, needed to step MAV down without inflating it past base.
    """
    eff = _effective_tag_effects()
    ds = eff["data_sensitivity"][asset.data_sensitivity.value]
    cr0, ir0 = ds["CR"], ds["IR"]
    cc = eff["criticality"][asset.criticality.value]
    ar0, floor = cc["AR"], cc["floor"]
    ceiling = eff["environment"][asset.environment.value]
    steps = max(0, int(eff.get("exposure", {}).get("internal_av_steps", 1)))

    # criticality raises the CR/IR floor ...
    cr_f, ir_f, ar_f = _max(cr0, floor), _max(ir0, floor), ar0
    # ... then the environment tier caps everything.
    cr, ir, ar = _min(cr_f, ceiling), _min(ir_f, ceiling), _min(ar_f, ceiling)

    metrics = {"CR": cr, "IR": ir, "AR": ar}
    reasons = [
        f"data_sensitivity={asset.data_sensitivity.value} -> CR:{cr0}, IR:{ir0} "
        "(FIPS 199 / SP 800-60 information impact)",
        f"criticality={asset.criticality.value} -> AR:{ar0}, CR/IR floor {floor} "
        "(FIPS 199 availability)",
    ]
    # Only report the ceiling when it actually lowered a requirement, so --explain
    # never claims a cap that didn't bite.
    if (cr, ir, ar) != (cr_f, ir_f, ar_f):
        reasons.append(
            f"environment={asset.environment.value} -> caps requirements at {ceiling} "
            f"(non-production) => CR:{cr}, IR:{ir}, AR:{ar}"
        )

    if asset.exposure == Exposure.internal:
        mav = base_av
        for _ in range(steps):
            mav = _AV_REDUCE_ONE[mav]
        if mav != base_av:
            metrics["MAV"] = mav
            reasons.append(
                f"exposure=internal -> MAV:{mav} (not internet-facing; attack "
                f"vector stepped down {steps} level(s) from base AV:{base_av})"
            )
        else:
            reasons.append(
                f"exposure=internal -> AV:{base_av} left unchanged "
                + ("(step-down disabled)" if steps == 0 else "(already minimal)")
            )
    else:
        reasons.append(
            f"exposure=external -> AV kept at base AV:{base_av} (worst-case reachability)"
        )

    return metrics, reasons


def append_metrics(base_vector: str, metrics: dict[str, str]) -> str:
    """Append environmental metrics to a base vector (preserves metric order)."""
    suffix = "/".join(f"{k}:{v}" for k, v in metrics.items())
    return f"{base_vector}/{suffix}" if suffix else base_vector
