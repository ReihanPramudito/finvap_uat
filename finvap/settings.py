"""Operator preferences (framework, CVSS version, LLM provider/model, offline,
report template) plus the remediation-SLA and tag-effect overrides.

A tiny JSON store at the project root (`finvap.config.json`), edited from the web
**Setup** / **Risk-model** / **Report** pages, that the scoring, mapping and
reporting engine reads. It is read from :mod:`finvap.config` at call time so it
survives a project switch and tests can redirect it. Preferences only — never
secrets (API keys live in `finvap.secrets.json`).
"""
from __future__ import annotations

import copy
import json

from . import config

# The settable keys, with type, choices, built-in default, label and a one-line
# explanation (shown by `finvap config --verbose` / `finvap config show -v`).
KEYS: list[dict] = [
    {"key": "framework", "type": "choice", "choices": ["rmit", "trm"], "default": "rmit",
     "label": "Regulatory framework",
     "help": "Which regulation findings are mapped against and cited in the report — "
             "BNM RMiT (Malaysia) or MAS TRM (Singapore)."},
    {"key": "cvss", "type": "choice", "choices": ["3.1", "4.0"], "default": "3.1",
     "label": "CVSS version",
     "help": "CVSS version used to score and display risk. 3.1 lets high-value assets "
             "amplify above the base score; 4.0 holds the worst case and only de-amplifies."},
    {"key": "provider", "type": "choice",
     "choices": ["ollama", "openai", "anthropic", "template"], "default": "ollama",
     "label": "LLM provider",
     "help": "Which LLM re-ranks regulatory clauses and writes the report prose. "
             "ollama = local & private (default); openai/anthropic = cloud (needs an API "
             "key — data leaves the host); template = no LLM (mapping can't run)."},
    {"key": "model", "type": "model", "default": "",
     "label": "LLM model id",
     "help": "Model id for the chosen provider (e.g. granite3.3:8b, gpt-4o-mini, "
             "claude-sonnet-4-6). Leave blank to use the provider's default."},
    # No longer surfaced in the UI: scoring always uses the online NVD and falls
    # back to scan-native/derived vectors at runtime if it's unreachable. Kept as an
    # internal default (and a knob the test suite can flip to stay off the network).
    {"key": "offline", "type": "bool", "default": False,
     "label": "Offline scoring",
     "help": "Skip NVD online lookups when scoring (use scan-native + derived vectors "
             "only). Internal default — scoring is always online with a runtime fallback."},
    {"key": "template", "type": "str", "default": "",
     "label": "Report template (.docx)",
     "help": "A custom Word template in templates/ to fill (e.g. 'VA Template.docx'). "
             "Blank = the bundled default template. Engagement/client details are "
             "collected on the Report page."},
]

_DEFAULTS = {k["key"]: k["default"] for k in KEYS}
_VALID = {k["key"]: set(k["choices"]) for k in KEYS if k["type"] == "choice"}


def path():
    return config.USER_CONFIG_PATH


def _read_all() -> dict:
    """The whole config file (preferences + the `sla` block); {} if absent/bad."""
    p = path()
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_all(data: dict) -> None:
    path().write_text(json.dumps(data, indent=2))


def load() -> dict:
    """Only the *saved* preferences (keys the user set); {} if none."""
    return {k: v for k, v in _read_all().items() if k in _DEFAULTS}


def save(values: dict) -> None:
    """Persist the preference keys, preserving any other block (e.g. `sla`)."""
    data = _read_all()
    data.update({k: values[k] for k in _DEFAULTS if k in values})
    _write_all(data)


def reset() -> bool:
    """Clear saved preferences (keep the `sla` block). True if anything was cleared."""
    data = _read_all()
    pref = {k for k in data if k in _DEFAULTS}
    if not pref:
        return False
    for k in pref:
        del data[k]
    if data:
        _write_all(data)
    else:
        path().unlink()
    return True


# --- Remediation SLA (two-tier deadline policy, edited via `finvap config sla`) ---

def load_sla() -> dict:
    """User overrides of the two-tier remediation SLA ({sev: {ext, int}}); {} if none."""
    sla = _read_all().get("sla")
    return sla if isinstance(sla, dict) else {}


def save_sla(sla: dict) -> None:
    """Persist the SLA overrides, preserving the preference keys."""
    data = _read_all()
    data["sla"] = sla
    _write_all(data)


def reset_sla() -> bool:
    """Clear SLA overrides (revert to the built-in policy default). True if removed."""
    data = _read_all()
    if "sla" not in data:
        return False
    del data["sla"]
    if data:
        _write_all(data)
    else:
        path().unlink()
    return True


def effective() -> dict:
    """Built-in defaults overlaid with saved values — for display in `config show`."""
    out = dict(_DEFAULTS)
    out.update(load())
    return out


# --- Tag -> CVSS effect overrides (edited via the web Risk-model page) ---------
# A `tag_effects` block holding ONLY the leaves the operator changed from the
# grounded NIST defaults (in risk/metrics.DEFAULT_TAG_EFFECTS), so "reset" = drop
# the block and a value "differs from default" iff it appears here.

def load_tag_effects() -> dict:
    """The saved tag-effect overrides ({} if the operator hasn't changed any)."""
    te = _read_all().get("tag_effects")
    return te if isinstance(te, dict) else {}


def save_tag_effects(overrides: dict) -> None:
    """Persist the tag-effect overrides, preserving the other blocks. An empty
    dict removes the block (back to the grounded defaults)."""
    data = _read_all()
    if overrides:
        data["tag_effects"] = overrides
    else:
        data.pop("tag_effects", None)
    if data:
        _write_all(data)
    elif path().exists():
        path().unlink()


def reset_tag_effects() -> bool:
    """Drop all tag-effect overrides (revert to NIST defaults). True if removed."""
    data = _read_all()
    if "tag_effects" not in data:
        return False
    del data["tag_effects"]
    if data:
        _write_all(data)
    else:
        path().unlink()
    return True


def _merge_tag_effects(defaults: dict, ov: dict) -> dict:
    """Deep-overlay the override leaves onto a copy of the defaults."""
    out = copy.deepcopy(defaults)
    for tag in ("data_sensitivity", "criticality"):
        for opt, vals in (ov.get(tag) or {}).items():
            if opt in out[tag] and isinstance(vals, dict):
                for k, v in vals.items():
                    if k in out[tag][opt]:
                        out[tag][opt][k] = v
    for opt, val in (ov.get("environment") or {}).items():
        if opt in out["environment"]:
            out["environment"][opt] = val
    exp = ov.get("exposure") or {}
    if "internal_av_steps" in exp:
        out["exposure"]["internal_av_steps"] = exp["internal_av_steps"]
    return out


def effective_tag_effects() -> dict:
    """The NIST defaults overlaid with the operator's overrides — what scoring uses."""
    from .risk.metrics import DEFAULT_TAG_EFFECTS
    return _merge_tag_effects(DEFAULT_TAG_EFFECTS, load_tag_effects())
