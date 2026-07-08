"""Tests for the operator-preferences store (`finvap.config.json`).

The web Setup / Risk-model / Report pages read and write this store; the scoring,
mapping and reporting engine reads it. `conftest` redirects
`config.USER_CONFIG_PATH` to a temp file per test.
"""
from finvap import settings as user_settings


# --- preferences store ------------------------------------------------------

def test_load_save_reset_round_trip():
    assert user_settings.load() == {}                       # nothing saved yet
    user_settings.save({"framework": "trm", "cvss": "4.0", "junk": "ignored"})
    saved = user_settings.load()
    assert saved == {"framework": "trm", "cvss": "4.0"}     # unknown keys dropped
    assert user_settings.reset() is True
    assert user_settings.load() == {} and user_settings.reset() is False


def test_effective_overlays_defaults():
    user_settings.save({"framework": "trm"})
    eff = user_settings.effective()
    assert eff["framework"] == "trm"          # saved
    assert eff["cvss"] == "3.1"               # default


def test_offline_and_template_persist():
    """The two settings the web Setup page exposes (once CLI `config` was removed)."""
    user_settings.save({"offline": True, "template": "VA Template.docx"})
    saved = user_settings.load()
    assert saved["offline"] is True and saved["template"] == "VA Template.docx"


# --- remediation SLA (web Report page) --------------------------------------

def test_sla_save_load_reset():
    assert user_settings.load_sla() == {}
    sla = {"Critical": {"ext": 7, "int": 14}}
    user_settings.save_sla(sla)
    assert user_settings.load_sla() == sla
    # SLA lives alongside preferences without clobbering them.
    user_settings.save({"framework": "trm"})
    assert user_settings.load_sla() == sla and user_settings.load()["framework"] == "trm"
    assert user_settings.reset_sla() is True
    assert user_settings.load_sla() == {} and user_settings.reset_sla() is False


# --- tag-effect overrides (Risk-model page) — merge over the grounded defaults

def test_tag_effects_save_load_reset_and_merge():
    from finvap.risk.metrics import DEFAULT_TAG_EFFECTS
    assert user_settings.load_tag_effects() == {}
    assert user_settings.effective_tag_effects() == DEFAULT_TAG_EFFECTS  # no overrides
    user_settings.save_tag_effects({"data_sensitivity": {"financial": {"IR": "M"}},
                                    "environment": {"staging": "H"},
                                    "exposure": {"internal_av_steps": 2}})
    eff = user_settings.effective_tag_effects()
    assert eff["data_sensitivity"]["financial"] == {"CR": "H", "IR": "M"}  # only IR changed
    assert eff["data_sensitivity"]["pii"] == {"CR": "H", "IR": "M"}        # untouched option
    assert eff["environment"]["staging"] == "H" and eff["exposure"]["internal_av_steps"] == 2
    # defaults are never mutated by the merge
    assert DEFAULT_TAG_EFFECTS["data_sensitivity"]["financial"] == {"CR": "H", "IR": "H"}
    assert user_settings.reset_tag_effects() is True
    assert user_settings.load_tag_effects() == {}
    assert user_settings.reset_tag_effects() is False
