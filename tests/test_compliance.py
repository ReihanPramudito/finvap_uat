"""Unit tests for Objective 1 — regulatory mapping + framework-adjusted scoring.

The fw_adj tests are pure (no ChromaDB / no LLM / no network). Mapping relevance
is now judged by the LLM re-ranker upstream, so here a "mapping" just means the
LLM confirmed a clause applies; compute_fw_adj only decides the deterministic
severity move (Model 1). Clause-parser tests run against the real regulation PDFs
when present and skip cleanly otherwise.
"""
import re
from types import SimpleNamespace

import pytest

from finvap.compliance import compute_fw_adj, finding_query
from finvap.compliance.regulations import load_clauses, regulation_path
from finvap.models import Asset, Criticality, DataSensitivity, Environment, Exposure

# Asset profiles --------------------------------------------------------------
PAYMENT_GW = Asset(ip_address="10.0.0.1", criticality=Criticality.critical,
                   data_sensitivity=DataSensitivity.financial,
                   exposure=Exposure.external, environment=Environment.production)
HIGH_INTERNAL = Asset(ip_address="10.0.0.2", criticality=Criticality.high,
                      data_sensitivity=DataSensitivity.internal,
                      exposure=Exposure.internal, environment=Environment.production)
LOW_BOX = Asset(ip_address="10.0.0.3", criticality=Criticality.low,
                data_sensitivity=DataSensitivity.public,
                exposure=Exposure.internal, environment=Environment.uat)

# An LLM-selected clause is, by definition, relevant — so fixtures only vary the
# binding type (S = Standard/binding, G = Guidance) which gates the RMiT raise.
BINDING = [{"binding": "S"}]
GUIDANCE = [{"binding": "G"}]


def _sev(base, adj, score, mappings, asset, fw="rmit"):
    return compute_fw_adj(base, adj, score, mappings, asset, fw)[0]


# --- raises (bounded, single band, gated on BASE severity) ------------------
def test_base_medium_raises_one_band_to_high_on_payment_gateway():
    sev, score, reason = compute_fw_adj("Medium", "Medium", 5.5, BINDING, PAYMENT_GW, "rmit")
    assert sev == "High"
    assert score >= 7.0          # score floored into the High band
    assert "raised" in reason


def test_high_to_critical_needs_strict_gate():
    assert _sev("High", "High", 7.5, BINDING, PAYMENT_GW, "rmit") == "Critical"


def test_rmit_raise_needs_binding_not_guidance():
    # A Guidance (G) clause must not trigger the RMiT raise.
    assert _sev("High", "High", 7.5, GUIDANCE, PAYMENT_GW, "rmit") == "High"


def test_trm_raise_uses_any_selected_clause():
    # TRM has no S/G markers, so any LLM-selected clause on a critical/financial asset qualifies.
    assert _sev("High", "High", 7.5, GUIDANCE, PAYMENT_GW, "trm") == "Critical"


def test_high_value_by_criticality_caps_at_high():
    # high criticality (internal data) is high-value -> Medium becomes High, not Critical.
    assert _sev("Medium", "Medium", 5.0, BINDING, HIGH_INTERNAL, "rmit") == "High"


def test_low_base_mapped_is_not_inflated():
    # The weak-SSH-MAC case: base Low, context-bumped to Medium, mapped to a binding
    # crypto clause on a payment gateway -> must STAY Medium, never jump to High.
    assert _sev("Low", "Medium", 4.4, BINDING, PAYMENT_GW, "rmit") == "Medium"


def test_low_value_asset_mapped_is_held():
    assert _sev("Medium", "Medium", 5.0, BINDING, LOW_BOX, "rmit") == "Medium"


# --- drops (de-prioritise unmapped noise, guarded) --------------------------
def test_no_match_lowers_medium_to_low_even_on_payment_gateway():
    # The timestamp case: no applicable clause -> de-prioritised, regardless of asset value.
    sev, score, reason = compute_fw_adj("Medium", "Medium", 5.5, [], PAYMENT_GW, "rmit")
    assert sev == "Low"
    assert score <= 3.9
    assert "lowered" in reason


def test_no_match_never_downgrades_high():
    assert _sev("High", "High", 7.5, [], LOW_BOX, "rmit") == "High"


def test_no_match_never_downgrades_critical():
    assert _sev("Critical", "Critical", 9.8, [], PAYMENT_GW, "rmit") == "Critical"


def test_low_floored_not_below_low():
    assert _sev("Low", "Low", 2.0, [], LOW_BOX, "rmit") == "Low"


def test_regulation_never_lowers_a_mapped_finding():
    # A mapped finding (even guidance-only) is never reduced below its environmental band.
    assert _sev("High", "High", 7.5, GUIDANCE, HIGH_INTERNAL, "rmit") == "High"


# --- query enrichment --------------------------------------------------------
def test_finding_query_joins_available_fields_and_skips_none():
    f = SimpleNamespace(name="rlogin", summary="root without password",
                        impact="full control", solution=None)
    q = finding_query(f)
    assert "rlogin" in q and "root without password" in q and "full control" in q
    assert "None" not in q


# --- clause parsers (need the PDFs; skip cleanly if absent) ------------------
@pytest.mark.skipif(not regulation_path("rmit").exists(), reason="RMiT PDF not present")
def test_rmit_parses_binding_clauses():
    clauses = load_clauses("rmit")
    assert len(clauses) > 50
    assert {c.binding for c in clauses} <= {"S", "G"}
    assert any(c.binding == "S" for c in clauses)
    c = clauses[0]
    assert re.match(r"\d+\.\d+", c.clause_id) and c.citation.startswith("RMIT")


@pytest.mark.skipif(not regulation_path("trm").exists(), reason="TRM PDF not present")
def test_trm_parses_numbered_clauses():
    clauses = load_clauses("trm")
    assert len(clauses) > 100
    c = clauses[0]
    assert re.match(r"\d+\.\d+\.\d+", c.clause_id) and c.citation.startswith("TRM")
