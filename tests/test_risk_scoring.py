"""Unit tests for the Objective 3 risk engine — fully offline (no DB, no NVD).

They lock in the defensible behaviour documented in docs/SCORING.md:
  * each asset-tag -> CVSS environmental-metric mapping;
  * cross-version conversion and its `derived` provenance labelling;
  * the environment ceiling and criticality floor;
  * the version semantics (3.1 amplifies above base; 4.0 only de-amplifies);
  * the headline edge case (a Medium CVE on a payment gateway becomes High);
  * idempotent persistence (one FindingScore row per finding+version).
"""
import json

import pytest

from finvap.models import (Asset, Criticality, DataSensitivity, Environment,
                           Exposure)
from finvap.risk import band, score_one
from finvap.risk.convert import detect_version, to_version, v2_to_v31, v31_to_v40
from finvap.risk.metrics import environmental_metrics
from finvap.risk.nvd import NvdClient

# Reusable vectors / assets -------------------------------------------------
V2_CRIT = "AV:N/AC:L/Au:N/C:C/I:C/A:C"                       # native v2, base 9.8/9.3
V31_MED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"     # native v3.1, base 6.5
OFFLINE = NvdClient(offline=True)


def payment_gw():
    return Asset(ip_address="10.0.0.1", criticality=Criticality.critical,
                 data_sensitivity=DataSensitivity.financial,
                 exposure=Exposure.external, environment=Environment.production)


def uat_box():
    return Asset(ip_address="10.0.0.2", criticality=Criticality.low,
                 data_sensitivity=DataSensitivity.public,
                 exposure=Exposure.internal, environment=Environment.uat)


# --- banding ---------------------------------------------------------------
@pytest.mark.parametrize("score,label", [
    (10.0, "Critical"), (9.0, "Critical"), (8.9, "High"), (7.0, "High"),
    (6.9, "Medium"), (4.0, "Medium"), (3.9, "Low"), (0.1, "Low"), (0.0, "None"),
])
def test_band_thresholds(score, label):
    assert band(score) == label


def test_band_none_passthrough():
    assert band(None) is None


# --- tag -> environmental metric mappings ----------------------------------
def test_data_sensitivity_drives_cr_ir():
    m, _ = environmental_metrics(payment_gw(), "N")       # financial
    assert (m["CR"], m["IR"]) == ("H", "H")


def test_criticality_floor_lifts_low_sensitivity():
    # internal data is normally CR:L, but a CRITICAL host floors CR/IR to H.
    a = Asset(ip_address="x", criticality=Criticality.critical,
              data_sensitivity=DataSensitivity.internal,
              exposure=Exposure.external, environment=Environment.production)
    m, _ = environmental_metrics(a, "N")
    assert (m["CR"], m["IR"], m["AR"]) == ("H", "H", "H")


def test_environment_ceiling_caps_a_uat_box():
    # financial+critical would be H/H/H, but development caps every requirement to L.
    a = Asset(ip_address="x", criticality=Criticality.critical,
              data_sensitivity=DataSensitivity.financial,
              exposure=Exposure.external, environment=Environment.development)
    m, reasons = environmental_metrics(a, "N")
    assert (m["CR"], m["IR"], m["AR"]) == ("L", "L", "L")
    assert any("caps requirements" in r for r in reasons)


def test_exposure_external_keeps_base_av():
    m, _ = environmental_metrics(payment_gw(), "N")       # external
    assert "MAV" not in m


@pytest.mark.parametrize("base_av,expected", [("N", "A"), ("A", "L"), ("L", "P")])
def test_exposure_internal_steps_av_down_one(base_av, expected):
    m, _ = environmental_metrics(uat_box(), base_av)     # internal
    assert m["MAV"] == expected


def test_exposure_internal_never_below_physical():
    m, _ = environmental_metrics(uat_box(), "P")
    assert "MAV" not in m  # already minimal, left unchanged (never inflated)


def test_tag_effect_overrides_flow_into_metrics():
    # The Risk-model page can retune any tag effect; overrides merge over defaults.
    from finvap import settings
    a = Asset(ip_address="x", criticality=Criticality.low,
              data_sensitivity=DataSensitivity.financial,
              exposure=Exposure.internal, environment=Environment.production)
    assert environmental_metrics(a, "N")[0] == {"CR": "H", "IR": "H", "AR": "L", "MAV": "A"}
    settings.save_tag_effects({"data_sensitivity": {"financial": {"IR": "M"}},
                               "exposure": {"internal_av_steps": 2}})
    m, _ = environmental_metrics(a, "N")
    assert m["IR"] == "M"          # override applied
    assert m["MAV"] == "L"         # two steps: N -> A -> L


# --- cross-version conversion + provenance ---------------------------------
def test_v2_to_v31_mapping():
    assert v2_to_v31({"AV": "N", "AC": "L", "Au": "N", "C": "C", "I": "C", "A": "C"}) \
        == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_v2_access_complexity_medium_folds_to_high():
    assert "/AC:H/" in v2_to_v31({"AV": "N", "AC": "M", "Au": "N",
                                  "C": "P", "I": "P", "A": "P"})


def test_v31_to_v40_scope_changed_mirrors_subsequent_impact():
    out = v31_to_v40({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C",
                      "C": "H", "I": "H", "A": "H"})
    assert "/AT:N/" in out and "/VC:H/VI:H/VA:H/" in out and out.endswith("SC:H/SI:H/SA:H")


def test_to_version_no_op_when_already_target():
    vec, converted = to_version(V31_MED, "3.1")
    assert vec == V31_MED and converted is False


def test_to_version_v2_to_40_chains():
    assert detect_version(to_version(V2_CRIT, "4.0")[0]) == "4.0"


def test_native_v31_is_scan_sourced_derived_otherwise():
    layers = score_one(V31_MED, "3.1", None, payment_gw(), OFFLINE)
    assert layers["3.1"].source == "scan"      # native version, used as-is
    assert layers["4.0"].source == "derived"   # converted up, no official 4.0


def test_v2_native_has_no_official_31_offline():
    layers = score_one(V2_CRIT, "2.0", None, payment_gw(), OFFLINE)
    assert layers["3.1"].source == "derived"
    assert layers["4.0"].source == "derived"


# --- the headline behaviour ------------------------------------------------
def test_medium_cve_on_payment_gateway_becomes_high_in_31():
    L = score_one(V31_MED, "3.1", None, payment_gw(), OFFLINE)["3.1"]
    assert L.base_severity == "Medium"
    assert L.adj_score > L.base_score
    assert L.adj_severity == "High"


def test_v40_preserves_worst_case_on_high_value_asset():
    # In 4.0, Security Requirements default to High, so a financial/critical asset
    # can't amplify above base — it holds the worst case.
    L = score_one(V31_MED, "3.1", None, payment_gw(), OFFLINE)["4.0"]
    assert L.adj_score == pytest.approx(L.base_score)


def test_test_box_de_amplifies_in_both_versions():
    layers = score_one(V2_CRIT, "2.0", None, uat_box(), OFFLINE)
    for v in ("3.1", "4.0"):
        assert layers[v].adj_score < layers[v].base_score


def test_same_cve_scores_differently_by_asset():
    crit = score_one(V2_CRIT, "2.0", None, payment_gw(), OFFLINE)["3.1"]
    box = score_one(V2_CRIT, "2.0", None, uat_box(), OFFLINE)["3.1"]
    assert crit.adj_score > box.adj_score
    assert crit.adj_severity == "Critical" and box.adj_severity != "Critical"


def test_scoring_is_deterministic():
    a = score_one(V31_MED, "3.1", "CVE-0000-0001", payment_gw(), OFFLINE)
    b = score_one(V31_MED, "3.1", "CVE-0000-0001", payment_gw(), OFFLINE)
    assert {v: L.adj_vector for v, L in a.items()} == {v: L.adj_vector for v, L in b.items()}


# --- NVD client (offline + cache parsing) ----------------------------------
def test_nvd_offline_returns_none_without_cache():
    assert NvdClient(offline=True).vector_for("CVE-2999-0001", "3.1") is None


def test_nvd_reads_vector_from_cache(tmp_path, monkeypatch):
    from finvap.risk import nvd
    monkeypatch.setattr(nvd, "_CACHE_DIR", tmp_path)
    payload = {"vulnerabilities": [{"cve": {"metrics": {"cvssMetricV31": [
        {"type": "Primary", "cvssData": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
    ]}}}]}
    (tmp_path / "CVE-2021-9999.json").write_text(json.dumps(payload))
    client = NvdClient(offline=True)  # offline, but cache hit still served
    assert client.vector_for("CVE-2021-9999", "3.1").startswith("CVSS:3.1/")
    assert client.vector_for("CVE-2021-9999", "4.0") is None  # no v4.0 in payload


# --- DB persistence + idempotency ------------------------------------------
def test_score_findings_is_idempotent(tmp_path, monkeypatch):
    from sqlmodel import Session, SQLModel, create_engine, select

    from finvap import db
    from finvap.models import Finding, FindingScore
    from finvap.risk import score_findings

    engine = create_engine(f"sqlite:///{tmp_path/'t.db'}")
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(db, "engine", engine)  # get_session() reads db.engine at call time

    with Session(engine) as s:
        asset = payment_gw()
        s.add(asset)
        s.commit()
        s.refresh(asset)
        s.add(Finding(asset_id=asset.id, tool="gvm", name="rce",
                      cvss_version="2.0", cvss_vector=V2_CRIT))
        s.commit()

    score_findings(offline=True)
    score_findings(offline=True)  # second run must upsert, not duplicate

    with Session(engine) as s:
        rows = s.exec(select(FindingScore)).all()
        assert {r.cvss_version for r in rows} == {"3.1", "4.0"}
        assert len(rows) == 2  # one per version, not four
        f = s.exec(select(Finding)).first()
        assert f.cvss_adjusted is not None and f.severity_adjusted is not None
