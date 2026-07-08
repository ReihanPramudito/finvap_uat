"""Heuristic cross-version CVSS vector conversion.

FIRST defines **no** official mapping between CVSS versions, so any score we
present in a version the scanner did not natively report is an approximation.
Every conversion here is therefore labelled ``source="derived"`` upstream and
documented in ``docs/SCORING.md`` so a reviewer can see exactly how it was
produced. Official scores (native scan vector, or NVD) are always preferred and
only fall through to these tables when nothing official exists for the target
version — which, on the old lab CVEs, is the norm for CVSS 4.0.

The tables below follow the metric definitions in the FIRST CVSS v2, v3.1 and
v4.0 specifications and the conventional community mapping (e.g. v2 ``AC:M`` has
no v3 equivalent, so it folds into the harder ``AC:H``).
"""
from __future__ import annotations


def parse_vector(vector: str) -> tuple[str, dict[str, str]]:
    """Return (version, {metric: value}) for a CVSS vector string.

    version is "2.0" | "3.0" | "3.1" | "4.0". v2 vectors have no ``CVSS:`` prefix.
    """
    vector = vector.strip()
    parts = [p for p in vector.split("/") if p]
    version = "2.0"
    metrics: dict[str, str] = {}
    for part in parts:
        key, sep, val = part.partition(":")
        if not sep:
            continue
        if key == "CVSS":
            version = val
            continue
        metrics[key] = val
    return version, metrics


def detect_version(vector: str) -> str:
    return parse_vector(vector)[0]


# --- v2 -> v3.1 -------------------------------------------------------------
# v3.1 collapses Access Complexity to L/H and renames Authentication -> Privileges
# Required; v2 has no User Interaction or Scope, so we take the worst-case
# (UI:N, S:U). Impact: None/Partial/Complete -> None/Low/High.
_V2_AV = {"L": "L", "A": "A", "N": "N"}
_V2_AC = {"L": "L", "M": "H", "H": "H"}
_V2_AU_TO_PR = {"N": "N", "S": "L", "M": "H"}
_V2_IMPACT = {"N": "N", "P": "L", "C": "H"}


def v2_to_v31(metrics: dict[str, str]) -> str:
    av = _V2_AV.get(metrics.get("AV", "N"), "N")
    ac = _V2_AC.get(metrics.get("AC", "L"), "L")
    pr = _V2_AU_TO_PR.get(metrics.get("Au", "N"), "N")
    c = _V2_IMPACT.get(metrics.get("C", "N"), "N")
    i = _V2_IMPACT.get(metrics.get("I", "N"), "N")
    a = _V2_IMPACT.get(metrics.get("A", "N"), "N")
    return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:N/S:U/C:{c}/I:{i}/A:{a}"


# --- v3.x -> v4.0 -----------------------------------------------------------
# v4.0 adds Attack Requirements (AT, none in v3 -> AT:N) and splits impact into
# Vulnerable-System (VC/VI/VA) and Subsequent-System (SC/SI/SA). v3 Scope models
# the same idea: S:U -> impact confined to the vulnerable system (SC/SI/SA:N);
# S:C -> it crosses a boundary, so mirror the impact onto the subsequent system.
_V3_UI_TO_V4 = {"N": "N", "R": "A", "P": "P", "A": "A"}


def v31_to_v40(metrics: dict[str, str]) -> str:
    av = metrics.get("AV", "N")
    ac = metrics.get("AC", "L")
    pr = metrics.get("PR", "N")
    ui = _V3_UI_TO_V4.get(metrics.get("UI", "N"), "N")
    c, i, a = metrics.get("C", "N"), metrics.get("I", "N"), metrics.get("A", "N")
    scope_changed = metrics.get("S", "U") == "C"
    sc, si, sa = (c, i, a) if scope_changed else ("N", "N", "N")
    return (
        f"CVSS:4.0/AV:{av}/AC:{ac}/AT:N/PR:{pr}/UI:{ui}"
        f"/VC:{c}/VI:{i}/VA:{a}/SC:{sc}/SI:{si}/SA:{sa}"
    )


def to_version(vector: str, target: str) -> tuple[str, bool]:
    """Convert ``vector`` to the target CVSS version ("3.1" | "4.0").

    Returns (vector_in_target_version, was_converted). ``was_converted`` is False
    when the source already matches the target (the vector is returned unchanged
    and the caller should keep its original, official provenance).
    """
    version, metrics = parse_vector(vector)

    if target == "3.1":
        if version.startswith("3"):
            return vector, False
        if version == "2.0":
            return v2_to_v31(metrics), True
        raise ValueError(f"cannot convert {version} -> 3.1")

    if target == "4.0":
        if version == "4.0":
            return vector, False
        if version.startswith("3"):
            return v31_to_v40(metrics), True
        if version == "2.0":
            return v31_to_v40(parse_vector(v2_to_v31(metrics))[1]), True
        raise ValueError(f"cannot convert {version} -> 4.0")

    raise ValueError(f"unsupported target version {target!r}")
