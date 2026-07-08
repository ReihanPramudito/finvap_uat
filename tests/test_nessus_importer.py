"""Tests for the Nessus (.nessus) importer — fully offline against a synthetic
fixture. The headline test (`test_imported_vectors_are_scorable`) proves an
imported finding's normalised CVSS vector feeds the Obj 3 risk engine, i.e. an
imported scan flows through scoring exactly like a GVM scan.

When a real Nessus Essentials export is available, drop it in fixtures/ and add
a parse assertion here (as we did for GVM) to lock in any field-name surprises.
"""
from pathlib import Path

import pytest

from finvap.scanners.nessus_importer import NessusImporter, NessusImportError

FIXTURE = Path(__file__).parent / "fixtures" / "nessus_sample.nessus"


def _parse():
    return NessusImporter().import_file(FIXTURE)


def _by_name(result, needle):
    for f in result.findings:
        if needle in f.name:
            return f
    raise AssertionError(f"no finding matching {needle!r}")


def test_parses_hosts_and_findings():
    r = _parse()
    assert r.tool == "nessus"
    assert len(r.assets) == 1
    a = r.assets[0]
    assert a.ip_address == "192.168.44.150"
    assert a.hostname == "payments.lab.local"
    assert "Ubuntu" in (a.os or "")
    assert len(r.findings) == 3
    assert all(f.tool == "nessus" and f.ip_address == "192.168.44.150" for f in r.findings)


def test_v3_preferred_over_v2_and_multi_cve():
    f = _by_name(_parse(), "MS17-010")
    assert f.cvss_version == "3.1"
    assert f.cvss_vector == "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"  # v3 wins over v2
    assert f.cvss_base == 8.1
    assert f.cve == "CVE-2017-0143,CVE-2017-0144"  # comma-joined like GVM
    assert f.severity == "High"  # banded from the 8.1 base, not Nessus's "Critical" attr
    assert f.port == 445 and f.protocol == "tcp"
    assert "ms17-010" in (f.references or "")  # see_also folded into references


def test_v2_vector_is_normalised_for_the_risk_engine():
    f = _by_name(_parse(), "vsftpd")
    assert f.cvss_version == "2.0"
    assert f.cvss_vector == "AV:N/AC:L/Au:N/C:P/I:P/A:P"  # "CVSS2#" prefix stripped
    assert f.cvss_base == 7.5 and f.severity == "High"
    assert f.cve == "CVE-2011-2523"


def test_info_finding_without_cvss_falls_back_to_nessus_severity():
    f = _by_name(_parse(), "Nessus Scan Information")
    assert f.cvss_base is None and f.cvss_vector is None and f.cvss_version is None
    assert f.cve is None
    assert f.severity == "Log"   # @severity="0" -> Log (no CVSS base to band)
    assert f.port is None        # port 0 == host-level, not an open port


def test_ports_extracted_excluding_host_level():
    ports = {(p.port, p.protocol) for p in _parse().ports}
    assert ports == {(445, "tcp"), (21, "tcp")}  # the port-0 info item is excluded


def test_imported_vectors_are_scorable():
    from finvap.models import Asset
    from finvap.risk import score_one
    from finvap.risk.nvd import NvdClient

    asset = Asset(ip_address="192.168.44.150")  # default context tags
    nvd = NvdClient(offline=True)  # no network: v2->3.1 falls back to derived
    scored = 0
    for f in _parse().findings:
        if not f.cvss_vector:
            continue
        layers = score_one(f.cvss_vector, f.cvss_version, f.cve, asset, nvd)
        assert layers["3.1"].adj_score > 0
        assert layers["4.0"].adj_score > 0
        scored += 1
    assert scored == 2  # the two findings that carry a CVSS vector


def test_rejects_non_nessus_xml(tmp_path):
    bad = tmp_path / "x.nessus"
    bad.write_text("<foo><bar/></foo>")
    with pytest.raises(NessusImportError):
        NessusImporter().import_file(bad)


# Regression lock against the real export the user provided (git-ignored sensitive
# infra data — so this runs only on the dev machine and asserts counts/shape, never
# the actual IPs or hostnames).
_REAL = Path(__file__).resolve().parent.parent / "IPT.nessus"


@pytest.mark.skipif(not _REAL.exists(), reason="real IPT.nessus not present (git-ignored)")
def test_real_nessus_export_parses_and_normalises():
    r = NessusImporter().import_file(_REAL)
    assert len(r.assets) == 2
    assert all(a.ip_address for a in r.assets)
    assert any(a.hostname for a in r.assets)        # NetBIOS-name fallback populates these
    assert len(r.findings) == 159
    scored = [f for f in r.findings if f.cvss_vector]
    assert len(scored) == 3                          # the 3 medium SSL-cert findings
    for f in scored:
        assert f.cvss_version in ("2.0", "3.1")
        assert "#" not in f.cvss_vector              # Nessus "CVSS2#" prefix stripped
        if f.cvss_version == "3.1":
            assert f.cvss_vector.startswith("CVSS:")  # parseable by the risk engine
