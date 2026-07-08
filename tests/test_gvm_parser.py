"""Regression tests for the GVM result parser and result-fetch filter.

These run fully offline against a captured GMP 22.7 report (a real Full-and-Fast
scan of Metasploitable2), so they need neither a running gvmd nor network access.
They lock in the bugs found during live validation:
  * the result-fetch filter must page through ALL results (``rows=-1``) and
    include the Critical band (``levels=chml``) — a 10-row / ``hml`` filter
    silently dropped most findings and every critical;
  * the parser must skip the ``<detection>`` back-reference ``<result>`` nodes.
"""
from collections import Counter
from pathlib import Path

from lxml import etree

from finvap.scanners.gvm_scanner import GvmScanner, cvss_to_severity

FIXTURE = Path(__file__).parent / "fixtures" / "gvm_metasploitable.xml"


def _parse():
    root = etree.parse(str(FIXTURE)).getroot()
    return GvmScanner._parse(root, "192.168.44.128")


def test_parses_every_real_result_and_skips_backrefs():
    root = etree.parse(str(FIXTURE)).getroot()
    # The raw report has more <result> descendants (detection back-refs) than
    # real findings — the parser must keep only the direct-child results.
    assert len(root.findall(".//result")) > len(root.findall("result"))
    result = _parse()
    assert len(result.findings) == 77
    assert all(f.ip_address for f in result.findings)  # no host-less phantoms


def test_severity_breakdown():
    by = Counter(f.severity for f in _parse().findings)
    assert by == {"Critical": 15, "High": 14, "Medium": 42, "Low": 6}


def test_cve_extraction_single_and_multi():
    with_cve = [f for f in _parse().findings if f.cve]
    assert len(with_cve) == 48
    for f in with_cve:  # every emitted token is a CVE id
        for token in f.cve.split(","):
            assert token.startswith("CVE-"), token
    # multi-CVE findings are comma-joined (e.g. the Tomcat default-creds NVT)
    assert any("," in f.cve for f in with_cve)


def test_cvss_version_detected_from_severities():
    versions = Counter(f.cvss_version for f in _parse().findings)
    assert versions["2.0"] == 56
    assert versions["3.1"] == 21


def test_core_fields_present_on_every_finding():
    for f in _parse().findings:
        assert f.name
        assert f.tool == "gvm"
        assert f.cvss_base is not None
        assert f.severity


def test_result_filter_avoids_truncation_and_critical_drop():
    # Built without a live gvmd, so the filter is unit-testable on its own.
    fs = GvmScanner()._result_filter()
    assert "rows=-1" in fs                 # else the default 10-row page truncates
    levels = fs.split("levels=")[1].split()[0]
    assert "c" in levels                   # else the Critical band is dropped
    assert "min_qod=70" in fs


def test_result_filter_scopes_to_task_to_prevent_cross_scan_leak():
    # The task_id MUST be in the filter string; passing it as the get_results
    # parameter alongside a filter is ignored by GVMD, so without this every other
    # task's results leak into the fetch once a second scan exists in gvmd.
    fs = GvmScanner()._result_filter("TASK-123")
    assert fs.startswith("task_id=TASK-123 ")
    assert "rows=-1" in fs and "min_qod=70" in fs   # base filter still intact
    # no scope when none given (keeps the standalone filter test valid)
    assert not GvmScanner()._result_filter().startswith("task_id=")


def test_cvss_to_severity_bands():
    assert cvss_to_severity(9.8) == "Critical"
    assert cvss_to_severity(7.0) == "High"
    assert cvss_to_severity(4.0) == "Medium"
    assert cvss_to_severity(0.1) == "Low"
    assert cvss_to_severity(0.0) == "Log"
    assert cvss_to_severity(None) is None


class _FakeGmp:
    """Minimal gmp stub yielding a scripted sequence of task statuses for _poll."""

    def __init__(self, statuses, progresses=None):
        self._statuses = list(statuses)
        self._progresses = list(progresses or [])

    def get_task(self, task_id):
        status = self._statuses.pop(0)
        progress = self._progresses.pop(0) if self._progresses else 50
        return etree.fromstring(
            f"<get_tasks_response><task><status>{status}</status>"
            f"<progress>{progress}</progress></task></get_tasks_response>"
        )


def test_poll_reports_progress_and_returns_terminal_status():
    seen = []
    scanner = GvmScanner(poll_interval=0)
    gmp = _FakeGmp(["Running", "Running", "Done"], [10, 60, -1])
    status = scanner._poll(gmp, "task-1", progress_callback=lambda s, p: seen.append((s, p)))
    assert status == "Done"
    assert seen[0] == ("Running", 10)
    assert seen[-1] == ("Done", 100)  # a finished task clamps to 100% for the UI


def test_poll_waits_through_a_long_run_without_a_cap():
    # A Full-and-Fast scan across many hosts can stay 'Running' for hours: _poll
    # keeps polling until a terminal status rather than giving up on a wall clock.
    scanner = GvmScanner(poll_interval=0)
    gmp = _FakeGmp(["Running"] * 50 + ["Done"], [5] * 50 + [-1])
    assert scanner._poll(gmp, "task-1") == "Done"
