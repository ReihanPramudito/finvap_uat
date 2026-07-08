"""NVD lookup for *official* CVSS vectors, used to upgrade a finding's base
score to a version the scanner didn't natively report (e.g. a v2-only NVT that
NVD also scores under v3.1).

Design notes:
  * stdlib only (urllib) — keeps the risk engine free of an HTTP dependency.
  * Every response is cached as JSON under ``data/nvd_cache/`` so a cohort is
    fetched once; later runs (and the test suite) are fully offline.
  * Fail-safe: any network/parse error returns ``None`` and the caller falls
    back to a derived conversion. NVD is an enhancement, never a hard dependency.
  * ``NVD_API_KEY`` (env) raises the rate limit; without it we self-throttle.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

from ..config import DATA_DIR

_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CACHE_DIR = DATA_DIR / "nvd_cache"

# Where each target version's vector lives in the NVD response, best metric first.
_METRIC_KEYS = {
    "3.1": ("cvssMetricV31", "cvssMetricV30"),
    "4.0": ("cvssMetricV40",),
}


class NvdClient:
    def __init__(self, *, offline: bool = False, api_key: str | None = None,
                 timeout: float = 10.0):
        self.offline = offline
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.timeout = timeout
        # NVD's published limits: 5 req / 30s anonymous, 50 req / 30s with a key.
        self._min_interval = 0.6 if self.api_key else 6.0
        self._last_request = 0.0

    def vector_for(self, cve: str, target: str) -> str | None:
        """Return NVD's official vector for ``cve`` in the target version, or None.

        ``cve`` may be a comma-joined list (a finding can cite several); the first
        is used as the finding's primary identifier.
        """
        cve = (cve or "").split(",")[0].strip().upper()
        if not cve.startswith("CVE-"):
            return None
        data = self._fetch(cve)
        if not data:
            return None
        try:
            metrics = data["vulnerabilities"][0]["cve"]["metrics"]
        except (KeyError, IndexError, TypeError):
            return None
        for key in _METRIC_KEYS.get(target, ()):
            entries = metrics.get(key) or []
            primary = next((e for e in entries if e.get("type") == "Primary"), None)
            chosen = primary or (entries[0] if entries else None)
            if chosen:
                vec = chosen.get("cvssData", {}).get("vectorString")
                if vec:
                    return vec
        return None

    def _fetch(self, cve: str) -> dict | None:
        cache_file = _CACHE_DIR / f"{cve}.json"
        if cache_file.exists():
            try:
                return json.loads(cache_file.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        if self.offline:
            return None

        self._throttle()
        req = urllib.request.Request(f"{_API}?cveId={cve}")
        if self.api_key:
            req.add_header("apiKey", self.api_key)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
            return None

        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        try:
            cache_file.write_text(json.dumps(data))
        except OSError:
            pass
        return data

    def _throttle(self) -> None:
        wait = self._min_interval - (time.monotonic() - self._last_request)
        if wait > 0:
            time.sleep(wait)
        self._last_request = time.monotonic()
