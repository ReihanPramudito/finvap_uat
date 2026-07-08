"""GVM / Greenbone (OpenVAS) scanner via python-gvm over the gvmd unix socket.

Flow: authenticate -> create target -> create task (Full and Fast) -> start ->
poll until done -> fetch + parse results into findings.

NOTE: this needs a working `gvm-setup` (synced feeds, services running) and
credentials in FINVAP_GVM_USER / FINVAP_GVM_PASS. The result XML field names can
vary slightly between GMP versions, so `_parse` reads severity from both the
result level and the NVT level. Validate against live output once GVM is up.
"""
from __future__ import annotations

import os
import time

from ..config import DATA_DIR, GVM_PASSWORD, GVM_SOCKET, GVM_USERNAME
from .base import DiscoveredAsset, DiscoveredFinding, ScanResult

# Built-in GVM identifiers (stable across installs).
FULL_AND_FAST_CONFIG = "daba56c8-73ec-11df-a475-002264764cea"
OPENVAS_SCANNER = "08b69003-5fc2-4037-a479-93b440211c73"

_SEVERITY_BANDS = [(9.0, "Critical"), (7.0, "High"), (4.0, "Medium"), (0.1, "Low")]


def cvss_to_severity(score: float | None) -> str | None:
    if score is None:
        return None
    for threshold, label in _SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "Log"


class GvmScanError(RuntimeError):
    """A GVM scan could not be completed — gvmd unreachable, auth failed, or timed out.

    Carries a human-readable, actionable message so the CLI can show guidance
    (e.g. "run `sudo gvm-start`") instead of a raw traceback.
    """


class GvmScanner:
    name = "gvm"

    def __init__(self, socket_path: str = GVM_SOCKET, username: str = GVM_USERNAME,
                 password: str = GVM_PASSWORD, config_id: str = FULL_AND_FAST_CONFIG,
                 scanner_id: str = OPENVAS_SCANNER, poll_interval: int = 20,
                 min_qod: int = 70, result_levels: str = "chml"):
        self.socket_path = socket_path
        self.username = username
        self.password = password
        self.config_id = config_id
        self.scanner_id = scanner_id
        self.poll_interval = poll_interval
        self.min_qod = min_qod
        self.result_levels = result_levels

    def scan(self, target: str, *, progress_callback=None, **kwargs) -> ScanResult:
        from gvm.connections import UnixSocketConnection
        from gvm.errors import GvmError
        from gvm.protocols.gmp import Gmp
        from gvm.transforms import EtreeCheckCommandTransform

        if not self.password:
            raise GvmScanError(
                "GVM password not set — put FINVAP_GVM_PASS in .env (see `finvap doctor`)."
            )
        if not os.path.exists(self.socket_path):
            raise GvmScanError(
                f"Cannot reach gvmd at {self.socket_path} — is GVM running? "
                f"Start it with `sudo gvm-start`, then verify with `finvap doctor`."
            )

        connection = UnixSocketConnection(path=self.socket_path)
        try:
            with Gmp(connection, transform=EtreeCheckCommandTransform()) as gmp:
                try:
                    gmp.authenticate(self.username, self.password)
                except GvmError as e:
                    raise GvmScanError(
                        f"GVM authentication failed for user {self.username!r}: {e}"
                    ) from e

                stamp = int(time.time())
                target_id = gmp.create_target(
                    name=f"finvap-{target}-{stamp}",
                    hosts=target.split(),
                    port_range="1-65535",
                ).get("id")
                task_id = gmp.create_task(
                    name=f"finvap-scan-{target}-{stamp}",
                    config_id=self.config_id,
                    target_id=target_id,
                    scanner_id=self.scanner_id,
                ).get("id")
                gmp.start_task(task_id)

                status = self._poll(gmp, task_id, progress_callback)

                results = gmp.get_results(
                    details=True, filter_string=self._result_filter(task_id)
                )

                # Persist the raw result XML to data/ BEFORE parsing, so an
                # expensive scan is never lost to a parser bug — we can re-parse
                # the saved file offline.
                from lxml import etree as _etree
                xml_bytes = _etree.tostring(results, pretty_print=True)
                out_path = DATA_DIR / f"gvm-{target.replace('/', '_')}-{stamp}.xml"
                out_path.write_bytes(xml_bytes)

                result = self._parse(results, target)
                result.raw_output = xml_bytes.decode("utf-8", "replace")
                result.raw_output_path = str(out_path)
                result.status = status
                # Audit detail: what the GVM scan actually did (no single argv —
                # it's GMP over a socket — so record the task/target it created).
                result.meta = {
                    "target_id": target_id, "task_id": task_id,
                    "config": "Full and Fast", "scanner": self.scanner_id,
                    "terminal_status": status, "result_filter": self._result_filter(task_id),
                }
                return result
        except OSError as e:
            # Socket missing / connection refused -> gvmd is almost certainly down.
            raise GvmScanError(
                f"Cannot reach gvmd at {self.socket_path} — is GVM running? "
                f"Start it with `sudo gvm-start`, then verify with `finvap doctor`. ({e})"
            ) from e
        except GvmError as e:
            raise GvmScanError(f"GVM command failed: {e}") from e

    def _result_filter(self, task_id: str | None = None) -> str:
        """GMP filter for fetching this scan's results.

        Three GMP gotchas, all confirmed against live GMP 22.7 output:
          * **Scope to THIS scan with ``task_id=`` IN the filter string.** Passing
            ``task_id`` as the ``get_results`` *parameter* alongside a ``filter``
            string is silently ignored — GVMD applies the filter as-is, so as soon
            as a second scan exists in gvmd the fetch leaks every other task's
            results into this report (e.g. an old host's findings re-appear under a
            new scan). Putting ``task_id=`` in the filter scopes it correctly.
          * Without ``rows=-1`` the default page size (10) silently truncates the
            report — we stored 10 of ~700, losing all but the first page of
            criticals.
          * ``levels=hml`` does NOT include the Critical band; it needs an
            explicit 'c' (``levels=chml``) or every CVSS>=9 finding is dropped.
        ``min_qod`` drops low-confidence detections (OpenVAS's standard 70%
        quality-of-detection bar); ``sort-reverse=severity`` puts the worst
        findings first for the severity-driven UI.
        """
        scope = f"task_id={task_id} " if task_id else ""
        return (
            f"{scope}rows=-1 apply_overrides=0 min_qod={self.min_qod} "
            f"levels={self.result_levels} sort-reverse=severity"
        )

    def _poll(self, gmp, task_id: str, progress_callback=None) -> str:
        """Poll a running task until it reaches a terminal state.

        Returns the terminal status ("Done" / "Stopped" / "Interrupted"). Waits
        as long as the scan needs — a Full-and-Fast scan across many hosts can run
        for hours, so there is no wall-clock cap. Interrupt the CLI (Ctrl-C) to
        abandon a run; the task is left in gvmd and can be inspected in GSA.
        """
        terminal = ("Done", "Stopped", "Interrupted")
        while True:
            task = gmp.get_task(task_id)
            status = task.findtext(".//status") or "Unknown"
            progress = _to_int(task.findtext(".//progress"))
            if progress_callback is not None:
                pct = 100 if status == "Done" else max(progress or 0, 0)
                progress_callback(status, pct)
            if status in terminal:
                return status
            time.sleep(self.poll_interval)

    @staticmethod
    def _parse(results_xml, target: str) -> ScanResult:
        result = ScanResult(tool="gvm", target=target)
        seen: set[str] = set()

        # Direct children only: with details=True each <result> embeds a
        # <detection><result id=.../></detection> back-reference, so .//result
        # would pick those bare id-only nodes up as phantom (host-less) findings.
        for res in results_xml.findall("result"):
            host = (res.findtext("host") or "").strip()
            if not host:
                continue
            if host not in seen:
                seen.add(host)
                result.assets.append(DiscoveredAsset(ip_address=host))

            cvss_base = _to_float(res.findtext("severity"))
            cves: list[str] = []
            solution = None
            summary = impact = affected = None

            nvt = res.find("nvt")
            cvss_version = None
            cvss_vector = None
            if nvt is not None:
                if cvss_base is None:
                    cvss_base = _to_float(nvt.findtext("cvss_base"))
                cvss_version, cvss_vector = _cvss_version_vector(nvt)
                refs = nvt.find("refs")
                if refs is not None:
                    cves = [r.get("id") for r in refs.findall("ref")
                            if r.get("type") == "cve" and r.get("id")]
                # Richer context lives in the pipe-delimited <tags> blob
                # (summary|impact|affected|solution|...). Used for regulatory
                # mapping (Obj 1) and reporting (Obj 4).
                tags = _parse_tags(nvt.findtext("tags"))
                summary = tags.get("summary")
                impact = tags.get("impact")
                affected = tags.get("affected")
                sol = nvt.find("solution")
                if sol is not None and sol.text and sol.text.strip():
                    solution = sol.text.strip()
                else:
                    solution = tags.get("solution")

            port_text = res.findtext("port") or ""
            port, protocol = None, None
            if "/" in port_text:
                p, _, proto = port_text.partition("/")
                port = int(p) if p.isdigit() else None
                protocol = proto or None

            qod = _to_int(res.findtext("qod/value"))

            result.findings.append(DiscoveredFinding(
                ip_address=host,
                name=res.findtext("name") or "Unnamed finding",
                tool="gvm",
                description=res.findtext("description"),
                port=port,
                protocol=protocol,
                cve=",".join(cves) or None,
                summary=summary,
                impact=impact,
                affected=affected,
                cvss_base=cvss_base,
                cvss_version=cvss_version,
                cvss_vector=cvss_vector,
                severity=res.findtext("threat") or cvss_to_severity(cvss_base),
                qod=qod,
                solution=solution,
                references="\n".join(cves) or None,
            ))
        return result


def _parse_tags(tags_text) -> dict[str, str]:
    """Parse GMP's pipe-delimited NVT ``<tags>`` blob into a dict.

    Format: ``key1=value1|key2=value2|...`` (e.g.
    ``summary=...|impact=...|affected=...|solution=...``). Empty values are
    dropped so callers can rely on ``.get()`` returning a non-empty string or None.
    """
    out: dict[str, str] = {}
    for segment in (tags_text or "").split("|"):
        key, sep, value = segment.partition("=")
        value = value.strip()
        if sep and value:
            out[key.strip()] = value
    return out


def _to_float(value) -> float | None:
    try:
        f = float(value)
        return f if f >= 0 else None
    except (TypeError, ValueError):
        return None


def _to_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _cvss_version_vector(nvt) -> tuple[str | None, str | None]:
    """CVSS version + native base vector from GMP's ``<severities><severity>``.

    GMP 22.x emits ``<severity type="cvss_base_v2|cvss_base_v3">`` blocks, each
    carrying the base vector in ``<value>`` (v3 prefixed ``CVSS:3.1/...``, v2
    bare ``AV:.../...``). Prefer v3 when both exist. The vector is the risk
    engine's primary input (Obj 3 environmental recompute), so we capture it
    here. Confirmed against real GMP 22.7 output (Metasploitable result XML).
    """
    by_type: dict[str, str] = {}
    for s in nvt.findall("severities/severity"):
        t = s.get("type") or ""
        val = (s.findtext("value") or "").strip()
        if val:
            by_type[t] = val
    for t, val in by_type.items():
        if "v3" in t:
            return "3.1", val
    for t, val in by_type.items():
        if "v2" in t:
            return "2.0", val
    return None, None
