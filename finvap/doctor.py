"""Readiness checks behind ``finvap doctor``.

Verifies the environment can actually run a GVM scan — socket reachable, GMP
auth works, feeds present, and a usable scan config + scanner exist — and fails
gracefully, explaining *what* to fix. Aimed at testers per the distribution
plan, and at catching the exact failure modes seen during setup (GVM not
started, a down PostgreSQL cluster, feeds not yet synced, credentials missing).
"""
from __future__ import annotations

import importlib.util
import os
import socket
from dataclasses import dataclass

from .config import GVM_PASSWORD, GVM_SOCKET, GVM_USERNAME
from .scanners.gvm_scanner import FULL_AND_FAST_CONFIG, OPENVAS_SCANNER

OK, WARN, FAIL = "OK", "WARN", "FAIL"


@dataclass
class Check:
    status: str  # OK | WARN | FAIL
    name: str
    detail: str = ""


def _postgres_check() -> Check | None:
    """gvmd reads its DB from the PostgreSQL cluster; if that cluster is down, gvmd
    exits at startup and `gvm-start` times out. The `postgresql.service` wrapper can
    read 'active (exited)' while the real `postgresql@<ver>-main` cluster is down, so
    check the cluster directly — this is the #1 recurring `gvm-start` failure."""
    import shutil
    import subprocess

    if not shutil.which("pg_lsclusters"):
        return None  # not a Debian-cluster PostgreSQL (or not installed) — skip
    try:
        out = subprocess.run(["pg_lsclusters", "-h"], capture_output=True,
                             text=True, timeout=10).stdout
    except (subprocess.SubprocessError, OSError):
        return None
    down, up = [], 0
    for line in out.splitlines():
        f = line.split()
        if len(f) >= 4:  # Ver Cluster Port Status Owner ...
            (down.append((f[0], f[1])) if f[3].lower() == "down" else None)
            up += f[3].lower() != "down"
    if down:
        ver, cluster = down[0]
        return Check(FAIL, "PostgreSQL cluster",
                     f"{ver}/{cluster} is DOWN — gvmd can't reach its DB. Fix: "
                     f"sudo systemctl start postgresql@{ver}-main")
    if up:
        return Check(OK, "PostgreSQL cluster", f"{up} cluster(s) up")
    return None


def _gvm_checks() -> list[Check]:
    checks: list[Check] = []

    checks.append(Check(
        OK if GVM_PASSWORD else FAIL,
        "GVM credentials",
        f"user={GVM_USERNAME!r}, password "
        + ("set" if GVM_PASSWORD else "MISSING — set FINVAP_GVM_PASS in .env"),
    ))

    pg = _postgres_check()
    if pg is not None:
        checks.append(pg)

    if not os.path.exists(GVM_SOCKET):
        checks.append(Check(
            FAIL, "gvmd socket",
            f"{GVM_SOCKET} not found — is GVM running? (sudo gvm-start)",
        ))
        return checks
    checks.append(Check(OK, "gvmd socket", GVM_SOCKET))

    try:
        from gvm.connections import UnixSocketConnection
        from gvm.protocols.gmp import Gmp
        from gvm.transforms import EtreeCheckCommandTransform

        connection = UnixSocketConnection(path=GVM_SOCKET)
        with Gmp(connection, transform=EtreeCheckCommandTransform()) as gmp:
            checks.append(Check(OK, "GMP version", gmp.get_version().findtext("version") or "?"))

            try:
                gmp.authenticate(GVM_USERNAME, GVM_PASSWORD)
                checks.append(Check(OK, "GMP authentication", f"as {GVM_USERNAME}"))
            except Exception as e:  # bad creds, locked account, ...
                checks.append(Check(FAIL, "GMP authentication", f"failed: {e}"))
                return checks

            try:
                syncing = [
                    (f.findtext("type") or f.findtext("name") or "?")
                    for f in gmp.get_feeds().findall(".//feed")
                    if f.find("currently_syncing") is not None
                ]
                checks.append(Check(
                    WARN if syncing else OK, "feeds",
                    f"still syncing: {', '.join(syncing)} — results may lack "
                    "CVE/CPE enrichment until done" if syncing else "all synced",
                ))
            except Exception as e:
                checks.append(Check(WARN, "feeds", f"could not read feed status: {e}"))

            cfgs = gmp.get_scan_configs().findall(".//config")
            has_faf = any(c.get("id") == FULL_AND_FAST_CONFIG for c in cfgs)
            checks.append(Check(
                OK if has_faf else FAIL, "scan config",
                "Full-and-Fast present" if has_faf
                else f"Full-and-Fast missing ({len(cfgs)} configs) — GVMD_DATA feed not imported yet",
            ))

            scanners = gmp.get_scanners().findall(".//scanner")
            has_openvas = any(s.get("id") == OPENVAS_SCANNER for s in scanners)
            checks.append(Check(
                OK if has_openvas else FAIL, "scanner",
                "OpenVAS Default present" if has_openvas else "OpenVAS scanner missing",
            ))
    except Exception as e:  # socket present but gvmd not accepting connections
        checks.append(Check(FAIL, "GMP connection", f"{type(e).__name__}: {e}"))

    return checks


def _target_check(target: str) -> Check:
    """Lightweight TCP reachability probe (no root needed, unlike ICMP)."""
    for port in (445, 80, 22, 139, 3306, 21):
        try:
            with socket.create_connection((target, port), timeout=1):
                return Check(OK, "target reachable", f"{target} (tcp/{port} open)")
        except OSError:
            continue
    return Check(
        WARN, "target reachable",
        f"{target}: no common TCP port responded (host down/firewalled?)",
    )


def _report_checks() -> list[Check]:
    """Readiness for `finvap report` (Obj 4): rendering deps + the LLM provider.

    LLM/PDF gaps are WARN, not FAIL — the report still generates (template prose
    for a missing LLM, DOCX for a missing PDF engine)."""
    checks: list[Check] = []

    missing = [m for m in ("docx", "lxml") if importlib.util.find_spec(m) is None]
    checks.append(Check(
        OK if not missing else FAIL, "report deps",
        "python-docx present" if not missing
        else f"missing {missing} — run `pip install -e .`",
    ))

    import shutil
    soffice = shutil.which("soffice") or shutil.which("libreoffice")
    if soffice:
        checks.append(Check(OK, "PDF engine", f"LibreOffice ({soffice})"))
    else:
        checks.append(Check(
            WARN, "PDF engine",
            "LibreOffice not found (DOCX still works; needed for the report PDF) — "
            "`sudo apt install -y libreoffice`",
        ))

    try:
        from .reporting.providers import get_provider
        prov = get_provider()  # the configured default (FINVAP_LLM_PROVIDER)
        if prov.name == "template":
            # report can fall back to template prose, but `finvap map` needs an LLM.
            checks.append(Check(
                WARN, "report/mapping LLM",
                "template mode: reports OK, but `finvap map` requires an LLM "
                "(set FINVAP_LLM_PROVIDER=ollama)",
            ))
        else:
            ok, reason = prov.available()
            checks.append(Check(
                OK if ok else WARN, f"report/mapping LLM ({prov.name})",
                reason if ok else f"{reason} — report falls back to template; `map` needs this",
            ))
    except Exception as e:
        checks.append(Check(WARN, "report/mapping LLM", f"provider error: {e}"))
    return checks


def run_checks(target: str | None = None) -> list[Check]:
    checks = _gvm_checks()
    if target:
        checks.append(_target_check(target))
    checks += _report_checks()
    return checks
