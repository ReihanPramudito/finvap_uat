"""One-shot entry point: `finvap <target>` (or `finvap <file.nessus>`).

Scans (nmap + GVM) or imports a Nessus file, then hands off to the local web UI
where the operator does everything else — asset tagging, scoring, regulatory
mapping and report generation. The CLI's job ends at ingest; there is no headless
end-to-end path (that was removed to keep the tool small and its testing simple).

Design: calls the already-factored scanners + ingest directly, under the single
audit run the `assess` command opens, so `finvap logs` (in the UI) shows the scan
as one run. A hard scan/import failure raises :class:`PipelineError`.
"""
from __future__ import annotations

from pathlib import Path

from . import audit, db
from .ingest import ingest


class PipelineError(RuntimeError):
    """A scan/import failed in a way that stops the run (carries a clear message)."""


def _is_nessus(source: str) -> bool:
    p = Path(source)
    return source.lower().endswith(".nessus") or (p.exists() and p.is_file())


# --------------------------------------------------------------------------- #
# Scan / import
# --------------------------------------------------------------------------- #

def _scan(console, target: str):
    """nmap discovery + GVM vuln scan, ingested. Raises PipelineError on a hard
    GVM failure."""
    from .scanners.nmap_scanner import NmapScanner

    console.print(f"[cyan]nmap[/cyan] scanning [bold]{target}[/bold] …")
    result = NmapScanner().scan(target)
    row = ingest(result)
    console.print(f"  [green]ok[/green] {len(result.assets)} host(s), "
                  f"{len(result.ports)} open port(s)  (scan #{row.id})")
    audit.event("nmap.scan", target=target,
                summary=f"ran `{' '.join(result.command or ['nmap'])}` → "
                        f"{len(result.assets)} host(s), {len(result.ports)} port(s)",
                detail={"argv": result.command, "hosts": len(result.assets),
                        "ports": len(result.ports), "scan_id": row.id})

    from rich.progress import (BarColumn, Progress, SpinnerColumn,
                               TaskProgressColumn, TextColumn, TimeElapsedColumn)

    from .scanners.gvm_scanner import GvmScanError, GvmScanner
    try:
        with Progress(SpinnerColumn(), TextColumn("[cyan]gvm[/cyan] {task.description}"),
                      BarColumn(), TaskProgressColumn(), TimeElapsedColumn(),
                      console=console, transient=True) as progress:
            bar = progress.add_task(f"scanning {target}", total=100)
            result = GvmScanner().scan(
                target,
                progress_callback=lambda s, p: progress.update(
                    bar, completed=p, description=f"scanning {target} [{s}]"),
            )
    except GvmScanError as e:
        raise PipelineError(f"GVM scan failed: {e}") from e
    row = ingest(result, raw_output_path=result.raw_output_path)
    console.print(f"  [green]ok[/green] {len(result.findings)} finding(s)  (scan #{row.id})")
    if result.status and result.status != "Done":
        console.print(f"  [yellow]note:[/yellow] scan ended as {result.status} — results may be partial")
    audit.event("gvm.scan", target=target,
                summary=f"GVM Full-and-Fast → {len(result.findings)} finding(s) "
                        f"[{result.status or 'unknown'}]",
                detail={**(result.meta or {}), "findings": len(result.findings),
                        "scan_id": row.id, "raw_xml": result.raw_output_path})


# MAC-OUI vendor substrings → a friendlier device hint (helps a tester tell the
# lab VMs apart from real hardware in the discovery output).
_VENDOR_HINTS = {
    "pcs systemtechnik": "VirtualBox VM", "oracle": "VirtualBox VM",
    "vmware": "VMware VM", "qemu": "QEMU/KVM VM", "red hat": "QEMU/KVM VM",
    "parallels": "Parallels VM", "xensource": "Xen VM",
}


def _device_hint(vendor: str | None) -> str:
    """A short identification for a host from its MAC vendor (VM type, else the
    vendor name verbatim); empty string if unknown."""
    if not vendor:
        return ""
    low = vendor.lower()
    for needle, label in _VENDOR_HINTS.items():
        if needle in low:
            return label
    return vendor


def _local_ips() -> set[str]:
    """Best-effort set of this machine's own IPv4 addresses — so discovery can flag
    the scanning host itself. Enumerates *every* interface (not just the default
    route), so a multi-NIC host-only + NAT lab still recognises the scanner on the
    subnet being scanned."""
    import re
    import subprocess
    ips: set[str] = set()
    try:                                    # every configured IPv4 address
        out = subprocess.run(["ip", "-o", "-4", "addr", "show"],
                             capture_output=True, text=True, timeout=5)
        ips.update(re.findall(r"\binet (\d+\.\d+\.\d+\.\d+)/", out.stdout))
    except (OSError, subprocess.SubprocessError):
        pass
    if not ips:                             # fallback: just the egress interface's IP
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("10.255.255.255", 1))
                ips.add(s.getsockname()[0])
            finally:
                s.close()
        except OSError:
            pass
    return ips


def _default_gateway() -> str | None:
    """The IPv4 default gateway (Linux ``/proc/net/route``), or None."""
    import socket
    import struct
    try:
        with open("/proc/net/route") as fh:
            for line in fh.read().splitlines()[1:]:
                f = line.split()
                if len(f) > 2 and f[1] == "00000000":       # destination 0.0.0.0
                    return socket.inet_ntoa(struct.pack("<L", int(f[2], 16)))
    except (OSError, ValueError):
        pass
    return None


def discover_hosts(targets: str, *, console) -> None:
    """nmap host-discovery only: print which IPs in ``targets`` are live, annotated
    so it's clear what each one is (the scanner itself, the gateway, a lab VM, …).

    A quick "what's alive on this subnet" utility — no vuln scan, no ingest, no
    project, no web UI (and nothing written to the audit trail). Raises
    :class:`PipelineError` if nmap can't run.
    """
    import re

    from rich.table import Table

    from .scanners.nmap_scanner import NmapScanner

    scan_target = " ".join(p for p in re.split(r"[,\s]+", targets.strip()) if p)
    console.print(f"[cyan]nmap[/cyan] discovering live hosts on [bold]{scan_target}[/bold] …")
    try:
        hosts = NmapScanner().discover(scan_target)
    except RuntimeError as e:
        raise PipelineError(str(e)) from e

    if hosts:
        local, gateway = _local_ips(), _default_gateway()
        table = Table(title=f"Live hosts ({len(hosts)})")
        table.add_column("IP address")
        table.add_column("Hostname")
        table.add_column("MAC")
        table.add_column("Identification")
        for h in hosts:
            if h["ip"].startswith("127.") or h["ip"] in local:
                ident = "this machine (scanner)"
            elif gateway and h["ip"] == gateway:
                ident = "network gateway / router"
            else:
                ident = _device_hint(h.get("vendor"))
            table.add_row(h["ip"], h.get("hostname") or "[dim]—[/dim]",
                          h.get("mac") or "[dim]—[/dim]", ident or "[dim]—[/dim]")
        console.print(table)
    else:
        console.print("[yellow]No live hosts found in that range.[/yellow]")

    console.print(
        "\n[dim]Note: this discovery sweep is limited to hosts that responded to "
        "probes at the time it was performed. A host that filters or suppresses "
        "discovery traffic (for example, behind a host-based firewall) may be "
        "active yet not appear above; its absence from this list must not be "
        "interpreted as confirmation that the host is offline. To assess a specific "
        "system, supply its address directly to[/dim] [cyan]finvap <ip>[/cyan][dim], "
        "which probes the host regardless.[/dim]")


def _import(console, file: str):
    from .scanners.nessus_importer import NessusImporter, NessusImportError

    console.print(f"[cyan]import[/cyan] reading [bold]{file}[/bold] …")
    try:
        result = NessusImporter().import_file(file)
    except NessusImportError as e:
        raise PipelineError(f"Nessus import failed: {e}") from e
    row = ingest(result, raw_output_path=result.raw_output_path)
    console.print(f"  [green]ok[/green] {len(result.assets)} host(s), "
                  f"{len(result.findings)} finding(s)  (scan #{row.id})")
    audit.event("import.nessus", target=file,
                summary=f"imported {len(result.findings)} finding(s), "
                        f"{len(result.assets)} host(s) from {file}",
                detail={"file": file, "findings": len(result.findings),
                        "assets": len(result.assets), "scan_id": row.id})


# --------------------------------------------------------------------------- #
# Pipeline
# --------------------------------------------------------------------------- #

def run_pipeline(source: str, *, console,
                 open_browser: bool = True, port: int | None = None) -> None:
    """Scan/import ``source``, then open the local web UI at the setup page.

    Everything after ingest (tagging, scoring, mapping, reporting) happens in the
    browser. ``launch`` blocks until the operator stops the server (Ctrl-C).
    """
    is_nessus = _is_nessus(source)
    if is_nessus and not Path(source).exists():
        raise PipelineError(f"file not found: {source}")

    db.init_db()
    console.print("\n[bold]── scan ──[/bold]")
    if is_nessus:
        _import(console, source)
    else:
        _scan(console, source)

    from .web.server import launch
    console.print("\n[bold]→ opening the web UI[/bold] — set run options + asset tags on "
                  "the setup page, then it scores, maps and writes the report.")
    launch(console=console, path="/setup", open_browser=open_browser, port=port)
