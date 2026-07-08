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

def _scan(console, target: str, gvm: bool):
    """nmap discovery (+ optional GVM vuln scan), ingested. Raises PipelineError
    on a hard GVM failure."""
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

    if not gvm:
        return
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

def run_pipeline(source: str, *, console, gvm: bool = True,
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
        _scan(console, source, gvm)

    from .web.server import launch
    console.print("\n[bold]→ opening the web UI[/bold] — set run options + asset tags on "
                  "the setup page, then it scores, maps and writes the report.")
    launch(console=console, path="/setup", open_browser=open_browser, port=port)
