"""FinVAP command-line interface (Typer).

Deliberately tiny — three commands:

  finvap <target>        scan (nmap + GVM) or import a .nessus file, then open the
  finvap <file.nessus>   local web UI where you tag, score, map and report
  finvap <target> -d     just list which target IPs are live (host sweep only)
  finvap web             re-open the web UI on the current project
  finvap doctor          check the environment is ready to run a GVM scan

Everything else (tagging, scoring, regulatory mapping, editing, reporting,
settings, projects, history) lives in the web UI. Run `finvap web` to open it.
"""
from __future__ import annotations

import re
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from typer.core import TyperCommand, TyperGroup

from . import audit


class RootedCommand(TyperCommand):
    """Show usage as ``finvap …`` instead of the internal command name.

    The bare-target route dispatches to a hidden ``assess`` command; without this
    its ``--help`` would read ``Usage: finvap assess …`` and imply an ``assess``
    subcommand the user never types. Force the program name to ``finvap``.
    """
    def format_usage(self, ctx, formatter):
        formatter.write_usage("finvap", " ".join(self.collect_usage_pieces(ctx)))


class DefaultGroup(TyperGroup):
    """Let `finvap <target>` / `finvap <file.nessus>` run the assessment.

    If the first token isn't a known subcommand (and isn't an option/flag), treat
    it as a scan target / Nessus file and route to the hidden `assess` command —
    so the one-shot entry point is the default, while `web`/`doctor` still work.
    """
    default_cmd = "assess"

    def resolve_command(self, ctx, args):
        # Route a bare first token that isn't a known subcommand (and isn't an
        # option/flag) to the hidden `assess` command, so `finvap <target>` runs.
        # Decide up front via get_command rather than catching a UsageError from
        # super(): Typer >= 0.26 no longer lets that error propagate here, which
        # silently broke the old exception-based form (bare `finvap <ip>` printed
        # "No such command"). The lookup-first form is version-robust.
        if args and not args[0].startswith("-") and self.get_command(ctx, args[0]) is None:
            args = [self.default_cmd, *args]
        return super().resolve_command(ctx, args)


app = typer.Typer(
    cls=DefaultGroup,
    help=(
        "FinVAP — Financial Vulnerability Assessment Platform.\n"
        "\n"
        "\b\n"
        "Common usage:\n"
        "  finvap <target>            scan (nmap + GVM), then open the web UI\n"
        "  finvap <target> --discover list which target IPs are live (no scan / UI)\n"
        "  finvap <file.nessus>       import a Nessus export, then open the web UI\n"
        "  finvap web                 re-open the web UI on the current project\n"
        "  finvap doctor              check the environment is ready to scan"
    ),
    no_args_is_help=True,
)

console = Console()


@app.callback()
def _bootstrap():
    """Bind to the active project's DB (if any) before any command runs, so `web`
    opens the same project the last scan created."""
    from . import projects
    projects.load_active()


@app.command(hidden=True, cls=RootedCommand)
def assess(
    target: str = typer.Argument(
        ...,
        help="Scan targets — IP(s)/range/CIDR, comma-separated "
             "(e.g. 10.0.0.1,10.0.0.5-20,10.0.0.0/24), or a path to a .nessus file"),
    discover: bool = typer.Option(
        False, "--discover", "-d",
        help="List which target IPs are live (nmap host sweep) and exit — no vuln "
             "scan, no project, no web UI."),
    no_browser: bool = typer.Option(
        False, "--no-browser", help="Start the web UI without opening a browser."),
    port: Optional[int] = typer.Option(
        None, "--port", "-p", help="Port for the web UI (default: an auto-picked free port)."),
):
    """Scan TARGET (or import a .nessus file), then open the web UI to tag, score,
    map and report. This is what `finvap <target>` / `finvap <file.nessus>` runs."""
    from . import projects
    from .orchestrator import PipelineError, _is_nessus, discover_hosts, run_pipeline

    # --discover: a standalone liveness sweep — no project, no web UI, not audited.
    if discover:
        if _is_nessus(target):
            console.print("[red]--discover works on scan targets (IPs / range / CIDR), "
                          "not a .nessus file.[/red]")
            raise typer.Exit(1)
        try:
            discover_hosts(target, console=console)
        except PipelineError as e:
            console.print(f"[red]Discovery failed:[/red] {e}")
            raise typer.Exit(1)
        return

    # A real assessment is one audited run; sub-events (nmap/GVM/ingest) attach to it.
    with audit.run("assess", target=str(target)):
        # Normalise multi-target input (comma / whitespace separated) to space-separated
        # so nmap + GVM each receive individual hosts; ranges/CIDR pass through untouched.
        if _is_nessus(target):
            scan_target = proj_targets = target
        else:
            parts = [p for p in re.split(r"[,\s]+", target.strip()) if p]
            scan_target, proj_targets = " ".join(parts), ",".join(parts)

        # Each assessment is its own project (separate DB + client engagement).
        slug = projects.create(projects.default_name(proj_targets), targets=proj_targets)
        console.print(f"[dim]new project:[/dim] {slug}")

        try:
            run_pipeline(scan_target, console=console,
                         open_browser=not no_browser, port=port)
        except PipelineError as e:
            console.print(f"[red]Assessment stopped:[/red] {e}")
            raise typer.Exit(1)


@app.command()
def web(
    port: Optional[int] = typer.Option(
        None, "--port", "-p", help="Port to bind (default: an auto-picked free port)"),
    no_browser: bool = typer.Option(
        False, "--no-browser", help="Start the server without opening a browser"),
):
    """Open the local reporting web UI on the current project (serves 127.0.0.1)."""
    try:
        from .web.server import launch
    except ModuleNotFoundError as e:  # FastAPI/uvicorn not installed
        console.print("[red]The web UI needs FastAPI + uvicorn.[/red] "
                      "Reinstall with `pip install -e .` to pull them in.")
        raise typer.Exit(1) from e
    # First run with no projects: drop in the bundled sample scan so the UI has
    # something to show without a GVM scan. A freshly-seeded sample opens on the
    # Setup page, mirroring the hand-off right after a real scan completes.
    from . import samples
    seeded = samples.ensure_seeded(console)
    launch(port=port, open_browser=not no_browser, console=console,
           path="/setup" if seeded else "/")


@app.command()
def doctor(
    target: Optional[str] = typer.Argument(
        None, help="Optional host to TCP-reachability check, e.g. 192.168.44.128"),
):
    """Check the environment is ready to run a GVM scan (services, GMP, feeds)."""
    from .doctor import FAIL, OK, WARN, run_checks

    checks = run_checks(target)
    table = Table(title="finvap doctor")
    table.add_column("", justify="center")
    table.add_column("Check")
    table.add_column("Detail")
    colour = {OK: "green", WARN: "yellow", FAIL: "red"}
    for c in checks:
        table.add_row(f"[{colour[c.status]}]{c.status}[/]", c.name, c.detail)
    console.print(table)

    if any(c.status == FAIL for c in checks):
        console.print("[red]Not ready to scan[/red] — fix the FAIL items above.")
        raise typer.Exit(1)
    if any(c.status == WARN for c in checks):
        console.print("[yellow]Ready to scan, with warnings.[/yellow]")
    else:
        console.print("[green]All checks passed — ready to scan.[/green]")
