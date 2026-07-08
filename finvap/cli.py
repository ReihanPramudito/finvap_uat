"""FinVAP command-line interface (Typer).

Deliberately tiny — three commands:

  finvap <target>        scan (nmap + GVM) or import a .nessus file, then open the
  finvap <file.nessus>   local web UI where you tag, score, map and report
  finvap web             re-open the web UI on the current project
  finvap doctor          check the environment is ready to run a GVM scan

Everything else (tagging, scoring, regulatory mapping, editing, reporting,
settings, projects, history) lives in the web UI. Run `finvap web` to open it.
"""
from __future__ import annotations

import functools
import re
from typing import Optional

import click
import typer
from rich.console import Console
from rich.table import Table
from typer.core import TyperGroup

from . import audit


def audited(command: str, target_arg: str | None = None):
    """Record a command invocation in the audit trail (run id + start/outcome +
    duration). Sub-events emitted inside the body attach to the same run via a
    context variable, so deep modules need no run id threaded through."""
    def deco(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            target = None
            if target_arg is not None and kwargs.get(target_arg) is not None:
                target = str(kwargs[target_arg])
            with audit.run(command, target=target):
                return func(*args, **kwargs)
        return wrapper
    return deco


class DefaultGroup(TyperGroup):
    """Let `finvap <target>` / `finvap <file.nessus>` run the assessment.

    If the first token isn't a known subcommand (and isn't an option/flag), treat
    it as a scan target / Nessus file and route to the hidden `assess` command —
    so the one-shot entry point is the default, while `web`/`doctor` still work.
    """
    default_cmd = "assess"

    def resolve_command(self, ctx, args):
        try:
            return super().resolve_command(ctx, args)
        except click.exceptions.UsageError:
            if args and not args[0].startswith("-"):
                return super().resolve_command(ctx, [self.default_cmd, *args])
            raise


app = typer.Typer(
    cls=DefaultGroup,
    help="FinVAP - Financial Vulnerability Assessment Platform (CLI)",
    no_args_is_help=True,
)

console = Console()


@app.callback()
def _bootstrap():
    """Bind to the active project's DB (if any) before any command runs, so `web`
    opens the same project the last scan created."""
    from . import projects
    projects.load_active()


@app.command(hidden=True)
@audited("assess", target_arg="target")
def assess(
    target: str = typer.Argument(
        ...,
        help="Scan targets — IP(s)/range/CIDR, comma-separated "
             "(e.g. 10.0.0.1,10.0.0.5-20,10.0.0.0/24), or a path to a .nessus file"),
    gvm: bool = typer.Option(
        True, "--gvm/--no-gvm",
        help="Run the GVM vulnerability scan (default). --no-gvm does nmap discovery only."),
    no_browser: bool = typer.Option(
        False, "--no-browser", help="Start the web UI without opening a browser."),
    port: Optional[int] = typer.Option(
        None, "--port", "-p", help="Port for the web UI (default: an auto-picked free port)."),
):
    """Scan TARGET (or import a .nessus file), then open the web UI to tag, score,
    map and report. This is what `finvap <target>` / `finvap <file.nessus>` runs."""
    from . import projects
    from .orchestrator import PipelineError, _is_nessus, run_pipeline

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
        run_pipeline(scan_target, console=console, gvm=gvm,
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
    launch(port=port, open_browser=not no_browser, console=console)


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
