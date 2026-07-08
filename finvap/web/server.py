"""Launch the FinVAP reporting UI locally and (optionally) open a browser.

Single local operator: the server binds 127.0.0.1 only — never a routable
interface — and there is no auth layer. A free port is auto-picked unless one
is given, so two runs never collide.
"""
from __future__ import annotations

import os
import socket
import threading
import webbrowser

import uvicorn  # noqa: F401  (import here so a missing dep surfaces at `from .server import launch`)

from .app import create_app

_LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def _free_port(host: str) -> int:
    """Ask the OS for an unused port on ``host`` (bind to :0, read it back)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def _safe_host(host: str, console) -> str:
    """The UI has no auth — refuse to bind a routable interface. A non-loopback
    host (e.g. 0.0.0.0) falls back to 127.0.0.1 unless FINVAP_WEB_ALLOW_LAN=1."""
    if host in _LOOPBACK or os.environ.get("FINVAP_WEB_ALLOW_LAN") == "1":
        return host
    warn = (f"refusing to bind {host} — the UI has no auth; using 127.0.0.1 "
            f"(set FINVAP_WEB_ALLOW_LAN=1 to override)")
    if console is not None:
        console.print(f"[yellow]{warn}[/yellow]")
    else:
        print(warn)
    return "127.0.0.1"


def launch(host: str = "127.0.0.1", port: int | None = None, open_browser: bool = True,
           console=None, log_level: str = "warning", path: str = "/") -> None:
    """Serve the web UI (blocking, until Ctrl-C). Opens the browser shortly
    after the server starts so the request lands on a live listener. ``path`` is
    where the browser opens (e.g. ``/setup`` for a fresh scan)."""
    host = _safe_host(host, console)
    # Bring the active project's DB up to date before serving, so a tester who
    # updated FinVAP since their last scan doesn't hit a missing-column error.
    from ..migrate import ensure_schema
    ensure_schema()
    port = port or _free_port(host)
    url = f"http://{host}:{port}"
    msg = f"FinVAP reporting UI → {url}   (Ctrl-C to stop)"
    if console is not None:
        console.print(f"[bold green]{msg}[/bold green]")
    else:
        print(msg)

    if open_browser:
        # Fire slightly after uvicorn is up; webbrowser.open is a no-op on a
        # headless host (no DISPLAY), which is fine.
        threading.Timer(1.0, lambda: webbrowser.open(url + path)).start()

    uvicorn.run(create_app(), host=host, port=port, log_level=log_level)
