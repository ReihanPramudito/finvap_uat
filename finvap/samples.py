"""Bundled sample project — a raw DC-1 (VulnHub) GVM scan, for UAT.

Installing GVM (a multi-hour feed sync) and standing up a vulnerable VM is the
slowest part of evaluating FinVAP. So we ship the *findings* from one real DC-1
scan — no risk scores, no regulatory mappings, no AI prose, no engagement
details — and seed them on a genuinely empty install. The tester runs
``finvap web``, lands on the Setup page exactly as if their own scan had just
finished, and does the tagging → analysis → report themselves (this still needs
the local LLM). They skip only the GVM install and the vulnerable machine.

Seeding is conservative: it only ever fires when there are *no* projects, and it
never overwrites anything. The bundle lives in ``finvap/samples/`` so it ships
with the package (git + editable install).
"""
from __future__ import annotations

import shutil
from pathlib import Path

from . import config, projects

BUNDLE_DIR = Path(__file__).resolve().parent / "samples"
_SUFFIXES = (".db", ".meta.json", ".engagement.json")


def _bundled_slug() -> str | None:
    """The slug of the bundled sample (its ``*.meta.json`` stem), or None."""
    if not BUNDLE_DIR.exists():
        return None
    metas = sorted(BUNDLE_DIR.glob("*.meta.json"))
    return metas[0].name[: -len(".meta.json")] if metas else None


def ensure_seeded(console=None) -> str | None:
    """Seed the bundled sample project on a fresh install and make it active.

    Returns the seeded slug, or None if projects already exist (or no bundle is
    shipped). Safe to call every launch — it no-ops once anything exists.
    """
    projects.PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
    if any(projects.PROJECTS_DIR.glob("*.meta.json")):
        return None  # a real (or already-seeded) project exists — never touch it
    slug = _bundled_slug()
    if not slug:
        return None

    for suffix in _SUFFIXES:
        src = BUNDLE_DIR / f"{slug}{suffix}"
        if src.exists():
            shutil.copy2(src, projects.PROJECTS_DIR / src.name)

    uploads = BUNDLE_DIR / "uploads"
    if uploads.exists():
        config.UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
        for f in uploads.iterdir():
            if f.is_file():
                shutil.copy2(f, config.UPLOADS_DIR / f.name)

    projects.activate(slug)  # rebind the engine so the UI opens on the sample
    if console is not None:
        console.print(
            "[dim]Seeded a sample DC-1 scan — the UI opens on the Setup page so you "
            "can tag the asset and run the analysis without a GVM scan. Scan your own "
            "target any time with [/dim][cyan]finvap <ip>[/cyan][dim].[/dim]")
    return slug
