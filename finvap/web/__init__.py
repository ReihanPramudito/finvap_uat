"""FinVAP local reporting Web UI (Supervisor feature S5).

FastAPI + Jinja + HTMX, bound to 127.0.0.1 for a single local operator (no
auth, no external binding). It *wraps* the existing pipeline and reads/writes
the same SQLite DB — it never reimplements scanning, scoring, mapping or the
report engine.

Scaffold stage (S5.0): a read-only dashboard of the current dataset, plus the
`finvap web` launcher and the `finvap <target> --web` hand-off. Interactive
tagging, finding edits, settings and report generation land in S5.2–S5.5.

UI styling is adapted from VibeDocs (MIT © 2026 Brendon Teo); `htmx.min.js` is
vendored locally (htmx is BSD-2-Clause) so the UI needs no network access.
"""
