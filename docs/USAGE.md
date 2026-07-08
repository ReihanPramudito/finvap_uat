# FinVAP — Command Reference

FinVAP is **three commands**. You scan from the terminal; everything else — asset
tagging, scoring, regulatory mapping, finding edits, the report — happens in the
local web UI it opens for you. For the UI itself see [`WEBUI.md`](WEBUI.md).

```bash
finvap 192.168.1.10        # scan (nmap + GVM), then open the web UI to finish
finvap acme.nessus         # start from a Nessus import instead of a live scan
finvap web                 # re-open the UI on the current project (no re-scan)
finvap doctor              # check the environment is ready for a GVM scan
```

The database is created and migrated automatically on first scan / launch — there
is no init or migrate step.

---

## `finvap <target>` — scan / import, then open the UI

```
finvap TARGET [--no-gvm] [--no-browser] [--port N]
```

| Argument / option | Effect |
|-------------------|--------|
| `TARGET` | A single IP, a comma-separated list, an nmap range, or a CIDR — **or** a path to a `.nessus` file (imported instead of scanned). |
| `--no-gvm` | nmap discovery only (skip the GVM vulnerability scan). |
| `--no-browser` | Start the web server without opening a browser (headless host). |
| `--port N` | Port for the web UI (default: an auto-picked free port). |

Each run creates its own **project** (a separate SQLite DB + engagement). It scans
or imports, then opens the UI at the **Setup** page, where you choose the
framework / CVSS / LLM options, tag each asset's business context, and click
**Start analysis** (score → map → AI prose). You then review, edit and generate the
report from the browser. The UI binds `127.0.0.1` only, no auth.

GVM scans need Greenbone set up and the credentials exported (see the README);
`finvap doctor` checks readiness.

## `finvap web` — re-open the UI

```
finvap web [--port N] [--no-browser]
```

Opens the UI on the **current** project without re-scanning — for reviewing,
editing or regenerating a report later. Switch projects from the topbar menu.

## `finvap doctor` — environment check

```
finvap doctor [HOST]
```

Checks the services, GMP connection and feeds a GVM scan needs, and (optionally)
TCP-reachability to `HOST`. Exit code is non-zero if anything is a hard failure.

---

## What each asset-context tag does to the score

You set these four tags per asset on the UI's **Setup** page; they drive the
context-adjusted CVSS score. (The exact weights are editable on the **Risk model**
page — see [`SCORING.md`](SCORING.md).)

| Tag | Value → metric | Effect on risk |
|-----|----------------|----------------|
| `data_sensitivity` | financial → CR:H/IR:H · pii → H/M · confidential → M/M · internal → L/M · public → L/L | More sensitive data raises the confidentiality/integrity requirement (amplifies in 3.1; holds worst-case in 4.0). |
| `criticality` | critical/high → AR:H · medium → AR:M · low → AR:L | Sets the availability requirement **and** raises the CR/IR floor, so a mission-critical host can't score "low". |
| `exposure` | external → keep base AV · internal → step AV down one (N→A→L→P) | An internal-only host is less reachable, so its attack vector is reduced. AV is **never** inflated above base. |
| `environment` | production → cap H · staging/uat → cap M · development → cap L | Caps CR/IR/AR for non-production tiers, so a test box tagged `financial`/`critical` can't score like production. |

How they combine (per requirement):

```
CR = min( max(CR_from_sensitivity, floor_from_criticality), ceiling_from_environment )
IR = min( max(IR_from_sensitivity, floor_from_criticality), ceiling_from_environment )
AR = min( AR_from_criticality,                              ceiling_from_environment )
```

> A requirement only amplifies an impact the finding actually has — `IR:H` does
> nothing to a finding with no integrity impact (`I:N`).

Regulatory mapping needs the regulation PDF(s) in `regulations/`
(`pd-rmit-nov25.pdf` and/or `mas-trm-2021.pdf`); the local vector index builds on
first use.

---

## Environment variables

Set in a gitignored `.env` at the project root (or exported in the shell). Most
run options (framework, CVSS, provider, model, offline, template) are set in the UI
and saved to `finvap.config.json`; these env vars cover credentials and the LLM
backend.

| Variable | Default | Effect |
|----------|---------|--------|
| `FINVAP_GVM_USER` | `admin` | GVM/GMP username. |
| `FINVAP_GVM_PASS` | (empty) | GVM/GMP password — **required** for GVM scans. |
| `FINVAP_GVM_SOCKET` | `/run/gvmd/gvmd.sock` | Path to the `gvmd` unix socket. |
| `FINVAP_DB` | `data/finvap.db` | SQLite database file location (per project). |
| `FINVAP_AUDIT` | `1` (on) | Set to `0` to disable the audit trail / AI activity log. |
| `FINVAP_CONFIG` | `finvap.config.json` | Location of the saved run preferences. |
| `NVD_API_KEY` | (none) | Optional NVD key — only raises the lookup rate limit (faster first score run); does not change the resulting score. |
| `FINVAP_LLM_PROVIDER` | `ollama` | Report/mapping LLM: `ollama` / `openai` / `anthropic` / `template`. |
| `FINVAP_LLM_MODEL` | per-provider | Override the model id. |
| `FINVAP_OLLAMA_HOST` | `http://localhost:11434` | Ollama endpoint (point at a host/LAN Ollama if you wish). |
| `FINVAP_OLLAMA_MODEL` | `granite3.3:8b` | Default local model (IBM Granite). |
| `FINVAP_OLLAMA_FLUSH_EVERY` | `15` | Unload the Ollama model every N calls to free its server-side prompt cache (which otherwise grows ~150 MB per call until the kernel OOM-kills `ollama serve` on smaller machines). `0` disables; FinVAP also auto-retries a call if the server crashes and comes back. |
| `FINVAP_LLM_BASE_URL` | OpenAI | Base URL for an OpenAI-compatible endpoint (company gateway / vLLM). |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | (none) | Keys for the opt-in cloud providers. Can also be entered on the web **Setup** page, which stores them in a gitignored `finvap.secrets.json` (a UI-saved key overrides the env var). |
| `FINVAP_SECRETS` | `finvap.secrets.json` | Path to the UI-entered cloud API keys (gitignored, `0600`). |
| `FINVAP_WEB_ALLOW_LAN` | (off) | Allow binding a non-loopback interface for the UI (default refuses — the UI has no auth). |
