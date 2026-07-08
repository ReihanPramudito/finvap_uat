# FinVAP Reporting Web UI

A local, single-operator web front end for the reporting / human-in-the-loop side
of FinVAP (supervisor feature **S5**). It **wraps** the existing pipeline — it reads
and writes the same SQLite DB and calls the same scoring / mapping / report engine;
it does **not** reimplement any of them. The CLI remains the primary interface for
scanning.

Stack: **FastAPI + Jinja + HTMX**, server-rendered, with `htmx.min.js` vendored
locally so the UI needs **no network access**.

## Security model

- Binds **127.0.0.1 only** — never a routable interface. A non-loopback host (e.g.
  `0.0.0.0`) is refused and forced back to loopback unless `FINVAP_WEB_ALLOW_LAN=1`.
- **No auth** — it is meant for one operator on their own machine.
- Conservative response headers on every request: `nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, and a strict `Content-Security-Policy`
  (`default-src 'self'`) — everything is same-origin.
- Every LLM call the UI triggers goes through the **S1 audit trail + PII masking**
  (the recompute and report actions each run under one audited run; see *History*).

## Running it

```bash
# Open the UI on the current dataset (auto-picks a free port, opens a browser)
finvap web

# Fixed port / no browser
finvap web --port 8765 --no-browser

# Scan (opens the UI by default); many targets, comma-separated + ranges/CIDR:
finvap 10.0.0.1,10.0.0.10-20,192.168.1.0/24
```

`finvap <targets>` scans/imports and opens the UI; `finvap web` re-opens it on the
current project without re-scanning. **Each scan creates its own project** — a
separate DB + client engagement — so scans never accumulate into one report.

## Projects

Every scan/import is a **project** (`data/projects/<slug>.db`). The active project is
shown as a chip in the top bar; click it (or go to **`/projects`**) to **switch, rename
or delete**. Findings, engagement identity and the report are per project; run settings
and the SLA are global defaults.

## Pages

A scan opens **`/setup`**; from then on the flow is Setup → review/edit → Report.

| Page | Route | What it does |
|------|-------|--------------|
| **Projects** | `/projects` | List / switch / rename / delete projects (one per client engagement). |
| **Setup** | `/setup` | The entry page after a scan. Choose the **run settings** (framework / CVSS / provider / model, with **live model discovery**) and each asset's four **context tags**, then **Start analysis** — scores every finding, maps it to the framework's clauses, and **writes + saves the AI description/recommendation**, with a **progress bar**. A **Recompute (score + map)** button re-runs the lighter pass after a tag change (no prose rewrite). Degrades gracefully without an LLM. |
| **Dashboard** | `/` | Assets, findings and severity mix (regulatory-adjusted **fw_adj**). Each finding row has an **Edit** button; the findings table shows the top 25 with a **Show all N** button for the rest; a banner prompts you to run Setup if the data isn't analysed yet. |
| **Risk model** | `/risk-model` | Edit what each of the four **context tags** does to the CVSS environmental score (the Low/Med/High requirement per option, the criticality C/I **floor**, the environment **ceiling**, the internal-exposure Attack-Vector **step-down**). Grounded NIST defaults with a per-cell "changed" marker + **Reset to NIST defaults**; a change is audited (History) but never appears in the report. **Recompute** re-scores + refreshes the regulatory band from stored clauses — **no LLM**. |
| **CVSS calc** | `/cvss` | A standalone **CVSS 3.1 + 4.0** calculator (base / temporal / environmental) — pick metrics, the vector and score update live in the browser (FIRST.org formulae). |
| **Finding detail** | `/finding/{id}` | The three score layers (base / environmental / framework-adjusted) per CVSS version, mapped clauses, and the **AI-written** description/remediation. **Editing**: override severity/score, edit name/description/remediation (a durable edit the AI step won't overwrite), add/remove clauses — plus the manual **Report inputs** (steps, client / post-verification comments, PoC & post-verification **screenshot** uploads). |
| **Report** | `/report` | **Engagement identity** + the two-tier **remediation SLA** (they shape the report), plus per-report dates + cover fields → generate the filled **DOCX + PDF**. Degrades to DOCX-only if LibreOffice is unavailable. |
| **History** | `/logs` | The S1 audit trail. LLM-call events render the full **masking proof** (masked text sent, placeholder→real map kept local, raw + restored output, leak-check). |

## Manual report fields (the template tokens)

The report inputs on the finding page fill these template tokens: `{{F_STEPS}}` (one
numbered item per line), `{{F_CLIENT_COMMENTS}}`, `{{F_POSTVERIF_COMMENTS}}`, and the
embedded images `{{F_POC_SCREENSHOT}}` / `{{F_POSTVERIF_SCREENSHOT}}` (an *N/A —
non-intrusive assessment* note when none). The report page's cover fields fill
`{{DRAFT_FINAL}}` / `{{VERSION}}` / `{{COVER_DATE}}`. Screenshots are stored under
`data/uploads/` (gitignored) and embedded at fill time.

## Credits / licensing

- **htmx** (`static/js/htmx.min.js`) is vendored locally — htmx is BSD-2-Clause.
- The layout and visual style are **adapted from [VibeDocs](https://github.com/)**
  (MIT © 2026 Brendon Teo), rewritten standalone for FinVAP (no auth/theme/presence
  coupling). FinVAP uses its own regulatory-aware engine, not VibeDocs' backend.
- The **CVSS calculator** (`static/js/cvss_v4.js`, `cvss_v31.js`) is **ported from
  VibeDocs** (MIT © 2026 Brendon Teo) — 3.1 + 4.0 only (2.0 dropped), styling moved
  into `finvap.css` for the strict CSP. The 4.0 scoring is the official Red Hat /
  FIRST reference algorithm (BSD-2-Clause).
