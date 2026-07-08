# Custom Word report templates (S3)

FinVAP can fill a **custom Word `.docx` template** with the assessment data, so the
report's branding, cover, fonts and section layout are entirely yours. The result is
a finished **DOCX** (the editable artifact) plus a **PDF**.

The template report is the **only** report format — one step, no Markdown intermediate.

You generate it from the web UI's **Report** page: pick the template, fill the
engagement details + SLA, and click **Generate** → DOCX + PDF. Templates live in
`templates/`; the template dropdown on the **Setup** page (saved to
`finvap.config.json`) sets the default, otherwise the bundled `VA Template.docx` is
used. Drop your own `.docx` into `templates/` and it appears in the dropdown.

## The three fill mechanisms

| Mechanism | Use it for | How FinVAP fills it |
|---|---|---|
| **Word Document Properties** | scalar identity that repeats verbatim (client/company names, author, reviewer, dates) | set once → cascades to every field; entered on the Report page's engagement form |
| **`{{tokens}}`** | per-finding / per-row data, counts, the SLA table | text replace; repeatable rows & the finding block are cloned per item |
| **`[bracket]` instructions (Executive Summary only)** | the qualitative exec-summary prose | the LLM fills each bracket from the findings (masked + audited); everything else is verbatim |

The LLM also rewrites each finding's **Description** and **Recommendation** from the raw
scanner text into cleaner prose — grounded, so it can't invent CVEs, versions or hosts;
scores, CVEs, clauses, deadlines and the affected-asset list stay deterministic. Every
LLM call is masked + audited (see the **History** page). With the `template`
provider (no LLM), FinVAP falls back to the deterministic exec summary and the raw
scanner text.

### 1. Document Properties (identity + dates)

Author these with Word → *Insert → Quick Parts → Field → DocProperty* (or *Document
Property*). FinVAP sets them from the Report page's **engagement details** form
(saved to `finvap.engagement.json`, reused across runs):

| Property | Source |
|---|---|
| `Client_Full_Name`, `Client_Short_Name` | engagement form (saved & reused) |
| `Company_Full_Name`, `Company_Short_Name` | engagement form |
| `Author_Name`, `Author_Title`, `Reviewer_Name`, `Reviewer_Title` | engagement form |
| `Client_PIC_Name`, `Client_PIC_Title` | engagement form |
| `Date_Assessment`, `Date_DraftReport` | entered per report on the Report page |
| `Date_PostVerif`, `Date_FinalReport` | left as your placeholder (verification round) |
| `Framework` | set automatically from the mapped framework |

### 2. `{{tokens}}`

Put one example row in each summary table and one example finding block; FinVAP
clones them per item.

**Executive Summary** — `{{TOTAL_FINDINGS}}`, `{{N_CRITICAL}}` `{{N_HIGH}}`
`{{N_MEDIUM}}` `{{N_LOW}}` `{{N_INFO}}`, `{{SEVERITY_BREAKDOWN}}`.

**§2.4 Remediation timeline** (two tiers per severity) — `{{SLA_CRITICAL_EXT}}` /
`{{SLA_CRITICAL_INT}}`, and the same for `HIGH`, `MEDIUM`, `LOW`; plus
`{{DEADLINE_MANDATE_CLAUSE}}`. Edit the day-counts on the Report page's SLA form.

**§2.0 Scope** (one row per asset) — `{{ASSET_IP}}`, `{{ASSET_ENV}}`.

**§3.0 Technical Summary** (one row per vulnerability) — `{{REF}}`, `{{SEVERITY}}`,
`{{CVSS}}`, `{{VULN_NAME}}`, `{{STATUS}}`.

**§3.1 Regulatory Compliance Mapping** — `{{REF}}`, `{{SEVERITY}}`, `{{VULN_NAME}}`,
`{{CLAUSES}}`.

**§4.x Detailed finding block** (Heading 2 = `{{F_TITLE}}`, cloned per vulnerability):
`{{F_DESCRIPTION}}`, `{{F_RECOMMENDATION}}`, `{{F_STATUS}}`; the severity table
`{{F_SEVERITY}}` / `{{F_CVSS}}` / `{{F_VECTOR}}`; repeatable bullets/rows —
affected asset `{{F_ASSET_IP}} ({{F_ASSET_PROTO}} {{F_ASSET_PORT}}) … {{F_ASSET_CVSS}}
({{F_ASSET_SEVERITY}})`, `{{F_CVE}}`, `{{F_REF_LINK}}`, and the clause table
`{{F_CLAUSE_ID}}` / `{{F_CLAUSE_TITLE}}` / `{{F_CLAUSE_RATIONALE}}`.

### 3. Executive-summary `[brackets]`

In the Executive Summary only, leave the instruction inside the bracket — e.g.
`[Choose one: strong posture / moderate / highly vulnerable]`. The LLM fills each
from the findings; the fixed text around them is untouched. The single
`[Action-oriented remediation goal …]` bullet is expanded into as many bullets as
there are themes. Brackets **anywhere else** (screenshots, repro steps, client
comments) are left for you to complete by hand.

## How findings are organised

Findings are **grouped by vulnerability name**: one §4 section and one summary row per
unique vulnerability, listing every affected host with its own regulatory-adjusted
(fw_adj) severity. The headline severity/CVSS is the worst case across those hosts.
Sections are ordered worst-first and numbered 4.1, 4.2, … to match the summaries.
Severity cells are shaded with the palette in §2.3 (Critical `#C00000`, High
`#FF0000`, Medium `#FFC000`, Low `#92D050`, Info `#00B0F0`).

## Outputs & the table of contents

You get `report.docx` + `report.pdf`. The PDF is produced through a LibreOffice UNO
bridge that **refreshes the TOC index and fields** before export — a plain `soffice
--convert-to pdf` would leave the TOC stale. If UNO isn't available it falls back to
a plain convert (valid PDF, but open the DOCX once to refresh the TOC). Requires
LibreOffice (`soffice`) on the host.

## Authoring tips

- One example row per table, one example finding block — FinVAP clones them.
- Repeated identical placeholders (e.g. five severity counts) need **distinct** tokens
  so they can be told apart; don't reuse `{{Count}}` five times.
- Keep a real, updatable Table of Contents field (Heading styles drive it).
- Test against a populated database: drop `yours.docx` in `templates/`, pick it on
  the Setup page, then **Generate** on the Report page.
