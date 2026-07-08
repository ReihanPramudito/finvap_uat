# FinVAP — User Acceptance Testing (UAT) Guide

**Project:** FinVAP — Financial Vulnerability Assessment Platform
**Final Year Project**

Thank you for taking the time to test FinVAP. This guide walks you through installing it, running one real assessment against a test target, and exercising every feature you'll be asked about in the survey — in order, with no backtracking. Follow it top to bottom.

---

## What is FinVAP?

FinVAP scans infrastructure for vulnerabilities, then does what a generic scanner doesn't: it **re-scores every finding by the asset's business context** (a payment gateway isn't a test box), **maps each finding to the specific BNM RMiT / MAS TRM regulatory clause it implicates**, and generates an **auditor-ready DOCX + PDF report** — an AI writes the prose, but every score, clause citation and deadline is computed deterministically, not invented. You scan from the command line; everything else happens in a local web interface that opens automatically.

---

## Before you start

| | |
|---|---|
| **Time needed** | ~30 minutes of hands-on effort. Total wall-clock time is longer (1–2 hours) because the Greenbone feed sync and the vulnerability scan itself run in the background — you can do something else while they run. |
| **OS** | Kali Linux or Debian-based Linux |
| **Requires** | Python 3.13, ~5 GB free disk (scan feeds + LLM model), sudo access, internet connection |
| **You'll need** | A test target to scan — see **Step 5** below |

> **Only scan systems you own or are explicitly authorized to test.** Step 5 below sets up a dedicated, intentionally-vulnerable test VM for this purpose — do not point FinVAP at anything else.

---

## Step 1 — Get FinVAP

```bash
git clone https://github.com/ReihanPramudito/finvap_uat.git
cd finvap_uat
```

## Step 2 — Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Step 3 — Set up Greenbone/GVM (vulnerability scanning)

One-time setup; the feed sync is the slow part (several GB — let it run in the background).

```bash
sudo apt update && sudo apt install -y gvm gvm-tools
sudo gvm-setup && sudo gvm-start          # note the admin password it prints
export FINVAP_GVM_USER=admin
export FINVAP_GVM_PASS='<password-from-gvm-setup>'
finvap doctor                              # confirm everything is ready before continuing
```

`finvap doctor` should show all green/OK. If it doesn't, see **Troubleshooting** below before moving on — don't proceed to Step 4 with a failing `doctor` check.

## Step 4 — Install the local LLM

Powers the regulatory clause mapping and the AI-written report prose. Runs entirely on your machine — nothing here needs an internet API.

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull granite3.3:8b
```

This downloads a ~5 GB model; it can take a few minutes depending on your connection.

## Step 5 — Get a target to scan

FinVAP needs something to scan. The fastest option is **Metasploitable2** — a free, pre-built VM that's deliberately full of vulnerabilities, made exactly for this kind of testing.

1. Download it: <https://sourceforge.net/projects/metasploitable/> (or search "Metasploitable2 download" if that link has moved)
2. Import the `.vmdk` into VirtualBox or VMware as a new VM (no configuration needed — default settings work)
3. Boot it, log in (`msfadmin` / `msfadmin`), run `ifconfig` and note its IP address (e.g. `192.168.56.105`)
4. Make sure your host machine can reach that IP: `ping <that-ip>`

**Already have a lab machine you're authorized to scan?** Use its IP instead and skip the download.

---

## UAT Test Scenarios

Do these in order. Each one ends with what you should see — if something doesn't match, note it (that's exactly the kind of feedback we need).

### Scenario 1 — Scan the target and open FinVAP

1. With your venv active, run:
   ```bash
   finvap <target-ip>
   ```
2. Watch the terminal: an Nmap discovery scan runs first (fast), then the GVM vulnerability scan starts with a live progress bar. **This can take 15–45+ minutes** depending on your hardware and the target — this is normal, it hasn't frozen.
3. When it finishes, your browser opens automatically to the FinVAP **Setup** page.

**Expected result:** the terminal shows a host/port/finding summary, and a browser tab opens on its own at `http://127.0.0.1:<port>/setup`.

### Scenario 2 — Tag the asset and run the full analysis

1. On **Setup**, leave the Run settings at their defaults (framework `rmit`, CVSS `3.1`, provider `ollama`).
2. Under **Asset context tags**, click each **?** icon (Criticality, Data sensitivity, Exposure, Environment) to see what each option affects.
3. For your scanned asset, set: **Criticality = critical**, **Data sensitivity = financial**, **Exposure = external**, **Environment = production** — simulating a bank's internet-facing payment gateway.
4. Click **Start analysis**.
5. Wait for it to finish — it scores every finding, maps regulatory clauses, and writes AI descriptions (a few minutes).

**Expected result:** a progress bar completes and you land on a results summary (X findings scored, Y mapped).

### Scenario 3 — Review the dashboard and a Critical finding

1. Click **Dashboard** in the top nav.
2. Note the severity mix (Critical / High / Medium / Low counts).
3. Click any **Critical** finding's name.
4. On the finding page, review the **Risk score** table — the **Base**, **Environmental**, and **Framework-adjusted** rows, for both CVSS 3.1 and 4.0.
5. Look at **Applicable clauses** on the right — the specific RMiT clause(s) this finding is cited against.

**Expected result:** findings are listed worst-first; the finding page shows all three score layers with their CVSS vectors, and at least one cited clause appears for a mapped finding.

### Scenario 4 — Watch the score change with business context

This is FinVAP's core idea: the *same* vulnerability is scored differently depending on what it's sitting on.

1. Go back to **Setup**.
2. Re-tag the **same asset**: **Criticality = low**, **Data sensitivity = internal**, **Exposure = internal**, **Environment = development** — simulating a throwaway internal test box.
3. Click **Recompute (score + map)** (not "Start analysis" — this re-scores/re-maps without rewriting the AI prose, so it's quicker).
4. Once it finishes, open the **same finding** you looked at in Scenario 3.
5. Compare its score and severity now against what you saw before.

**Expected result:** the identical vulnerability now shows a different (typically lower) adjusted score/severity — proof the same CVE is prioritised differently by business context, not just its raw CVSS.

### Scenario 5 — Edit a finding

1. On any finding page, expand **Override severity / score**, set a severity manually (e.g. Critical), and submit.
2. Under **Details — editable**, change the description text and save.
3. Under **Applicable clauses**, add a clause manually (type e.g. `RMiT 10.20` and click Add).
4. Open a *different*, less important finding and click **Delete finding**, then confirm.

**Expected result:** the override shows a "score overridden" tag, your edited description persists, the clause list updates, and the deleted finding no longer appears anywhere on the dashboard.

### Scenario 6 — Generate the report

1. Click **Report** in the top nav.
2. Under **Engagement details**, fill in a client name, your name, etc., and click **Save engagement**.
3. Under **Remediation SLA**, type `0` into the Critical / Internet-facing field and click **Save SLA** — note the error message.
4. Correct it back to a real number (e.g. `7`) and click **Save SLA** again.
5. Under **Generate**, fill in the assessment window and draft date, then click **Generate DOCX + PDF**.
6. Once it finishes, download and open both files.

**Expected result:** step 3's invalid value is rejected with a clear message; after correcting it, the report generates and both the DOCX and PDF open showing a cover page, findings grouped by vulnerability with their adjusted severity, cited clauses, and a remediation deadline for each.

### Scenario 7 — Check the privacy / audit trail

1. Click **History** in the top nav.
2. Find an entry with action `llm.call` and open it.
3. Review the **AI call — PII masking proof** panel: the masked text actually sent to the model, the placeholder→real mapping (kept only on your machine), and the leak-check result.

**Expected result:** the leak-check shows **pass**, and the text sent to the AI model never contains your asset's real IP address or hostname.

---

### Optional, if you have extra time

- **Risk model** page — edit the weights each context tag applies to the score, then recompute.
- **CVSS calc** page — a standalone CVSS 3.1/4.0 calculator, independent of any scan data.

Neither is required for the survey — skip straight to the wrap-up if you're short on time.

---

## Wrap-up

Fill in the **`FinVAP_UAT_Template.docx`** questionnaire you were sent separately, and send it back. Every statement in it should now be answerable from what you just did — if anything feels unclear or you weren't able to form an opinion on a statement, say so in the Comments section.

---

## Troubleshooting

**`finvap doctor` reports a FAIL for GVM / `gvmd` won't start:**
Almost always Postgres isn't actually running under the `gvmd` service. See **[docs/GVM-SETUP.md](docs/GVM-SETUP.md)** for the exact fix (`pg_lsclusters` + starting the versioned cluster).

**The GVM scan seems stuck:**
It isn't — a full vulnerability scan genuinely takes 15–45+ minutes. The terminal's progress bar and status label update live; if the percentage is moving at all, it's working.

**Mapping / report prose didn't happen ("no LLM" note shown):**
Ollama isn't reachable or the model isn't pulled. Confirm with:
```bash
ollama list
```
`granite3.3:8b` should be listed. If not, re-run `ollama pull granite3.3:8b`.

**The PDF didn't generate (only the DOCX did):**
The PDF step needs LibreOffice:
```bash
sudo apt install -y libreoffice
```
The DOCX is unaffected either way — it's pure Python, no LibreOffice dependency.

**Browser didn't open automatically:**
Copy the URL printed in the terminal (`http://127.0.0.1:<port>`) into your browser manually.

**Port already in use / want to reopen the UI later without re-scanning:**
```bash
finvap web
```
Re-opens the interface on your current data — no need to scan again.

---

## Contact

For questions during testing, please contact:

**[Your name]** — [your email]
