# FinVAP — User Acceptance Testing (UAT) Guide

**Project:** FinVAP — Financial Vulnerability Assessment Platform
**Final Year Project**

Thank you for taking the time to test FinVAP. This guide walks you through
installing it, finding and scanning a purpose-built test target, and exercising
every feature you'll be asked about in the survey — in order, with no
backtracking. The **Scenarios** cover the main workflow (do these top to bottom);
the **Optional extras** at the end cover secondary features if you have time.

---

## About FinVAP

FinVAP is a vulnerability assessment tool for the financial sector. It scans
infrastructure, adjusts each finding's risk score based on the asset's business
context (criticality, data sensitivity, exposure, environment), maps findings to
**BNM RMiT** (Malaysia) / **MAS TRM** (Singapore) regulatory clauses, and
generates an auditor-ready DOCX/PDF report. You scan from the command line; all
the analysis — tagging, scoring, mapping, editing and reporting — happens in a
local web interface that opens automatically.

---

## Prerequisites

| | |
|---|---|
| **Time needed** | ~30–40 min hands-on; the scan + analysis (~1–1.5 hrs) run unattended in the background |
| **OS** | Kali Linux or Debian-based Linux |
| **Requires** | Python 3.13, ~5 GB free disk (scan feeds + LLM model), sudo access, internet connection |
| **You'll need** | A test target to scan — a free vulnerable VM, set up in **Step 5** below |

> **Authorization notice:** You must only scan systems you own or have explicit
> written authorization to test. Unauthorized scanning of third-party systems may
> constitute an offence under computer-misuse legislation in your jurisdiction and
> is strictly outside the scope of this evaluation. Step 5 provides a dedicated,
> self-hosted test target for this purpose — do not direct FinVAP at any other
> system.

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

One-time setup; the feed sync is the slow part (several GB — let it run in the
background).

```bash
sudo apt update && sudo apt install -y gvm gvm-tools
sudo gvm-setup && sudo gvm-start          # note the admin password it prints
export FINVAP_GVM_USER=admin
export FINVAP_GVM_PASS='<password-from-gvm-setup>'
finvap doctor                              # confirm everything is ready before continuing
```

`finvap doctor` should show all green/OK. If it doesn't, see **Troubleshooting**
below before moving on — don't proceed with a failing `doctor` check.

## Step 4 — Install the local LLM

Powers the regulatory clause mapping and the AI-written report prose. Runs
entirely on your machine — nothing here needs an internet API.

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull granite3.3:8b
```

This downloads a ~5 GB model; it can take a few minutes depending on your
connection.

## Step 5 — Get a target to scan

FinVAP needs something to scan. Use **DC-1**, a free, purpose-built vulnerable VM
from VulnHub — small and quick to scan, with a realistic mix of severities.

1. Download it: <https://www.vulnhub.com/entry/dc-1-1,292/> (or search
   "DC-1 vulnhub" if that link has moved).
2. Import the VM into **VirtualBox** or **VMware** (default settings are fine).
3. Set its network adapter to **Host-only** or **NAT Network** so your Kali host
   and the VM share a subnet.
4. Boot the VM. You do **not** need to log in — it just needs to be running.

Unlike some practice VMs, DC-1 doesn't hand you console credentials, so you can't
just log in and read its IP. That's fine — **Scenario 1** uses FinVAP itself to
find it.

**Already have a lab machine you're authorized to scan?** Use it instead and note
its IP.

---

## UAT Test Scenarios

Do these in order. Each ends with what you should see — if something doesn't
match, note it (that's exactly the kind of feedback we need).

### Scenario 1 — Discover the target's IP on your network

You need DC-1's IP address, and FinVAP can find it for you.

1. First find your own subnet. On the Kali host run `ip addr` and look at the
   host-only / NAT-network interface (commonly something like `192.168.56.x` for
   VirtualBox). The subnet is that address with `.0/24` (e.g. `192.168.56.0/24`).
2. Run a discovery sweep:
   ```bash
   finvap 192.168.56.0/24 --discover
   ```
3. FinVAP lists the live hosts with an **Identification** column — it flags *this
   machine (scanner)* and the *network gateway / router*, and hints at virtual
   machines by vendor. The remaining VM host is DC-1. Note its IP.

**Expected result:** a short table of live IPs; you can pick out DC-1 as the VM
that isn't your own machine or the gateway. Discovery runs no vulnerability scan
and creates no project — it's just a lookup.

### Scenario 2 — Scan the target and open FinVAP

1. With your venv active, run the scan against the IP from Scenario 1:
   ```bash
   finvap <dc-1-ip>
   ```
2. Watch the terminal: an Nmap discovery scan runs first (fast), then the GVM
   vulnerability scan starts with a live progress bar. **This can take 30–60+
   minutes** depending on your hardware — this is normal, it hasn't frozen.
3. When it finishes, your browser opens automatically to the FinVAP **Setup**
   page.

**Expected result:** the terminal shows a host/port/finding summary, and a
browser tab opens on its own at `http://127.0.0.1:<port>/setup`.

> Already have a `.nessus` export you're authorized to use? You can skip the live
> scan and run `finvap <file>.nessus` instead — every scenario from here on works
> identically (see also the Optional extras).

### Scenario 3 — Configure the run and tag the asset, then analyse

1. On **Setup**, under **Run settings**, choose:
   - **Regulatory framework** — `rmit` (BNM RMiT) or `trm` (MAS TRM), your choice.
   - **CVSS version** — `3.1` or `4.0`. (The report will state whichever you pick.)
   - **LLM provider** — leave as `ollama` (local). *Model* can stay blank for the
     default.
   - Note the line explaining that scores use the online **NVD**, falling back to
     the scanner's own CVSS if the NVD can't be reached.
2. Under **Asset context tags**, click each **?** icon (Criticality, Data
   sensitivity, Exposure, Environment) to see what each option affects.
3. For your scanned asset, set: **Criticality = critical**, **Data sensitivity =
   financial**, **Exposure = external**, **Environment = production** — simulating
   a bank's internet-facing payment gateway.
4. Click **Start analysis**.
5. Wait for it to finish — it scores every finding, maps regulatory clauses, and
   writes AI descriptions (a few minutes).

**Expected result:** a progress bar completes and you land on a results summary
(X findings scored, Y mapped).

### Scenario 4 — Review the dashboard

1. Click **Dashboard** in the top nav.
2. Note the severity mix (Critical / High / Medium / Low counts) and the findings
   list, sorted worst-first.

**Expected result:** findings are listed with their regulation-adjusted severity,
highest first, each showing its score.

### Scenario 5 — Inspect a finding (risk layers + regulatory clauses)

1. Open the **top finding** in the list (click its name).
2. Review the **Risk score** table — the **Base**, **Environmental**, and
   **Framework-adjusted** rows, shown for both CVSS 3.1 and 4.0 (the version you
   chose on Setup drives the headline severity shown elsewhere).
3. Look at **Applicable clauses** — the specific RMiT / TRM clause(s) this finding
   is cited against.

**Expected result:** the finding page shows all three score layers with their
CVSS vectors, and at least one cited clause for a mapped finding.

### Scenario 6 — See context-based scoring change the risk

This is FinVAP's core idea: the *same* vulnerability is scored differently
depending on what it's sitting on.

1. Go back to **Setup**.
2. Re-tag the **same asset**: **Criticality = low**, **Data sensitivity =
   internal**, **Exposure = internal**, **Environment = development** — simulating
   a throwaway internal test box.
3. Click **Recompute (score + map)** (not "Start analysis" — this re-scores and
   re-maps without rewriting the AI prose, so it's quicker).
4. When it finishes, open the **same finding** you looked at in Scenario 5.
5. Compare its score and severity now against what you saw before.

**Expected result:** the identical vulnerability now shows a different (typically
lower) adjusted score/severity — proof the same CVE is prioritised by business
context, not just its raw CVSS.

### Scenario 7 — Edit a finding (human-in-the-loop)

On any finding page:

1. Expand **Override severity / score**, set a severity manually, and click
   **Apply override**.
2. Under **Details**, edit the description text and click **Save text**.
3. Under **Applicable clauses**, add a clause manually (type e.g. `RMiT 10.20` or
   `TRM 7.4.1` — matching your chosen framework — and click **Add**).
4. Under **Report inputs**, add a **Proof-of-concept screenshot**, some
   **Reproduction steps**, and a **Client comments / justification** note, then
   click **Save report inputs**. (These flow into the report.)

**Expected result:** the override shows a "score overridden" tag, your edited
description and clause list persist, and the report inputs are saved.

### Scenario 8 — Delete a finding

1. Open a *less important* finding (further down the list) and click **Delete
   finding**, then confirm. (You can also delete straight from a dashboard row.)

**Expected result:** the deleted finding no longer appears anywhere on the
dashboard.

### Scenario 9 — Generate the report

1. Click **Report** in the top nav.
2. Under **Engagement details**, fill in a client name, your name, etc., and click
   **Save engagement**.
3. Under **Remediation SLA**, type `0` into the Critical / **Internet-facing**
   field and click **Save SLA** — note the error message.
4. Correct it back to a real number (e.g. `7`) and click **Save SLA** again.
5. Under **Generate**, fill in the assessment window and draft date, then click
   **Generate DOCX + PDF**.
6. When it finishes, download and open both files.

**Expected result:** step 3's invalid value is rejected with a clear message;
after correcting it, the report generates and both the DOCX and PDF open showing a
cover page, an executive summary, findings grouped by vulnerability with their
adjusted severity and cited clauses, a remediation deadline per severity, and the
CVSS version you chose on Setup.

### Scenario 10 — Verify privacy & the audit trail

1. Click **History** in the top nav.
2. Find an entry with action `llm.call` and open it.
3. Review the **AI call — PII masking proof** panel: the masked text actually sent
   to the model, the placeholder→real mapping (kept only on your machine), and the
   leak-check result.

**Expected result:** the leak-check shows **pass**, and the text sent to the AI
model never contains your asset's real IP address or hostname.

### Scenario 11 — Manage projects

Each scan you run becomes its own isolated project (its own database and client
details), so different engagements never mix.

1. In the top-left, click the **project name** chip → **Rename** the current
   project and save.
2. Click **Switch / manage projects…** to open the projects list. If you've run
   more than one scan, switch to another project and confirm the dashboard changes
   to that data.
3. From the projects list, **Delete** a project you no longer need and confirm.

**Expected result:** renaming updates the chip; switching swaps the whole dataset;
deleting removes that project. Your active project's data is unaffected by the
others.

---

## Optional extras

Not required for the survey — try any of these if you have time.

- **Reopen later without re-scanning** — `finvap web` reopens the UI on your
  current project. Handy if you close the browser or come back another day.
- **Import a Nessus file** — instead of a live GVM scan, `finvap <file>.nessus`
  imports an existing Nessus export; the rest of the workflow is identical.
- **Use a cloud LLM** — on **Setup**, choose the `openai` or `anthropic` provider,
  expand **Cloud API keys** and paste a key. A cloud model runs faster than the
  local one. Identifiers are still masked before anything is sent, and the key is
  stored only in a local file (`finvap.secrets.json`) — never uploaded elsewhere.
- **Tune the risk model** — the **Risk model** page lets you edit how much each
  context tag moves the score; **Recompute scores** applies the change, and
  **Reset to grounded defaults** reverts it.
- **Standalone CVSS calculator** — the **CVSS calc** page is a self-contained CVSS
  3.1 / 4.0 calculator, independent of any scan data.
- **Custom report template** — drop your own `.docx` template into `templates/`
  and pick it under **Run settings** on Setup to have the report filled into your
  own house style.

---

## Wrap-up

Fill in the **`FinVAP_UAT_Template.docx`** questionnaire you were sent separately
and send it back. Note anything unclear in the Comments section.

---

## Troubleshooting

**`finvap doctor` reports a FAIL for GVM / `gvmd` won't start:**
Almost always Postgres isn't actually running under the `gvmd` service. See
**[docs/GVM-SETUP.md](docs/GVM-SETUP.md)** for the exact fix (`pg_lsclusters` +
starting the versioned cluster).

**`--discover` shows no hosts / not the VM:**
Make sure the VM is booted and its network adapter is Host-only or NAT-network on
the same subnet as your Kali host. A firewalled host can be up yet not respond to
probes; running discovery with `sudo` enables ARP for more reliable results on a
local subnet.

**The GVM scan seems stuck:**
It isn't — a full vulnerability scan genuinely takes 30–60+ minutes. The progress
bar and status label update live; if the percentage is moving at all, it's
working.

**Mapping / report prose didn't happen ("no LLM" note shown):**
Ollama isn't reachable or the model isn't pulled. Confirm with `ollama list` —
`granite3.3:8b` should be listed. If not, re-run `ollama pull granite3.3:8b`.

**The PDF didn't generate (only the DOCX did):**
The PDF step needs LibreOffice: `sudo apt install -y libreoffice`. The DOCX is
unaffected either way.

**Browser didn't open automatically:**
Copy the URL printed in the terminal (`http://127.0.0.1:<port>`) into your
browser manually.

**Reopen the UI later without re-scanning:**
```bash
finvap web
```

---

## Contact

For questions during testing, please contact:

**[Your name]** — [your email]
