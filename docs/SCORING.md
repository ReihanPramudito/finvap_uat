# FinVAP Risk Scoring (Objective 3)

**Context-based risk scoring** — the platform's #1 survey-ranked feature (80% of
the 30 surveyed industry professionals trust a context-adjusted score over a
static CVSS base). The goal is to cut the "alert fatigue" that comes from
treating every CVSS 9.8 identically regardless of where it lives: the *same*
vulnerability is genuinely more dangerous on an internet-facing payment gateway
than on a throwaway UAT box, and the score should say so.

This document is the defensible methodology behind FinVAP's risk scoring (run from
the web UI's **Setup → Start analysis** / **Recompute**).

---

## 1. Method: true CVSS *environmental* recompute (not a heuristic overlay)

FinVAP does **not** invent a private formula and multiply the base score by a
fudge factor. It uses the **environmental metric group that already exists in the
CVSS standard** and recomputes the score with the official equations, via the
RedHat [`cvss`](https://pypi.org/project/cvss/) library (handles v2, v3.1 and
v4.0). Each asset's context tags are translated into standard CVSS environmental
metrics (`CR`, `IR`, `AR`, `MAV`), appended to the finding's base vector, and the
library produces the environmental score.

Because the maths is the standard's own, every number is reproducible and
auditable: paste the adjusted vector into any CVSS calculator and you get the
same figure.

### Three score layers (nothing is overwritten)

For every finding, per version, FinVAP keeps three layers in the `FindingScore`
table:

1. **base / true** — the standards base score, with a `source` provenance label
   (see §3).
2. **adjusted** — the CVSS *environmental* recompute from asset context (this
   objective).
3. **framework-adjusted** (`fw_adj_*`) — the **regulatory priority** under the
   selected framework (Objective 1), layered on top of the environmental score.
   Filled by the mapping step; see §10. It can move the band up *or* down, but the
   environmental risk in layer 2 is always retained and shown.

---

## 2. Versions: CVSS 3.1 **and** 4.0

Both versions are computed and stored on every run; `--cvss 3.1|4.0` only selects
which one is displayed (default **3.1**) and mirrored onto the at-a-glance
`findings` table. Switching versions is therefore instant and never re-scores.

**CVSS v2 is input-only** — old NVTs report a v2 vector, which is converted up
(§4) and never reported as a v2 result.

### The one semantic difference you must know

The two specifications define the Security Requirements (`CR`/`IR`/`AR`)
*oppositely*, and FinVAP applies each natively (the most defensible choice):

| | CVSS 3.1 | CVSS 4.0 |
|---|---|---|
| `CR`/`IR`/`AR` default ("Not Defined") | **Medium** | **High** |
| Effect of `CR:H` (e.g. a financial asset) | raises **above** base | = base (already worst-case) |
| Effect of `CR:L` (e.g. a public asset) | lowers below base | lowers below base |
| Net behaviour | adjusts **both ways** | **de-amplify from worst-case only** |

So in **3.1** a high-value asset can push a *Medium* finding up into *High*; in
**4.0** the high-value asset simply retains the worst-case base, and only
*lower*-value assets see the score fall. Both are faithful to their respective
FIRST specifications. This is visible in the worked examples (§7).

---

## 3. Base-score provenance (always labelled)

FIRST defines no official conversion between CVSS versions, so a score presented
in a version the scanner did not natively emit is, at best, an approximation.
FinVAP makes the source explicit on every layer:

| `source` | Meaning | Authority |
|----------|---------|-----------|
| `scan`    | the scanner's native vector, used as-is | highest |
| `nvd`     | NVD's official vector for that CVE in that version | high |
| `derived` | FinVAP's heuristic cross-version conversion (§4) | approximate |

Resolution order per (finding, version): **native vector → NVD → derived.** NVD
lookups are on by default, cached under `data/nvd_cache/`, fail-safe (any network
error falls back to derived), and accelerated by an optional `NVD_API_KEY`;
`--offline` skips them entirely. On the old lab CVEs, NVD typically holds only a
v2 score, so **CVSS 4.0 is almost always `derived`** — as expected.

---

## 4. Cross-version conversion (the `derived` tables)

Conversions follow the FIRST metric definitions and conventional community
mappings. They are approximations, labelled `derived`, and never override an
official score.

**v2 → v3.1** (v3.1 collapses Access Complexity to L/H, renames Authentication →
Privileges Required, and has no User Interaction/Scope, so worst-case `UI:N`,
`S:U` are assumed):

| v2 | → v3.1 | | v2 | → v3.1 |
|----|--------|---|----|--------|
| `AV:L/A/N` | `AV:L/A/N` | | `Au:N/S/M` | `PR:N/L/H` |
| `AC:L` | `AC:L` | | `C/I/A:N` | `…:N` |
| `AC:M`/`AC:H` | `AC:H` | | `C/I/A:P` | `…:L` |
| | | | `C/I/A:C` | `…:H` |

**v3.1 → v4.0** (v4.0 adds Attack Requirements `AT` — none in v3, so `AT:N` — and
splits impact into Vulnerable-System `VC/VI/VA` and Subsequent-System `SC/SI/SA`.
v3 Scope models the same boundary-crossing idea: `S:U` confines impact to the
vulnerable system, `S:C` mirrors it onto the subsequent system):

- `AV/AC/PR` carried across unchanged; `UI:R → UI:A`.
- `VC/VI/VA = C/I/A`.
- `S:U → SC/SI/SA = N`; `S:C → SC/SI/SA = C/I/A`.

**v2 → v4.0** chains v2 → v3.1 → v4.0.

---

## 5. Asset context → CVSS environmental metrics

Every mapping is grounded in a published standard so it can be defended rather
than asserted. Implemented in `finvap/risk/metrics.py` as `DEFAULT_TAG_EFFECTS`.

**These are the defaults, but they're editable.** The web UI's **Risk model** page
lets an operator retune any tag's effect (the Low/Med/High requirement each option
sets, the criticality floor, the environment ceiling, and how far internal exposure
steps the Attack Vector down). Overrides are stored as a `tag_effects` block in
`finvap.config.json` (only the changed leaves) and merged over these defaults by
`settings.effective_tag_effects()`; **Reset** drops the block. A change is recorded
in the audit trail (deviating from the grounded defaults) but never appears in the
report, and **Recompute** re-scores every finding + refreshes the regulatory band
from the already-chosen clauses — no LLM. The tables below are the shipped defaults.

### 5.1 `data_sensitivity` → Confidentiality / Integrity Requirement
*Grounding: FIPS 199 + NIST SP 800-60 information-impact levels.*

| `data_sensitivity` | CR | IR |
|--------------------|----|----|
| `financial`        | H  | H  |
| `pii`              | H  | M  |
| `confidential`     | M  | M  |
| `internal`         | L  | M  |
| `public`           | L  | L  |

### 5.2 `criticality` → Availability Requirement (+ CR/IR floor)
*Grounding: FIPS 199 availability impact. A mission-critical host can't be "low".*

| `criticality` | AR | raises CR/IR floor to |
|---------------|----|-----------------------|
| `critical`    | H  | H |
| `high`        | H  | H |
| `medium`      | M  | M |
| `low`         | L  | L |

`CR = min(max(CR_from_sensitivity, floor), ceiling)` (and likewise IR/AR).

### 5.3 `exposure` → Modified Attack Vector
*Grounding: CVSS v3.1/v4.0 spec, Attack Vector definition.*

- `external` → keep the base Attack Vector (worst-case reachability stands).
- `internal` → step the Attack Vector down one level of reachability
  (`N→A→L→P`), modelling a host that is not internet-facing. **AV is never
  inflated above base.**

### 5.4 `environment` → ceiling on CR/IR/AR
*Grounding: a non-production tier carries lower real-world requirements; this also
stops it double-counting with `criticality`.*

| `environment` | requirement ceiling |
|---------------|---------------------|
| `production`  | H (full weight) |
| `staging`     | M |
| `uat`         | M |
| `development` | L |

The ceiling only ever lowers a requirement, never raises it — so a test box
tagged `financial`/`critical` cannot score like production.

### 5.5 Re-banding (uniform across versions)

Every score layer is banded the same way (matching the CVSS qualitative scale):

`Critical ≥ 9.0 · High ≥ 7.0 · Medium ≥ 4.0 · Low ≥ 0.1 · None = 0`

---

## 6. What was deliberately left out

`compensating_controls` was **removed**. It was the one non-standard, subjective
modifier ("we have a WAF, knock a point off") with no grounding in a CVSS metric
or a published impact standard, and so the hardest to defend. FinVAP scores from
**asset-intrinsic context only**.

---

## 7. Worked examples

Same vulnerability, two assets — a **payment gateway**
(`critical`/`financial`/`external`/`production`) and a **UAT test box**
(`low`/`public`/`internal`/`uat`). Numbers are reproducible by re-tagging + rescoring.

### A medium information-disclosure finding (native v3.1, base C:L/I:L/A:N)

| Asset | v3.1 base → adj | v4.0 base → adj |
|-------|-----------------|-----------------|
| payment gateway | 6.5 Medium → **7.5 High** | 6.9 Medium → 6.9 Medium |
| UAT test box    | 6.5 Medium → 4.2 Medium | 6.9 Medium → 5.3 Medium |

In 3.1 the gateway's high requirements push the Medium up into **High**; in 4.0
the gateway retains the worst-case base while the test box de-amplifies. Both
correct per §2.

### A critical RCE finding (native v2, base C:C/I:C/A:C)

| Asset | v3.1 base → adj | v4.0 base → adj |
|-------|-----------------|-----------------|
| payment gateway | 9.8 Critical → 9.8 Critical | 9.3 Critical → 9.3 Critical |
| UAT test box    | 9.8 Critical → **6.9 Medium** | 9.3 Critical → **7.3 High** |

The same RCE that is rightly *Critical* on the payment gateway drops to
*Medium*/*High* on a throwaway UAT box — the alert-fatigue reduction this
objective exists to deliver. (On the real Metasploitable dataset, re-tagging the
host as a UAT box dropped **40 of 77** findings by at least one band.)

---

## 8. How it's run

Scoring runs in the web UI: on the **Setup** page you tag each asset (criticality,
data sensitivity, exposure, environment) and pick the CVSS version + offline mode,
then **Start analysis** (or **Recompute** after a tag change) scores every finding
in both CVSS 3.1 and 4.0. The per-finding page shows the base → environmental →
regulation-adjusted layers and the reasoning; the **Risk model** page edits the
tag→metric weights. Scoring is idempotent — one `FindingScore` row per (finding,
version) is upserted. The band displayed (3.1 or 4.0) is a run setting.

---

## 9. Regulatory mapping + priority layer — `fw_adj` (Objective 1)

The mapping step (framework `rmit`|`trm`) maps each finding to the regulatory clauses it
implicates, then computes a **regulatory-priority** band into `fw_adj_*`. This is
*not* "the danger" — it is how much the selected framework cares — so the
environmental risk (layer 2) is always retained and shown.

### Mapping: RAG candidates + LLM re-rank
The clause PDFs are chunked per clause and embedded (ChromaDB ONNX
`all-MiniLM-L6-v2`). For each finding, RAG retrieves the top-`k` **candidate**
clauses by cosine similarity, then the configured LLM (Granite, local by default)
**selects** the clause(s) that genuinely apply, or **none**.

*Why not pure similarity:* on real findings the embedding scores clustered in
0.15–0.33 and **mis-ranked** — e.g. a weak-SSH-MAC crypto finding scored ~0.15
against the Cryptography clause while an irrelevant ICMP-timestamp finding scored
~0.30 against a Network-Resilience clause. No similarity floor separates those.
Given the real candidates, the LLM reliably distinguishes a **control failure**
(missing/weak encryption, cleartext credentials, weak crypto, default creds,
missing patch) from **reconnaissance / information disclosure** (timestamps,
banners, supported protocols → no clause).

**Anti-hallucination is preserved:** the LLM may only choose from the retrieved
candidates, so every citation is a real, verifiable clause ID (`RMIT S 10.20`,
`TRM 10.1.2`) — it cannot invent regulation. Verdicts use temperature 0 and are
cached for reproducibility; `map --explain` shows the model's one-line rationale.

### Severity move (Model 1 — the number stays standards-based)
Relevance is judged by the LLM; the **number is deterministic CVSS**. The rule is
isolated in `compute_fw_adj` so it can later be swapped for an LLM-driven decision:

- **Raise** one band — only when the finding maps to a **binding** clause, is
  already a real vulnerability (**base ≥ Medium**), and sits on a high-value asset
  (critical/high criticality, or financial/PII data). Gating on the *base*
  severity is deliberate: a low-impact finding mapped to a binding clause (e.g.
  weak SSH MAC, base Low) stays at its environmental band instead of inflating.
- **High → Critical** only under the **strict gate**: `criticality=critical` and
  `data_sensitivity ∈ {financial, pii}` (RMiT additionally requires a binding `S`
  (Standard) clause). Reserves Critical for genuine high-stakes violations.
- **Lower** to Low when no clause applies and the finding is only Low/Medium
  (de-prioritise framework-irrelevant noise). A technically **High/Critical
  finding is never downgraded** by regulatory silence (compliance ≠ security).

**Why bounded, not the report's literal "medium → critical":** applied verbatim,
every mapped finding on a critical/financial asset would become Critical,
recreating the alert fatigue Objective 3 exists to remove. Keying the raise on a
binding clause **and base severity** keeps the differentiation while still
delivering the payment-data thesis. *Live example* (HTB host tagged
critical/financial): cleartext FTP → **High** citing RMiT cryptography `S 10.21`;
weak SSH MAC → **Medium** citing `S 10.20`; TCP/ICMP timestamps → **Low** (no
applicable clause).

*Grounding:* operationalises the report's "Regulatory-Weighted Risk Scoring"
(Part 1 §2.2.5); FIPS 199 high-water-mark justifies reserving the top band for the
critical + financial/PII combination. `--explain` shows the LLM's clause rationale
and the reason for every raise/lower. **Mapping now requires an LLM** (local
Granite by default — the privacy NFR holds); `finvap doctor` reports its readiness.

---

## 10. References

- FIRST, *CVSS v3.1 Specification Document* — Environmental Metric Group.
- FIRST, *CVSS v4.0 Specification Document* — Environmental (Modified Base
  Metrics) and Security Requirements.
- NIST FIPS 199, *Standards for Security Categorization of Federal Information and
  Information Systems*.
- NIST SP 800-60, *Guide for Mapping Types of Information and Information Systems
  to Security Categories*.
- BNM *Risk Management in Technology (RMiT)*; MAS *Technology Risk Management
  (TRM)* Guidelines — the regulatory frameworks Objective 1 maps findings to.
