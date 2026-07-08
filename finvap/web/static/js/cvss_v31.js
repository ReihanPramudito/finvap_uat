/* ------------------------------------------------------------------
 * CVSS v3.1 calculator — pure-client implementation.
 * Ported from VibeDocs (MIT © 2026 Brendon Teo); the 2.0 calculator and the
 * CSP-blocked runtime <style> injection were dropped — all styling lives in
 * finvap.css. Follows the FIRST.org v3.1 specification.
 *
 *   mountCvssV31Calculator(hostEl, onChange?)
 *
 * Supports the FULL spec — Base, Temporal AND Environmental groups (Temporal /
 * Environmental collapsed by default). `onChange(vector, baseScore, severity,
 * extra)` fires on every change; `extra` carries temporal/environmental/overall.
 * ------------------------------------------------------------------ */

// Build a metric group's DOM. Each metric is a labelled row of buttons.
function _cvssBuildGroup(state, metrics, onSet){
  const metricsEl = document.createElement("div");
  metricsEl.className = "cvss-metrics";
  for (const [key, label, options] of metrics){
    const row = document.createElement("div");
    row.className = "cvss-metric";
    row.innerHTML = `<label>${label} <code class="muted small">(${key})</code></label>`;
    const btnRow = document.createElement("div");
    btnRow.className = "cvss-options";
    for (const [v, vLabel] of options){
      const b = document.createElement("button");
      b.type = "button";
      b.className = "cvss-opt";
      b.textContent = vLabel;
      b.dataset.v = v;
      if (state[key] === v) b.classList.add("active");
      b.addEventListener("click", () => {
        state[key] = v;
        for (const sib of btnRow.querySelectorAll(".cvss-opt"))
          sib.classList.toggle("active", sib.dataset.v === v);
        if (onSet) onSet(key, v);
      });
      btnRow.appendChild(b);
    }
    row.appendChild(btnRow);
    metricsEl.appendChild(row);
  }
  return metricsEl;
}

// Build a collapsible section for Temporal / Environmental.
function _cvssBuildCollapse(titleText, helperText){
  const section = document.createElement("section");
  section.className = "cvss-group is-collapsed";
  const header = document.createElement("button");
  header.type = "button";
  header.className = "cvss-group-h";
  header.innerHTML =
    `<span class="cvss-group-caret" aria-hidden="true">▸</span>` +
    `<span class="cvss-group-title">${titleText}</span>` +
    (helperText
      ? `<span class="cvss-group-help muted small">${helperText}</span>`
      : "");
  const body = document.createElement("div");
  body.className = "cvss-group-body";
  header.addEventListener("click", () => {
    section.classList.toggle("is-collapsed");
    header.querySelector(".cvss-group-caret").textContent =
      section.classList.contains("is-collapsed") ? "▸" : "▾";
  });
  section.appendChild(header);
  section.appendChild(body);
  return { section, body };
}

// Base metric definitions. Order matters — it determines vector order.
const _CVSS31_METRICS = [
  ["AV", "Attack Vector",     [["N","Network"],["A","Adjacent"],["L","Local"],["P","Physical"]]],
  ["AC", "Attack Complexity", [["L","Low"],["H","High"]]],
  ["PR", "Privileges Required", [["N","None"],["L","Low"],["H","High"]]],
  ["UI", "User Interaction",  [["N","None"],["R","Required"]]],
  ["S",  "Scope",             [["U","Unchanged"],["C","Changed"]]],
  ["C",  "Confidentiality",   [["N","None"],["L","Low"],["H","High"]]],
  ["I",  "Integrity",         [["N","None"],["L","Low"],["H","High"]]],
  ["A",  "Availability",      [["N","None"],["L","Low"],["H","High"]]],
];

const _CVSS31_TEMPORAL = [
  ["E",  "Exploit Code Maturity",
    [["X","Not Defined"],["U","Unproven"],["P","Proof-of-Concept"],["F","Functional"],["H","High"]]],
  ["RL", "Remediation Level",
    [["X","Not Defined"],["O","Official Fix"],["T","Temporary Fix"],["W","Workaround"],["U","Unavailable"]]],
  ["RC", "Report Confidence",
    [["X","Not Defined"],["U","Unknown"],["R","Reasonable"],["C","Confirmed"]]],
];

const _CVSS31_ENV_REQ = [
  ["CR", "Confidentiality Requirement",
    [["X","Not Defined"],["L","Low"],["M","Medium"],["H","High"]]],
  ["IR", "Integrity Requirement",
    [["X","Not Defined"],["L","Low"],["M","Medium"],["H","High"]]],
  ["AR", "Availability Requirement",
    [["X","Not Defined"],["L","Low"],["M","Medium"],["H","High"]]],
];

const _CVSS31_ENV_MODIFIED = [
  ["MAV","Modified Attack Vector",
    [["X","Not Defined"],["N","Network"],["A","Adjacent"],["L","Local"],["P","Physical"]]],
  ["MAC","Modified Attack Complexity",
    [["X","Not Defined"],["L","Low"],["H","High"]]],
  ["MPR","Modified Privileges Required",
    [["X","Not Defined"],["N","None"],["L","Low"],["H","High"]]],
  ["MUI","Modified User Interaction",
    [["X","Not Defined"],["N","None"],["R","Required"]]],
  ["MS", "Modified Scope",
    [["X","Not Defined"],["U","Unchanged"],["C","Changed"]]],
  ["MC", "Modified Confidentiality",
    [["X","Not Defined"],["N","None"],["L","Low"],["H","High"]]],
  ["MI", "Modified Integrity",
    [["X","Not Defined"],["N","None"],["L","Low"],["H","High"]]],
  ["MA", "Modified Availability",
    [["X","Not Defined"],["N","None"],["L","Low"],["H","High"]]],
];

const _CVSS31_W = {
  AV:{N:0.85,A:0.62,L:0.55,P:0.2},
  AC:{L:0.77,H:0.44},
  PR:{ U:{N:0.85,L:0.62,H:0.27}, C:{N:0.85,L:0.68,H:0.5} },
  UI:{N:0.85,R:0.62},
  C: {N:0,L:0.22,H:0.56},
  I: {N:0,L:0.22,H:0.56},
  A: {N:0,L:0.22,H:0.56},
  E: {X:1.0, U:0.91, P:0.94, F:0.97, H:1.0},
  RL:{X:1.0, O:0.95, T:0.96, W:0.97, U:1.0},
  RC:{X:1.0, U:0.92, R:0.96, C:1.0},
  CR:{X:1.0, L:0.5, M:1.0, H:1.5},
  IR:{X:1.0, L:0.5, M:1.0, H:1.5},
  AR:{X:1.0, L:0.5, M:1.0, H:1.5},
};

function _cvss31_mod(state, modKey, baseKey, table){
  const v = state[modKey];
  const useBase = !v || v === "X";
  const k = useBase ? state[baseKey] : v;
  return table[k];
}

// CVSS 3.1 spec roundup — multiplies by 100,000, ceils, divides back.
function _cvss31_roundUp(x){
  const i = Math.round(x * 100000);
  if (i % 10000 === 0) return i / 100000;
  return (Math.floor(i / 10000) + 1) / 10;
}

function _cvss31_severity(score){
  if (score >= 9.0) return "Critical";
  if (score >= 7.0) return "High";
  if (score >= 4.0) return "Medium";
  if (score >  0)   return "Low";
  return "None";
}

// Returns { base, temporal, environmental, overall, severity, vector } or null.
function _cvss31_score(m){
  for (const [k] of _CVSS31_METRICS) if (!m[k]) return null;

  // ---- Base ----
  const Iss = 1 - (1 - _CVSS31_W.C[m.C]) * (1 - _CVSS31_W.I[m.I]) * (1 - _CVSS31_W.A[m.A]);
  let Impact;
  if (m.S === "U") Impact = 6.42 * Iss;
  else             Impact = 7.52 * (Iss - 0.029) - 3.25 * Math.pow(Iss - 0.02, 15);

  const PR = _CVSS31_W.PR[m.S][m.PR];
  const Exploitability = 8.22 * _CVSS31_W.AV[m.AV] * _CVSS31_W.AC[m.AC] * PR * _CVSS31_W.UI[m.UI];

  let base = 0;
  if (Impact > 0){
    if (m.S === "U") base = _cvss31_roundUp(Math.min(Impact + Exploitability, 10));
    else             base = _cvss31_roundUp(Math.min(1.08 * (Impact + Exploitability), 10));
  }

  // ---- Temporal ----
  const E  = _CVSS31_W.E [m.E  || "X"];
  const RL = _CVSS31_W.RL[m.RL || "X"];
  const RC = _CVSS31_W.RC[m.RC || "X"];
  const temporal = _cvss31_roundUp(base * E * RL * RC);
  const temporalSet = (m.E && m.E !== "X") || (m.RL && m.RL !== "X") || (m.RC && m.RC !== "X");

  // ---- Environmental ----
  const CR = _CVSS31_W.CR[m.CR || "X"];
  const IR = _CVSS31_W.IR[m.IR || "X"];
  const AR = _CVSS31_W.AR[m.AR || "X"];

  const MAVw = _cvss31_mod(m, "MAV", "AV", _CVSS31_W.AV);
  const MACw = _cvss31_mod(m, "MAC", "AC", _CVSS31_W.AC);
  const MUIw = _cvss31_mod(m, "MUI", "UI", _CVSS31_W.UI);
  const MS   = (m.MS && m.MS !== "X") ? m.MS : m.S;
  const PRv  = (m.MPR && m.MPR !== "X") ? m.MPR : m.PR;
  const MPRw = _CVSS31_W.PR[MS][PRv];
  const MCw  = _cvss31_mod(m, "MC", "C", _CVSS31_W.C);
  const MIw  = _cvss31_mod(m, "MI", "I", _CVSS31_W.I);
  const MAw  = _cvss31_mod(m, "MA", "A", _CVSS31_W.A);

  const MISS = Math.min(
    1 - (1 - CR * MCw) * (1 - IR * MIw) * (1 - AR * MAw),
    0.915
  );
  let ModImpact;
  if (MS === "U") ModImpact = 6.42 * MISS;
  else            ModImpact = 7.52 * (MISS - 0.029) - 3.25 * Math.pow(MISS * 0.9731 - 0.02, 13);
  const ModExploitability = 8.22 * MAVw * MACw * MPRw * MUIw;

  let environmental = 0;
  if (ModImpact > 0){
    if (MS === "U") environmental = _cvss31_roundUp(Math.min(ModImpact + ModExploitability, 10));
    else            environmental = _cvss31_roundUp(Math.min(1.08 * (ModImpact + ModExploitability), 10));
    environmental = _cvss31_roundUp(environmental * E * RL * RC);
  }
  const envSet = temporalSet ||
    (m.CR  && m.CR  !== "X") || (m.IR && m.IR !== "X") || (m.AR && m.AR !== "X") ||
    (m.MAV && m.MAV !== "X") || (m.MAC && m.MAC !== "X") || (m.MPR && m.MPR !== "X") ||
    (m.MUI && m.MUI !== "X") || (m.MS  && m.MS  !== "X") ||
    (m.MC  && m.MC  !== "X") || (m.MI  && m.MI  !== "X") || (m.MA  && m.MA  !== "X");

  // ---- Vector + headline severity ----
  const overall = envSet ? environmental : (temporalSet ? temporal : base);
  const severity = _cvss31_severity(overall);

  const parts = ["CVSS:3.1"];
  for (const [k] of _CVSS31_METRICS) parts.push(`${k}:${m[k]}`);
  for (const [k] of _CVSS31_TEMPORAL) if (m[k] && m[k] !== "X") parts.push(`${k}:${m[k]}`);
  for (const [k] of _CVSS31_ENV_REQ)      if (m[k] && m[k] !== "X") parts.push(`${k}:${m[k]}`);
  for (const [k] of _CVSS31_ENV_MODIFIED) if (m[k] && m[k] !== "X") parts.push(`${k}:${m[k]}`);
  const vector = parts.join("/");

  return {
    base,
    temporal,        temporal_set: temporalSet,
    environmental,   environmental_set: envSet,
    overall,
    severity,
    vector,
  };
}

function mountCvssV31Calculator(host, onChange){
  if (!host) return;
  host.innerHTML = "";
  const m = {};

  const wrap = document.createElement("div");
  wrap.className = "cvss-wrap";
  const groupsCol = document.createElement("div");
  groupsCol.className = "cvss-groups";

  // --- Base (always visible) ---
  const baseGroup = document.createElement("section");
  baseGroup.className = "cvss-group";
  const baseHeader = document.createElement("div");
  baseHeader.className = "cvss-group-h";
  baseHeader.style.cursor = "default";
  baseHeader.innerHTML =
    `<span class="cvss-group-title">Base Metrics</span>` +
    `<span class="cvss-group-help muted small">Always required — describe the vulnerability itself</span>`;
  const baseBody = document.createElement("div");
  baseBody.className = "cvss-group-body";
  baseBody.appendChild(_cvssBuildGroup(m, _CVSS31_METRICS, () => update()));
  baseGroup.appendChild(baseHeader);
  baseGroup.appendChild(baseBody);
  groupsCol.appendChild(baseGroup);

  // --- Temporal (collapsed) ---
  const temporal = _cvssBuildCollapse(
    "Temporal Metrics",
    "Optional — adjust as exploit/remediation status evolves"
  );
  temporal.body.appendChild(_cvssBuildGroup(m, _CVSS31_TEMPORAL, () => update()));
  groupsCol.appendChild(temporal.section);

  // --- Environmental (collapsed) ---
  const env = _cvssBuildCollapse(
    "Environmental Metrics",
    "Optional — tailor to the deployment's actual exposure"
  );
  const reqHeading = document.createElement("p");
  reqHeading.className = "muted small";
  reqHeading.style.margin = "0 0 6px";
  reqHeading.textContent = "Security Requirements (CIA importance to this deployment)";
  env.body.appendChild(reqHeading);
  env.body.appendChild(_cvssBuildGroup(m, _CVSS31_ENV_REQ, () => update()));

  const modHeading = document.createElement("p");
  modHeading.className = "muted small";
  modHeading.style.margin = "12px 0 6px";
  modHeading.textContent = "Modified Base Metrics (re-score the base for this environment)";
  env.body.appendChild(modHeading);
  env.body.appendChild(_cvssBuildGroup(m, _CVSS31_ENV_MODIFIED, () => update()));

  groupsCol.appendChild(env.section);
  wrap.appendChild(groupsCol);

  // --- Output panel ---
  const out = document.createElement("div");
  out.className = "cvss-output";
  out.innerHTML = `
    <div class="cvss-score-wrap">
      <span class="cvss-score" id="v31-score">—</span>
      <span class="cvss-sev"   id="v31-sev"></span>
    </div>
    <div class="cvss-vector-wrap">
      <input id="v31-vec" type="text" readonly placeholder="Pick metrics to build the vector…">
      <button id="v31-copy" type="button" class="btn tiny">Copy</button>
    </div>
    <div class="cvss-extra-scores" id="v31-extra" hidden></div>`;
  wrap.appendChild(out);
  host.appendChild(wrap);

  function update(){
    const r = _cvss31_score(m);
    const scoreEl = host.querySelector("#v31-score");
    const sevEl   = host.querySelector("#v31-sev");
    const vecEl   = host.querySelector("#v31-vec");
    const extraEl = host.querySelector("#v31-extra");
    if (!r){
      scoreEl.textContent = "—";
      sevEl.textContent = "";
      sevEl.className = "cvss-sev";
      vecEl.value = "";
      extraEl.hidden = true;
      extraEl.innerHTML = "";
      if (onChange) onChange(null, null, null, null);
      return;
    }
    scoreEl.textContent = r.overall.toFixed(1);
    sevEl.textContent   = r.severity;
    sevEl.className     = "cvss-sev sev-" + r.severity.toLowerCase();
    vecEl.value         = r.vector;

    const lines = [];
    lines.push(`<span>Base <strong>${r.base.toFixed(1)}</strong></span>`);
    if (r.temporal_set || r.environmental_set){
      lines.push(`<span>Temporal <strong>${r.temporal.toFixed(1)}</strong></span>`);
    }
    if (r.environmental_set){
      lines.push(`<span>Environmental <strong>${r.environmental.toFixed(1)}</strong></span>`);
    }
    extraEl.hidden = (lines.length <= 1);
    extraEl.innerHTML = lines.join("");

    if (onChange){
      onChange(r.vector, r.base, r.severity, {
        temporal_score:      r.temporal,
        environmental_score: r.environmental,
        overall_score:       r.overall,
      });
    }
  }

  host.querySelector("#v31-copy").addEventListener("click", async () => {
    const v = host.querySelector("#v31-vec").value;
    if (!v) return;
    try {
      await navigator.clipboard.writeText(v);
      const b = host.querySelector("#v31-copy"); const t = b.textContent;
      b.textContent = "✓ Copied"; setTimeout(() => b.textContent = t, 1200);
    } catch(_) {}
  });

  update();
}

window.mountCvssV31Calculator = mountCvssV31Calculator;
