/* CVSS calculator page glue — mounts the 4.0 + 3.1 widgets and drives the tabs.
   Moved out of an inline <script> so it runs under FinVAP's strict CSP (no nonce).
   Loaded after cvss_v4.js and cvss_v31.js so the mount functions exist. */
(function () {
  "use strict";
  function init() {
    var v4  = document.getElementById("standalone-cvss-v4");
    var v31 = document.getElementById("standalone-cvss-v31");
    if (v4  && window.mountCvssCalculator)    window.mountCvssCalculator(v4);
    if (v31 && window.mountCvssV31Calculator) window.mountCvssV31Calculator(v31);

    var tabs = document.querySelectorAll(".cvss-tab");
    var panes = {
      v4:  document.getElementById("pane-v4"),
      v31: document.getElementById("pane-v31"),
    };
    tabs.forEach(function (t) {
      t.addEventListener("click", function () {
        tabs.forEach(function (x) {
          x.classList.toggle("active", x === t);
          x.setAttribute("aria-selected", x === t ? "true" : "false");
        });
        Object.keys(panes).forEach(function (k) {
          if (panes[k]) panes[k].classList.toggle("is-hidden", k !== t.dataset.tab);
        });
      });
    });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
