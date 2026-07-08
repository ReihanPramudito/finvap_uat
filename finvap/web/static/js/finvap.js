// FinVAP reporting UI — client glue.
// Deliberately tiny: the UI is server-rendered (Jinja) and progressively
// enhanced with HTMX. Loaded as a same-origin file so it works under the strict
// CSP (inline handlers are blocked; delegated listeners here are not).
(function () {
  "use strict";

  // Make any element with data-href behave like a link (e.g. whole table rows).
  // Ignores clicks on real controls inside the row so buttons/links still work.
  document.addEventListener("click", function (e) {
    if (e.target.closest("a, button, input, select, textarea, label")) return;
    var el = e.target.closest("[data-href]");
    if (el) window.location = el.getAttribute("data-href");
  });

  // Close the topbar project menu when clicking anywhere outside it.
  document.addEventListener("click", function (e) {
    document.querySelectorAll("details.project-menu[open]").forEach(function (d) {
      if (!d.contains(e.target)) d.removeAttribute("open");
    });
  });

  // Model dropdown: reveal the free-text field only when "custom…" is chosen.
  // Delegated so it survives HTMX swaps of the model field (provider change).
  document.addEventListener("change", function (e) {
    if (e.target.id !== "model-select") return;
    var custom = document.getElementById("model-custom");
    if (!custom) return;
    var on = e.target.value === "__custom__";
    custom.hidden = !on;
    if (on) custom.focus();
  });

  // Model discovery (GET /models) can time out or drop while a heavy job hogs
  // the machine, and HTMX never retries — without this the field would sit on
  // "discovering models…" forever. Swap in an inline retry link instead.
  function modelDiscoveryFailed(evt) {
    var cfg = evt.detail && evt.detail.requestConfig;
    if (!cfg || String(cfg.path).indexOf("/models") !== 0) return;
    var field = document.getElementById("model-field");
    if (!field) return;
    field.innerHTML = '<span class="muted tiny">model discovery failed — ' +
                      '<a href="#" id="model-retry">retry</a></span>';
  }
  ["htmx:timeout", "htmx:sendError", "htmx:responseError"].forEach(function (ev) {
    document.body.addEventListener(ev, modelDiscoveryFailed);
  });
  document.addEventListener("click", function (e) {
    if (e.target.id !== "model-retry") return;
    e.preventDefault();
    var field = document.getElementById("model-field");
    var prov = document.querySelector("[name=provider]");
    field.innerHTML = '<span class="muted tiny">discovering models…</span>';
    htmx.ajax("GET", "/models", {
      target: "#model-field", swap: "innerHTML",
      values: { provider: prov ? prov.value : "ollama" },
    });
  });
})();
