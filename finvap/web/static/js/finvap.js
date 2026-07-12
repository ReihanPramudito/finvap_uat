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

  // Keyboard: Enter on a focused [data-href] element (e.g. an audit row with tabindex) navigates.
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Enter") return;
    if (e.target.closest("a, button, input, select, textarea")) return;
    var el = e.target.closest("[data-href]");
    if (el) window.location = el.getAttribute("data-href");
  });

  // Close the topbar project menu when clicking anywhere outside it.
  document.addEventListener("click", function (e) {
    document.querySelectorAll("details.project-menu[open], details.del[open]").forEach(function (d) {
      if (!d.contains(e.target)) d.removeAttribute("open");
    });
  });

  // Tag-guide popovers act like an accordion: opening one closes the others.
  // `toggle` doesn't bubble, so listen in the capture phase.
  document.addEventListener("toggle", function (e) {
    var d = e.target;
    if (!d.open || !d.matches || !d.matches("details.tag-guide")) return;
    document.querySelectorAll("details.tag-guide[open]").forEach(function (o) {
      if (o !== d) o.removeAttribute("open");
    });
  }, true);

  // Clicking outside an open tag-guide popover closes it.
  document.addEventListener("click", function (e) {
    document.querySelectorAll("details.tag-guide[open]").forEach(function (d) {
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

  // Risk-model L/M/H pickers: light the "changed" marker + tint the select whenever
  // its value differs from the shipped default (data-default). Delegated + re-synced
  // after htmx swaps so it survives Save / Reset re-renders.
  function syncLvl(sel) {
    if (!sel.classList.contains("lvl") || !sel.hasAttribute("data-default")) return;
    var changed = sel.value !== sel.getAttribute("data-default");
    sel.classList.toggle("changed", changed);
    var cell = sel.closest(".lvl-cell");
    if (cell) cell.classList.toggle("is-changed", changed);
  }
  function syncAllLvl(root) {
    (root || document).querySelectorAll("select.lvl[data-default]").forEach(syncLvl);
  }
  document.addEventListener("change", function (e) {
    if (e.target && e.target.matches && e.target.matches("select.lvl")) syncLvl(e.target);
  });
  document.body.addEventListener("htmx:afterSwap", function (e) { syncAllLvl(e.target); });
  syncAllLvl();

  // Report-input screenshots: show a local preview when an image is picked (before upload).
  // Delegated so it survives HTMX swaps of #finding-body.
  document.addEventListener("change", function (e) {
    var inp = e.target;
    if (!inp.matches || !inp.matches('input[type="file"][data-preview]')) return;
    var box = document.getElementById(inp.dataset.preview);
    if (!box) return;
    var img = box.querySelector("img");
    var file = inp.files && inp.files[0];
    if (file && file.type.indexOf("image/") === 0) {
      img.src = URL.createObjectURL(file);
      box.classList.add("has-img");
    } else {
      box.classList.remove("has-img");
    }
  });
})();
