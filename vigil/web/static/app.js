// Small progressive enhancements. Every page works without JavaScript.
(function () {
  "use strict";

  // Live mode: refresh every 15 s, only while the tab is visible, remembered per browser.
  const box = document.getElementById("live");
  let timer = null;
  const store = {
    get: (k) => { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set: (k, v) => { try { localStorage.setItem(k, v); } catch (e) { /* storage off */ } },
  };
  function schedule() {
    clearTimeout(timer);
    document.body.classList.toggle("is-live", box.checked);
    if (box.checked && document.visibilityState === "visible") {
      timer = setTimeout(() => location.reload(), 15000);
    }
  }
  if (box) {
    box.checked = store.get("vigil-live") === "1";
    box.addEventListener("change", () => { store.set("vigil-live", box.checked ? "1" : "0"); schedule(); });
    document.addEventListener("visibilitychange", schedule);
    schedule();
  }

  // "/" jumps to the IP search, like most dashboards.
  const search = document.getElementById("ip-search");
  document.addEventListener("keydown", (e) => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
    if (e.key === "/" && !typing && search) { e.preventDefault(); search.focus(); }
  });

  // Whole table rows are clickable (links inside them still work normally).
  document.querySelectorAll("tr[data-href]").forEach((row) => {
    row.classList.add("row-link");
    row.addEventListener("click", (e) => {
      if (e.target.closest("a, input, button, label, select")) return;
      location.href = row.dataset.href;
    });
  });

  // Select-all checkbox and the bulk-action bar.
  const all = document.getElementById("select-all");
  const boxes = () => document.querySelectorAll("input.pick");
  const bulk = document.querySelector(".bulk");
  function refreshBulk() {
    if (!bulk) return;
    const n = Array.from(boxes()).filter((b) => b.checked).length;
    bulk.querySelectorAll("button").forEach((b) => { b.disabled = n === 0; });
    const label = bulk.querySelector(".picked");
    if (label) label.textContent = n ? n + " selected" : "";
  }
  if (all) all.addEventListener("change", () => { boxes().forEach((b) => { b.checked = all.checked; }); refreshBulk(); });
  boxes().forEach((b) => b.addEventListener("change", refreshBulk));
  refreshBulk();

  // Filter dropdowns apply immediately.
  document.querySelectorAll("form.filters select").forEach((s) => {
    s.addEventListener("change", () => s.form.submit());
  });
})();
