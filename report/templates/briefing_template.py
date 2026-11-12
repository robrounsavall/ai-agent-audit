"""Shared CSS extras and the small script for the report v2 briefing.

build-briefing.py inlines briefing.css plus REPORT_V2_CSS and REPORT_V2_JS.
The page is one offline HTML file: no font CDN, no external assets.

HTML_SHELL is the previous long-scroll layout. Report v2 does not fill it.
"""

HTML_SHELL = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
  <title>%%TITLE%%</title>
  <style>
%%CSS%%
  </style>
</head>
<body>

<!-- ============ NAV ============ -->
<nav class="nav">
  <div class="nav-inner">
    <a href="#top" class="brand">
      <span class="brand-mark"></span>
      <span>aiscan</span>
    </a>
    <div class="nav-links">
      <a href="#executive">Executive</a>
      <a href="#posture">Posture</a>
      <a href="#findings">Findings</a>
      <a href="#permissions">Permissions</a>
      <a href="#chat">Chat</a>
      <a href="#secrets-git">Secrets &amp; Git</a>
      %%CLOUD_AGENTS_NAV%%
      <a href="#methodology">Methodology</a>
      <a href="#appendix">Appendix</a>
    </div>
    <span class="nav-cta">
      <span class="dot"></span>
      <span>aiscan · %%ENGAGEMENT_DATE%%</span>
    </span>
  </div>
</nav>

<!-- ============ HERO ============ -->
<section id="top" class="hero">
  <div class="hero-inner">
    <div class="hero-text">
      <div class="mono-eyebrow">
        <span>/00</span><span>·</span><span>ENDPOINT POSTURE BRIEFING — CONFIDENTIAL</span>
      </div>
      <h1 class="display">AI Coding Tool<br/>Exposure<span class="display-period">.</span></h1>
      <p class="lede">%%HERO_LEDE%%</p>
      <ul class="meta-list">
        <li><span class="meta-dash">—</span>Customer · <strong style="color: var(--fg);">%%CUSTOMER%%</strong></li>
        <li><span class="meta-dash">—</span>Engagement · %%ENGAGEMENT_DATE%%</li>
        <li><span class="meta-dash">—</span>Operator · %%OPERATOR%%</li>
        <li><span class="meta-dash">—</span>Manifest SHA-256 · %%MANIFEST_HASH_SHORT%%…</li>
      </ul>
    </div>

    <div class="hero-aside">
      <div class="evidence-panel-head">
        <span>01 · EVIDENCE STATUS</span>
        <strong>Local endpoint collection</strong>
      </div>
%%COVER_STATUS%%
    </div>
  </div>
</section>

<!-- ============ EXECUTIVE SUMMARY ============ -->
<section id="executive" class="section">
  <div class="wrap">
    <header class="sh">
      <div class="kicker">
        <span class="num">/01</span>
        <span class="kicker-label">EXECUTIVE SUMMARY</span>
      </div>
      <h2 class="h2">%%EXECUTIVE_HEADLINE%%</h2>
      <p class="sub">%%EXECUTIVE_SUB%%</p>
    </header>

    <div class="sev-strip">
      <div>
        <div class="lbl">Critical</div>
        <div class="v red">%%COUNT_CRITICAL%%</div>
        <div class="note">needs action</div>
      </div>
      <div>
        <div class="lbl">High</div>
        <div class="v amber">%%COUNT_HIGH%%</div>
        <div class="note">high priority</div>
      </div>
      <div>
        <div class="lbl">Medium</div>
        <div class="v yellow">%%COUNT_MEDIUM%%</div>
        <div class="note">policy / backlog</div>
      </div>
      <div>
        <div class="lbl">Low</div>
        <div class="v green">%%COUNT_LOW%%</div>
        <div class="note">informational</div>
      </div>
    </div>

    <div class="sev-bar">
      <div class="hdr">
        <span>severity distribution · n = %%FINDINGS_TOTAL%%</span>
        <span>%%SEVERITY_BAR_NOTE%%</span>
      </div>
      <div class="sev-bar-track">
%%SEVERITY_BAR_SEGMENTS%%
      </div>
    </div>

    <div class="cases" style="margin-top: 56px;">
%%RISK_REGISTER%%
    </div>
  </div>
</section>

<!-- ============ POSTURE AT A GLANCE ============ -->
<section id="posture" class="section">
  <div class="wrap">
    <header class="sh">
      <div class="kicker">
        <span class="num">/02</span>
        <span class="kicker-label">POSTURE AT A GLANCE</span>
      </div>
      <h2 class="h2">Where each tool stands.</h2>
      <p class="sub">Detected tools, highest observed risk, and permission, approval, and activity counts, side by side.</p>
    </header>
    %%POSTURE_GRID%%
  </div>
</section>

<!-- ============ FINDINGS ============ -->
<section id="findings" class="section">
  <div class="wrap">
    <header class="sh">
      <div class="kicker">
        <span class="num">/03</span>
        <span class="kicker-label">FINDINGS</span>
      </div>
      <h2 class="h2">%%FINDINGS_TOTAL%% findings across %%FINDINGS_CATEGORIES%% categories.</h2>
      <p class="sub">Tabs are exposure categories. Use the filter to search across titles, samples, and tags. Per-hit secrets are grouped — full per-row evidence is in the appendix.</p>
    </header>

    <div class="filter">
      <input id="findings-search" type="search" placeholder="filter by title, sample text, or tag…" />
    </div>

    <div class="tab-bar" id="findings-tabs">%%FINDINGS_TABS%%</div>
    %%FINDINGS_PANELS%%
  </div>
</section>

<!-- ============ PERMISSIONS ============ -->
<section id="permissions" class="section section--alt">
  <div class="wrap">
    <header class="sh">
      <div class="kicker">
        <span class="num">/04</span>
        <span class="kicker-label">PERMISSIONS INVENTORY</span>
      </div>
      <h2 class="h2">Configured permission surface.</h2>
      <p class="sub">Settings-derived allow rules, MCP registrations, and observed approval decisions grouped by platform.</p>
    </header>

%%PERMISSIONS_SECTION%%
  </div>
</section>

<!-- ============ CHAT EXPOSURE ============ -->
<section id="chat" class="section">
  <div class="wrap">
    <header class="sh">
      <div class="kicker">
        <span class="num">/05</span>
        <span class="kicker-label">CHAT EXPOSURE</span>
      </div>
      <h2 class="h2">Plaintext transcripts on the developer endpoint.</h2>
      <p class="sub">Transcript text stays in <span class="mono">raw/</span>. Only counts and retention metadata land here. The 90-day mark is the stated policy.</p>
    </header>

%%CHAT_SECTION%%
  </div>
</section>

<!-- ============ SECRETS & GIT POSTURE ============ -->
<section id="secrets-git" class="section section--alt">
  <div class="wrap">
    <header class="sh">
      <div class="kicker">
        <span class="num">/06</span>
        <span class="kicker-label">SECRETS &amp; GIT POSTURE</span>
      </div>
      <h2 class="h2">Secret scanning and git posture.</h2>
      <p class="sub">The secrets scanner (Betterleaks, gitleaks, or trufflehog) scans chat exports and repo roots for credential-shaped strings; secret samples in evidence are shortened, and full hits stay in <span class="mono">raw/secrets-scan/findings.csv</span>. Other paths are masked only when the scan used -Redact. Git posture checks local repos for .env in history, hook presence, .gitignore coverage, and large blobs.</p>
    </header>

    <div class="two-col">
      <div class="panel">
        <h3>Secrets scan · %%SECRETS_TOTAL_HITS%% hits</h3>
%%SECRETS_SECTION%%
      </div>

      <div class="panel">
        <h3>Git posture · %%GIT_REPOS%% repos</h3>
%%GIT_SECTION%%
      </div>
    </div>
  </div>
</section>

%%CLOUD_AGENTS_SECTION%%

<!-- ============ METHODOLOGY ============ -->
<section id="methodology" class="section section--alt">
  <div class="wrap">
    <header class="sh">
      <div class="kicker">
        <span class="num">/07</span>
        <span class="kicker-label">METHODOLOGY &amp; ATTESTATION</span>
      </div>
      <h2 class="h2">How the evidence was produced.</h2>
      <p class="sub">Collectors read local endpoint state and wrote evidence into this output directory. Raw evidence remains local; anything you share should follow the evidence contract in <span class="mono">SCHEMA.md</span>.</p>
    </header>

%%COLLECTION_SCOPE%%

    <div class="table-wrap" style="max-height: none;"><table>
      <thead><tr><th>Collector</th><th>Work performed</th><th>Completed at</th><th>Duration</th><th>Version</th><th>Status</th></tr></thead>
      <tbody>%%COLLECTORS_TABLE%%</tbody>
    </table></div>

    <div class="attestation">
      <p><strong style="color: var(--green); font-weight: 500;">Manifest SHA-256</strong> (first 16 chars · full hashes in bundled manifest): <code>%%MANIFEST_HASH_SHORT%%</code></p>
      <p>Raw evidence remains in the local output directory; shareable bundles should be sanitized per <code>SCHEMA.md</code>.</p>
      <div class="sig-line">%%OPERATOR%% · %%GENERATED_AT%%</div>
    </div>
  </div>
</section>

<!-- ============ APPENDIX ============ -->
<section id="appendix" class="section">
  <div class="wrap">
    <header class="sh">
      <div class="kicker">
        <span class="num">/08</span>
        <span class="kicker-label">APPENDIX — EVIDENCE INDEX</span>
      </div>
      <h2 class="h2">Where to find the raw evidence behind each finding.</h2>
      <p class="sub">Per-hit secret-scanner rows are aggregated by rule type. Identical findings collapse into a single row with a hit count; full per-row detail lives in the linked CSV.</p>
    </header>

%%APPENDIX_NOTE%%

    <div class="table-wrap appendix-table" style="max-height: none;">
      <table>
        <thead>
          <tr>
            <th style="width: 90px;">Severity</th>
            <th>Finding</th>
            <th style="width: 100px;">Hits</th>
            <th>Evidence reference</th>
          </tr>
        </thead>
        <tbody>
%%APPENDIX_GROUPED_ROWS%%
        </tbody>
      </table>
    </div>
  </div>
</section>

<!-- ============ FOOTER ============ -->
<footer class="footer">
  <div class="foot-inner">
    <span>aiscan briefing · %%CUSTOMER%%</span>
    <span class="foot-meta">
      <span>end of report · %%ENGAGEMENT_DATE%%</span>
    </span>
  </div>
</footer>

<script>
(function () {
  // Tabs
  const tabBtns = document.querySelectorAll('#findings-tabs .tab-btn');
  const tabPanels = document.querySelectorAll('[data-tab].tab-panel');
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.tab;
      tabBtns.forEach(b => b.classList.toggle('active', b === btn));
      tabPanels.forEach(p => p.classList.toggle('active', p.dataset.tab === target));
    });
  });

  // Findings search
  const searchEl = document.getElementById('findings-search');
  if (searchEl) {
    searchEl.addEventListener('input', () => {
      const q = searchEl.value.toLowerCase();
      document.querySelectorAll('.frow').forEach(row => {
        const text = (row.textContent || '').toLowerCase();
        row.style.display = (!q || text.includes(q)) ? '' : 'none';
      });
    });
  }
})();
</script>
</body>
</html>
"""

# System fonts only. Inter / IBM Plex are named in briefing.css as a first
# choice; these overrides win so a machine without those faces still renders.
REPORT_V2_CSS = """
:root {
  --f-sans: ui-sans-serif, -apple-system, "Segoe UI", "Helvetica Neue", sans-serif;
  --f-mono: ui-monospace, "Cascadia Mono", "Cascadia Code", Consolas, monospace;
  --f-display: ui-sans-serif, "Segoe UI", sans-serif;
  --f-serif: ui-sans-serif, "Segoe UI", sans-serif;
  --section-y: 36px;
}
.report-summary { padding: 20px 0 12px; }
.report-summary .display {
  font-size: clamp(32px, 4vw, 48px);
  margin: 0 0 20px;
}
.report-summary .lede { margin-top: 0; margin-bottom: 20px; }
.report-summary .mono-eyebrow { margin-bottom: 12px; }
html { scroll-padding-top: calc(var(--tabbar-h, 56px) + 8px); }
h1, h2, h3, .agents-block, .section { scroll-margin-top: calc(var(--tabbar-h, 56px) + 8px); }
.summary-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 14px;
  margin: 22px 0 8px;
}
.summary-card {
  background: var(--bg-card);
  border: 1px solid var(--line);
  border-radius: var(--radius);
  padding: 14px 16px 16px;
}
.summary-card h3 {
  margin: 0 0 8px;
  font-size: 12px;
  letter-spacing: .06em;
  text-transform: uppercase;
  color: var(--fg-3);
  font-weight: 600;
}
.summary-card p { margin: 0; color: var(--fg-2); }
.agent-status { list-style: none; margin: 0; padding: 0; }
.agent-status li {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  padding: 3px 0;
  border-bottom: 1px solid var(--line);
  font-size: 14px;
}
.agent-status li:last-child { border-bottom: 0; }
.page-tablist {
  position: sticky;
  top: 0;
  z-index: 40;
  background: var(--bg);
  border-top: 1px solid var(--line);
  border-bottom: 1px solid var(--line);
}
.page-tablist-inner {
  max-width: var(--max-w);
  margin: 0 auto;
  padding: 10px var(--pad-x);
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.page-tab {
  appearance: none;
  background: transparent;
  color: var(--fg-3);
  border: 1px solid transparent;
  border-radius: 999px;
  padding: 6px 12px;
  font: 500 13px/1.2 var(--f-sans);
  cursor: pointer;
}
.page-tab:hover { color: var(--fg); }
.page-tab[aria-selected="true"] {
  color: var(--fg);
  background: var(--accent-2);
  border-color: var(--line-2);
}
.page-tab:focus-visible, .tab-btn:focus-visible, .finding-toggle:focus-visible, .goto-tab:focus-visible, .expand-all:focus-visible, .ev-collapse:focus-visible, .show-all-rows:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}
.page-tab--empty { opacity: 0.72; }
.tab-tag {
  margin-left: 6px;
  font-size: 11px;
  letter-spacing: .04em;
  text-transform: uppercase;
  color: var(--fg-2);
}
@media (max-width: 720px) {
  .page-tablist-inner {
    flex-wrap: nowrap;
    overflow-x: auto;
    mask-image: linear-gradient(to right, transparent, #000 12px, #000 calc(100% - 28px), transparent);
  }
  .page-tab { flex: 0 0 auto; white-space: nowrap; }
}
.filter-label {
  font-size: 14px;
  color: var(--fg);
  font-weight: 600;
}
.search-status, .search-other { margin: 8px 0 0; font-size: 14px; color: var(--fg-2); }
.search-other { display: flex; flex-wrap: wrap; gap: 8px; }
.search-other button, .goto-tab, .expand-all, .ev-collapse, .show-all-rows, .agents-toc button {
  font: 600 13px/1.2 var(--f-sans);
  color: var(--fg);
  background: var(--bg-card);
  border: 1px solid var(--line-2);
  border-radius: 999px;
  padding: 6px 12px;
  cursor: pointer;
}
.agents-toc { display: flex; flex-wrap: wrap; gap: 8px; margin: 0 0 20px; }
.change-counts { margin: 8px 0; padding-left: 18px; color: var(--fg); }
.change-counts strong { font-variant-numeric: tabular-nums; }
table.findings { table-layout: fixed; width: 100%; }
table.findings .col-sev { width: 108px; }
table.findings .col-evidence { width: 96px; }
table.findings .col-seen { width: 120px; }
table.findings .col-sample { width: 28%; }
tr.frow { cursor: pointer; }
tr.frow.is-open { background: var(--accent-2); box-shadow: inset 3px 0 0 var(--accent); }
.finding-toggle {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  width: 100%;
  margin: 0;
  padding: 0;
  border: 0;
  background: transparent;
  color: inherit;
  font: inherit;
  text-align: left;
  cursor: pointer;
}
.chevron {
  width: 0.55em;
  height: 0.55em;
  margin-top: 0.35em;
  border-right: 2px solid currentColor;
  border-bottom: 2px solid currentColor;
  transform: rotate(-45deg);
  flex: 0 0 auto;
}
tr.frow.is-open .chevron { transform: rotate(45deg); }
tr.fdetail td { background: color-mix(in srgb, var(--accent) 8%, var(--bg-card)); border-left: 3px solid var(--accent); }
.ev-panel { padding: 4px 0 0; }
.ev-collapse-bar {
  position: sticky;
  bottom: 0;
  display: flex;
  justify-content: flex-end;
  margin-top: 12px;
  padding: 8px 0;
  background: var(--bg-card);
  border-top: 1px solid var(--line);
}
.findings-tools { display: flex; justify-content: flex-end; margin: 0 0 8px; }
.low-allow summary { cursor: pointer; font-weight: 600; }
.show-all-rows, .changes-block { margin-top: 8px; }
.page-panel[hidden] { display: none !important; }
.empty-note {
  margin: 28px 0;
  padding: 16px 18px;
  border: 1px dashed var(--line-2);
  border-radius: var(--radius);
  color: var(--fg-2);
}
.report-summary .meta-list { margin-bottom: 36px; }
.page-panel .section { padding-top: 28px; padding-bottom: 40px; }
@media print {
  .page-tablist { display: none !important; }
  .page-panel[hidden] { display: block !important; }
  .summary-card, .agent-status, .agent-status li, .lede {
    background: #fff !important;
    color: #111 !important;
  }
}
"""

REPORT_V2_JS = """
(function () {
  var tabs = Array.prototype.slice.call(document.querySelectorAll("[data-page-tab]"));
  var panels = Array.prototype.slice.call(document.querySelectorAll("[data-page-panel]"));
  var lastFinding = null;

  function measureBar() {
    var bar = document.querySelector(".page-tablist");
    if (!bar) return;
    var h = Math.ceil(bar.getBoundingClientRect().height);
    document.documentElement.style.setProperty("--tabbar-h", h + "px");
  }
  measureBar();
  window.addEventListener("resize", measureBar);

  function headingOf(panel) {
    return panel.querySelector("h1, h2") || panel;
  }
  function show(id, opts) {
    opts = opts || {};
    tabs.forEach(function (tab) {
      var on = tab.getAttribute("data-page-tab") === id;
      tab.setAttribute("aria-selected", on ? "true" : "false");
      tab.tabIndex = on ? 0 : -1;
      if (on) tab.scrollIntoView({ inline: "nearest", block: "nearest" });
    });
    var active = null;
    panels.forEach(function (panel) {
      var on = panel.getAttribute("data-page-panel") === id;
      panel.hidden = !on;
      panel.classList.toggle("is-active", on);
      if (on) active = panel;
    });
    if (opts.user && active) {
      var head = headingOf(active);
      if (head.tabIndex < 0) head.tabIndex = -1;
      var bar = document.querySelector(".page-tablist");
      var offset = bar ? bar.getBoundingClientRect().height + 8 : 0;
      var top = active.getBoundingClientRect().top + window.pageYOffset - offset;
      window.scrollTo(0, Math.max(0, top));
      head.focus();
    }
    if (opts.url && history.replaceState) history.replaceState(null, "", "#" + id);
  }
  function wireKeys(list, items, onPick) {
    list.addEventListener("keydown", function (ev) {
      var i = items.indexOf(document.activeElement);
      if (i < 0) return;
      var next = null;
      if (ev.key === "ArrowRight" || ev.key === "ArrowDown") next = items[(i + 1) % items.length];
      else if (ev.key === "ArrowLeft" || ev.key === "ArrowUp") next = items[(i - 1 + items.length) % items.length];
      else if (ev.key === "Home") next = items[0];
      else if (ev.key === "End") next = items[items.length - 1];
      if (!next) return;
      ev.preventDefault();
      next.focus();
      onPick(next);
    });
  }
  var tablist = document.querySelector(".page-tablist");
  if (tablist) {
    wireKeys(tablist, tabs, function (tab) {
      show(tab.getAttribute("data-page-tab"), { user: true, url: true });
    });
  }
  tabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      show(tab.getAttribute("data-page-tab"), { user: true, url: true });
    });
  });
  document.addEventListener("click", function (ev) {
    var jump = ev.target.closest && ev.target.closest("[data-goto-tab]");
    if (!jump) return;
    ev.preventDefault();
    show(jump.getAttribute("data-goto-tab"), { user: true, url: true });
  });
  var initial = (location.hash || "").replace(/^#/, "");
  tabs.forEach(function (tab) {
    if (tab.getAttribute("data-page-tab") === initial) show(initial, { url: false });
  });

  var catList = document.getElementById("findings-tabs");
  var catBtns = Array.prototype.slice.call(document.querySelectorAll("#findings-tabs .tab-btn"));
  var catPanels = Array.prototype.slice.call(document.querySelectorAll("#panel-findings [data-tab].tab-panel"));
  function showCat(btn) {
    var target = btn.getAttribute("data-tab");
    catBtns.forEach(function (b) {
      var on = b === btn;
      b.classList.toggle("active", on);
      b.setAttribute("aria-selected", on ? "true" : "false");
      b.tabIndex = on ? 0 : -1;
    });
    catPanels.forEach(function (p) { p.classList.toggle("active", p.getAttribute("data-tab") === target); });
    btn.scrollIntoView({ inline: "nearest", block: "nearest" });
  }
  catBtns.forEach(function (btn) {
    btn.addEventListener("click", function () { showCat(btn); });
  });
  if (catList) {
    wireKeys(catList, catBtns, function (btn) { showCat(btn); });
  }

  function setOpen(row, open) {
    var btn = row.querySelector(".finding-toggle");
    var detail = row.nextElementSibling;
    if (!btn || !detail || !detail.classList.contains("fdetail")) return;
    btn.setAttribute("aria-expanded", open ? "true" : "false");
    detail.hidden = !open;
    row.classList.toggle("is-open", open);
    if (open) lastFinding = btn;
  }
  function closeOthers(panel, row) {
    panel.querySelectorAll("tr.frow").forEach(function (other) {
      if (other !== row) setOpen(other, false);
    });
  }
  document.addEventListener("click", function (ev) {
    var target = ev.target;
    if (!target.closest) return;
    var collapse = target.closest(".ev-collapse");
    if (collapse) {
      var detail = collapse.closest("tr.fdetail");
      var row = detail && detail.previousElementSibling;
      if (row) {
        setOpen(row, false);
        var toggle = row.querySelector(".finding-toggle");
        if (toggle) toggle.focus();
        var allBtn = row.closest(".tab-panel").querySelector(".expand-all");
        if (allBtn) allBtn.setAttribute("aria-pressed", "false");
      }
      return;
    }
    var expandAll = target.closest(".expand-all");
    if (expandAll) {
      var panel = expandAll.closest(".tab-panel");
      var pressed = expandAll.getAttribute("aria-pressed") === "true";
      panel.querySelectorAll("tr.frow").forEach(function (row) {
        if (row.hidden) return;
        setOpen(row, !pressed);
      });
      expandAll.setAttribute("aria-pressed", pressed ? "false" : "true");
      expandAll.textContent = pressed ? "Expand all" : "Collapse all";
      return;
    }
    var showAll = target.closest(".show-all-rows");
    if (showAll) {
      var block = showAll.closest(".changes-block");
      var extra = block && block.querySelector(".changes-extra");
      var open = showAll.getAttribute("aria-expanded") === "true";
      if (extra) extra.hidden = open;
      showAll.setAttribute("aria-expanded", open ? "false" : "true");
      showAll.textContent = open ? (showAll.getAttribute("data-show-label") || "Show all") : "Show less";
      return;
    }
    var jump = target.closest("[data-jump]");
    if (jump) {
      var dest = document.getElementById(jump.getAttribute("data-jump") || "");
      if (!dest) return;
      dest.scrollIntoView({ block: "start" });
      var head = dest.querySelector("h2, h3") || dest;
      if (head.tabIndex < 0) head.tabIndex = -1;
      head.focus();
      return;
    }
    var row = target.closest("tr.frow");
    if (!row || target.closest("a, input, textarea, select")) return;
    var btn = row.querySelector(".finding-toggle");
    if (!btn) return;
    var willOpen = btn.getAttribute("aria-expanded") !== "true";
    var panel = row.closest(".tab-panel");
    var allBtn = panel && panel.querySelector(".expand-all");
    var allMode = allBtn && allBtn.getAttribute("aria-pressed") === "true";
    if (willOpen && panel && !allMode) closeOthers(panel, row);
    setOpen(row, willOpen);
    if (!willOpen && allBtn) {
      allBtn.setAttribute("aria-pressed", "false");
      allBtn.textContent = "Expand all";
    }
  });
  document.addEventListener("keydown", function (ev) {
    if (ev.key !== "Escape") return;
    var detail = ev.target.closest && ev.target.closest("tr.fdetail");
    var row = detail ? detail.previousElementSibling : null;
    var toggle = (!row && ev.target.closest) ? ev.target.closest(".finding-toggle") : null;
    if (toggle && toggle.getAttribute("aria-expanded") === "true") {
      row = toggle.closest("tr.frow");
    }
    if (!row && lastFinding) row = lastFinding.closest("tr.frow");
    if (!row || !row.classList.contains("frow")) return;
    setOpen(row, false);
    var back = row.querySelector(".finding-toggle");
    if (back) back.focus();
  });

  function rowMatches(row, q) {
    var text = (row.getAttribute("data-search") || "").toLowerCase();
    return !q || text.indexOf(q) !== -1;
  }
  function setShown(row, shown) {
    row.hidden = !shown;
  }
  var searchEl = document.getElementById("findings-search");
  var statusEl = document.getElementById("findings-search-status");
  var otherEl = document.getElementById("findings-search-other");
  var clearBtn = document.getElementById("findings-search-clear");
  function applySearch() {
    if (!searchEl) return;
    var raw = searchEl.value || "";
    var q = raw.toLowerCase();
    var activeBtn = document.querySelector("#findings-tabs .tab-btn.active") || catBtns[0];
    var activeN = 0;
    var activeTotal = 0;
    var otherN = 0;
    if (otherEl) otherEl.innerHTML = "";
    catBtns.forEach(function (btn) {
      var slug = btn.getAttribute("data-tab");
      var panel = document.querySelector('#panel-findings .tab-panel[data-tab="' + slug + '"]');
      if (!panel) return;
      var n = 0;
      var total = 0;
      panel.querySelectorAll("tr.frow").forEach(function (row) {
        total += 1;
        var ok = rowMatches(row, q);
        setShown(row, ok);
        var detail = row.nextElementSibling;
        if (detail && detail.classList.contains("fdetail")) {
          var open = row.querySelector(".finding-toggle");
          var expanded = open && open.getAttribute("aria-expanded") === "true";
          detail.hidden = !(ok && expanded);
        }
        if (ok) n += 1;
      });
      var empty = panel.querySelector(".filter-empty");
      if (empty) {
        empty.hidden = !(q && n === 0);
        var cell = empty.querySelector("td");
        if (cell && q) cell.textContent = "No findings match \u201c" + raw + "\u201d.";
      }
      var ct = btn.querySelector(".ct");
      if (ct) {
        if (!btn.getAttribute("data-total")) btn.setAttribute("data-total", ct.textContent || "0");
        ct.textContent = q ? String(n) : btn.getAttribute("data-total");
      }
      if (btn === activeBtn) {
        activeN = n;
        activeTotal = total;
      } else if (q && n > 0) {
        otherN += n;
        if (otherEl) {
          var link = document.createElement("button");
          link.type = "button";
          link.textContent = n + " in " + (btn.getAttribute("data-label") || "this tab");
          link.addEventListener("click", function () { showCat(btn); applySearch(); });
          otherEl.appendChild(link);
        }
      }
    });
    if (clearBtn) clearBtn.hidden = !q;
    if (statusEl) {
      if (!q) statusEl.textContent = "";
      else if (activeN === 0 && otherN === 0) statusEl.textContent = "No findings match \u201c" + raw + "\u201d.";
      else {
        var msg = "Showing " + activeN + " of " + activeTotal + ".";
        if (otherN) msg += " " + otherN + " matches in other tabs.";
        statusEl.textContent = msg;
      }
    }
  }
  if (searchEl) searchEl.addEventListener("input", applySearch);
  if (clearBtn) clearBtn.addEventListener("click", function () {
    searchEl.value = "";
    applySearch();
    searchEl.focus();
  });
})();
(function () {
  function fallbackCopy(path, btn) {
    var ok = false;
    var ta = document.createElement("textarea");
    ta.value = path;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    document.body.removeChild(ta);
    if (ok) return true;
    var box = btn.parentNode.querySelector(".copy-path-fallback");
    if (!box) {
      box = document.createElement("input");
      box.type = "text";
      box.readOnly = true;
      box.className = "copy-path-fallback";
      btn.parentNode.insertBefore(box, btn.nextSibling);
    }
    box.value = path;
    box.title = "Press Ctrl+C";
    box.focus();
    box.select();
    btn.textContent = "Press Ctrl+C";
    return false;
  }
  function flash(btn) {
    btn.textContent = "Copied";
    setTimeout(function () { btn.textContent = "Copy path"; }, 1500);
  }
  document.addEventListener("click", function (ev) {
    var target = ev.target;
    var btn = target && target.closest ? target.closest("button.copy-path") : null;
    if (!btn) return;
    ev.preventDefault();
    ev.stopPropagation();
    var path = btn.dataset.path || "";
    if (window.isSecureContext && navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(path).then(function () { flash(btn); }, function () {
        if (fallbackCopy(path, btn)) flash(btn);
      });
    } else if (fallbackCopy(path, btn)) {
      flash(btn);
    }
  });
})();
"""
