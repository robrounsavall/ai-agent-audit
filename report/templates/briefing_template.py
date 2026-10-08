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
        <div class="note">action this week</div>
      </div>
      <div>
        <div class="lbl">High</div>
        <div class="v amber">%%COUNT_HIGH%%</div>
        <div class="note">30-day window</div>
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
      <p class="sub">gitleaks scans chat exports and repo roots for credential-shaped strings; samples are redacted and full hits stay in <span class="mono">raw/secrets-scan/findings.csv</span>. Git posture checks local repos for .env in history, hook presence, .gitignore coverage, and large blobs.</p>
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
      <p class="sub">Per-hit gitleaks rows are aggregated by rule type. Identical findings collapse into a single row with a hit count; full per-row detail lives in the linked CSV.</p>
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
.report-summary { padding: 48px 0 28px; }
.report-summary .display { margin: 12px 0 8px; }
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
  background: var(--nav-bg);
  border-top: 1px solid var(--line);
  border-bottom: 1px solid var(--line);
  backdrop-filter: saturate(180%) blur(14px);
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
  var tabs = document.querySelectorAll("[data-page-tab]");
  var panels = document.querySelectorAll("[data-page-panel]");
  function show(id) {
    tabs.forEach(function (tab) {
      var on = tab.getAttribute("data-page-tab") === id;
      tab.setAttribute("aria-selected", on ? "true" : "false");
    });
    panels.forEach(function (panel) {
      var on = panel.getAttribute("data-page-panel") === id;
      panel.hidden = !on;
      panel.classList.toggle("is-active", on);
    });
  }
  tabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      var id = tab.getAttribute("data-page-tab");
      show(id);
      if (history.replaceState) {
        history.replaceState(null, "", "#" + id);
      }
    });
  });
  var initial = (location.hash || "").replace(/^#/, "");
  tabs.forEach(function (tab) {
    if (tab.getAttribute("data-page-tab") === initial) {
      show(initial);
    }
  });

  var tabBtns = document.querySelectorAll("#findings-tabs .tab-btn");
  var tabPanels = document.querySelectorAll("#panel-findings [data-tab].tab-panel");
  tabBtns.forEach(function (btn) {
    btn.addEventListener("click", function () {
      var target = btn.dataset.tab;
      tabBtns.forEach(function (b) { b.classList.toggle("active", b === btn); });
      tabPanels.forEach(function (p) { p.classList.toggle("active", p.dataset.tab === target); });
    });
  });

  function rowMatches(row, q) {
    var text = (row.getAttribute("data-search") || row.textContent || "").toLowerCase();
    return !q || text.indexOf(q) !== -1;
  }
  function setShown(row, shown) {
    row.hidden = !shown;
    row.style.display = shown ? "" : "none";
  }
  var searchEl = document.getElementById("findings-search");
  if (searchEl) {
    searchEl.addEventListener("input", function () {
      var q = searchEl.value.toLowerCase();
      var buttons = document.querySelectorAll("#findings-tabs .tab-btn");
      var firstMatch = null;
      var activeHas = false;
      buttons.forEach(function (btn) {
        var slug = btn.getAttribute("data-tab");
        var panel = document.querySelector('#panel-findings .tab-panel[data-tab="' + slug + '"]');
        if (!panel) return;
        var n = 0;
        panel.querySelectorAll(".frow").forEach(function (row) {
          var ok = rowMatches(row, q);
          setShown(row, ok);
          if (ok) n += 1;
        });
        var empty = panel.querySelector(".filter-empty");
        if (empty) setShown(empty, q && n === 0);
        var ct = btn.querySelector(".ct");
        if (ct) {
          if (!btn.getAttribute("data-total")) btn.setAttribute("data-total", ct.textContent || "0");
          ct.textContent = q ? String(n) : btn.getAttribute("data-total");
        }
        if (n > 0 && !firstMatch) firstMatch = btn;
        if (btn.classList.contains("active") && n > 0) activeHas = true;
      });
      document.querySelectorAll("#panel-findings .case").forEach(function (card) {
        setShown(card, rowMatches(card, q));
      });
      var appendixHits = 0;
      document.querySelectorAll("#panel-findings .appendix-table tbody tr").forEach(function (row) {
        if (row.classList.contains("filter-empty")) return;
        var ok = rowMatches(row, q);
        setShown(row, ok);
        if (ok) appendixHits += 1;
      });
      var appendixEmpty = document.querySelector("#panel-findings .appendix-table .filter-empty");
      if (appendixEmpty) setShown(appendixEmpty, q && appendixHits === 0);
      if (q && !activeHas && firstMatch) firstMatch.click();
    });
  }
})();
"""
