"""HTML shell for CIO briefing — dark editorial template (Geist + JetBrains Mono).

Placeholders use %%NAME%% tokens. The build-briefing.py renderer fills these
in via a single dict.replace() pass. Keep tokens in one canonical place (here)
so adding a new token is a one-file edit.
"""

HTML_SHELL = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
  <title>%%TITLE%%</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
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
