"""HTML for the cross-agent access map.

Public integration points:

- ``render_access_map_section(envelopes) -> str``
- ``render_access_map_nav(envelopes) -> str``

Both take the same ``envelopes`` dict ``build-briefing.py`` already loads.
This module may import that file's helpers. It does not modify it.
"""

from __future__ import annotations

import importlib.util
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any

_REPORT_DIR = Path(__file__).resolve().parents[1]
if str(_REPORT_DIR) not in sys.path:
    sys.path.insert(0, str(_REPORT_DIR))

from access_map import build_access_map

_PILL = {
    "yes": "critical",
    "partial": "medium",
    "no": "ok",
    "unknown": "skipped",
}

_ACCESS_CSS = """
.access-scroll { overflow: visible; max-height: none; }
.access-map { min-width: 0; border-collapse: separate; border-spacing: 0; }
.access-map th, .access-map td { min-width: 108px; }
.access-agent { min-width: 160px; text-align: left; }
.access-cell { position: relative; vertical-align: top; }
.access-cell--yes { background: var(--red-bg); }
.access-cell--partial { background: var(--amber-bg); }
.access-cell--no { background: rgba(16,185,129,.10); }
.access-cell--unknown { background: transparent; }
.access-chip {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  width: 100%;
  margin: 0;
  padding: 4px 8px;
  background: transparent;
  cursor: pointer;
  text-align: left;
  font: inherit;
}
.access-chip:focus-visible, .help-tip:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}
.access-info, .help-tip {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 16px;
  height: 16px;
  border-radius: 50%;
  border: 1px solid currentColor;
  font-family: var(--f-sans);
  font-size: 11px;
  font-weight: 600;
  line-height: 1;
  letter-spacing: 0;
  text-transform: none;
  flex: 0 0 auto;
}
.help-tip {
  margin-left: 6px;
  padding: 0;
  color: var(--fg-2);
  background: var(--bg-card);
  cursor: pointer;
  vertical-align: middle;
}
.help-pop {
  display: block;
  margin-top: 6px;
  font-family: var(--f-sans);
  font-size: 13px;
  font-weight: 400;
  letter-spacing: 0;
  text-transform: none;
  color: var(--fg);
  white-space: normal;
}
.help-pop[hidden] { display: none !important; }
.access-popover {
  position: absolute;
  z-index: 30;
  top: calc(100% + 6px);
  left: 0;
  width: max-content;
  min-width: 220px;
  max-width: min(320px, 70vw);
  padding: 10px 12px;
  background: var(--bg-card);
  color: var(--fg);
  border: 1px solid var(--line-2);
  border-radius: 6px;
  box-shadow: var(--shadow);
}
.access-popover.access-popover--end { left: auto; right: 0; }
.access-popover[hidden] { display: none !important; }
.access-reason {
  margin: 0;
  font-size: 14px;
  line-height: 1.4;
  color: var(--fg);
}
.access-meta {
  margin: 8px 0 0;
  font-family: var(--f-mono);
  font-size: 12px;
  letter-spacing: .04em;
  text-transform: uppercase;
  color: var(--fg-2);
}
.access-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 14px 22px;
  list-style: none;
  margin: 0 0 18px;
  padding: 0;
  color: var(--fg-2);
  font-size: 14px;
}
.access-legend li { display: inline-flex; align-items: center; gap: 8px; }
@media (min-width: 721px) {
  .access-map { min-width: 920px; }
  .access-map thead th {
    position: sticky;
    top: var(--tabbar-h, 56px);
    z-index: 3;
    background: var(--bg-card);
  }
  .access-map .access-agent {
    position: sticky;
    left: 0;
    z-index: 2;
    background: var(--bg);
  }
  .access-map thead .access-agent { z-index: 4; background: var(--bg-card); }
}
@media (max-width: 720px) {
  .access-map, .access-map tbody, .access-map tr, .access-map th, .access-map td {
    display: block;
    min-width: 0;
    width: auto;
  }
  .access-map thead { display: none; }
  .access-map tr {
    border: 1px solid var(--line);
    margin: 0 0 12px;
    padding: 8px;
    background: var(--bg-card);
  }
  .access-map .access-agent { font-size: 16px; padding-bottom: 6px; }
  .access-cell { display: flex; align-items: center; gap: 8px; padding: 4px 0; }
  .access-cell::before {
    content: attr(data-label);
    flex: 0 0 7.5rem;
    font-family: var(--f-mono);
    font-size: 11px;
    letter-spacing: .06em;
    text-transform: uppercase;
    color: var(--fg-2);
  }
}
"""

_ACCESS_JS = """
<script>
(function () {
  if (window.__aiscanAccessBound) return;
  window.__aiscanAccessBound = true;
  function closePops(except) {
    document.querySelectorAll(".access-popover, .help-pop").forEach(function (pop) {
      if (pop === except) return;
      pop.hidden = true;
      var id = pop.id;
      if (!id) return;
      var opener = document.querySelector('[aria-controls="' + id + '"]');
      if (opener) opener.setAttribute("aria-expanded", "false");
    });
  }
  document.addEventListener("click", function (ev) {
    var help = ev.target.closest && ev.target.closest(".help-tip");
    var chip = ev.target.closest && ev.target.closest(".access-chip");
    if (!help && !chip) {
      if (!ev.target.closest || !ev.target.closest(".access-popover, .help-pop")) closePops(null);
      return;
    }
    ev.preventDefault();
    var btn = help || chip;
    var pop = document.getElementById(btn.getAttribute("aria-controls") || "");
    if (!pop) return;
    var open = btn.getAttribute("aria-expanded") === "true";
    closePops(open ? null : pop);
    if (!open) {
      pop.hidden = false;
      btn.setAttribute("aria-expanded", "true");
      var cell = btn.closest(".access-cell");
      if (cell && pop.classList.contains("access-popover")) {
        var rect = cell.getBoundingClientRect();
        pop.classList.toggle("access-popover--end", rect.left > window.innerWidth * 0.55);
      }
    }
  });
  document.addEventListener("keydown", function (ev) {
    if (ev.key !== "Escape") return;
    var openBtn = document.querySelector('.access-chip[aria-expanded="true"], .help-tip[aria-expanded="true"]');
    if (!openBtn) return;
    closePops(null);
    openBtn.focus();
  });
})();
</script>
"""


@lru_cache(maxsize=1)
def _esc_fn():
    """Reuse build-briefing._esc so escaping matches the rest of the report."""
    path = Path(__file__).resolve().parents[1] / "build-briefing.py"
    spec = importlib.util.spec_from_file_location("aiscan_build_briefing", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load briefing helpers from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module._esc


def _esc(value: Any) -> str:
    return _esc_fn()(value)


def render_access_map_nav(envelopes: dict[str, dict]) -> str:
    """Sticky-nav anchor for the access map. Always emitted."""
    _ = envelopes
    return '<a href="#access-map">Access</a>'


def render_access_map_section(envelopes: dict[str, dict]) -> str:
    """Self-contained access-map section, including its evidence index."""
    grid = build_access_map(envelopes or {})
    rows_html = []
    for row in grid["rows"]:
        agent_cells = grid["cells"][row["id"]]
        present = "collected" if row["present"] else "not collected"
        present_cls = "ok" if row["present"] else "skipped"
        body = "".join(
            _render_cell(
                agent_cells[column["id"]],
                column,
                str(row.get("label") or row["id"]),
                str(row["id"]),
            )
            for column in grid["columns"]
        )
        rows_html.append(
            "<tr>"
            f"<th scope='row' class='access-agent' id='agent-{_esc(row['id'])}'>"
            f"<strong>{_esc(row['label'])}</strong>"
            f"<div class='access-meta'><span class='pill {present_cls}'>{_esc(present)}</span></div></th>"
            f"{body}</tr>"
        )
    headers = []
    for column in grid["columns"]:
        tip_id = f"access-tip-{column['id']}"
        headers.append(
            f"<th scope='col' id='col-{_esc(column['id'])}'>"
            f"<span class='access-col'>{_esc(column['short'])}</span>"
            f"<button type='button' class='help-tip' aria-expanded='false' aria-controls='{tip_id}' "
            f"aria-label='{_esc(column['label'])}'><span aria-hidden='true'>?</span></button>"
            f"<span id='{tip_id}' class='help-pop' role='tooltip' hidden>{_esc(column['label'])}</span>"
            f"</th>"
        )
    return f"""<style>{_ACCESS_CSS}</style>
<section id="access-map" class="section">
  <div class="wrap">
    <header class="sh">
      <div class="kicker">
        <span class="num">/09</span>
        <span class="kicker-label">CROSS-AGENT ACCESS</span>
      </div>
      <h2 class="h2">{_esc(grid["headline"])}</h2>
      <p class="sub">What each agent on this machine or account can actually do, read only from the evidence envelopes. Unknown means that evidence cannot tell.</p>
    </header>
    <ul class="access-legend">
      <li><span class="pill critical">yes</span> recorded capability (approval: auto-approve or bypass)</li>
      <li><span class="pill medium">partial</span> limited grant, mix, or indirect signal</li>
      <li><span class="pill ok">no</span> recorded restriction, or nothing in an inventory that ran</li>
      <li><span class="pill skipped">unknown</span> evidence cannot tell</li>
    </ul>
    <p class="posture-grid-caption">Color tracks access risk. The headline counts yes only, not partial or unknown. Network cells show the MCP server count when that collector records one. Select a cell to read the evidence.</p>
    <div class="table-wrap access-scroll" style="max-height: none;">
      <table class="posture-grid access-map">
        <thead><tr><th scope="col" class="access-agent">Agent</th>{''.join(headers)}</tr></thead>
        <tbody>{''.join(rows_html)}</tbody>
      </table>
    </div>
  </div>
</section>
{_ACCESS_JS}"""


def _render_cell(cell: dict[str, Any], column: dict[str, Any], agent_label: str, agent_id: str) -> str:
    column_id = str(column.get("id") or "")
    value = str(cell.get("value") or "unknown")
    pill = _PILL.get(value, "skipped")
    anchor = str(cell.get("anchor") or "")
    capability = str(column.get("label") or column.get("short") or column_id)
    short = str(column.get("short") or capability)
    meta_bits = [f"evidence {_esc(cell.get('evidence') or 'none')}"]
    if column_id == "network":
        mcp_count = cell.get("mcp_count")
        if mcp_count is None:
            meta_bits.append("MCP not recorded")
        else:
            try:
                shown = int(mcp_count)
            except (TypeError, ValueError, OverflowError):
                shown = 0
            meta_bits.append(f"{shown} MCP")
    label = f"{agent_label}, {capability}, {value}, show evidence"
    return (
        f"<td class='access-cell access-cell--{_esc(value)}' data-label='{_esc(short)}' "
        f"headers='agent-{_esc(agent_id)} col-{_esc(column_id)}'>"
        f"<button type='button' class='access-chip pill {pill}' aria-expanded='false' "
        f"aria-controls='{_esc(anchor)}' aria-label='{_esc(label)}'>"
        f"<span class='access-chip-value'>{_esc(value)}</span>"
        f"<span class='access-info' aria-hidden='true'>i</span></button>"
        f"<div id='{_esc(anchor)}' class='access-popover' role='dialog' hidden>"
        f"<p class='access-reason'>{_esc(cell.get('reason') or '')}</p>"
        f"<p class='access-meta'>{' · '.join(meta_bits)}</p>"
        "</div></td>"
    )


def _render_evidence_row(row: dict[str, Any], column: dict[str, Any], cell: dict[str, Any]) -> str:
    value = str(cell.get("value") or "unknown")
    pill = _PILL.get(value, "skipped")
    sources = cell.get("sources") or []
    source_text = ", ".join(str(item) for item in sources) if sources else "n/a"
    return (
        f"<tr id='{_esc(cell.get('anchor') or '')}'>"
        f"<td><strong>{_esc(row['label'])}</strong></td>"
        f"<td>{_esc(column['label'])}</td>"
        f"<td><span class='pill {pill}'>{_esc(value)}</span></td>"
        f"<td class='mono'>{_esc(cell.get('evidence') or 'none')}</td>"
        f"<td>{_esc(cell.get('reason') or '')}</td>"
        f"<td class='mono'>{_esc(source_text)}</td>"
        "</tr>"
    )
