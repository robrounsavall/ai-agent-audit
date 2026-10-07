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
.access-map { min-width: 920px; }
.access-map th, .access-map td { min-width: 108px; }
.access-map td.access-agent { min-width: 160px; }
.access-cell--yes { background: var(--red-bg); }
.access-cell--partial { background: var(--amber-bg); }
.access-cell--no { background: rgba(16,185,129,.10); }
.access-cell--unknown { background: transparent; }
.access-map a.pill { text-decoration: none; }
.access-reason {
  margin-top: 8px;
  font-size: 12px;
  line-height: 1.35;
  color: var(--fg-3);
}
.access-meta {
  margin-top: 6px;
  font-family: var(--f-mono);
  font-size: 10.5px;
  letter-spacing: .04em;
  text-transform: uppercase;
  color: var(--fg-4);
}
.access-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 14px 22px;
  list-style: none;
  margin: 0 0 18px;
  padding: 0;
  color: var(--fg-3);
  font-size: 13px;
}
.access-legend li { display: inline-flex; align-items: center; gap: 8px; }
.access-map-evidence { margin-top: 28px; }
.access-map-evidence h3 {
  font-family: var(--f-display);
  font-weight: 500;
  font-size: 22px;
  margin: 0 0 8px;
}
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
        body = "".join(_render_cell(agent_cells[column["id"]], column["id"]) for column in grid["columns"])
        rows_html.append(
            "<tr>"
            f"<td class='access-agent'><strong>{_esc(row['label'])}</strong>"
            f"<div class='access-meta'><span class='pill {present_cls}'>{_esc(present)}</span></div></td>"
            f"{body}</tr>"
        )
    headers = "".join(
        f"<th title='{_esc(column['label'])}'>{_esc(column['short'])}</th>"
        for column in grid["columns"]
    )
    evidence_rows = []
    for row in grid["rows"]:
        for column in grid["columns"]:
            evidence_rows.append(_render_evidence_row(row, column, grid["cells"][row["id"]][column["id"]]))
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
    <p class="posture-grid-caption">Color tracks access risk. The headline counts yes only, not partial or unknown. Each cell links to the evidence row below. Network cells show the MCP server count when that collector records one.</p>
    <div class="table-wrap" style="max-height: none;">
      <table class="posture-grid access-map">
        <thead><tr><th>Agent</th>{headers}</tr></thead>
        <tbody>{''.join(rows_html)}</tbody>
      </table>
    </div>
    <div class="access-map-evidence" id="access-map-evidence">
      <h3>Evidence behind each cell</h3>
      <p class="sub">Anchors match the grid. Sources are evidence files and the field or finding that decided the cell.</p>
      <div class="table-wrap" style="max-height: none;">
        <table>
          <thead><tr><th>Agent</th><th>Capability</th><th>Value</th><th>Evidence</th><th>Why</th><th>Source</th></tr></thead>
          <tbody>{''.join(evidence_rows)}</tbody>
        </table>
      </div>
    </div>
  </div>
</section>"""


def _render_cell(cell: dict[str, Any], column_id: str) -> str:
    value = str(cell.get("value") or "unknown")
    pill = _PILL.get(value, "skipped")
    anchor = str(cell.get("anchor") or "")
    meta_bits = [f"evidence {_esc(cell.get('evidence') or 'none')}"]
    if column_id == "network":
        mcp_count = cell.get("mcp_count")
        if mcp_count is None:
            meta_bits.append("MCP not recorded")
        else:
            meta_bits.append(f"{int(mcp_count)} MCP")
    return (
        f"<td class='access-cell access-cell--{_esc(value)}'>"
        f"<a class='pill {pill}' href='#{_esc(anchor)}'>{_esc(value)}</a>"
        f"<div class='access-reason'>{_esc(cell.get('reason') or '')}</div>"
        f"<div class='access-meta'>{' · '.join(meta_bits)}</div>"
        "</td>"
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
