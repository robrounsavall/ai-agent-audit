"""Server-rendered HTML for the hub dashboard.

Plain string building, the same approach as ``report/``. Every value that
came from a scan goes through ``esc`` before it reaches the page. The pages
carry no inline script and no inline style, so the server can send a strict
Content-Security-Policy.
"""

from __future__ import annotations

import html
import json
import math
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlencode

import hub_paths  # noqa: F401

from hub_bundle import SEVERITIES
from hub_db import TRIAGE_STATES
from hub_queries import PAGE_SIZE

SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
TRIAGE_LABEL = {
    "open": "Needs review",
    "acknowledged": "Acknowledged",
    "accepted_risk": "Accepted risk",
    "false_positive": "False positive",
}
NAV = (
    ("overview", "/", "Overview"),
    ("findings", "/findings", "Findings"),
    ("permissions", "/permissions", "Permissions"),
    ("mcp", "/mcp", "MCP servers"),
    ("accounts", "/accounts", "Accounts"),
    ("scans", "/scans", "Scans"),
    ("settings", "/settings", "Settings"),
)


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _num(value: Any) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return "0"


def _parse(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def age(value: str) -> str:
    when = _parse(value)
    if when is None:
        return ""
    seconds = (datetime.now(timezone.utc) - when).total_seconds()
    if seconds < 0:
        return "in the future"
    if seconds < 90:
        return "just now"
    for size, unit in ((86400 * 365, "year"), (86400 * 30, "month"), (86400, "day"), (3600, "hour"), (60, "minute")):
        if seconds >= size:
            count = int(seconds // size)
            return f"{count} {unit}{'' if count == 1 else 's'} ago"
    return "just now"


def when(value: str, *, with_age: bool = False) -> str:
    """A ``<time>`` the page script rewrites into the viewer's local time."""
    parsed = _parse(value)
    if parsed is None:
        return '<span class="muted">unknown</span>'
    text = parsed.strftime("%Y-%m-%d %H:%M UTC")
    tail = f' <span class="muted">({esc(age(value))})</span>' if with_age else ""
    return f'<time datetime="{esc(value)}" data-local>{esc(text)}</time>{tail}'


def sev_badge(severity: str) -> str:
    sev = severity if severity in SEV_LABEL else "low"
    label = SEV_LABEL.get(severity, severity or "Unknown")
    return f'<span class="sev sev-{sev}"><i aria-hidden="true"></i>{esc(label)}</span>'


def sev_counts(counts: dict[str, int]) -> str:
    """Counts per severity as labeled chips. Zeroes are shown muted."""
    parts = []
    for sev in SEVERITIES:
        count = int(counts.get(sev) or 0)
        cls = f"count sev-{sev}" + ("" if count else " zero")
        parts.append(
            f'<span class="{cls}" title="{esc(SEV_LABEL[sev])}"><i aria-hidden="true"></i>'
            f'{_num(count)}<span class="sr"> {esc(SEV_LABEL[sev].lower())}</span></span>'
        )
    return '<span class="counts">' + "".join(parts) + "</span>"


def pill(text: str, kind: str = "") -> str:
    return f'<span class="pill {esc(kind)}">{esc(text)}</span>'


def _url(path: str, **params: Any) -> str:
    clean = {key: value for key, value in params.items() if value not in ("", None)}
    return path + ("?" + urlencode(clean) if clean else "")


def finding_url(row: dict[str, Any]) -> str:
    return _url("/finding", host=row["host_id"], collector=row["collector"], key=row["finding_key"])


def table(headers: list[str], rows: list[list[str]], *, empty: str = "Nothing to show.", cls: str = "") -> str:
    if not rows:
        return f'<p class="empty">{esc(empty)}</p>'
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    return f'<div class="table-wrap"><table class="{esc(cls)}"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def pager(path: str, params: dict[str, Any], total: int, offset: int) -> str:
    if total <= PAGE_SIZE:
        return f'<p class="muted small">{_num(total)} row{"" if total == 1 else "s"}</p>'
    last = min(offset + PAGE_SIZE, total)
    links = []
    if offset > 0:
        links.append(f'<a class="btn" href="{esc(_url(path, **{**params, "offset": max(offset - PAGE_SIZE, 0)}))}">Previous</a>')
    if last < total:
        links.append(f'<a class="btn" href="{esc(_url(path, **{**params, "offset": offset + PAGE_SIZE}))}">Next</a>')
    return f'<p class="pager"><span class="muted small">{_num(offset + 1)}–{_num(last)} of {_num(total)}</span>{"".join(links)}</p>'


def select(name: str, options: list[tuple[str, str]], current: str, label: str) -> str:
    opts = "".join(
        f'<option value="{esc(value)}"{" selected" if value == current else ""}>{esc(text)}</option>'
        for value, text in options
    )
    return f'<label class="field"><span>{esc(label)}</span><select name="{esc(name)}">{opts}</select></label>'


def stat(label: str, value: Any, note: str = "", *, href: str = "", hero: bool = False) -> str:
    inner = (
        f'<span class="stat-label">{esc(label)}</span>'
        f'<span class="stat-value">{esc(value)}</span>'
        + (f'<span class="stat-note">{note}</span>' if note else "")
    )
    cls = "stat hero" if hero else "stat"
    if href:
        return f'<a class="{cls}" href="{esc(href)}">{inner}</a>'
    return f'<div class="{cls}">{inner}</div>'


# ---- chart ----------------------------------------------------------------

def _nice_step(top: int, ticks: int = 4) -> int:
    if top <= ticks:
        return 1
    rough = top / ticks
    power = 10 ** math.floor(math.log10(rough))
    for mult in (1, 2, 5, 10):
        if rough <= mult * power:
            return int(mult * power)
    return int(10 * power)


def severity_chart(points: list[dict[str, Any]], *, title: str) -> str:
    """Stacked columns: open findings by severity, one column per scan.

    Severity is a state, so it wears the status colors and every place it
    appears also carries the severity name. Each column is a link to its
    scan, and the scans table is the same data as a table.
    """
    if not points:
        return '<p class="empty">No scans yet.</p>'
    width, height = 760, 240
    left, right, top, bottom = 44, 12, 12, 30
    plot_w, plot_h = width - left - right, height - top - bottom
    peak = max(sum(int(p[sev]) for sev in SEVERITIES) for p in points) or 1
    step = _nice_step(peak)
    y_max = step * math.ceil(peak / step)
    slot = plot_w / len(points)
    bar_w = min(24.0, max(slot - 6, 3.0))
    gap = 2.0

    def y_of(value: float) -> float:
        return top + plot_h - (value / y_max) * plot_h

    parts = [
        f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="{esc(title)}">'
    ]
    for tick in range(0, y_max + 1, step):
        y = y_of(tick)
        cls = "axis" if tick == 0 else "grid"
        parts.append(f'<line class="{cls}" x1="{left}" x2="{width - right}" y1="{y:.1f}" y2="{y:.1f}"/>')
        parts.append(f'<text class="tick" x="{left - 8}" y="{y + 4:.1f}" text-anchor="end">{tick:,}</text>')

    label_every = max(1, math.ceil(len(points) / 8))
    for index, point in enumerate(points):
        x = left + slot * index + (slot - bar_w) / 2
        total = sum(int(point[sev]) for sev in SEVERITIES)
        tip = {
            "title": f"{point['host']} · {point['scanned_at'][:10]}",
            "rows": [[SEV_LABEL[sev], int(point[sev]), sev] for sev in SEVERITIES],
            "total": total,
        }
        summary = ", ".join(f"{int(point[sev])} {sev}" for sev in SEVERITIES)
        parts.append(
            f'<a href="/scans/{int(point["scan_id"])}" class="col" data-tip="{esc(json.dumps(tip))}"'
            f' aria-label="{esc(point["host"])} {esc(point["scanned_at"][:10])}: {esc(summary)}">'
        )
        parts.append(f'<rect class="hit" x="{left + slot * index:.1f}" y="{top}" width="{slot:.1f}" height="{plot_h}"/>')
        base = 0
        # Low at the baseline, critical on top: the worst band sits where the
        # eye lands, and its top edge is the column's rounded data end.
        stack = [sev for sev in reversed(SEVERITIES) if int(point[sev]) > 0]
        for position, sev in enumerate(stack):
            value = int(point[sev])
            y_top = y_of(base + value)
            y_bottom = y_of(base)
            seg_h = y_bottom - y_top
            if position > 0:
                seg_h -= gap
            base += value
            if seg_h <= 0.5:
                continue
            if position == len(stack) - 1 and seg_h > 4:
                r = min(4.0, bar_w / 2)
                parts.append(
                    f'<path class="seg sev-{sev}" d="M{x:.1f},{y_top + seg_h:.1f} V{y_top + r:.1f}'
                    f' Q{x:.1f},{y_top:.1f} {x + r:.1f},{y_top:.1f} H{x + bar_w - r:.1f}'
                    f' Q{x + bar_w:.1f},{y_top:.1f} {x + bar_w:.1f},{y_top + r:.1f} V{y_top + seg_h:.1f} Z"/>'
                )
            else:
                parts.append(
                    f'<rect class="seg sev-{sev}" x="{x:.1f}" y="{y_top:.1f}" width="{bar_w:.1f}" height="{seg_h:.1f}"/>'
                )
        parts.append("</a>")
        if index % label_every == 0 or index == len(points) - 1:
            if index == len(points) - 1 and index % label_every and len(points) > 1 and slot * (index % label_every) < 56:
                continue
            parts.append(
                f'<text class="tick" x="{x + bar_w / 2:.1f}" y="{height - 10}" text-anchor="middle">'
                f'{esc(point["scanned_at"][5:10])}</text>'
            )
    parts.append("</svg>")
    legend = "".join(
        f'<span class="key sev-{sev}"><i aria-hidden="true"></i>{esc(SEV_LABEL[sev])}</span>' for sev in SEVERITIES
    )
    return f'<div class="chart-box">{"".join(parts)}<div class="legend">{legend}</div></div>'


# ---- layout ---------------------------------------------------------------

def page(title: str, active: str, body: str, *, csrf: str = "", version: str = "") -> str:
    current = ' aria-current="page"'
    nav = "".join(
        f'<a href="{href}"{current if key == active else ""}>{esc(label)}</a>'
        for key, href, label in NAV
    )
    logout = (
        f'<form method="post" action="/logout" class="logout"><input type="hidden" name="csrf" value="{esc(csrf)}">'
        '<button class="link" type="submit">Sign out</button></form>'
    ) if csrf else ""
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{esc(title)} · aiscan hub</title>"
        '<link rel="stylesheet" href="/static/hub.css">'
        '<script src="/static/hub.js" defer></script>'
        "</head><body>"
        '<header class="top"><div class="top-inner">'
        '<a class="brand" href="/"><span class="mark" aria-hidden="true"></span>aiscan hub</a>'
        f'<nav aria-label="Main">{nav}</nav>{logout}'
        "</div></header>"
        f'<main>{body}</main>'
        f'<footer class="foot">aiscan hub {esc(version)} · data stays in this hub\'s database · '
        '<a href="/api/v1/overview">JSON API</a></footer>'
        '<div id="tip" class="tip" role="status" hidden></div>'
        "</body></html>"
    )


def login_page(message: str = "") -> str:
    note = f'<p class="alert">{esc(message)}</p>' if message else ""
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>Sign in · aiscan hub</title>"
        '<link rel="stylesheet" href="/static/hub.css"></head><body>'
        '<main class="login"><h1>aiscan hub</h1>'
        f"{note}"
        "<p>Paste the access token that <code>aiscan hub</code> printed when it started. "
        "It is also in the <code>ui-token</code> file next to the hub database.</p>"
        '<form method="post" action="/login"><label class="field"><span>Access token</span>'
        '<input type="password" name="token" autocomplete="current-password" autofocus required></label>'
        '<button class="btn primary" type="submit">Sign in</button></form>'
        "</main></body></html>"
    )


def empty_hub() -> str:
    return (
        '<section class="card"><h2>No scans in the hub yet</h2>'
        "<p>The hub shows scans after they are added to its database. Run a scan and add it in one step:</p>"
        "<pre>.\\aiscan.ps1 all -Hub</pre>"
        "<p>Or add scan folders you already have. A folder that holds several scans is walked one level down:</p>"
        "<pre>.\\aiscan.ps1 hub-import -OutDir C:\\scans</pre>"
        "<p>Only the <code>evidence</code> layer is stored. Transcripts and per-hit rows under "
        "<code>raw</code> are never read.</p></section>"
    )


# ---- pages ----------------------------------------------------------------

def _finding_rows(rows: list[dict[str, Any]], *, show_host: bool = True) -> list[list[str]]:
    out = []
    for row in rows:
        cells = [
            sev_badge(row["severity"]),
            f'<a href="{esc(finding_url(row))}">{esc(row["title"] or row["finding_id"])}</a>'
            f'<div class="muted small mono">{esc(row["finding_id"])}</div>',
        ]
        if show_host:
            cells.append(f'<a href="/hosts/{int(row["host_id"])}">{esc(row["host"])}</a>')
        cells += [
            esc(row["collector"]),
            _num(row["evidence_count"]),
            when(row["first_seen_at"]),
            pill("Resolved", "ok") if row["status"] == "resolved" else pill(TRIAGE_LABEL.get(row["triage"], row["triage"]), "t-" + row["triage"]),
        ]
        out.append(cells)
    return out


def overview_page(data: dict[str, Any]) -> str:
    ov = data["overview"]
    if not ov["scans"]:
        return empty_hub()
    attention = ov["attention"]["critical"] + ov["attention"]["high"]
    tiles = "".join([
        stat("Needs review: critical and high", _num(attention),
             "open, not yet triaged", href=_url("/findings", status="open", triage="attention"), hero=True),
        stat("Open findings", _num(ov["open_total"]), sev_counts(ov["open"]), href="/findings"),
        stat("Machines", _num(ov["hosts"]), f"{_num(ov['scans'])} scans stored"),
        stat("AI agents detected", _num(ov["agents"]), "across all machines"),
        stat("Allow rules", _num(ov["allow_rules"]), "in current permissions", href="/permissions"),
        stat("MCP servers", _num(ov["mcp_servers"]), "distinct names", href="/mcp"),
    ])
    changes = [
        [
            f'<a href="/scans/{int(c["scan_id"])}">{when(c["scanned_at"])}</a>'
            f'<div class="muted small">{esc(c["host"])}</div>',
            _num(c["new_high_or_critical"]),
            f'<span class="nw">+{_num(c["findings_added"])} / −{_num(c["findings_resolved"])}</span>',
            _num(c["mcp_servers_added"]),
            _num(c["allow_rules_added"]),
            pill(f'{c["drift_warnings"]} drift', "warn") if c["drift_warnings"] else '<span class="muted">none</span>',
        ]
        for c in data["changes"]
    ]
    attention_rows = [
        [
            sev_badge(row["severity"]),
            f'<a href="{esc(finding_url(row))}">{esc(row["title"] or row["finding_id"])}</a>'
            f'<div class="muted small"><a href="/hosts/{int(row["host_id"])}">{esc(row["host"])}</a> · {esc(row["collector"])}</div>',
            when(row["first_seen_at"]),
        ]
        for row in data["attention"]
    ]
    host_rows = [
        [
            f'<a href="/hosts/{int(h["id"])}">{esc(h["name"])}</a>',
            when(h["last_seen"], with_age=True),
            sev_counts(h["open"]),
            esc(", ".join(h["agents"])) or '<span class="muted">none detected</span>',
            _num(h["scan_count"]),
        ]
        for h in data["hosts"]
    ]
    return (
        f'<div class="head"><h1>Fleet posture</h1><p class="muted">Last scan {when(ov["last_scan"], with_age=True)}</p></div>'
        f'<section class="stats">{tiles}</section>'
        '<section class="card"><h2>Open findings over time</h2>'
        '<p class="muted small">One column per scan. Each column counts what was open across every machine as of that scan.</p>'
        f'{severity_chart(data["trend"], title="Open findings by severity, one column per scan")}</section>'
        '<div class="grid2">'
        '<section class="card"><h2>Needs review</h2>'
        + table(["Severity", "Finding", "First seen"], attention_rows,
                empty="Nothing critical or high is waiting for review.")
        + f'<p><a href="{esc(_url("/findings", status="open", triage="attention"))}">All findings that need review</a></p></section>'
        '<section class="card"><h2>What changed</h2>'
        + table(["Scan", "New high or critical", "Findings", "New MCP servers", "New allow rules", "Drift"],
                changes, empty="No scan differs from the one before it yet.")
        + "</section></div>"
        '<section class="card"><h2>Machines</h2>'
        + table(["Machine", "Last scan", "Open findings", "Agents detected", "Scans"], host_rows)
        + "</section>"
    )


def host_page(data: dict[str, Any]) -> str:
    h = data["host"]
    runs = [
        [
            esc(r["label"]) + (f' <span class="muted small mono">{esc(r["collector"])}</span>' if r["label"] != r["collector"] else ""),
            pill("Detected", "ok") if r["platform_detected"] else pill(r["detection_status"] or "not detected", "muted"),
            _num(r["finding_count"]),
            _num(r["rule_count"]),
            f'<a href="/scans/{int(r["scan_id"])}">{when(r["ran_at"])}</a>',
            esc(r["version"]),
        ]
        for r in data["runs"]
    ]
    return (
        f'<div class="head"><p class="crumb"><a href="/">Overview</a> / Machine</p><h1>{esc(h["name"])}</h1>'
        f'<p class="muted">Last scan {when(h["last_seen"], with_age=True)} · first seen {when(h["first_seen"])} · '
        f'{_num(h["scan_count"])} scans · aiscan {esc(h["aiscan_version"] or "unknown")}</p></div>'
        '<section class="stats">'
        + stat("Open findings", _num(sum(h["open"].values())), sev_counts(h["open"]),
               href=_url("/findings", host=h["id"]))
        + stat("AI agents detected", _num(len(h["agents"])), esc(", ".join(h["agents"])))
        + "</section>"
        '<section class="card"><h2>Open findings over time</h2>'
        f'{severity_chart(data["trend"], title="Open findings by severity on this machine, one column per scan")}</section>'
        '<section class="card"><h2>Current state by collector</h2>'
        '<p class="muted small">The newest run of each collector. A re-run of one collector updates only its row.</p>'
        + table(["Collector", "Status", "Findings", "Rules", "Last run", "Schema"], runs)
        + "</section>"
        '<section class="card"><h2>Open findings</h2>'
        + table(["Severity", "Finding", "Source", "Evidence", "First seen", "State"],
                _finding_rows(data["findings"], show_host=False), empty="No open findings on this machine.")
        + f'<p><a href="{esc(_url("/findings", host=h["id"], status="all"))}">Full history for this machine</a></p></section>'
        '<section class="card"><h2>Scans</h2>' + _scan_table(data["scans"], show_host=False) + "</section>"
    )


def _scan_table(rows: list[dict[str, Any]], *, show_host: bool = True) -> str:
    out = []
    for s in rows:
        posture = {sev: s[f"posture_{sev}"] for sev in SEVERITIES}
        cells = [f'<a href="/scans/{int(s["id"])}">{when(s["scanned_at"])}</a>']
        if show_host:
            cells.append(f'<a href="/hosts/{int(s["host_id"])}">{esc(s["host"])}</a>')
        cells += [
            _num(s["collector_count"]),
            _num(s["finding_count"]),
            sev_counts(posture),
            esc(s["launched_by"]),
            esc(s["reason"]),
            pill("share-safe", "ok") if s["share_safe"] else pill("as scanned", "muted"),
        ]
        out.append(cells)
    headers = ["Scan"] + (["Machine"] if show_host else []) + [
        "Collectors", "Findings in scan", "Open after scan", "Launched by", "Reason", "Content"]
    return table(headers, out, empty="No scans stored.")


def scans_page(data: dict[str, Any]) -> str:
    return (
        '<div class="head"><h1>Scans</h1><p class="muted">Every scan stored in the hub, newest first.</p></div>'
        f'<section class="card">{_scan_table(data["scans"])}{pager("/scans", {}, data["total"], data["offset"])}</section>'
    )


def _changes_block(changes: dict[str, Any] | None) -> str:
    if not changes:
        return '<p class="empty">A one-collector scan is not compared with an earlier scan.</p>'
    summary = changes.get("summary") or {}
    if summary.get("comparison") != "diff":
        return '<p class="empty">This is the first full scan for this machine, so there is nothing to compare it with. It is a baseline, not a clean result.</p>'
    tiles = "".join(
        stat(label, _num(summary.get(key)))
        for key, label in (
            ("new_high_or_critical", "New high or critical"), ("findings_added", "Findings added"),
            ("findings_resolved", "Findings resolved"), ("mcp_servers_added", "MCP servers added"),
            ("allow_rules_added", "Allow rules added"), ("drift_warnings", "Drift warnings"),
        )
    )
    rows = [
        [sev_badge(f.get("severity", "")), esc(f.get("title", "")), esc(f.get("category", "")),
         f'<span class="mono small">{esc(f.get("sample_redacted", ""))}</span>']
        for f in changes.get("findings") or []
    ]
    prev = changes.get("previous_scan_id")
    link = f' Compared with <a href="/scans/{int(prev)}">the scan before it</a>.' if prev else ""
    return (
        f'<p class="muted small">Computed by <code>core/scan_diff.py</code>, the same code that writes <code>changes.json</code>.{link}</p>'
        f'<div class="stats compact">{tiles}</div>'
        + table(["Severity", "Change", "Category", "Detail"], rows, empty="No change needs attention.")
    )


def scan_page(data: dict[str, Any]) -> str:
    s = data["scan"]
    runs = [
        [esc(r["collector"]),
         pill("Detected", "ok") if r["platform_detected"] else pill(r["detection_status"] or "not detected", "muted"),
         _num(r["finding_count"]), _num(r["rule_count"]), when(r["ran_at"]), esc(r["version"])]
        for r in s["runs"]
    ]
    for err in s["errors"]:
        runs.append([esc(err.get("collector")), pill(err.get("detection_status") or "error", "bad"), "", "", "", ""])
    findings = [
        [sev_badge(f["severity"]),
         f'<a href="{esc(_url("/finding", host=s["host_id"], collector=f["collector"], key=f["finding_key"]))}">{esc(f["title"] or f["finding_id"])}</a>'
         f'<div class="muted small mono">{esc(f["finding_id"])}</div>',
         esc(f["collector"]), esc(f["category"]), _num(f["evidence_count"]),
         f'<span class="mono small">{esc(f["sample"][:240])}</span>']
        for f in s["findings"]
    ]
    content = (
        "Share-safe: secrets, paths, and emails were masked before this scan left its machine."
        if s["share_safe"] else
        "As scanned: this scan was added on the machine it ran on, with the text the scan wrote."
    )
    return (
        f'<div class="head"><p class="crumb"><a href="/scans">Scans</a> / <a href="/hosts/{int(s["host_id"])}">{esc(s["host"])}</a></p>'
        f'<h1>Scan of {esc(s["host"])}</h1><p class="muted">{when(s["scanned_at"], with_age=True)}</p></div>'
        '<section class="card"><dl class="meta">'
        f'<div><dt>Launched by</dt><dd>{esc(s["launched_by"])}</dd></div>'
        f'<div><dt>Reason</dt><dd>{esc(s["reason"])}</dd></div>'
        f'<div><dt>aiscan version</dt><dd>{esc(s["aiscan_version"] or "unknown")}</dd></div>'
        f'<div><dt>Added to hub</dt><dd>{when(s["ingested_at"])} ({esc(s["via"])})</dd></div>'
        f'<div><dt>Scan folder name</dt><dd>{esc(s["source_label"] or "unknown")}</dd></div>'
        f'<div><dt>Content</dt><dd>{esc(content)}</dd></div>'
        "</dl></section>"
        f'<section class="card"><h2>What changed</h2>{_changes_block(data["changes"])}</section>'
        '<section class="card"><h2>Collectors</h2>'
        + table(["Collector", "Status", "Findings", "Rules", "Ran", "Schema"], runs)
        + "</section>"
        f'<section class="card"><h2>Findings in this scan ({_num(len(findings))})</h2>'
        + table(["Severity", "Finding", "Source", "Category", "Evidence", "Sample"], findings,
                empty="This scan reported no findings.")
        + "</section>"
    )


def findings_page(data: dict[str, Any]) -> str:
    f = data["filters"]
    params = {k: v for k, v in f.items() if v not in ("", None)}
    form = (
        '<form class="filters" method="get" action="/findings">'
        + select("status", [("open", "Open"), ("resolved", "Resolved"), ("all", "Open and resolved")], f["status"], "Status")
        + select("severity", [("", "Any")] + [(s, SEV_LABEL[s]) for s in SEVERITIES], f["severity"], "Severity")
        + select("triage", [("", "Any"), ("attention", "Needs review")] + [(s, TRIAGE_LABEL[s]) for s in TRIAGE_STATES[1:]], f["triage"], "Review state")
        + select("collector", [("", "Any")] + [(c, c) for c in data["collectors"]], f["collector"], "Source")
        + select("host", [("", "Any")] + [(str(h["id"]), h["name"]) for h in data["hosts"]], str(f["host"] or ""), "Machine")
        + f'<label class="field grow"><span>Search</span><input type="search" name="q" value="{esc(f["q"])}" placeholder="Title, id, or category"></label>'
        + '<button class="btn primary" type="submit">Apply</button><a class="btn" href="/findings">Reset</a></form>'
    )
    return (
        '<div class="head"><h1>Findings</h1><p class="muted">One row per finding per machine, tracked across scans. '
        "A finding is open while the newest run of its collector still reports it.</p></div>"
        f'<section class="card">{form}'
        + table(["Severity", "Finding", "Machine", "Source", "Evidence", "First seen", "State"],
                _finding_rows(data["rows"]), empty="No findings match these filters.")
        + pager("/findings", params, data["total"], data["offset"])
        + "</section>"
    )


def finding_page(data: dict[str, Any], csrf: str) -> str:
    f = data["finding"]
    history = [
        [
            f'<a href="/scans/{int(h["scan_id"])}">{when(h["ran_at"])}</a>',
            pill("Reported", "bad") if h["present"] else pill("Not reported", "ok"),
            sev_badge(h["severity"]) if h["present"] else "",
            _num(h["evidence_count"]) if h["present"] else "",
            f'<span class="mono small">{esc((h["sample"] or "")[:200])}</span>',
        ]
        for h in f["history"]
    ]
    options = "".join(
        f'<option value="{esc(s)}"{" selected" if s == f["triage"] else ""}>{esc(TRIAGE_LABEL[s])}</option>'
        for s in TRIAGE_STATES
    )
    status = pill("Resolved", "ok") if f["status"] == "resolved" else pill("Open", "bad")
    resolved = f'<div><dt>Resolved</dt><dd>{when(f["resolved_at"])}</dd></div>' if f["status"] == "resolved" else ""
    tags = " ".join(pill(t, "muted") for t in f["tags"]) or '<span class="muted">none</span>'
    return (
        f'<div class="head"><p class="crumb"><a href="/findings">Findings</a> / <a href="/hosts/{int(f["host_id"])}">{esc(f["host"])}</a></p>'
        f'<h1>{esc(f["title"] or f["finding_id"])}</h1><p>{sev_badge(f["severity"])} {status} '
        f'<span class="muted mono small">{esc(f["finding_id"])}</span></p></div>'
        '<div class="grid2"><section class="card"><h2>Details</h2><dl class="meta">'
        f'<div><dt>Machine</dt><dd><a href="/hosts/{int(f["host_id"])}">{esc(f["host"])}</a></dd></div>'
        f'<div><dt>Source</dt><dd>{esc(f["collector"])}</dd></div>'
        f'<div><dt>Category</dt><dd>{esc(f["category"])}</dd></div>'
        f'<div><dt>Evidence count</dt><dd>{_num(f["evidence_count"])}</dd></div>'
        f'<div><dt>First seen</dt><dd>{when(f["first_seen_at"], with_age=True)}</dd></div>'
        f'<div><dt>Last seen</dt><dd>{when(f["last_seen_at"], with_age=True)}</dd></div>'
        f'{resolved}'
        f'<div><dt>Reported in</dt><dd>{_num(f["occurrences"])} run{"" if f["occurrences"] == 1 else "s"}</dd></div>'
        f'<div><dt>Tags</dt><dd>{tags}</dd></div>'
        "</dl>"
        + (f'<h3>Latest sample</h3><pre class="sample">{esc(f["sample"])}</pre>' if f["sample"] else "")
        + "</section>"
        '<section class="card"><h2>Review</h2>'
        '<p class="muted small">Your decision stays with this finding on this machine across later scans. '
        "It does not change what the scanner reports.</p>"
        '<form method="post" action="/findings/triage" class="stack">'
        f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
        f'<input type="hidden" name="host" value="{int(f["host_id"])}">'
        f'<input type="hidden" name="collector" value="{esc(f["collector"])}">'
        f'<input type="hidden" name="key" value="{esc(f["finding_key"])}">'
        f'<label class="field"><span>State</span><select name="state">{options}</select></label>'
        f'<label class="field"><span>Note</span><textarea name="note" rows="4" maxlength="2000">{esc(f["note"])}</textarea></label>'
        '<button class="btn primary" type="submit">Save</button>'
        + (f'<p class="muted small">Last saved {when(f["triage_at"])}</p>' if f["triage_at"] else "")
        + "</form></section></div>"
        '<section class="card"><h2>History</h2>'
        '<p class="muted small">Every run of this collector on this machine, newest first.</p>'
        + table(["Run", "This finding", "Severity", "Evidence", "Sample"], history)
        + "</section>"
    )


def permissions_page(data: dict[str, Any]) -> str:
    f = data["filters"]
    params = {k: v for k, v in f.items() if v not in ("", None)}
    totals = data["totals"]
    tiles = "".join(
        stat(f"{label} rules", _num(sum(totals[key].values())), sev_counts(totals[key]),
             href=_url("/permissions", decision=key))
        for key, label in (("allow", "Allow"), ("ask", "Ask"), ("deny", "Deny"))
    )
    form = (
        '<form class="filters" method="get" action="/permissions">'
        + select("decision", [("allow", "Allow"), ("ask", "Ask"), ("deny", "Deny"), ("all", "Any")], f["decision"], "Decision")
        + select("risk", [("", "Any")] + [(s, SEV_LABEL[s]) for s in SEVERITIES], f["risk"], "Risk")
        + select("host", [("", "Any")] + [(str(h["id"]), h["name"]) for h in data["hosts"]], str(f["host"] or ""), "Machine")
        + f'<label class="field grow"><span>Search</span><input type="search" name="q" value="{esc(f["q"])}" placeholder="Rule, command, or scope"></label>'
        + '<button class="btn primary" type="submit">Apply</button><a class="btn" href="/permissions">Reset</a></form>'
    )
    rows = [
        [sev_badge(r["risk"]), f'<span class="mono">{esc(r["rule"])}</span>' + (f' <span class="muted small">×{int(r["n"])}</span>' if r["n"] > 1 else ""),
         pill(r["decision"], "d-" + r["decision"]), esc(r["exposure_category"]),
         f'<a href="/hosts/{int(r["host_id"])}">{esc(r["host"])}</a>', esc(r["collector"]),
         f'<span class="mono small">{esc(r["scope_label"])}</span>', esc(r["source_kind"])]
        for r in data["rows"]
    ]
    return (
        '<div class="head"><h1>Permissions</h1><p class="muted">What each agent is allowed to do right now, '
        "from the newest run of each collector on each machine. Risk is the scanner's rating of the rule.</p></div>"
        f'<section class="stats">{tiles}</section>'
        f'<section class="card">{form}'
        + table(["Risk", "Rule", "Decision", "Exposure", "Machine", "Agent", "Scope", "Source"], rows,
                empty="No rules match these filters.")
        + pager("/permissions", params, data["total"], data["offset"])
        + "</section>"
    )


def mcp_page(data: dict[str, Any]) -> str:
    rows = [
        [f'<span class="mono">{esc(m["name"])}</span>', esc(", ".join(m["tools"])), esc(", ".join(m["hosts"])),
         when(m["first_seen"], with_age=True)]
        for m in data["servers"]
    ]
    return (
        '<div class="head"><h1>MCP servers</h1><p class="muted">Servers named in current evidence: MCP tool rules, '
        "server lists, and runtime transports. A new server also shows up as a change on its scan.</p></div>"
        '<section class="card">'
        + table(["Server", "Configured in", "Machines", "First seen in hub"], rows, empty="No MCP servers in current evidence.")
        + "</section>"
    )


def accounts_page(data: dict[str, Any]) -> str:
    rows = [
        [f'<a href="/hosts/{int(a["host_id"])}">{esc(a["host"])}</a>', esc(a["tool"]),
         pill(a["signed_in"] or "unknown", {"yes": "ok", "no": "muted"}.get(a["signed_in"], "warn")),
         esc(a["account"]), esc(a["organization"]), esc(a["plan"]), esc(a["auth_method"]),
         f'<span class="mono small">{esc(a["source"])}</span>', when(a["last_sign_in"]) if a["last_sign_in"] else ""]
        for a in data["accounts"]
    ]
    return (
        '<div class="head"><h1>Accounts</h1><p class="muted">Which identity each tool is signed in as, from the newest '
        "<code>accounts</code> run on each machine. The scanner never stores token or key values. "
        "A scan pushed from another machine shows <code>&lt;email&gt;</code> in place of addresses.</p></div>"
        '<section class="card">'
        + table(["Machine", "Tool", "Signed in", "Account", "Organization", "Plan", "Auth", "Source", "Last sign-in"], rows,
                empty="No accounts evidence stored.")
        + "</section>"
    )


def settings_page(data: dict[str, Any]) -> str:
    tokens = [
        [esc(t["name"]), when(t["created_at"]),
         when(t["last_used_at"], with_age=True) if t["last_used_at"] else '<span class="muted">never</span>',
         pill("Revoked", "bad") if t["revoked_at"] else pill("Active", "ok")]
        for t in data["tokens"]
    ]
    return (
        '<div class="head"><h1>Settings</h1></div>'
        '<section class="card"><h2>This hub</h2><dl class="meta">'
        f'<div><dt>Database</dt><dd class="mono">{esc(data["db_path"])}</dd></div>'
        f'<div><dt>Size</dt><dd>{esc(data["db_size"])}</dd></div>'
        f'<div><dt>Listening on</dt><dd class="mono">{esc(data["listen"])}</dd></div>'
        f'<div><dt>aiscan version</dt><dd>{esc(data["version"])}</dd></div>'
        "</dl></section>"
        '<section class="card"><h2>Ingest tokens</h2>'
        "<p class=\"muted small\">A token lets another machine push share-safe scans to this hub. "
        "It cannot read anything. Tokens are created and revoked from the command line:</p>"
        "<pre>python hub\\aiscan_hub.py token create --name laptop\npython hub\\aiscan_hub.py token revoke --name laptop</pre>"
        + table(["Name", "Created", "Last used", "State"], tokens, empty="No ingest tokens. Only this machine can add scans.")
        + "</section>"
        '<section class="card"><h2>Retention</h2>'
        "<p class=\"muted small\">Scans stay until you remove them. Each machine's newest scan is always kept.</p>"
        "<pre>python hub\\aiscan_hub.py prune --keep-days 365 --dry-run</pre></section>"
    )


def message_page(title: str, text: str) -> str:
    return f'<div class="head"><h1>{esc(title)}</h1></div><section class="card"><p>{esc(text)}</p><p><a href="/">Back to the overview</a></p></section>'
