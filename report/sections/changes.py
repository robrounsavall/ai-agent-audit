"""HTML fragment for the scan-to-scan changes envelope.

Integration should load ``evidence/changes.json`` and pass the dict here.
Both functions return an empty string when ``env`` is missing or is not a
changes envelope. A first scan (``summary.comparison == "first_scan"``) renders
a short explanation instead of an empty diff.

``render_changes_section(env)`` returns a ``<section id="changes">`` fragment.
``render_changes_nav(env)`` returns one nav anchor, ``<a href="#changes">``,
for the same cases the section renders.

Escaping matches ``report/build-briefing.py`` (``html.escape`` via its ``_esc``
when that module imports). CSS classes are the briefing's existing ones
(``section``, ``kicker``, ``sev-strip``, ``pill``, ``mcp-table``, ``panel``).
"""

from __future__ import annotations

import html
import importlib.util
from pathlib import Path
from typing import Any, Callable

_esc_impl: Callable[[Any], str] | None = None


def _fallback_esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _load_esc() -> Callable[[Any], str]:
    """Use build-briefing._esc when the briefing module imports cleanly."""
    path = Path(__file__).resolve().parent.parent / "build-briefing.py"
    try:
        spec = importlib.util.spec_from_file_location("aiscan_build_briefing", path)
        if spec is None or spec.loader is None:
            return _fallback_esc
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        esc = getattr(module, "_esc", None)
        if callable(esc):
            return esc
    except Exception:
        return _fallback_esc
    return _fallback_esc


def _esc(value: Any) -> str:
    global _esc_impl
    if _esc_impl is None:
        _esc_impl = _load_esc()
    return _esc_impl(value)


def _summary(env: dict[str, Any]) -> dict[str, Any]:
    summary = env.get("summary")
    return summary if isinstance(summary, dict) else {}


def _changes(env: dict[str, Any]) -> dict[str, Any]:
    changes = env.get("changes")
    return changes if isinstance(changes, dict) else {}


def _usable(env: dict[str, Any] | None) -> bool:
    if not isinstance(env, dict) or not env:
        return False
    summary = _summary(env)
    comparison = summary.get("comparison")
    if comparison in {"diff", "first_scan"}:
        return True
    if env.get("collector") == "changes" and _changes(env):
        return True
    return False


def _pill(severity: str) -> str:
    label = str(severity or "low").lower()
    if label not in {"critical", "high", "medium", "low"}:
        label = "low"
    return f'<span class="pill {label}">{_esc(label)}</span>'


def _fmt_num(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return _esc(value)
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return _esc(value)


def _fmt_when(value: Any) -> str:
    text = str(value or "").replace("T", " ")
    if len(text) >= 16:
        text = text[:16]
    return text


def _table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return ""
    head = "".join(f"<th>{_esc(header)}</th>" for header in headers)
    body = []
    for row in rows:
        cells = "".join(f"<td>{cell}</td>" for cell in row)
        body.append(f"<tr>{cells}</tr>")
    return (
        '<div class="table-wrap"><table class="mcp-table"><thead><tr>'
        f"{head}</tr></thead><tbody>{''.join(body)}</tbody></table></div>"
    )


def _block(title: str, meta: str, body: str) -> str:
    if not body:
        return ""
    return (
        '<div class="mcp-summary" style="margin-top:36px">'
        '<div class="rule-group-head">'
        f"<h4>{_esc(title)}</h4>"
        f'<span class="meta">{_esc(meta)}</span>'
        f"</div>{body}</div>"
    )


def _header(num_label: str, kicker: str, title: str, sub: str) -> str:
    return (
        '<header class="sh">'
        '<div class="kicker">'
        f'<span class="num">{_esc(num_label)}</span>'
        f'<span class="kicker-label">{_esc(kicker)}</span>'
        "</div>"
        f'<h2 class="h2">{_esc(title)}</h2>'
        f'<p class="sub">{_esc(sub)}</p>'
        "</header>"
    )


def _section(inner: str) -> str:
    return f'<section id="changes" class="section"><div class="wrap">{inner}</div></section>'


def _first_scan_section(env: dict[str, Any]) -> str:
    summary = _summary(env)
    label = str(summary.get("current_label") or "this scan")
    inner = (
        _header(
            "CHG",
            "SCAN CHANGES",
            "Nothing to compare yet.",
            "This is the first scan in the history folder. The next run will show "
            "what was added, what went away, and any collector that goes quiet.",
        )
        + '<div class="panel"><p>'
        + _esc(
            f"{label} is the baseline. Keep each run in its own dated folder "
            "(for example a folder named for the day) and diff again after the next scan. "
            "Nothing here is marked new, resolved, or clean — there is no earlier scan to judge against."
        )
        + "</p></div>"
    )
    return _section(inner)


def _location_drift(collectors: dict[str, Any]) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    for name in sorted(collectors):
        entry = collectors.get(name)
        if not isinstance(entry, dict):
            continue
        for item in entry.get("drift") or []:
            if not isinstance(item, dict):
                continue
            kind = str(item.get("kind") or "")
            if kind in {"data_to_zero", "not_detected"}:
                rows.append((name, kind, str(item.get("detail") or "")))
    return rows


def _headline(summary: dict[str, Any], location_rows: list[tuple[str, str, str]]) -> tuple[str, str]:
    if location_rows:
        return (
            "A collector that used to find data now looks empty.",
            "That is possible data-location drift, not a clean result. "
            "Providers sometimes move tokens or transcripts off the machine. "
            "Resolved findings on a quiet collector are not evidence the issue is fixed.",
        )
    if int(summary.get("new_high_or_critical") or 0) > 0:
        return (
            "New high-severity findings since the last scan.",
            "High and critical items that were not in the previous scan, "
            "plus anything else that was added or removed.",
        )
    changed = int(summary.get("collectors_changed") or 0)
    if changed:
        return (
            "What changed since the last scan.",
            "Findings, rules, MCP servers, and summary counters compared with the previous run.",
        )
    return (
        "No material changes since the last scan.",
        "The collectors in this run match the previous scan on findings, rules, MCP servers, and counters.",
    )


def _non_mcp_allow_count(collectors: dict[str, Any], side: str) -> int:
    total = 0
    for entry in collectors.values():
        if not isinstance(entry, dict):
            continue
        block = entry.get("allow_rules")
        if not isinstance(block, dict):
            continue
        for rule in block.get(side) or []:
            if not isinstance(rule, dict):
                continue
            if str(rule.get("rule_type") or "") == "mcp_tool":
                continue
            total += int(rule.get("count") or 1)
    return total


def _metric_strip(summary: dict[str, Any], allow_added: int) -> str:
    cells = (
        ("New high / critical", summary.get("new_high_or_critical") or 0, "red"),
        ("Drift warnings", summary.get("drift_warnings") or 0, "amber"),
        ("New MCP servers", summary.get("mcp_servers_added") or 0, "yellow"),
        ("New allow rules", allow_added, ""),
    )
    parts = []
    for label, value, tone in cells:
        tone_cls = f" {tone}" if tone else ""
        parts.append(
            "<div>"
            f'<div class="lbl">{_esc(label)}</div>'
            f'<div class="v{tone_cls}">{_esc(int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0)}</div>'
            "</div>"
        )
    return f'<div class="sev-strip">{"".join(parts)}</div>'


def _finding_rows(collectors: dict[str, Any]) -> list[list[str]]:
    rows: list[list[str]] = []
    for name in sorted(collectors):
        entry = collectors[name]
        findings = entry.get("findings") if isinstance(entry, dict) else None
        if not isinstance(findings, dict):
            continue
        for item in findings.get("added") or []:
            if not isinstance(item, dict):
                continue
            rows.append([
                "Added",
                _pill(str(item.get("severity") or "")),
                _esc(name),
                _esc(item.get("title") or item.get("id") or ""),
            ])
        for item in findings.get("resolved") or []:
            if not isinstance(item, dict):
                continue
            rows.append([
                "Resolved",
                _pill(str(item.get("severity") or "")),
                _esc(name),
                _esc(item.get("title") or item.get("id") or ""),
            ])
        for item in findings.get("severity_changed") or []:
            if not isinstance(item, dict):
                continue
            change = (
                f'{_pill(str(item.get("before") or ""))}'
                f' <span class="mono">→</span> '
                f'{_pill(str(item.get("after") or ""))}'
            )
            rows.append([
                "Severity",
                change,
                _esc(name),
                _esc(item.get("title") or item.get("id") or ""),
            ])
    return rows


def _flag_rows(env: dict[str, Any]) -> list[list[str]]:
    rows: list[list[str]] = []
    for finding in env.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        rows.append([
            _pill(str(finding.get("severity") or "")),
            _esc(finding.get("title") or ""),
            f"<code>{_esc(finding.get('sample_redacted') or '')}</code>",
        ])
    return rows


def _named_rows(collectors: dict[str, Any], bucket: str) -> list[list[str]]:
    rows: list[list[str]] = []
    for name in sorted(collectors):
        entry = collectors[name]
        block = entry.get(bucket) if isinstance(entry, dict) else None
        if not isinstance(block, dict):
            continue
        for server in block.get("added") or []:
            rows.append(["Added", _esc(name), f"<code>{_esc(server)}</code>"])
        for server in block.get("removed") or []:
            rows.append(["Removed", _esc(name), f"<code>{_esc(server)}</code>"])
    return rows


def _rule_rows(collectors: dict[str, Any], *, allow_only: bool) -> list[list[str]]:
    rows: list[list[str]] = []
    bucket = "allow_rules" if allow_only else "rules"
    for name in sorted(collectors):
        entry = collectors[name]
        block = entry.get(bucket) if isinstance(entry, dict) else None
        if not isinstance(block, dict):
            continue
        for side, label in (("added", "Added"), ("removed", "Removed")):
            for rule in block.get(side) or []:
                if not isinstance(rule, dict):
                    continue
                rule_type = str(rule.get("rule_type") or "")
                decision = str(rule.get("decision") or "").lower()
                if allow_only and rule_type == "mcp_tool":
                    continue
                if not allow_only and decision == "allow":
                    continue
                rows.append([
                    label,
                    _esc(name),
                    _pill(str(rule.get("risk") or "low")),
                    f"<code>{_esc(rule.get('rule') or '')}</code>",
                ])
    return rows


def _counter_rows(collectors: dict[str, Any]) -> list[list[str]]:
    rows: list[list[str]] = []
    for name in sorted(collectors):
        entry = collectors[name]
        counters = entry.get("counters") if isinstance(entry, dict) else None
        if not isinstance(counters, list):
            continue
        for item in counters:
            if not isinstance(item, dict):
                continue
            rows.append([
                _esc(name),
                f"<code>{_esc(item.get('key') or '')}</code>",
                f'<span class="mono">{_fmt_num(item.get("before"))}</span>',
                f'<span class="mono">{_fmt_num(item.get("after"))}</span>',
            ])
    return rows


def _platform_rows(collectors: dict[str, Any]) -> list[list[str]]:
    rows: list[list[str]] = []
    labels = {
        "newly_detected": "Newly detected",
        "no_longer_detected": "No longer detected",
    }
    for name in sorted(collectors):
        entry = collectors[name]
        platform = entry.get("platform") if isinstance(entry, dict) else None
        if not isinstance(platform, dict):
            continue
        change = str(platform.get("change") or "")
        if change not in labels:
            continue
        rows.append([_esc(name), _esc(labels[change])])
    return rows


def _drift_rows(collectors: dict[str, Any]) -> list[list[str]]:
    rows: list[list[str]] = []
    kind_labels = {
        "data_to_zero": "Data gone",
        "not_detected": "Not detected",
        "version_changed": "Version changed",
    }
    for name in sorted(collectors):
        entry = collectors[name]
        if not isinstance(entry, dict):
            continue
        for item in entry.get("drift") or []:
            if not isinstance(item, dict):
                continue
            kind = str(item.get("kind") or "")
            rows.append([
                _esc(name),
                _esc(kind_labels.get(kind, kind or "drift")),
                _esc(item.get("detail") or ""),
            ])
    return rows


def _diff_section(env: dict[str, Any]) -> str:
    summary = _summary(env)
    changes = _changes(env)
    collectors = changes.get("collectors")
    if not isinstance(collectors, dict):
        collectors = {}
    location_rows = _location_drift(collectors)
    title, sub = _headline(summary, location_rows)
    current_label = str(summary.get("current_label") or changes.get("current_label") or "current")
    previous_label = str(summary.get("previous_label") or changes.get("previous_label") or "previous")
    current_when = _fmt_when(summary.get("current_ran_at") or changes.get("current_ran_at"))
    previous_when = _fmt_when(summary.get("previous_ran_at") or changes.get("previous_ran_at"))
    compared = (
        f"Compared {current_label}"
        + (f" ({current_when})" if current_when else "")
        + f" with {previous_label}"
        + (f" ({previous_when})" if previous_when else "")
        + "."
    )
    allow_added = _non_mcp_allow_count(collectors, "added")
    allow_removed = _non_mcp_allow_count(collectors, "removed")
    parts = [
        _header("CHG", "SCAN CHANGES", title, sub),
        f'<p class="sub">{_esc(compared)}</p>',
        _metric_strip(summary, allow_added),
    ]
    if location_rows:
        parts.append(
            '<div class="panel" style="margin-top:28px"><p>'
            '<span class="pill high">drift</span> '
            + _esc(
                "Possible data-location drift. A collector that used to find data "
                "now reports nothing, or the platform is no longer detected. "
                "Do not read that as a clean scan."
            )
            + "</p></div>"
        )
    flagged = len([f for f in (env.get("findings") or []) if isinstance(f, dict)])
    drift_n = int(summary.get("drift_warnings") or 0)
    parts.append(_block(
        "Flagged since the last scan",
        f"{flagged} change finding" if flagged == 1 else f"{flagged} change findings",
        _table(["Severity", "What changed", "Detail"], _flag_rows(env)),
    ))
    parts.append(_block(
        "Drift warnings",
        f"{drift_n} warning" if drift_n == 1 else f"{drift_n} warnings",
        _table(["Collector", "Kind", "Detail"], _drift_rows(collectors)),
    ))
    parts.append(_block(
        "Platform detection",
        "newly detected or no longer detected",
        _table(["Collector", "Change"], _platform_rows(collectors)),
    ))
    finding_rows = _finding_rows(collectors)
    parts.append(_block(
        "Findings",
        (
            f"{int(summary.get('findings_added') or 0)} added · "
            f"{int(summary.get('findings_resolved') or 0)} resolved · "
            f"{int(summary.get('findings_severity_changed') or 0)} severity changed"
        ),
        _table(["Change", "Severity", "Collector", "Finding"], finding_rows),
    ))
    parts.append(_block(
        "MCP servers",
        (
            f"{int(summary.get('mcp_servers_added') or 0)} added · "
            f"{int(summary.get('mcp_servers_removed') or 0)} removed"
        ),
        _table(["Change", "Collector", "Server"], _named_rows(collectors, "mcp_servers")),
    ))
    parts.append(_block(
        "Allow rules",
        f"{allow_added} added · {allow_removed} removed",
        _table(["Change", "Collector", "Risk", "Rule"], _rule_rows(collectors, allow_only=True)),
    ))
    parts.append(_block(
        "Other rules",
        "deny, ask, and non-allow changes",
        _table(["Change", "Collector", "Risk", "Rule"], _rule_rows(collectors, allow_only=False)),
    ))
    parts.append(_block(
        "Summary counters",
        f"{int(summary.get('counters_moved') or 0)} moved",
        _table(["Collector", "Counter", "Before", "After"], _counter_rows(collectors)),
    ))
    if not any(part for part in parts[3:]):
        parts.append(
            '<div class="panel" style="margin-top:28px"><p>No material changes since the previous scan.</p></div>'
        )
    return _section("".join(parts))


def render_changes_section(env: dict | None) -> str:
    """Return the changes section, a first-scan note, or an empty string."""
    if not _usable(env):
        return ""
    assert env is not None
    if _summary(env).get("comparison") == "first_scan":
        return _first_scan_section(env)
    return _diff_section(env)


def render_changes_nav(env: dict | None) -> str:
    """Return a nav anchor when the section would render, else an empty string."""
    if not render_changes_section(env):
        return ""
    return '<a href="#changes">Changes</a>'
