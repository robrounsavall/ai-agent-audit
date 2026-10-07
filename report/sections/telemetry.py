"""HTML sections for the telemetry-import evidence envelope.

Public integration surface (pass the ``evidence/telemetry.json`` object):

    render_approvals_section(env) -> str
    render_usage_section(env) -> str
    approvals_nav_link(env) -> str
    usage_nav_link(env) -> str
    telemetry_nav_links(env) -> str

Each returns an empty string when that side of the envelope has no evidence
(missing envelope, ``platform_detected`` false, or a zero count).

Escaping uses ``build-briefing.py``'s ``_esc`` helper. Section markup uses
the briefing's existing classes (``section``, ``perm-summary``, ``table-wrap``,
``mode-chip``, ``surface-note``, ``pill``). Kicker numbers ``/09`` and ``/10``
are placeholders the integrator can renumber.
"""

from __future__ import annotations

import html
import importlib.util
from pathlib import Path
from typing import Any

APPROVALS_SECTION_ID = "telemetry-approvals"
USAGE_SECTION_ID = "telemetry-usage"
APPROVALS_KICKER_NUM = "/09"
USAGE_KICKER_NUM = "/10"

COST_LABEL = "from the Cursor dashboard usage export"
TOKENS_ONLY_LABEL = "tokens only"

_ESC = None


def _load_esc():
    global _ESC
    if _ESC is not None:
        return _ESC
    path = Path(__file__).resolve().parent.parent / "build-briefing.py"
    try:
        spec = importlib.util.spec_from_file_location("aiscan_build_briefing", path)
        if spec is None or spec.loader is None:
            raise ImportError(str(path))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _ESC = module._esc
    except Exception:
        _ESC = lambda value: html.escape(str(value if value is not None else ""))
    return _ESC


def _esc(value: Any) -> str:
    return _load_esc()(value)


def _summary(env: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(env, dict):
        return {}
    summary = env.get("summary")
    return summary if isinstance(summary, dict) else {}


def _count(summary: dict[str, Any], key: str) -> int:
    try:
        return int(summary.get(key) or 0)
    except (TypeError, ValueError):
        return 0


def _rows(summary: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = summary.get(key)
    if not isinstance(value, list):
        return []
    return [row for row in value if isinstance(row, dict)]


def _detected(env: dict[str, Any] | None) -> bool:
    return isinstance(env, dict) and env.get("platform_detected") is not False


def has_approval_evidence(env: dict[str, Any] | None) -> bool:
    if not _detected(env):
        return False
    summary = _summary(env)
    if _count(summary, "approval_events") > 0:
        return True
    return bool(
        _rows(summary, "approvals_by_tool")
        or _rows(summary, "approvals_by_source")
        or _rows(summary, "approvals_by_day")
    )


def has_usage_evidence(env: dict[str, Any] | None) -> bool:
    if not _detected(env):
        return False
    summary = _summary(env)
    if _count(summary, "usage_events") > 0 or _count(summary, "total_tokens") > 0:
        return True
    if summary.get("cost_basis") == "cursor_dashboard" and _count(summary, "cost_cents") > 0:
        return True
    return bool(_rows(summary, "usage_by_tool") or _rows(summary, "usage_by_model"))


def approvals_nav_link(env: dict[str, Any] | None) -> str:
    if not has_approval_evidence(env):
        return ""
    return f'<a href="#{APPROVALS_SECTION_ID}">Approvals</a>'


def usage_nav_link(env: dict[str, Any] | None) -> str:
    if not has_usage_evidence(env):
        return ""
    return f'<a href="#{USAGE_SECTION_ID}">Usage</a>'


def telemetry_nav_links(env: dict[str, Any] | None) -> str:
    parts = [part for part in (approvals_nav_link(env), usage_nav_link(env)) if part]
    return "\n".join(parts)


def _group_map(summary: dict[str, Any]) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for row in _rows(summary, "approvals_by_group"):
        found[str(row.get("group") or "")] = row
    return found


def _tile(label: str, value: Any, note: str) -> str:
    return (
        f'<div class="ps"><div class="label">{_esc(label)}</div>'
        f'<div class="n">{_esc(value)}</div>'
        f'<div class="note">{_esc(note)}</div></div>'
    )


def _table(headers: list[str], rows: list[list[tuple[Any, str]]]) -> str:
    head = "".join(f"<th>{_esc(header)}</th>" for header in headers)
    body_rows = []
    for row in rows:
        cells = []
        for value, kind in row:
            css = {"num": " class='num'", "mono": " class='mono'"}.get(kind, "")
            cells.append(f"<td{css}>{_esc(value)}</td>")
        body_rows.append(f"<tr>{''.join(cells)}</tr>")
    if not body_rows:
        return ""
    return (
        '<div class="table-wrap"><table>'
        f"<thead><tr>{head}</tr></thead>"
        f"<tbody>{''.join(body_rows)}</tbody></table></div>"
    )


def _group_block(title: str, meta: str, inner: str) -> str:
    if not inner:
        return ""
    return (
        '<div class="rule-group">'
        '<div class="rule-group-head">'
        f"<h4>{_esc(title)}</h4>"
        f'<span class="meta">{_esc(meta)}</span>'
        "</div>"
        f"{inner}</div>"
    )


def _section(section_id: str, num: str, kicker: str, title: str, sub_html: str, inner: str, *, alt: bool) -> str:
    alt_cls = " section--alt" if alt else ""
    return (
        f'<section id="{section_id}" class="section{alt_cls}">\n'
        '  <div class="wrap">\n'
        '    <header class="sh">\n'
        '      <div class="kicker">\n'
        f'        <span class="num">{_esc(num)}</span>\n'
        f'        <span class="kicker-label">{_esc(kicker)}</span>\n'
        "      </div>\n"
        f'      <h2 class="h2">{_esc(title)}</h2>\n'
        f'      <p class="sub">{sub_html}</p>\n'
        "    </header>\n"
        f"    {inner}\n"
        "  </div>\n"
        "</section>"
    )


def _format_cents(cents: int) -> str:
    sign = "-" if cents < 0 else ""
    amount = abs(int(cents))
    return f"{sign}${amount // 100}.{amount % 100:02d}"


def render_approvals_section(env: dict[str, Any] | None) -> str:
    """Render the approval rollup, or "" when the envelope has none."""
    if not has_approval_evidence(env):
        return ""
    summary = _summary(env)
    groups = _group_map(summary)
    config = groups.get("config rule") or {}
    user = groups.get("user") or {}
    hook = groups.get("hook") or {}
    tiles = [
        _tile("Approvals", _count(summary, "approvals"), "accept"),
        _tile("Denials", _count(summary, "denials"), "reject"),
        _tile(
            "Config rule",
            int(config.get("approvals") or _count(summary, "config_approvals")),
            "no prompt",
        ),
        _tile(
            "User",
            int(user.get("approvals") or _count(summary, "user_approvals")),
            "prompted",
        ),
        _tile(
            "Hook",
            int(hook.get("approvals") or _count(summary, "hook_approvals")),
            "hook",
        ),
    ]
    percent = _count(summary, "config_approval_percent")
    share_note = ""
    if _count(summary, "approvals") and percent >= 50:
        share_note = (
            f'<p class="surface-note">{_esc(percent)}% of approvals came from '
            "config rules, which apply without a prompt.</p>"
        )
    coverage = (
        '<p class="surface-note">Claude Code does not persist individual approve '
        "clicks. These counts come from imported OpenTelemetry "
        "<code>tool_decision</code> events. Without that export, approvals are "
        "not on disk. Auto-approved means <code>source=config</code>.</p>"
    )
    chips = []
    for row in _rows(summary, "top_auto_approved"):
        chips.append(
            "<div class='mode-chip'><span>"
            f"{_esc(row.get('tool'))}</span><strong>{_esc(row.get('count'))}</strong></div>"
        )
    chip_html = ""
    if chips:
        chip_html = _group_block(
            "Top auto-approved tools",
            "source=config",
            f'<div class="mode-grid">{"".join(chips)}</div>',
        )
    tool_table = _table(
        ["Tool", "Harness", "Approvals", "Denials", "Auto-approved", "No prompt"],
        [
            [
                (row.get("tool"), "text"),
                (row.get("harness"), "mono"),
                (row.get("approvals"), "num"),
                (row.get("denials"), "num"),
                (row.get("auto_approved"), "num"),
                (row.get("unprompted"), "num"),
            ]
            for row in _rows(summary, "approvals_by_tool")
        ],
    )
    source_table = _table(
        ["Source", "Group", "Approvals", "Denials"],
        [
            [
                (row.get("source"), "mono"),
                (row.get("group"), "text"),
                (row.get("approvals"), "num"),
                (row.get("denials"), "num"),
            ]
            for row in _rows(summary, "approvals_by_source")
        ],
    )
    day_table = _table(
        ["Day", "Approvals", "Denials"],
        [
            [
                (row.get("day"), "mono"),
                (row.get("approvals"), "num"),
                (row.get("denials"), "num"),
            ]
            for row in _rows(summary, "approvals_by_day")
        ],
    )
    inner = (
        f'<div class="perm-summary">{"".join(tiles)}</div>'
        f"{coverage}{share_note}{chip_html}"
        + _group_block("By tool", "approvals and denials", tool_table)
        + _group_block("By source", "config rule, user, hook", source_table)
        + _group_block("By day", "calendar date on the event timestamp", day_table)
    )
    sub = (
        "Imported <code>claude_code.tool_decision</code> events. "
        "Config-rule approvals were applied without a prompt. "
        "User approvals are prompt answers. Hook approvals came from a hook."
    )
    return _section(
        APPROVALS_SECTION_ID,
        APPROVALS_KICKER_NUM,
        "APPROVAL TELEMETRY",
        "Approval decisions from imported telemetry.",
        sub,
        inner,
        alt=False,
    )


def _cost_cell(row: dict[str, Any]) -> str:
    if row.get("cost_basis") == "cursor_dashboard" and "cost_cents" in row:
        try:
            cents = int(row.get("cost_cents") or 0)
        except (TypeError, ValueError):
            return TOKENS_ONLY_LABEL
        return f"{_format_cents(cents)} ({cents} cents)"
    return TOKENS_ONLY_LABEL


def render_usage_section(env: dict[str, Any] | None) -> str:
    """Render usage and cost, or "" when the envelope has neither."""
    if not has_usage_evidence(env):
        return ""
    summary = _summary(env)
    cursor_cost = summary.get("cost_basis") == "cursor_dashboard" and "cost_cents" in summary
    tiles = [
        _tile("Events", _count(summary, "usage_events"), "usage rows"),
        _tile("Total tokens", _count(summary, "total_tokens"), "exported totals"),
        _tile("Input", _count(summary, "input_tokens"), "tokens"),
        _tile("Output", _count(summary, "output_tokens"), "tokens"),
    ]
    if cursor_cost:
        cents = _count(summary, "cost_cents")
        tiles.append(_tile("Cost", _format_cents(cents), COST_LABEL))
    else:
        tiles.append(_tile("Cost", "n/a", TOKENS_ONLY_LABEL))
    if cursor_cost:
        mixed = _count(summary, "usage_rows_tokens_only") > 0
        extra = (
            " Rows without cost_cents stay tokens only."
            if mixed
            else ""
        )
        note = (
            f'<p class="surface-note">Cost is { _esc(COST_LABEL) }. '
            "The dollar figure is that exported cent total, written as dollars. "
            f"Dollars are not estimated from token counts.{_esc(extra)}</p>"
        )
    else:
        note = (
            '<p class="surface-note">Tokens only. Dollars are not estimated '
            "from token counts.</p>"
        )
    headers = [
        "Tool",
        "Harness",
        "Events",
        "Input",
        "Output",
        "Cache read",
        "Cache write",
        "Total",
        "Cost",
    ]

    def usage_rows(key: str, label_key: str) -> str:
        table = _table(
            ["Name" if label_key == "model" else "Tool", *headers[1:]],
            [
                [
                    (row.get(label_key), "text"),
                    (row.get("harness"), "mono"),
                    (row.get("events"), "num"),
                    (row.get("input_tokens"), "num"),
                    (row.get("output_tokens"), "num"),
                    (row.get("cache_read_tokens"), "num"),
                    (row.get("cache_write_tokens"), "num"),
                    (row.get("total_tokens"), "num"),
                    (_cost_cell(row), "mono"),
                ]
                for row in _rows(summary, key)
            ],
        )
        title = "By model" if label_key == "model" else "By tool"
        return _group_block(title, "sum of exported columns", table)

    inner = f'<div class="perm-summary">{"".join(tiles)}</div>{note}'
    inner += usage_rows("usage_by_tool", "tool")
    inner += usage_rows("usage_by_model", "model")
    if cursor_cost:
        sub = (
            "Cursor rows with <code>cost_cents</code> are labeled "
            f"{_esc(COST_LABEL)}. Other harnesses are tokens only."
        )
    else:
        sub = "Tokens only. Dollars are not estimated from token counts."
    return _section(
        USAGE_SECTION_ID,
        USAGE_KICKER_NUM,
        "USAGE AND COST",
        "Token and cost totals from imported usage exports.",
        sub,
        inner,
        alt=True,
    )
