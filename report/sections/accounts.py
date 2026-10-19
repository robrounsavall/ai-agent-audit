"""HTML table for the accounts evidence envelope.

``render_accounts_block(env)`` returns a fragment for the agents tab.
``env`` is ``evidence/accounts.json`` or None when that collector did not run.
Emails are shown on a local briefing and replaced with ``<email>`` when
``AISCAN_REDACT`` is set.
"""

from __future__ import annotations

import html
import re
from typing import Any

from common import mask_secrets, redact_paths, redaction_disabled

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+")

_COLUMNS = (
    ("tool", "Tool"),
    ("signed_in", "Signed in"),
    ("account", "Account"),
    ("organization", "Organization"),
    ("plan", "Plan"),
    ("auth_method", "Auth"),
    ("source", "Source"),
    ("last_sign_in", "Last sign-in"),
)


def _cell(value: Any) -> str:
    text = str(value or "")
    text = mask_secrets(text)
    if not redaction_disabled():
        text = _EMAIL_RE.sub("<email>", text)
        text = redact_paths(text)
    return html.escape(text)


def render_accounts_block(env: dict[str, Any] | None) -> str:
    """Account table, or a one-line note when the collector did not run."""
    if not isinstance(env, dict):
        return (
            '<p class="sub">Account identities were not collected in this scan. '
            "They are part of <span class=\"mono\">aiscan all</span>.</p>"
        )
    rows = env.get("accounts")
    if not isinstance(rows, list):
        rows = []
    summary = env.get("summary") if isinstance(env.get("summary"), dict) else {}
    signed = int(summary.get("signed_in") or 0)
    distinct = int(summary.get("distinct_accounts") or 0)
    body_rows: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        cells = "".join(f"<td>{_cell(row.get(key))}</td>" for key, _label in _COLUMNS)
        body_rows.append(f"<tr>{cells}</tr>")
    if body_rows:
        table = (
            '<div class="table-wrap table-scroll" style="max-height:none">'
            '<table class="mcp-table"><thead><tr>'
            + "".join(f"<th>{html.escape(label)}</th>" for _key, label in _COLUMNS)
            + "</tr></thead><tbody>"
            + "".join(body_rows)
            + "</tbody></table></div>"
        )
    else:
        table = "<p>No account rows were recorded.</p>"
    note = (
        "Identifiers come from local config only. Tokens, API key values, cookies, "
        "and credential-store contents are not read. Codex email and plan are decoded "
        "from the id_token payload; the token is discarded. Cursor's state database is "
        "copied, then only the cached email and membership keys are read. "
        "Emails are masked when this briefing is built with -Redact."
    )
    return (
        '<header class="sh" style="margin-top: 28px;">'
        '<div class="kicker"><span class="num">/04a</span>'
        '<span class="kicker-label">ACCOUNTS</span></div>'
        "<h2 class=\"h2\">Which account each tool is signed in as.</h2>"
        f"<p class=\"sub\">{signed} signed in, {distinct} distinct identities. {html.escape(note)}</p>"
        "</header>"
        f"{table}"
    )
