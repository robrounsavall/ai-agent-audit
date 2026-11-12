"""The detail panel under a finding row: what to do, and exactly where.

Reads the per-hit rows the collectors leave under raw/ and turns them into
one entry per distinct value, each with every place that value appears: the
tool, the file, the line and column, and for chat transcripts the session
and message it came from.

Three levels of disclosure, decided by the caller's context object:

  default        the matched value and the text around it, as stored in
                 raw/, with full local paths. The file holds live
                 credentials and stays on this machine. This is also the
                 -ShowSecrets build.
  local links    full local paths with copy and open-in-editor links.
                 Values stay masked.
  redact         paths are hashed or shortened, values are masked, and no
                 surrounding text is shown. Safe to forward. Used when
                 -Redact or -AgentMode is set.

Nothing here decides the level. Every value and path goes through the
context's own display functions.
"""

from __future__ import annotations

import csv
import html
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from common import mask_secrets, redact_sample
from remediation import SECRET_ACTIONS, SECRET_LABELS, guidance_for

MAX_CSV_ROWS = 60000
MAX_LOCATIONS_PER_FINDING = 300
MAX_LOCATIONS_PER_VALUE = 40
MAX_VALUE_CHARS = 400
OPEN_GROUPS_UP_TO = 3

PII_LABELS = {
    "CREDIT_CARD": "Card number",
    "TEST_CARD": "Test card number",
    "US_SSN": "US Social Security number",
    "IBAN_CODE": "IBAN",
    "EMAIL_ADDRESS": "Email address",
    "PHONE_NUMBER": "Phone number",
    "IP_ADDRESS": "Public IP address",
}

TOOL_LABELS = {
    "claude": "Claude Code",
    "codex": "Codex",
    "cursor": "Cursor",
    "cursor-composer": "Cursor Composer",
    "grok": "Grok Build",
    "copilot": "GitHub Copilot",
}

# Specific credential types first, the two length-only matchers last.
_TYPE_RANK = {
    "aws_key": 0, "github_pat": 1, "slack_token": 2, "vendor_token": 3,
    "google_api": 4, "password_assign": 5, "url_userinfo": 6,
    "authorization": 7, "bearer": 8, "hex_secret": 20, "generic_secret": 21,
}

# The exact shapes redact_sample writes. A sample_redacted column that is not
# one of these is masked again before it is shown.
_REDACTED_RE = re.compile(
    r"(?:.{1,16}\.\.\..{1,16} \([^()]*\)|\*\*\*\*REDACTED:[^*]*\*\*\*\*)"
)
_DIGITS_RE = re.compile(r"^\d+$")
_AWS_DOC_KEYS = {"AKIAIOSFODNN7EXAMPLE", "ASIAIOSFODNN7EXAMPLE"}


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _num(value: str) -> str:
    value = (value or "").strip()
    return value if value.isascii() and _DIGITS_RE.match(value) else ""


def _score(value: str) -> str:
    """A scanner score as a short decimal, or '' when it is not a finite number."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return ""
    if number != number or number in (float("inf"), float("-inf")):
        return ""
    return f"{number:.3f}".rstrip("0").rstrip(".")


def _read_rows(path: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            for idx, row in enumerate(csv.DictReader(handle)):
                if idx >= MAX_CSV_ROWS:
                    break
                rows.append(
                    {
                        str(k).strip().lower(): (v if isinstance(v, str) else "")
                        for k, v in row.items()
                        if k is not None
                    }
                )
    except Exception:
        return rows
    return rows


def _value_from(row: dict[str, str], kind: str) -> tuple[str, bool]:
    """(value, already_masked). A sample_redacted column is never trusted as-is."""
    if "sample_redacted" in row:
        sample = (row.get("sample_redacted") or "").strip()
        if sample and not _REDACTED_RE.fullmatch(sample):
            sample = redact_sample(sample, kind)
        return sample, True
    return (row.get("sample") or "").strip(), False


def describe_path(path: str) -> tuple[str, str]:
    """(tool, kind of file) worked out from where a file lives."""
    text = str(path or "")
    norm = text.replace("\\", "/").lower()
    if norm.startswith("composerdata:"):
        return "Cursor", "Composer chat in Cursor's state database"
    match = re.search(r"/raw/chat-history/([a-z0-9-]+)/", norm)
    if match:
        tool = TOOL_LABELS.get(match.group(1), match.group(1))
        return tool, "copy made by this scan"
    if "/.claude/projects/" in norm:
        return "Claude Code", "session log"
    if "/.codex/sessions/" in norm or "/.codex/archived_sessions/" in norm:
        return "Codex", "session rollout"
    if "/.cursor/projects/" in norm:
        return "Cursor", "agent transcript"
    if "/.grok/sessions/" in norm:
        return "Grok Build", "session file"
    if "/workspacestorage/" in norm and "/chatsessions/" in norm:
        return "GitHub Copilot", "chat session"
    return "", "file"


def value_hint(kind: str, value: str) -> tuple[str, bool]:
    """(note, unlikely_to_be_a_credential) for a matched value."""
    if value in _AWS_DOC_KEYS:
        return "AWS documentation example key, not a real credential", True
    if kind == "hex_secret":
        length = len(value)
        if length == 40:
            return "40 hex characters: the length of a git commit id (SHA-1)", True
        if length == 64:
            return "64 hex characters: the length of a SHA-256 digest", True
        if length == 32:
            return "32 hex characters: the length of an MD5 digest or a UUID without dashes", False
        return f"{length} hex characters", False
    if kind == "generic_secret":
        if value.count("/") >= 2 and "+" not in value and "=" not in value:
            return "looks like a path, not a key", True
        if value.startswith("eyJ"):
            return "starts with eyJ: a base64 JSON object, usually a JWT segment", False
        return f"{len(value)} characters", False
    return "", False


class HitStore:
    """Per-hit rows from raw/, grouped by the finding they belong to."""

    def __init__(self, root: Path | str | None):
        self._pii: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._chat: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._git: dict[str, list[dict[str, Any]]] = defaultdict(list)
        if root is None:
            return
        raw = Path(root) / "raw"
        self._load_pii(raw / "pii-scan" / "findings.csv")
        self._load_chat(raw / "chat-history-hits" / "secret-hits.csv")
        self._load_git(raw / "git-posture" / "locations.csv")

    def _load_pii(self, path: Path) -> None:
        for row in _read_rows(path):
            entity = (row.get("entity") or "").strip()
            file = (row.get("file") or "").strip()
            if not entity or not file or not re.fullmatch(r"[A-Za-z0-9_\-]{1,40}", entity):
                continue
            value, masked = _value_from(row, entity)
            line = _num(row.get("line", ""))
            if line == "0":
                # Older scans stored one row per secret type per file with no
                # position and the type name in the sample column.
                line, value, masked = "", "", True
            kind = entity.lower()
            if kind.startswith("secret_"):
                kind = kind[len("secret_"):]
            self._pii[entity.lower()].append({
                "kind": kind,
                "entity": entity.upper(),
                "value": value,
                "masked": masked,
                "path": file,
                "line": line,
                "col": _num(row.get("col", "")),
                "score": _score((row.get("score") or "").strip()),
                "before": row.get("before", "") or "",
                "after": row.get("after", "") or "",
            })

    def _load_chat(self, path: Path) -> None:
        for row in _read_rows(path):
            tool = (row.get("tool") or "").strip().lower()
            file = (row.get("file") or "").strip()
            kind = (row.get("type") or "").strip().lower()
            if not tool or not file or not re.fullmatch(r"[a-z0-9_\-]{1,40}", kind):
                continue
            value, masked = _value_from(row, kind)
            self._chat[tool].append({
                "kind": kind,
                "entity": "",
                "value": value,
                "masked": masked,
                "path": file,
                "line": _num(row.get("line", "")),
                "col": _num(row.get("col", "")),
                "before": row.get("before", "") or "",
                "after": row.get("after", "") or "",
                "source": (row.get("source") or "").strip(),
                "workspace": (row.get("workspace") or "").strip(),
                "role": (row.get("role") or "").strip(),
                "time": (row.get("time") or "").strip(),
                "tool": tool,
            })

    def _load_git(self, path: Path) -> None:
        for row in _read_rows(path):
            finding = (row.get("finding") or "").strip().lower()
            repo = (row.get("repo") or "").strip()
            if not finding or not repo:
                continue
            self._git[finding].append({
                "repo": repo,
                "path": (row.get("path") or "").strip(),
                "commit": (row.get("commit") or "").strip(),
                "date": (row.get("date") or "").strip(),
                "note": (row.get("note") or "").strip(),
            })

    def hits(self, finding: dict[str, Any]) -> list[dict[str, Any]]:
        fid = str(finding.get("id") or "").lower()
        if fid.startswith("pii_scan."):
            return self._pii.get(fid[len("pii_scan."):], [])
        if fid.startswith("chat_history.secret."):
            return self._chat.get(fid[len("chat_history.secret."):], [])
        return []

    def repo_rows(self, finding: dict[str, Any]) -> list[dict[str, Any]]:
        return self._git.get(str(finding.get("id") or "").lower(), [])


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def _kind_label(hit: dict[str, Any]) -> str:
    entity = hit.get("entity") or ""
    if entity in PII_LABELS:
        return PII_LABELS[entity]
    return SECRET_LABELS.get(hit["kind"], hit["kind"].replace("_", " "))


def _shown_value(hit: dict[str, Any], ctx: Any) -> str:
    """The value as this build is allowed to show it."""
    value = hit.get("value") or ""
    if not value:
        return ""
    if hit.get("masked"):
        return value
    if ctx.reveal:
        if len(value) > MAX_VALUE_CHARS:
            return value[:MAX_VALUE_CHARS] + f"... ({len(value)} characters)"
        return value
    return redact_sample(value, hit.get("entity") or hit["kind"])


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def render_guidance(finding: dict[str, Any]) -> str:
    guide = guidance_for(finding)
    if not guide:
        return ""
    steps = "".join(f"<li>{_esc(step)}</li>" for step in guide.get("steps") or [])
    links = "".join(
        f'<a href="{_esc(url)}" target="_blank" rel="noopener noreferrer">{_esc(label)} ↗</a>'
        for label, url in guide.get("links") or []
    )
    links_html = f'<p class="fix-links">{links}</p>' if links else ""
    return (
        '<div class="ev-sec fix">'
        "<h4>Why it matters</h4>"
        f'<p class="fix-risk">{_esc(guide.get("risk", ""))}</p>'
        "<h4>What to do</h4>"
        f'<ol class="fix-steps">{steps}</ol>{links_html}'
        "</div>"
    )


def _location_html(hit: dict[str, Any], ctx: Any, shown: str) -> str:
    """One place a value was found.

    A chat-transcript hit has two files: the tool's own session log, which is
    the one to delete, and this scan's export of it, which is where the line
    and column were measured. A hit from pii-scan has one.
    """
    path = str(hit.get("path") or "")
    tool, kind = describe_path(path)
    if hit.get("tool") and not tool:
        tool = TOOL_LABELS.get(hit["tool"], hit["tool"])
    line, col = hit.get("line") or "", hit.get("col") or ""
    position = ""
    if line:
        position = f"line {line}" + (f", column {col}" if col else "")

    head = []
    if tool:
        head.append(f'<span class="hit-tool">{_esc(ctx.text(tool))}</span>')
    if hit.get("role"):
        head.append(f'<span class="hit-kind">{_esc(ctx.text(hit["role"]))} message</span>')
    if hit.get("time"):
        head.append(f'<span class="hit-kind">{_esc(ctx.text(hit["time"].replace("T", " ")))}</span>')
    if hit.get("workspace"):
        head.append(f'<span class="hit-kind">workspace {_esc(ctx.text(hit["workspace"]))}</span>')

    def row(label: str, inner: str) -> str:
        return f'<div class="hit-where"><span class="hit-label">{_esc(label)}</span> {inner}</div>'

    rows = []
    source = str(hit.get("source") or "")
    if source:
        _s_tool, s_kind = describe_path(source)
        if source.lower().startswith("composerdata:"):
            origin = f'<span class="ev-path">{_esc(ctx.text(source))}</span>'
        else:
            origin = ctx.path_html(source, folder=True) + " " + ctx.editor_links_html(source)
        rows.append(row(f"Original {s_kind}", origin))
    where = [ctx.path_html(path, folder=True)]
    if position:
        where.append(f'<span class="ev-line">{_esc(position)}</span>')
    if hit.get("score"):
        where.append(f'<span class="ev-line">score {_esc(hit["score"])}</span>')
    where.append(ctx.editor_links_html(path, line, col))
    label = "Exact position, in this scan's copy" if source else kind.capitalize()
    rows.append(row(label, " ".join(part for part in where if part)))

    snippet = ""
    if ctx.reveal and not hit.get("masked") and (hit.get("before") or hit.get("after")):
        snippet = (
            '<pre class="hit-ctx">'
            f'{_esc(hit.get("before") or "")}<mark class="hit-secret">{_esc(shown)}</mark>'
            f'{_esc(hit.get("after") or "")}</pre>'
        )

    blob = " ".join(
        ctx.text(part).lower()
        for part in (tool, kind, path, source, hit.get("workspace") or "", hit.get("role") or "", hit.get("time") or "")
        if part
    )
    head_html = f'<div class="hit-head">{" ".join(head)}</div>' if head else ""
    return f'<li class="hit" data-text="{_esc(blob)}">{head_html}{"".join(rows)}{snippet}</li>'


def render_hits(finding: dict[str, Any], hits: list[dict[str, Any]], ctx: Any, raw_ref: str) -> str:
    """Distinct values, each with every stored location."""
    if not hits:
        return ""
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for hit in hits:
        groups[(hit["kind"], hit.get("value") or "")].append(hit)

    def order(item: tuple[tuple[str, str], list[dict[str, Any]]]) -> tuple[int, int, int, str]:
        (kind, value), members = item
        _hint, unlikely = value_hint(kind, value)
        return (_TYPE_RANK.get(kind, 10), 1 if unlikely else 0, -len(members), value)

    ordered = sorted(groups.items(), key=order)
    files = {hit["path"] for hit in hits}
    type_counts = Counter(_kind_label(members[0]) for _key, members in ordered)
    by_type = ", ".join(
        f"{label} {count}" for label, count in type_counts.most_common()
    )
    summary = (
        f"{_plural(len(hits), 'location')} in {_plural(len(files), 'file')}, "
        f"{_plural(len(ordered), 'distinct value')}"
    )

    parts: list[str] = []
    budget = MAX_LOCATIONS_PER_FINDING
    shown_groups = 0
    for index, ((kind, value), members) in enumerate(ordered):
        if budget <= 0:
            break
        shown_groups += 1
        first = members[0]
        shown = _shown_value(first, ctx)
        hint, unlikely = value_hint(kind, value) if not first.get("masked") else ("", False)
        member_files = {m["path"] for m in members}
        take = members[: min(MAX_LOCATIONS_PER_VALUE, budget)]
        budget -= len(take)
        items = "".join(_location_html(m, ctx, shown) for m in take)
        more = ""
        if len(take) < len(members):
            more = f'<p class="ev-more">+{len(members) - len(take)} more locations of this value in {_esc(ctx.text(raw_ref))}</p>'
        value_html = (
            f'<code class="hit-secret">{_esc(shown)}</code>' if shown
            else '<span class="hit-novalue">position not recorded by this scan</span>'
        )
        copy = ""
        if ctx.reveal and value and not first.get("masked"):
            copy = (
                f'<button type="button" class="copy-path" data-label="Copy value" '
                f'data-path="{_esc(value)}">Copy value</button>'
            )
        is_pii = first.get("entity") in PII_LABELS
        action = "" if is_pii else SECRET_ACTIONS.get(kind, "")
        note_bits = []
        if hint:
            note_bits.append(hint)
        if action and not unlikely:
            note_bits.append(action)
        note = f'<p class="hit-note">{_esc(" · ".join(note_bits))}</p>' if note_bits else ""
        blob = ctx.text(_kind_label(first)).lower()
        if ctx.reveal and not first.get("masked"):
            blob += " " + value.lower()
        open_attr = " open" if index < OPEN_GROUPS_UP_TO else ""
        dim = " hit-group--unlikely" if unlikely else ""
        parts.append(
            f'<details class="hit-group{dim}" data-text="{_esc(blob)}"{open_attr}>'
            f'<summary><span class="chevron" aria-hidden="true"></span>'
            f'<span class="hit-num">{index + 1}</span>'
            f'<span class="hit-type">{_esc(_kind_label(first))}</span>{value_html}'
            f'<span class="hit-count">{_esc(_plural(len(members), "location"))} in '
            f'{_esc(_plural(len(member_files), "file"))}</span></summary>'
            f'<div class="hit-body"><div class="hit-actions">{note}{copy}</div>'
            f'<ol class="hit-list">{items}</ol>{more}</div>'
            "</details>"
        )
    tail = ""
    if shown_groups < len(ordered):
        tail = (
            f'<p class="ev-more">+{len(ordered) - shown_groups} more distinct values in '
            f"{_esc(ctx.text(raw_ref))}</p>"
        )
    masked_note = ""
    if not ctx.reveal:
        masked_note = (
            '<p class="hit-masked-note">Values are masked in this copy. Rebuild without -Redact '
            "(or with -ShowSecrets) to see each value and the text around it.</p>"
        )
    return (
        '<div class="ev-sec hits">'
        f"<h4>Where it is</h4>"
        f'<p class="hit-summary">{_esc(summary)}. {_esc(by_type)}.</p>{masked_note}'
        '<div class="hit-tools"><input type="search" class="hit-filter" '
        'placeholder="Filter by tool, path, or type" aria-label="Filter locations" /></div>'
        f'{"".join(parts)}{tail}'
        "</div>"
    )


def render_repo_rows(rows: list[dict[str, Any]], ctx: Any) -> str:
    """Affected repositories for a git finding, one row per repo and path."""
    if not rows:
        return ""
    by_repo: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_repo[row["repo"]].append(row)
    parts = []
    for repo in sorted(by_repo, key=str.lower)[:MAX_LOCATIONS_PER_FINDING]:
        entries = []
        for row in by_repo[repo][:MAX_LOCATIONS_PER_VALUE]:
            bits = []
            if row.get("path"):
                bits.append(f'<span class="ev-path">{_esc(ctx.text(row["path"]))}</span>')
            if row.get("commit") and re.fullmatch(r"[0-9a-fA-F]{4,40}", row["commit"]):
                when = f' on {_esc(ctx.text(row["date"]))}' if row.get("date") else ""
                bits.append(f'<span class="ev-line">added in commit <code>{_esc(row["commit"])}</code>{when}</span>')
            if row.get("note"):
                bits.append(f'<span class="ev-line">{_esc(ctx.text(row["note"]))}</span>')
            if bits:
                entries.append(f"<li>{' '.join(bits)}</li>")
        inner = f'<ul class="repo-paths">{"".join(entries)}</ul>' if entries else ""
        parts.append(
            f'<li class="hit"><div class="hit-where">{ctx.path_html(repo, folder=False)}'
            f'{ctx.editor_links_html(repo, "", "", folder=True)}</div>{inner}</li>'
        )
    return (
        '<div class="ev-sec hits"><h4>Where it is</h4>'
        f'<p class="hit-summary">{len(by_repo)} {"repository" if len(by_repo) == 1 else "repositories"}.</p>'
        f'<ol class="hit-list">{"".join(parts)}</ol></div>'
    )


def render_rules(rules: list[dict[str, Any]], ctx: Any, limit: int = 40) -> str:
    """The permission rules a finding is about."""
    if not rules:
        return ""
    rows = []
    for rule in rules[:limit]:
        text = str(rule.get("rule") or rule.get("command_or_tool_redacted") or "")
        scope = str(rule.get("scope_label_redacted") or rule.get("scope") or "")
        decision = str(rule.get("decision") or "")
        source = str(rule.get("settings_source") or rule.get("source_kind") or "")
        rows.append(
            "<tr>"
            f'<td><code>{_esc(ctx.text(text))}</code></td>'
            f"<td>{_esc(ctx.text(scope))}</td>"
            f"<td>{_esc(ctx.text(decision))}</td>"
            f"<td>{_esc(ctx.text(source))}</td>"
            "</tr>"
        )
    more = f'<p class="ev-more">+{len(rules) - limit} more under Agents, Permissions.</p>' if len(rules) > limit else ""
    return (
        '<div class="ev-sec"><h4>Rules behind this finding</h4>'
        '<table class="rule-mini"><thead><tr><th>Rule</th><th>Scope</th><th>Decision</th><th>Source</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>{more}</div>'
    )


def related_rules(finding: dict[str, Any], envelopes: dict[str, dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Rules from the finding's own collector that the finding is about."""
    if not envelopes:
        return []
    collector = str(finding.get("_collector") or "")
    env = envelopes.get(collector)
    if not isinstance(env, dict):
        return []
    rules = [r for r in (env.get("rules") or []) if isinstance(r, dict)]
    fid = str(finding.get("id") or "").lower()
    if fid.startswith(("git.", "pii_scan.", "chat_history.")):
        return []
    if fid == "codex.trust.broad":
        return [r for r in rules if str(r.get("rule") or "").startswith("trust_level=")]
    category = str(finding.get("category") or "")
    wanted = [
        r for r in rules
        if str(r.get("exposure_category") or "") == category
        and str(r.get("decision") or "") == "allow"
    ]
    if ".permission" in fid or ".rules." in fid or ".mcp." in fid:
        return wanted
    return []
