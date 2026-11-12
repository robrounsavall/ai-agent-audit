"""
Chat history exporter and evidence collector.

Usage:
    python chat-history.py --evidence-root ./audit-run [--raw-root ./raw] [--include-tool-details] [--dry-run]

Writes raw markdown under <raw-root>/chat-history/{claude,codex,cursor,cursor-composer,grok,copilot}/YYYY-MM-DD.md
and emits evidence/chat-history.json with counts, sizes, and secret-hit findings only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import unquote

import compressed
import paths
from common import (
    APPDATA,
    add_base_args,
    compute_scope_hash,
    finish_collector,
    looks_like_secret,
    make_envelope,
    make_finding,
    resolve_raw_root,
    secret_types_in,
    validate_evidence_root,
)

__version__ = "1.4.0"

COLLECTOR = "chat-history"

RETENTION_DAYS = 90
ACTIVE_GAP_CAP_MINUTES = 30
_TIMESTAMP_RE = re.compile(r"<timestamp>([^<]+)</timestamp>")
CLAUDE_PERMISSION_SUBTYPES = {"permission_request", "permission_response"}


def metric_token(value: str) -> str:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value.strip())
    return re.sub(r"[^a-z0-9]+", "_", spaced.lower()).strip("_")


def escape_md_fence(value):
    if value is None:
        return ""
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return text.replace("```", "``\\`")


def get_content_text(content, include_tool_details=False):
    if content is None:
        return ""
    if isinstance(content, str):
        return content.strip()

    parts = []
    if isinstance(content, list):
        for item in content:
            if not isinstance(item, dict):
                continue
            t = item.get("type")
            if t == "text" and item.get("text"):
                parts.append(str(item["text"]).strip())
            elif t in ("input_text", "output_text") and item.get("text"):
                parts.append(str(item["text"]).strip())
            elif t == "tool_use":
                if include_tool_details:
                    parts.append(
                        f"\n[tool_use: {item.get('name')}]\n```json\n"
                        + escape_md_fence(item.get("input"))
                        + "\n```"
                    )
                else:
                    parts.append(f"[tool_use: {item.get('name')}]")
            elif t == "tool_result":
                if include_tool_details:
                    parts.append(
                        "\n[tool_result]\n```text\n"
                        + escape_md_fence(item.get("content"))
                        + "\n```"
                    )
                else:
                    parts.append("[tool_result omitted]")
            elif t:
                parts.append(f"[{t} omitted]")
    elif isinstance(content, dict):
        if content.get("text"):
            parts.append(str(content["text"]).strip())
        elif content.get("message"):
            parts.append(str(content["message"]).strip())
        else:
            parts.append(escape_md_fence(content))

    return "\n\n".join(p for p in parts if p and p.strip()).strip()


def _json_object(raw: str) -> dict | None:
    """One JSON value, or None when it is not an object. Never raises."""
    try:
        obj = json.loads(raw)
    except (json.JSONDecodeError, ValueError, RecursionError):
        return None
    return obj if isinstance(obj, dict) else None


def _message_parts(message) -> tuple[object, str]:
    """Content and role from a message that may be an object or a plain string."""
    if isinstance(message, dict):
        return message.get("content"), str(message.get("role") or "")
    if isinstance(message, str):
        return message, ""
    return None, ""


def _sqlite_ro_uri(path: Path) -> str:
    """Read-only SQLite URI. Encodes #, ?, and % so they stay in the path."""
    return Path(path).resolve().as_uri() + "?mode=ro&immutable=1"


def read_text_lines(path: Path, problems: list | None = None) -> list[str] | None:
    """Lines from a UTF-8 file. A BOM is accepted. A bad byte is reported, not fatal."""
    try:
        return path.read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeDecodeError):
        if problems is not None:
            problems.append("unreadable")
        return None


def parse_iso(s):
    if not s:
        return None
    try:
        s = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is not None:
            dt = dt.astimezone().replace(tzinfo=None)
        return dt
    except (ValueError, TypeError):
        return None


def parse_cursor_embedded_timestamp(content):
    raw = None
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                raw = item.get("text", "")
                break
    elif isinstance(content, str):
        raw = content
    if raw:
        m = _TIMESTAMP_RE.search(raw)
        if m:
            try:
                s = m.group(1).strip()
                s_clean = re.sub(r"\s*\(UTC[^)]*\)$", "", s).strip()
                return datetime.strptime(s_clean, "%A, %B %d, %Y, %I:%M %p")
            except ValueError:
                pass
    return None


def add_entry(buckets, ts, tool, role, text, source, workspace=""):
    if not text or not text.strip():
        return
    date_key = ts.strftime("%Y-%m-%d")
    buckets[date_key].append({
        "ts": ts,
        "tool": tool,
        "role": role,
        "text": text.strip(),
        "source": source,
        "workspace": workspace,
    })


def estimate_active_minutes(buckets, cap_minutes=ACTIVE_GAP_CAP_MINUTES) -> int:
    """Estimate active time from transcript timestamps.

    This is intentionally a capped-gap estimate, not a timesheet. Consecutive
    messages from the same source/session count when they are close together;
    long breaks are capped so overnight gaps do not become work time.
    """
    by_source: dict[str, list[datetime]] = defaultdict(list)
    for entries in buckets.values():
        for entry in entries:
            by_source[str(entry.get("source", ""))].append(entry["ts"])

    cap_seconds = cap_minutes * 60
    total_seconds = 0.0
    for timestamps in by_source.values():
        ordered = sorted(timestamps)
        for prev, curr in zip(ordered, ordered[1:]):
            gap = (curr - prev).total_seconds()
            if gap <= 0:
                continue
            total_seconds += min(gap, cap_seconds)
    return round(total_seconds / 60)


def export_buckets(buckets, tool_name, folder_name, output_root):
    out_dir = output_root / folder_name
    out_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    total_entries = 0
    files_info = []

    for date_key in sorted(buckets):
        entries = sorted(buckets[date_key], key=lambda e: (e["ts"], e["source"]))
        path = out_dir / f"{date_key}.md"

        lines = [
            f"# {tool_name} Chat History - {date_key}",
            "",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Entries: {len(entries)}",
            "",
        ]

        by_source = {}
        for e in entries:
            by_source.setdefault(e["source"], []).append(e)

        for source in sorted(by_source):
            group = by_source[source]
            ws = group[0].get("workspace", "")
            ws_label = f" - {ws}" if ws else ""
            lines += [f"## Session{ws_label}", "", f"Source: `{source}`", ""]
            for e in group:
                role = e["role"] or "message"
                lines += [
                    f"### {e['ts'].strftime('%H:%M:%S')} - {role}",
                    "",
                    e["text"],
                    "",
                ]

        content = "\n".join(lines)
        path.write_text(content, encoding="utf-8")
        written += 1
        total_entries += len(entries)
        files_info.append({
            "path": path,
            "date": date_key,
            "entries": len(entries),
            "size": len(content.encode("utf-8")),
            "has_secret": looks_like_secret(content),
            "secret_types": secret_types_in(content),
        })

    return {
        "tool": tool_name,
        "folder": folder_name,
        "files": written,
        "entries": total_entries,
        "active_minutes_estimated": estimate_active_minutes(buckets),
        "files_info": files_info,
    }


def collect_claude(buckets, include_tool_details, root, metrics=None, problems=None):
    if not root.exists():
        return
    metrics = metrics if metrics is not None else {}
    for jsonl in root.rglob("*.jsonl"):
        relative = jsonl.relative_to(root)
        workspace = relative.parts[0] if relative.parts else ""
        lines = read_text_lines(jsonl, problems)
        if lines is None:
            continue
        for raw in lines:
            obj = _json_object(raw)
            if obj is None:
                continue
            try:
                subtype = obj.get("subtype")
                if subtype in CLAUDE_PERMISSION_SUBTYPES:
                    metrics[f"claude_{subtype}s"] = int(metrics.get(f"claude_{subtype}s", 0)) + 1
                    if subtype == "permission_response" and obj.get("granted") is True:
                        metrics["claude_granted_permission_responses"] = (
                            int(metrics.get("claude_granted_permission_responses", 0)) + 1
                        )
                permission_mode = obj.get("permissionMode")
                if isinstance(permission_mode, str) and permission_mode.strip():
                    mode_key = metric_token(permission_mode)
                    metrics[f"claude_permission_mode_{mode_key}"] = (
                        int(metrics.get(f"claude_permission_mode_{mode_key}", 0)) + 1
                    )
                    metrics["claude_permission_mode_events_total"] = (
                        int(metrics.get("claude_permission_mode_events_total", 0)) + 1
                    )
                if obj.get("type") not in ("user", "assistant") or not obj.get("timestamp"):
                    continue
                ts = parse_iso(obj["timestamp"])
                if ts is None:
                    continue
                content, role = _message_parts(obj.get("message"))
                text = get_content_text(content, include_tool_details)
                add_entry(buckets, ts, "Claude", role, text, str(jsonl), workspace)
            except (TypeError, ValueError, AttributeError, RecursionError):
                continue


def claude_history_roots(tp: paths.ToolPaths) -> list[Path]:
    roots = [tp.claude_projects]
    # Older Claude installs kept JSONL transcript history under AppData\Roaming\Claude.
    roots.append(APPDATA / "Claude")

    unique: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        key = str(root.resolve()).lower()
        if key not in seen:
            seen.add(key)
            unique.append(root)
    return unique


def collect_claude_roots(buckets, include_tool_details, roots: list[Path], metrics=None, problems=None):
    for root in roots:
        collect_claude(buckets, include_tool_details, root, metrics=metrics, problems=problems)


def _copilot_response_text(response, include_tool_details=False):
    """Pull readable text out of a Copilot response part list. Defensive:
    the part schema is version-drifty, so harvest known string fields and
    fall back to a typed placeholder."""
    parts = response if isinstance(response, list) else [response]
    chunks = []
    for part in parts:
        if isinstance(part, str):
            chunks.append(part)
        elif isinstance(part, dict):
            text = part.get("value") or part.get("text")
            if isinstance(text, str) and text.strip():
                chunks.append(text)
            elif include_tool_details and part.get("kind"):
                chunks.append(f"[{part['kind']} omitted]")
    return "\n".join(chunks)


def parse_copilot_requests(reqs, include_tool_details=False):
    """Pure: Copilot chat requests[] -> [(ts, role, text)]. Unknown fields skipped."""
    out = []
    for req in reqs:
        if not isinstance(req, dict):
            continue
        ts_ms = req.get("timestamp")
        try:
            ts = datetime.fromtimestamp(float(ts_ms) / 1000.0)
        except (TypeError, ValueError, OSError, OverflowError):
            continue
        msg = (req.get("message") or {}).get("text")
        if isinstance(msg, str) and msg.strip():
            out.append((ts, "user", msg))
        resp_text = _copilot_response_text(req.get("response"), include_tool_details)
        if resp_text.strip():
            out.append((ts, "assistant", resp_text))
    return out


def collect_copilot(buckets, include_tool_details, workspace_storage, problems=None):
    """
    VS Code Copilot Chat sessions:

        <workspaceStorage>/<md5>/chatSessions/<uuid>.jsonl

    Log-structured JSONL: kind=0 carries initial state (may embed requests),
    kind=2 with k=["requests"] appends request batches. Only user prompt text
    and response text are exported; rendered context blobs stay behind.
    A file that cannot be decoded is recorded in ``problems`` and skipped.
    """
    if not workspace_storage.exists():
        return
    try:
        session_files = list(workspace_storage.glob("*/chatSessions/*.jsonl"))
    except OSError:
        if problems is not None:
            problems.append("unreadable")
        return
    for jsonl in session_files:
        workspace = jsonl.parent.parent.name
        lines = read_text_lines(jsonl, problems)
        if lines is None:
            continue
        for raw in lines:
            obj = _json_object(raw)
            if obj is None:
                continue
            kind = obj.get("kind")
            v = obj.get("v")
            reqs = None
            if kind == 0 and isinstance(v, dict):
                reqs = v.get("requests")
            elif kind == 2 and obj.get("k") == ["requests"] and isinstance(v, list):
                reqs = v
            if not reqs:
                continue
            for ts, role, text in parse_copilot_requests(reqs, include_tool_details):
                add_entry(buckets, ts, "Copilot", role, text, str(jsonl), workspace=workspace)


# Codex writes the same turn as a response_item and, on older builds, again as
# an event_msg. A later shape is kept only when that role and text were not
# already counted. See collect_codex.
_CODEX_TEXT_PARTS = {"text", "input_text", "output_text"}
_CODEX_REQUEST_MARKER = "## My request for Codex:"
# Whole-part wrappers Codex injects as user-role prompt scaffolding.
# Matching is case-insensitive and requires both ends, except the AGENTS.md
# heading, which is injected context even when the closing tag is absent.
_CODEX_CONTEXT_WRAPPERS = (
    ("<environment_context>", "</environment_context>"),
    ("<user_instructions>", "</user_instructions>"),
    ("<environments_instructions>", "</environments_instructions>"),
    ("<apps_instructions>", "</apps_instructions>"),
    ("<skills_instructions>", "</skills_instructions>"),
    ("<plugins_instructions>", "</plugins_instructions>"),
    ("<skill>", "</skill>"),
    ("<collaboration_mode>", "</collaboration_mode>"),
    ("<multi_agent_mode>", "</multi_agent_mode>"),
    ("<realtime_conversation>", "</realtime_conversation>"),
    ("<context_window_guidance>", "</context_window_guidance>"),
    ("<context_window>", "</context_window>"),
    ("<tools>", "</tools>"),
    ("<turn_aborted>", "</turn_aborted>"),
    ("<subagent_notification>", "</subagent_notification>"),
    ("<instructions>", "</instructions>"),
)
_CODEX_AGENTS_HEADING = "# agents.md instructions for "
# thread_history SQLite is a projection and is often touched just after the
# rollout file. A gap this large means the database moved on without a new
# rollout file, which this collector does not read.
_CODEX_SQLITE_NEWER_SECONDS = 24 * 60 * 60


def _fresh_codex_stats() -> dict:
    return {
        "files_seen": 0,
        "files_read": 0,
        "messages": 0,
        "compressed_unreadable": 0,
        "compressed_not_scanned": 0,
        "thread_history_dbs": 0,
        "rollout_migrations": False,
        "sqlite_history_gap": "",
    }


def _is_injected_context(text: str) -> bool:
    """True when a user part is prompt scaffolding rather than a person typing."""
    folded = text.strip().casefold()
    if not folded:
        return True
    if folded.startswith(_CODEX_AGENTS_HEADING):
        return True
    for start, end in _CODEX_CONTEXT_WRAPPERS:
        if folded.startswith(start) and folded.endswith(end):
            return True
    return False


def _user_chat_text(text: str) -> str:
    """Drop injected context. Keep the request that follows Codex's own marker."""
    if not isinstance(text, str):
        return ""
    marker_at = text.find(_CODEX_REQUEST_MARKER)
    if marker_at >= 0:
        text = text[marker_at + len(_CODEX_REQUEST_MARKER):]
    text = text.strip()
    if not text or _is_injected_context(text):
        return ""
    return text


def _content_parts(content) -> list[str]:
    if isinstance(content, str):
        return [content.strip()] if content.strip() else []
    if not isinstance(content, list):
        return []
    parts = []
    for item in content:
        if isinstance(item, str) and item.strip():
            parts.append(item.strip())
            continue
        if not isinstance(item, dict):
            continue
        kind = str(item.get("type") or "").casefold()
        if kind in _CODEX_TEXT_PARTS and item.get("text"):
            piece = str(item["text"]).strip()
            if piece:
                parts.append(piece)
    return parts


def _join_user_parts(parts: list[str]) -> str:
    kept = [_user_chat_text(part) for part in parts]
    return "\n\n".join(part for part in kept if part).strip()


def _join_assistant_parts(parts: list[str]) -> str:
    return "\n\n".join(part for part in parts if part and part.strip()).strip()


def _legacy_message_text(payload: dict, role: str, include_tool_details: bool) -> str:
    message = payload.get("message")
    if isinstance(message, str) and message.strip():
        text = message.strip()
    else:
        text = get_content_text(payload, include_tool_details)
    if role == "user":
        return _user_chat_text(text)
    return text.strip() if isinstance(text, str) else ""


def _classify_codex_line(obj: dict, include_tool_details: bool):
    """Return ``(shape, role, text)`` for one rollout line, or None.

    ``shape`` is ``response`` (current ``response_item`` message), ``completed``
    (paginated ``item_completed`` user/assistant item), or ``legacy``
    (``event_msg`` user_message / agent_message). Developer and system roles
    are skipped. Inter-agent ``response_item`` / ``agent_message`` is skipped
    unless ``include_tool_details`` is set. The legacy ``event_msg``
    ``agent_message`` is the assistant's reply, not inter-agent traffic.
    """
    payload = obj.get("payload")
    if not isinstance(payload, dict):
        return None
    record_type = obj.get("type")
    ptype = payload.get("type")
    if record_type == "response_item" and ptype == "message":
        role = str(payload.get("role") or "").casefold()
        if role not in ("user", "assistant"):
            return None
        parts = _content_parts(payload.get("content"))
        text = _join_user_parts(parts) if role == "user" else _join_assistant_parts(parts)
        if not text:
            return None
        return ("response", role, text)
    if record_type == "response_item" and ptype == "agent_message":
        if not include_tool_details:
            return None
        text = _join_assistant_parts(_content_parts(payload.get("content")))
        if not text:
            return None
        return ("response", "assistant", text)
    if record_type != "event_msg":
        return None
    if ptype == "item_completed":
        item = payload.get("item")
        if not isinstance(item, dict):
            return None
        item_type = str(item.get("type") or "")
        if item_type == "UserMessage":
            role = "user"
            text = _join_user_parts(_content_parts(item.get("content")))
        elif item_type == "AgentMessage":
            role = "assistant"
            text = _join_assistant_parts(_content_parts(item.get("content")))
        else:
            return None
        if not text:
            return None
        return ("completed", role, text)
    if ptype == "user_message":
        text = _legacy_message_text(payload, "user", include_tool_details)
        if not text:
            return None
        return ("legacy", "user", text)
    if ptype == "agent_message":
        text = _legacy_message_text(payload, "assistant", include_tool_details)
        if not text:
            return None
        return ("legacy", "assistant", text)
    return None


def _merge_codex_shapes(groups: list[list[tuple]]) -> list[tuple]:
    """Keep every line from the first non-empty shape, then new texts only.

    Repeated messages inside one shape stay. The same role and text written
    again as another shape does not count a second time.
    """
    represented: set[tuple[str, str]] = set()
    chosen = []
    filtering = False
    for group in groups:
        if not filtering:
            emit = list(group)
            filtering = True
        else:
            emit = [entry for entry in group if (entry[1], entry[2]) not in represented]
        for entry in emit:
            represented.add((entry[1], entry[2]))
            chosen.append(entry)
    return chosen


def _rollout_timestamp(obj: dict, path: Path, cached):
    ts = parse_iso(obj.get("timestamp"))
    if ts is not None:
        return ts, cached
    payload = obj.get("payload")
    ms = payload.get("completed_at_ms") if isinstance(payload, dict) else None
    if isinstance(ms, (int, float)) and not isinstance(ms, bool):
        if ms > 1_000_000_000_000:
            return datetime.fromtimestamp(ms / 1000.0), cached
        if ms > 1_000_000_000:
            return datetime.fromtimestamp(float(ms)), cached
    if cached is None:
        try:
            cached = datetime.fromtimestamp(path.stat().st_mtime)
        except OSError:
            cached = datetime.now()
    return cached, cached


def _codex_scan_roots(root: Path) -> tuple[Path, list[Path]]:
    """Codex home and the rollout directories under it.

    A real scan passes ``<CODEX_HOME>/sessions``. Archived threads are moved
    to the sibling ``archived_sessions`` directory and stay readable. Any
    other root is scanned as itself so tests can point at a fixture folder.
    """
    root = Path(root)
    if root.name == "sessions":
        home = root.parent
        roots = []
        if root.exists():
            roots.append(root)
        archived = home / "archived_sessions"
        try:
            archived_exists = archived.exists()
        except OSError:
            archived_exists = False
        if archived_exists:
            roots.append(archived)
        return home, roots
    try:
        exists = root.exists()
    except OSError:
        exists = False
    return root, [root] if exists else []


def _read_rollout_lines(path: Path, problems: list | None, stats: dict) -> list[str] | None:
    """Lines from a rollout, or None when this file cannot be read.

    A missing zstd backend is recorded and the file is not opened. A
    compressed file that fails (``ZstdUnavailable``, ``TooLarge``,
    ``DecompressTimeout``, ``UnicodeError``, ``OSError``) is recorded and
    skipped. A plain file that cannot be decoded is recorded by
    ``read_text_lines``.
    """
    if compressed.is_compressed(path):
        if compressed.zstd_backend() is None:
            stats["compressed_not_scanned"] += 1
            if problems is not None:
                problems.append("compressed_not_scanned")
            return None
        try:
            text = compressed.read_text(
                path, errors="replace", max_bytes=compressed.MAX_DECOMPRESSED_BYTES
            )
        except (
            compressed.ZstdUnavailable,
            compressed.TooLarge,
            compressed.DecompressTimeout,
            UnicodeError,
            OSError,
        ):
            stats["compressed_unreadable"] += 1
            if problems is not None:
                problems.append("unreadable")
            return None
        stats["files_read"] += 1
        return text.splitlines()
    lines = read_text_lines(path, problems)
    if lines is not None:
        stats["files_read"] += 1
    return lines


def _observe_sqlite_history(home: Path, rollout_files: list[Path], stats: dict) -> None:
    """Note when ``thread_history_*.sqlite`` may hold messages we did not read.

    Rollout JSONL is still the durable record. The SQLite file is a
    rebuildable projection. This does not open the database. It only checks
    that the file exists and whether it is newer than every rollout we saw.
    """
    try:
        dbs = [path for path in home.glob("thread_history_*.sqlite") if path.is_file()]
    except OSError:
        dbs = []
    stats["thread_history_dbs"] = len(dbs)
    try:
        stats["rollout_migrations"] = (home / "rollout-migrations").is_dir()
    except OSError:
        stats["rollout_migrations"] = False
    if not dbs:
        return
    if not rollout_files:
        stats["sqlite_history_gap"] = "no_rollouts"
        return
    try:
        newest_db = max(path.stat().st_mtime for path in dbs)
        newest_rollout = max(path.stat().st_mtime for path in rollout_files)
    except OSError:
        return
    if newest_db > newest_rollout + _CODEX_SQLITE_NEWER_SECONDS:
        stats["sqlite_history_gap"] = "newer_than_rollouts"


def codex_coverage_findings(stats: dict | None) -> list[dict]:
    """Coverage notes for Codex history this collector did not fully read."""
    if not stats:
        return []
    findings = []
    not_scanned = int(stats.get("compressed_not_scanned") or 0)
    if not_scanned:
        noun = "log" if not_scanned == 1 else "logs"
        findings.append(
            make_finding(
                "chat_history.codex.compressed_not_scanned",
                "low",
                "General Tooling",
                f"{not_scanned} compressed Codex session {noun} not scanned",
                evidence_count=not_scanned,
                sample_redacted=f"files={not_scanned}",
                tags=["coverage_gap"],
            )
        )
    unreadable = int(stats.get("compressed_unreadable") or 0)
    if unreadable:
        noun = "log" if unreadable == 1 else "logs"
        findings.append(
            make_finding(
                "chat_history.codex.compressed_unreadable",
                "low",
                "General Tooling",
                f"{unreadable} compressed Codex session {noun} could not be read",
                evidence_count=unreadable,
                sample_redacted=f"files={unreadable}",
                tags=["coverage_gap"],
            )
        )
    files_seen = int(stats.get("files_seen") or 0)
    files_read = int(stats.get("files_read") or 0)
    messages = int(stats.get("messages") or 0)
    if files_read > 0 and messages == 0:
        findings.append(
            make_finding(
                "chat_history.codex.format_drift",
                "low",
                "General Tooling",
                "Codex session files were found but no chat messages were recognized",
                evidence_count=files_seen,
                sample_redacted=(
                    f"files={files_seen} read={files_read} messages=0; format may have changed"
                ),
                tags=["coverage_gap"],
            )
        )
    gap = str(stats.get("sqlite_history_gap") or "")
    if gap:
        dbs = int(stats.get("thread_history_dbs") or 0)
        if gap == "no_rollouts":
            sample = f"rollout_files=0 thread_history_sqlite={dbs}"
        else:
            sample = f"rollout_files={files_seen} thread_history_sqlite={dbs} newer_than_rollouts=yes"
        if stats.get("rollout_migrations"):
            sample += " rollout_migrations=present"
        findings.append(
            make_finding(
                "chat_history.codex.sqlite_history_not_counted",
                "low",
                "General Tooling",
                "Codex thread history may be in SQLite and was not counted",
                evidence_count=dbs or 1,
                sample_redacted=sample,
                tags=["coverage_gap"],
            )
        )
    return findings


def collect_codex(buckets, include_tool_details, root, problems=None, stats=None):
    """Collect Codex chat from rollout JSONL under ``root``.

    Accepts the legacy shape (``event_msg`` / ``user_message`` or
    ``agent_message``) and the current shape (``response_item`` /
    ``message`` with ``input_text`` or ``output_text`` parts). Paginated
    history also stores the visible turn on ``event_msg`` / ``item_completed``
    (``UserMessage`` and ``AgentMessage``). When more than one shape is
    present, a later copy of the same role and text is not counted again.

    ``stats``, when a dict, receives file and message counts plus the flags
    ``codex_coverage_findings`` turns into coverage notes. Compressed reads
    that fail are also appended to ``problems``.
    """
    if not isinstance(stats, dict):
        stats = {}
    stats.update(_fresh_codex_stats())
    home, roots = _codex_scan_roots(Path(root))
    files: list[Path] = []
    for scan_root in roots:
        files.extend(compressed.jsonl_files(scan_root))
    files = sorted(set(files))
    stats["files_seen"] = len(files)
    _observe_sqlite_history(home, files, stats)
    messages = 0
    for jsonl in files:
        lines = _read_rollout_lines(jsonl, problems, stats)
        if not lines:
            continue
        grouped: dict[str, list[tuple]] = {"response": [], "completed": [], "legacy": []}
        file_ts = None
        for raw in lines:
            obj = _json_object(raw)
            if obj is None:
                continue
            try:
                classified = _classify_codex_line(obj, include_tool_details)
                if classified is None:
                    continue
                shape, role, text = classified
                ts, file_ts = _rollout_timestamp(obj, jsonl, file_ts)
                grouped[shape].append((ts, role, text))
            except (TypeError, ValueError, AttributeError, RecursionError, OSError):
                continue
        for ts, role, text in _merge_codex_shapes(
            [grouped["response"], grouped["completed"], grouped["legacy"]]
        ):
            add_entry(buckets, ts, "Codex", role, text, str(jsonl))
            messages += 1
    stats["messages"] = messages


def grok_workspace_label(slug):
    decoded = unquote(slug)
    m = re.search(r"cursor-projects[\\/](.+)$", decoded)
    return m.group(1) if m else decoded


def collect_grok(buckets, include_tool_details, root, problems=None):
    """
    Grok chat_history.jsonl: role-tagged messages (`type`: system/user/
    assistant), content is a list of {type: text, text: ...} or a plain
    string. No per-message timestamp field exists, so the session file's
    mtime stands in (same fallback pattern as collect_codex).

    updates.jsonl and events.jsonl are metadata-only sources (counts/sizes,
    handled in grok.py, not here) — never opened for text here.
    """
    if not root.exists():
        return
    for jsonl in root.rglob("chat_history.jsonl"):
        session_dir = jsonl.parent
        workspace = grok_workspace_label(session_dir.parent.name)
        summary = {}
        summary_path = session_dir / "summary.json"
        if summary_path.is_file():
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8-sig"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
                summary = {}
                if problems is not None:
                    problems.append("unreadable")
        start_ts = parse_iso(summary.get("created_at")) if isinstance(summary, dict) else None
        end_ts = parse_iso(summary.get("updated_at")) if isinstance(summary, dict) else None
        fallback_ts = datetime.fromtimestamp(jsonl.stat().st_mtime)
        lines = read_text_lines(jsonl, problems)
        if lines is None:
            continue
        messages = []
        for raw in lines:
            obj = _json_object(raw)
            if obj is None:
                continue
            try:
                role = obj.get("type")
                if role not in ("user", "assistant"):
                    continue
                text = get_content_text(obj.get("content"), include_tool_details)
                if text:
                    messages.append((role, text))
            except (TypeError, ValueError, AttributeError, RecursionError):
                continue

        if start_ts and end_ts and end_ts > start_ts and len(messages) > 1:
            span = (end_ts - start_ts).total_seconds()
            step = span / max(len(messages) - 1, 1)
            for idx, (role, text) in enumerate(messages):
                add_entry(
                    buckets,
                    start_ts + timedelta(seconds=step * idx),
                    "Grok",
                    role,
                    text,
                    str(jsonl),
                    workspace,
                )
        else:
            for role, text in messages:
                add_entry(buckets, fallback_ts, "Grok", role, text, str(jsonl), workspace)


def cursor_workspace_label(slug):
    m = re.search(r"cursor-projects-(.+)$", slug)
    return m.group(1) if m else slug


def collect_cursor_transcripts(buckets, include_tool_details, root, problems=None):
    if not root.exists():
        return
    for project_dir in root.iterdir():
        if not project_dir.is_dir():
            continue
        workspace = cursor_workspace_label(project_dir.name)
        transcripts_dir = project_dir / "agent-transcripts"
        if not transcripts_dir.exists():
            continue
        for session_dir in transcripts_dir.iterdir():
            if not session_dir.is_dir():
                continue
            uuid = session_dir.name
            jsonl = session_dir / f"{uuid}.jsonl"
            if not jsonl.exists():
                continue
            file_time = datetime.fromtimestamp(jsonl.stat().st_mtime)
            last_known_ts = file_time
            lines = read_text_lines(jsonl, problems)
            if lines is None:
                continue
            for raw in lines:
                obj = _json_object(raw)
                if obj is None:
                    continue
                try:
                    role = obj.get("role")
                    if role not in ("user", "assistant"):
                        continue
                    content, _message_role = _message_parts(obj.get("message"))
                    ts = last_known_ts
                    if role == "user":
                        parsed = parse_cursor_embedded_timestamp(content)
                        if parsed:
                            ts = parsed
                            last_known_ts = parsed
                    text = get_content_text(content, include_tool_details)
                    add_entry(buckets, ts, "Cursor", role, text, str(jsonl), workspace)
                except (TypeError, ValueError, AttributeError, RecursionError):
                    continue


def cursor_composer_workspace(composer):
    if not isinstance(composer, dict):
        return ""
    ws = composer.get("workspaceIdentifier")
    if not isinstance(ws, dict):
        return ""
    uri = ws.get("uri")
    if not isinstance(uri, dict):
        return ""
    fs = uri.get("fsPath", "")
    if not isinstance(fs, str) or not fs:
        return ""
    parts = fs.replace("\\", "/").rstrip("/").split("/")
    try:
        idx = next(i for i, p in enumerate(parts) if p == "cursor-projects")
        return "/".join(parts[idx + 1:]) if idx + 1 < len(parts) else parts[-1]
    except StopIteration:
        return parts[-1] if parts else ""


def collect_cursor_composer(buckets, db):
    if not db.exists():
        return
    try:
        con = sqlite3.connect(_sqlite_ro_uri(db), uri=True)
    except (sqlite3.Error, OSError, ValueError) as e:
        print(f"  Warning: cannot open state.vscdb: {e}", file=sys.stderr)
        return
    cur = con.cursor()
    try:
        cur.execute("SELECT value FROM ItemTable WHERE key='composer.composerHeaders'")
        row = cur.fetchone()
        if not row or row[0] is None:
            return
        try:
            header = json.loads(row[0])
        except (json.JSONDecodeError, ValueError, RecursionError):
            return
        composers = header.get("allComposers", []) if isinstance(header, dict) else []
        if not isinstance(composers, list):
            return
        for composer in composers:
            if not isinstance(composer, dict):
                continue
            cid = str(composer.get("composerId") or "")
            workspace = cursor_composer_workspace(composer)
            cur.execute("SELECT value FROM cursorDiskKV WHERE key=?", (f"composerData:{cid}",))
            cd_row = cur.fetchone()
            if not cd_row or cd_row[0] is None:
                continue
            try:
                composer_data = json.loads(cd_row[0])
            except (json.JSONDecodeError, ValueError, RecursionError):
                continue
            headers = (
                composer_data.get("fullConversationHeadersOnly", [])
                if isinstance(composer_data, dict)
                else []
            )
            if not isinstance(headers, list):
                continue
            for h in headers:
                if not isinstance(h, dict):
                    continue
                bid = h.get("bubbleId")
                if not bid:
                    continue
                try:
                    cur.execute(
                        "SELECT value FROM cursorDiskKV WHERE key=?",
                        (f"bubbleId:{cid}:{bid}",),
                    )
                except sqlite3.Error as e:
                    print(f"  Warning: cursor composer bubble read failed: {e}", file=sys.stderr)
                    continue
                brow = cur.fetchone()
                if not brow or brow[0] is None:
                    continue
                try:
                    bubble = json.loads(brow[0])
                except (json.JSONDecodeError, ValueError, RecursionError):
                    continue
                if not isinstance(bubble, dict):
                    continue
                text = str(bubble.get("text") or "").strip()
                if not text:
                    continue
                ts = parse_iso(bubble.get("createdAt"))
                if ts is None:
                    continue
                role = "user" if bubble.get("type") == 1 else "assistant"
                add_entry(buckets, ts, "Cursor", role, text, f"composerData:{cid}", workspace)
    except sqlite3.Error as e:
        print(f"  Warning: cursor composer collection failed: {e}", file=sys.stderr)
    finally:
        con.close()


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def relative_raw_path(path: Path, raw_root: Path) -> str:
    try:
        rel = path.relative_to(raw_root)
        return "raw/" + rel.as_posix()
    except ValueError:
        audit_root = raw_root.parent
        try:
            return path.relative_to(audit_root).as_posix()
        except ValueError:
            return "raw/chat-history/" + path.name


def build_evidence(
    results,
    raw_root: Path,
    tp: paths.ToolPaths,
    claude_roots: list[Path] | None = None,
    metrics: dict | None = None,
    parse_problems: list | None = None,
    codex_stats: dict | None = None,
) -> dict:
    claude_roots = claude_roots or [tp.claude_projects]
    scanned = [
        *(str(root) for root in claude_roots),
        str(tp.codex_sessions),
        str(tp.cursor_projects),
        str(tp.cursor_db),
        str(tp.grok_sessions),
    ]
    scope_hash = compute_scope_hash(scanned)
    platform_detected = any(Path(p).exists() for p in scanned)

    envelope = make_envelope(
        COLLECTOR,
        __version__,
        scope_hash,
        platform_detected=platform_detected,
    )

    raw_pointers = []
    findings = []
    per_tool = {}
    all_dates: list[datetime] = []
    total_messages = 0
    total_bytes = 0
    secret_file_count = 0

    secret_by_tool: dict[str, dict] = {}

    for result in results:
        tool_key = result["folder"]
        tool_files = result["files_info"]
        per_tool[tool_key] = {
            "file_count": result["files"],
            "message_count": result["entries"],
            "total_bytes": sum(f["size"] for f in tool_files),
            "active_minutes_estimated": int(result.get("active_minutes_estimated") or 0),
        }
        total_messages += result["entries"]
        total_bytes += sum(f["size"] for f in tool_files)

        for finfo in tool_files:
            all_dates.append(datetime.strptime(finfo["date"], "%Y-%m-%d"))
            pointer_path = relative_raw_path(finfo["path"], raw_root)
            sha = file_sha256(finfo["path"]) if finfo["path"].exists() else "dry-run"
            raw_pointers.append({
                "kind": "chat_transcript",
                "path": pointer_path,
                "sha256": sha,
            })
            if finfo["has_secret"]:
                secret_file_count += 1
                bucket = secret_by_tool.setdefault(
                    tool_key,
                    {"count": 0, "severity": "high", "types": set()},
                )
                bucket["count"] += 1
                bucket["types"].update(finfo["secret_types"])
                if "aws_key" in finfo["secret_types"]:
                    bucket["severity"] = "critical"

    for tool_key, info in secret_by_tool.items():
        findings.append(
            make_finding(
                f"chat_history.secret.{tool_key}",
                info["severity"],
                "Secrets Exposure",
                f"Chat transcripts contain potential secrets ({tool_key})",
                evidence_count=info["count"],
                sample_redacted=f"{info['count']} files flagged",
                secret_redacted=True,
                tags=[
                    "chat_plaintext",
                    "gh_token_present" if "github_pat" in info["types"] else "history_retention",
                ],
            )
        )

    if all_dates:
        oldest = min(all_dates)
        newest = max(all_dates)
        age_days = (datetime.now() - oldest).days
        if age_days > RETENTION_DAYS:
            findings.append(
                make_finding(
                    "chat_history.retention.exceeds_90d",
                    "medium",
                    "Cross-Agent Visibility",
                    f"Chat history retention exceeds {RETENTION_DAYS} days",
                    evidence_count=len(all_dates),
                    first_seen=oldest.isoformat(),
                    last_seen=newest.isoformat(),
                    tags=["history_retention"],
                )
            )
        envelope["summary"] = {
            "total_files": sum(r["files"] for r in results),
            "total_messages": total_messages,
            "total_bytes": total_bytes,
            "oldest_date": oldest.strftime("%Y-%m-%d"),
            "newest_date": newest.strftime("%Y-%m-%d"),
            "retention_days": age_days,
            "secret_hit_files": secret_file_count,
            "active_minutes_estimated": sum(
                int(v.get("active_minutes_estimated") or 0) for v in per_tool.values()
            ),
            "active_gap_cap_minutes": ACTIVE_GAP_CAP_MINUTES,
            **{f"{k}_files": v["file_count"] for k, v in per_tool.items()},
            **{f"{k}_messages": v["message_count"] for k, v in per_tool.items()},
            **{f"{k}_active_minutes_estimated": v["active_minutes_estimated"] for k, v in per_tool.items()},
        }
    else:
        envelope["summary"] = {
            "total_files": 0,
            "total_messages": 0,
            "total_bytes": 0,
            "secret_hit_files": 0,
            "active_minutes_estimated": 0,
            "active_gap_cap_minutes": ACTIVE_GAP_CAP_MINUTES,
        }

    envelope["summary"]["discovery"] = paths.safe_path_meta(tp)
    envelope["summary"]["claude_sources_scanned"] = len(claude_roots)
    if metrics:
        for key, value in sorted(metrics.items()):
            if isinstance(value, int):
                envelope["summary"][key] = value
    if parse_problems:
        envelope["summary"]["parse_errors"] = len(parse_problems)
        findings.append(
            make_finding(
                "chat_history.parse_error",
                "low",
                "General Tooling",
                "Chat history skipped files that could not be decoded",
                evidence_count=len(parse_problems),
                sample_redacted=f"files={len(parse_problems)}",
                tags=["config_parse_error"],
            )
        )
    if codex_stats is not None:
        envelope["summary"]["codex_session_files_seen"] = int(codex_stats.get("files_seen") or 0)
        findings.extend(codex_coverage_findings(codex_stats))
    envelope["findings"] = findings
    envelope["raw_pointers"] = raw_pointers
    return envelope


def main():
    parser = argparse.ArgumentParser(description="Export AI chat history and evidence")
    add_base_args(parser)
    paths.add_path_args(parser)
    parser.add_argument("--include-tool-details", action="store_true")
    args = parser.parse_args()

    evidence_root = validate_evidence_root(args.evidence_root)
    raw_root = resolve_raw_root(evidence_root, args.raw_root)
    chat_output = raw_root / "chat-history"
    tp = paths.resolve_from_args(args)
    claude_roots = claude_history_roots(tp)

    results = []
    metrics: dict = {}
    parse_problems: list[str] = []
    codex_stats: dict = {}
    sources = [
        (
            "Claude",
            defaultdict(list),
            lambda b: collect_claude_roots(
                b, args.include_tool_details, claude_roots, metrics=metrics, problems=parse_problems
            ),
            "claude",
        ),
        (
            "Codex",
            defaultdict(list),
            lambda b: collect_codex(
                b,
                args.include_tool_details,
                tp.codex_sessions,
                problems=parse_problems,
                stats=codex_stats,
            ),
            "codex",
        ),
        (
            "Cursor",
            defaultdict(list),
            lambda b: collect_cursor_transcripts(
                b, args.include_tool_details, tp.cursor_projects, problems=parse_problems
            ),
            "cursor",
        ),
        (
            "Cursor Composer",
            defaultdict(list),
            lambda b: collect_cursor_composer(b, tp.cursor_db),
            "cursor-composer",
        ),
        (
            "Grok",
            defaultdict(list),
            lambda b: collect_grok(
                b, args.include_tool_details, tp.grok_sessions, problems=parse_problems
            ),
            "grok",
        ),
        (
            "Copilot",
            defaultdict(list),
            lambda b: collect_copilot(
                b,
                args.include_tool_details,
                tp.vscode_workspace_storage,
                problems=parse_problems,
            ),
            "copilot",
        ),
    ]
    for tool_name, buckets, collector, folder in sources:
        print(f"Collecting {tool_name}...", end=" ", flush=True)
        collector(buckets)
        if args.dry_run:
            r = {
                "tool": tool_name,
                "folder": folder,
                "files": len(buckets),
                "entries": sum(len(v) for v in buckets.values()),
                "active_minutes_estimated": estimate_active_minutes(buckets),
                "files_info": [
                    {
                        "path": chat_output / folder / f"{dk}.md",
                        "date": dk,
                        "entries": len(ev),
                        "size": sum(len(e["text"].encode()) for e in ev),
                        "has_secret": any(looks_like_secret(e["text"]) for e in ev),
                        "secret_types": list({
                            t for e in ev for t in secret_types_in(e["text"])
                        }),
                    }
                    for dk, ev in buckets.items()
                ],
            }
        else:
            r = export_buckets(buckets, tool_name, folder, chat_output)
        results.append(r)
        print(f"{r['files']} files, {r['entries']} entries")

    envelope = build_evidence(
        results,
        raw_root,
        tp,
        claude_roots=claude_roots,
        metrics=metrics,
        parse_problems=parse_problems,
        codex_stats=codex_stats,
    )
    finish_collector(envelope, evidence_root, dry_run=args.dry_run)

    if not envelope["platform_detected"]:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
