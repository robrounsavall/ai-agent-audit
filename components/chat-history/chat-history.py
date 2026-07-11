"""
Chat history exporter and evidence collector.

Usage:
    python chat-history.py --evidence-root ./audit-run [--raw-root ./raw] [--include-tool-details] [--dry-run]

Writes raw markdown under <raw-root>/chat-history/{claude,codex,cursor,cursor-composer}/YYYY-MM-DD.md
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

__version__ = "1.0.0"

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


def collect_claude(buckets, include_tool_details, root, metrics=None):
    if not root.exists():
        return
    metrics = metrics if metrics is not None else {}
    for jsonl in root.rglob("*.jsonl"):
        relative = jsonl.relative_to(root)
        workspace = relative.parts[0] if relative.parts else ""
        try:
            lines = jsonl.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for raw in lines:
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                continue
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
            msg = obj.get("message", {})
            text = get_content_text(msg.get("content"), include_tool_details)
            add_entry(buckets, ts, "Claude", msg.get("role", ""), text, str(jsonl), workspace)


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


def collect_claude_roots(buckets, include_tool_details, roots: list[Path], metrics=None):
    for root in roots:
        collect_claude(buckets, include_tool_details, root, metrics=metrics)


def collect_codex(buckets, include_tool_details, root):
    if not root.exists():
        return
    for jsonl in root.rglob("*.jsonl"):
        try:
            lines = jsonl.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for raw in lines:
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if obj.get("type") != "event_msg" or not obj.get("payload"):
                continue
            payload = obj["payload"]
            ptype = payload.get("type")
            if ptype not in ("user_message", "agent_message"):
                continue
            role = "user" if ptype == "user_message" else "assistant"
            ts = parse_iso(obj.get("timestamp")) or datetime.fromtimestamp(jsonl.stat().st_mtime)
            text = (
                str(payload["message"]) if payload.get("message")
                else get_content_text(payload, include_tool_details)
            )
            add_entry(buckets, ts, "Codex", role, text, str(jsonl))


def grok_workspace_label(slug):
    decoded = unquote(slug)
    m = re.search(r"cursor-projects[\\/](.+)$", decoded)
    return m.group(1) if m else decoded


def collect_grok(buckets, include_tool_details, root):
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
        try:
            summary_path = session_dir / "summary.json"
            if summary_path.exists():
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            summary = {}
        start_ts = parse_iso(summary.get("created_at")) if isinstance(summary, dict) else None
        end_ts = parse_iso(summary.get("updated_at")) if isinstance(summary, dict) else None
        fallback_ts = datetime.fromtimestamp(jsonl.stat().st_mtime)
        try:
            lines = jsonl.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        messages = []
        for raw in lines:
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                continue
            role = obj.get("type")
            if role not in ("user", "assistant"):
                continue
            text = get_content_text(obj.get("content"), include_tool_details)
            if text:
                messages.append((role, text))

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


def collect_cursor_transcripts(buckets, include_tool_details, root):
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
            try:
                lines = jsonl.read_text(encoding="utf-8").splitlines()
            except OSError:
                continue
            for raw in lines:
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if obj.get("role") not in ("user", "assistant"):
                    continue
                ts = last_known_ts
                if obj["role"] == "user":
                    parsed = parse_cursor_embedded_timestamp(obj.get("message", {}).get("content"))
                    if parsed:
                        ts = parsed
                        last_known_ts = parsed
                text = get_content_text(obj.get("message", {}).get("content"), include_tool_details)
                add_entry(buckets, ts, "Cursor", obj["role"], text, str(jsonl), workspace)


def cursor_composer_workspace(composer):
    ws = composer.get("workspaceIdentifier", {})
    fs = ws.get("uri", {}).get("fsPath", "")
    if not fs:
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
    uri = "file:" + str(db).replace("\\", "/") + "?mode=ro&immutable=1"
    try:
        con = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as e:
        print(f"  Warning: cannot open state.vscdb: {e}", file=sys.stderr)
        return
    cur = con.cursor()
    try:
        cur.execute("SELECT value FROM ItemTable WHERE key='composer.composerHeaders'")
        row = cur.fetchone()
        if not row or row[0] is None:
            return
        composers = json.loads(row[0]).get("allComposers", [])
        for composer in composers:
            cid = composer.get("composerId", "")
            workspace = cursor_composer_workspace(composer)
            cur.execute("SELECT value FROM cursorDiskKV WHERE key=?", (f"composerData:{cid}",))
            cd_row = cur.fetchone()
            if not cd_row or cd_row[0] is None:
                continue
            headers = json.loads(cd_row[0]).get("fullConversationHeadersOnly", [])
            for h in headers:
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
                b = json.loads(brow[0])
                text = b.get("text", "").strip()
                if not text:
                    continue
                ts = parse_iso(b.get("createdAt"))
                if ts is None:
                    continue
                role = "user" if b.get("type") == 1 else "assistant"
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

    sources = [
        ("Claude", defaultdict(list), lambda b: collect_claude_roots(b, args.include_tool_details, claude_roots, metrics=metrics), "claude"),
        ("Codex", defaultdict(list), lambda b: collect_codex(b, args.include_tool_details, tp.codex_sessions), "codex"),
        ("Cursor", defaultdict(list), lambda b: collect_cursor_transcripts(b, args.include_tool_details, tp.cursor_projects), "cursor"),
        ("Cursor Composer", defaultdict(list), lambda b: collect_cursor_composer(b, tp.cursor_db), "cursor-composer"),
        ("Grok", defaultdict(list), lambda b: collect_grok(b, args.include_tool_details, tp.grok_sessions), "grok"),
    ]

    results = []
    metrics: dict = {}
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

    envelope = build_evidence(results, raw_root, tp, claude_roots=claude_roots, metrics=metrics)
    finish_collector(envelope, evidence_root, dry_run=args.dry_run)

    if not envelope["platform_detected"]:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
