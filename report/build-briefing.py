#!/usr/bin/env python3
"""
Build a self-contained executive HTML briefing from aiscan evidence.

This rev targets the dark editorial template — Geist +
JetBrains Mono, warm-near-black background, single amber accent, mono `/NN`
section kickers. Structural change worth flagging:

  - Appendix rows are aggregated by (severity, title, ref). Identical
    gitleaks findings — the historical pain point that produced ~170
    near-identical "raw/secrets-scan/findings.csv" rows — collapse to one
    row per rule with a count badge.

Usage:
    python build-briefing.py --evidence-root <path> --out <html-path> \\
        [--customer <name>] [--operator <name>]
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import html
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

LIB_DIR = Path(__file__).resolve().parent.parent / "lib"
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
sys.path.insert(0, str(LIB_DIR))
sys.path.insert(0, str(TEMPLATES_DIR))

from briefing_template import HTML_SHELL  # noqa: E402


def read_frontmatter(evidence_root: Path) -> dict[str, str]:
    """Read optional chain-of-custody frontmatter if a run produced one.

    aiscan runs have no chain-of-custody file, so this normally returns {}.
    Kept for compatibility with evidence roots produced by engagement tooling.
    """
    path = evidence_root / "chain-of-custody.md"
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return {}
    match = re.match(r"^---\r?\n(.*?)\r?\n---\r?\n", text, re.DOTALL)
    if not match:
        return {}
    meta: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            meta[key.strip()] = value.strip()
    return meta


SUPPORTED_MAJOR = 1

PLATFORM_COLLECTORS = ("claude", "cowork", "cursor", "codex", "copilot", "grok")


def _is_detected(env: dict[str, Any] | None) -> bool:
    return bool(env and env.get("platform_detected", True))


def _visible_platform_collectors(envelopes: dict[str, dict[str, Any]]) -> tuple[str, ...]:
    return tuple(
        key for key in PLATFORM_COLLECTORS
        if not (key == "copilot" and not _is_detected(envelopes.get(key)))
    )


TOOL_LABELS = {
    "claude": "Claude Code",
    "cowork": "Claude Cowork",
    "cursor": "Cursor",
    "codex": "Codex Desktop",
    "copilot": "GitHub Copilot",
    "grok": "Grok Build",
    "chat-history": "Chat History",
    "secrets-scan": "Secrets Scan",
    "git-posture": "Git Posture",
    "discovery": "Discovery",
    "pii-scan": "PII Scan",
}
COLLECTOR_PURPOSES = {
    "chat-history": ("Chat transcripts", "Transcript export across detected AI tools"),
    "claude": ("Claude posture", "Claude settings, permissions, and MCP posture"),
    "cowork": ("Cowork posture", "Claude desktop app session workspaces, preview cache, and cloud bridging"),
    "cursor": ("Cursor posture", "Cursor local state, durable rules, and approval events"),
    "codex": ("Codex posture", "Codex config, trusted projects, and MCP posture"),
    "copilot": ("GitHub Copilot posture", "Copilot local settings detection"),
    "git-posture": ("Git posture", "Local repository hygiene checks"),
    "grok": ("Grok posture", "Grok config and session posture"),
    "secrets-scan": ("Secrets scan", "gitleaks scan over chat exports and repo roots"),
    "discovery": ("Discovery", "Local tool path and capability discovery"),
    "pii-scan": ("PII scan", "Regulated-data scan: cards, SSNs, IBANs, emails, phones, public IPs"),
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

EXPOSURE_CATEGORIES = [
    "Shell Execution",
    "Network Egress",
    "Data Access",
    "Telemetry Configuration",
    "Cross-Agent Visibility",
    "MCP Tooling",
    "Secrets Exposure",
    "Source Code Egress",
    "Git Posture",
    "Identity & SSO",
    "General Tooling",
    "PII Exposure",
]

PERMISSION_CATEGORIES = {
    "Shell Execution",
    "Network Egress",
    "Data Access",
    "Telemetry Configuration",
    "Cross-Agent Visibility",
    "MCP Tooling",
    "General Tooling",
}

# ─────────────────────────────────────────────────────────────────────────────
# Loaders & helpers (largely unchanged)
# ─────────────────────────────────────────────────────────────────────────────


def _parse_major(version: str) -> int | None:
    match = re.match(r"^(\d+)", str(version or ""))
    return int(match.group(1)) if match else None


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _scope_label_display(scope: str, scope_label: str) -> str:
    label = str(scope_label or "")
    if not label:
        return str(scope or "")
    if re.fullmatch(rf"{re.escape(str(scope))}#[0-9a-f]{{12}}", label):
        if scope == "user":
            return "user configuration"
        if scope == "project":
            return "project configuration"
        if scope == "workspace":
            return "workspace configuration"
        return f"{scope} configuration"
    return label


def _display_redaction_tokens(value: Any) -> str:
    text = str(value or "")
    replacements = {
        "user": "user configuration",
        "project": "project configuration",
        "workspace": "workspace configuration",
    }
    for scope, label in replacements.items():
        text = re.sub(rf"\b{scope}#[0-9a-f]{{12}}\b", label, text)
    return text


def _display_finding_title(finding: dict[str, Any]) -> str:
    finding_id = str(finding.get("id", ""))
    if finding_id == "claude.permission.skip_dangerous_prompt":
        return "Claude dangerous-mode confirmation prompt is disabled"
    return str(finding.get("title", ""))


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def load_evidence(evidence_root: Path) -> dict[str, dict[str, Any]]:
    evidence_dir = evidence_root / "evidence"
    if not evidence_dir.is_dir():
        raise FileNotFoundError(f"Evidence directory not found: {evidence_dir}")

    files = sorted(evidence_dir.glob("*.json"))
    if not files:
        raise FileNotFoundError(f"No evidence JSON files in {evidence_dir}")

    envelopes: dict[str, dict[str, Any]] = {}
    for path in files:
        data = _load_json(path)
        if data is None:
            raise ValueError(f"Invalid JSON: {path}")
        major = _parse_major(str(data.get("version", "")))
        if major is None or major != SUPPORTED_MAJOR:
            raise ValueError(
                f"Schema version mismatch in {path.name}: "
                f"got {data.get('version')}, supported major {SUPPORTED_MAJOR}"
            )
        name = data.get("collector") or path.stem
        envelopes[name] = data
    return envelopes


def load_collectors_run(evidence_root: Path) -> list[dict[str, Any]]:
    path = evidence_root / "collectors_run.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
        return []
    except (OSError, json.JSONDecodeError):
        return []


def manifest_sha256(evidence_root: Path) -> str:
    path = evidence_root / "manifest.json"
    if not path.exists():
        return "manifest not present"
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collector_status(
    name: str,
    envelope: dict[str, Any] | None,
    run_row: dict[str, Any] | None,
) -> str:
    if envelope is not None and not envelope.get("platform_detected", True):
        return "skipped"
    if run_row is None:
        if envelope is not None:
            return "ok"
        return "skipped"
    exit_code = run_row.get("exit_code")
    if exit_code is None:
        return "error"
    return "ok" if exit_code == 0 else "error"


def _duration_sec(run_row: dict[str, Any] | None) -> str:
    if not run_row:
        return "unknown"
    started = run_row.get("started_at", "")
    ended = run_row.get("ended_at", "")
    if not started or not ended:
        return "unknown"
    try:
        t0 = datetime.fromisoformat(str(started))
        t1 = datetime.fromisoformat(str(ended))
        elapsed = (t1 - t0).total_seconds()
        if 0 < elapsed < 1:
            return "<1s"
        secs = int(elapsed)
        if secs < 60:
            return f"{secs}s"
        return f"{secs // 60}m {secs % 60}s"
    except ValueError:
        return "unknown"


def _format_timestamp(value: Any) -> str:
    if not value:
        return "not recorded"
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        offset = dt.strftime("%z")
        suffix = f" {offset}" if offset else ""
        return dt.strftime("%Y-%m-%d %H:%M:%S") + suffix
    except ValueError:
        return str(value)


def aggregate_findings(envelopes: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for collector, env in envelopes.items():
        if collector == "discovery":
            continue
        for item in env.get("findings") or []:
            if not isinstance(item, dict):
                continue
            row = dict(item)
            row["_collector"] = collector
            if row.get("id") == "claude.permission.skip_dangerous_prompt":
                row["severity"] = "high"
                row["title"] = _display_finding_title(row)
                row["sample_redacted"] = "skipDangerousModePermissionPrompt=true"
            findings.append(row)
    findings.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(str(f.get("severity", "low")), 9),
            -(int(f.get("evidence_count") or 1)),
            str(f.get("title", "")),
        )
    )
    return findings


def severity_counts(findings: list[dict[str, Any]]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for f in findings:
        sev = str(f.get("severity", "low"))
        if sev in SEVERITY_ORDER:
            counts[sev] += 1
    return counts


CHAT_HISTORY_TOOL_KEYS = ("claude", "codex", "cursor", "cursor-composer", "grok", "copilot")


def _chat_per_tool_breakdown_exists(chat_sum: dict[str, Any]) -> bool:
    if not chat_sum:
        return False
    for key in ("sources", "by_tool", "per_tool"):
        val = chat_sum.get(key)
        if isinstance(val, dict) and val:
            return True
    return any(
        f"{tool}_messages" in chat_sum or f"{tool}_files" in chat_sum
        for tool in CHAT_HISTORY_TOOL_KEYS
    )


def _platform_chat_metric(chat_sum: dict[str, Any], platform_key: str, metric: str) -> int | None:
    """Per-platform chat metric from chat-history summary, or None if absent."""
    if platform_key == "cursor":
        cursor = chat_sum.get(f"cursor_{metric}")
        composer = chat_sum.get(f"cursor-composer_{metric}")
        if cursor is None and composer is None:
            return None
        return int(cursor or 0) + int(composer or 0)
    key = f"{platform_key}_{metric}"
    if key not in chat_sum:
        return None
    return int(chat_sum.get(key) or 0)


def _platform_chat_cell(chat_sum: dict[str, Any], platform_key: str) -> str:
    messages = _platform_chat_metric(chat_sum, platform_key, "messages")
    if messages is not None:
        return str(messages)
    files = _platform_chat_metric(chat_sum, platform_key, "files")
    if files is not None:
        return f"{files} files"
    return "-"


def _platform_active_time_cell(chat_sum: dict[str, Any], platform_key: str) -> str:
    minutes = _platform_chat_metric(chat_sum, platform_key, "active_minutes_estimated")
    if minutes is None:
        return "-"
    return _format_minutes_estimate(minutes)


def _approval_evidence_cell(
    platform: str,
    env: dict[str, Any] | None,
    allow_cnt: int,
    chat_sum: dict[str, Any] | None = None,
) -> str:
    if not env:
        return "-"
    summary = env.get("summary") or {}
    chat_sum = chat_sum or {}
    if platform == "claude":
        summary = env.get("summary") or {}
        if summary.get("otel_enabled"):
            return "OTEL configured"
        return "available via OTEL"
    events = int(summary.get("permission_events") or summary.get("approval_requests") or 0)
    if events:
        return str(events)
    if platform == "grok" and (
        str(summary.get("permission_mode") or "").lower() == "always-approve"
        or bool(summary.get("yolo"))
    ):
        return "bypassed"
    if platform == "claude" and allow_cnt:
        return "settings only"
    return "-"


def render_posture_grid(envelopes: dict[str, dict[str, Any]]) -> str:
    """Glanceable per-platform posture table (A6).

    Reads only summary + rules/findings. Graceful for missing evidence.
    """
    row_items: list[tuple[int, int, str]] = []
    chat_env = envelopes.get("chat-history") or {}
    chat_sum = chat_env.get("summary") or {}
    secrets_env = envelopes.get("secrets-scan") or {}
    secrets_summary = secrets_env.get("summary") or {}
    secrets_hits = int(secrets_summary.get("hits") or 0)
    secrets_targets = int(secrets_summary.get("targets") or 0)
    has_per_tool_chat = _chat_per_tool_breakdown_exists(chat_sum)
    chat_corpus_total = int(chat_sum.get("total_messages") or 0)

    for seq, key in enumerate(_visible_platform_collectors(envelopes)):
        label = TOOL_LABELS.get(key, key)
        env = envelopes.get(key)
        detected = bool(env and env.get("platform_detected", True)) if env is not None else False

        det_label = "yes" if detected else ("not collected" if env is None else "no")

        # highest-risk severity from findings, falling back to rule risk
        risk_flag = "none"
        risk_rank = 9
        if env:
            for f in (env.get("findings") or []):
                sev = str(f.get("severity", "low")).lower()
                if sev in SEVERITY_ORDER and SEVERITY_ORDER[sev] < risk_rank:
                    risk_rank, risk_flag = SEVERITY_ORDER[sev], sev
            for r in (env.get("rules") or []):
                rk = str(r.get("risk", "")).lower()
                if rk in SEVERITY_ORDER and SEVERITY_ORDER[rk] < risk_rank:
                    risk_rank, risk_flag = SEVERITY_ORDER[rk], rk

        # counts
        rules = [r for r in (env.get("rules") or []) if isinstance(r, dict)] if env else []
        allow_cnt = sum(
            1 for r in rules
            if r.get("decision") == "allow"
            and r.get("rule_type") != "mcp_tool"
            and r.get("source_kind") not in ("session_event", "session_prefix")
        )
        mcp_cnt = sum(1 for r in rules if r.get("rule_type") == "mcp_tool")
        approval_evidence = _approval_evidence_cell(key, env, allow_cnt, chat_sum)

        if has_per_tool_chat:
            chat_cell = _platform_chat_cell(chat_sum, key)
            active_cell = _platform_active_time_cell(chat_sum, key)
        else:
            chat_cell = "n/a"
            active_cell = "n/a"

        row_items.append((
            risk_rank, seq,
            f"<tr>"
            f"<td><strong>{_esc(label)}</strong></td>"
            f"<td>{det_label}</td>"
            f"<td>{_esc(risk_flag)}</td>"
            f"<td class='num'>{mcp_cnt}</td>"
            f"<td class='num'>{allow_cnt}</td>"
            f"<td class='num'>{_esc(approval_evidence)}</td>"
            f"<td class='num'>{chat_cell}</td>"
            f"<td class='num'>{_esc(active_cell)}</td>"
            f"</tr>"
        ))

    # Most severe platforms first; stable within equal risk.
    row_items.sort(key=lambda t: (t[0], t[1]))
    rows = [html for _, _, html in row_items]

    header = "<tr><th>Platform</th><th>Detected</th><th>Highest-risk</th><th>MCP rules</th><th>Stored allow rules</th><th>Approval evidence</th><th>Chat msgs</th><th>Active est.</th></tr>"
    caption_parts: list[str] = []
    caption_parts.append(
        "Stored allow rules are durable non-MCP permission entries. Approval evidence shows recorded prompt decisions when available. For Claude Code, local transcripts do not reliably distinguish a user-click accept from config, mode, or always-allow behavior; use OTEL tool_decision telemetry for click/source attribution."
    )
    if not has_per_tool_chat and chat_corpus_total:
        caption_parts.append(f"Chat corpus total: {chat_corpus_total} messages across all tools.")
    elif has_per_tool_chat and int(chat_sum.get("active_minutes_estimated") or 0):
        caption_parts.append(
            f"Active estimate total: {_format_minutes_estimate(int(chat_sum.get('active_minutes_estimated') or 0))} using a {int(chat_sum.get('active_gap_cap_minutes') or 30)}-minute capped-gap method."
        )
    if secrets_env:
        target_text = f" across {secrets_targets} targets" if secrets_targets else ""
        caption_parts.append(
            f"Secrets scan total: {secrets_hits} hits{target_text}; reported under Findings / Secrets Exposure."
        )
    caption = (
        f"<p class='posture-grid-caption'>{_esc(' '.join(caption_parts))}</p>"
        if caption_parts
        else ""
    )
    table = f"<table class='posture-grid'><thead>{header}</thead><tbody>{''.join(rows)}</tbody></table>{caption}"
    return table


def build_tools_table(
    envelopes: dict[str, dict[str, Any]],
    discovery: dict[str, Any] | None,
    runs: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return one row per scoped tool/collector with detection + status."""
    discovery_tools: dict[str, dict[str, Any]] = {}
    if discovery:
        summary = discovery.get("summary") or {}
        for item in summary.get("tools") or []:
            if isinstance(item, dict) and item.get("name"):
                discovery_tools[str(item["name"])] = item

    rows: list[dict[str, Any]] = []
    for key in PLATFORM_COLLECTORS:
        label = TOOL_LABELS.get(key, key)
        env = envelopes.get(key)
        disc = discovery_tools.get(key, {})
        detected = disc.get("detected")
        if detected is None:
            detected = bool(env and env.get("platform_detected"))
        if key == "copilot" and not detected:
            continue
        version = disc.get("version") or (env or {}).get("summary", {}).get("version", "unknown")
        if version == "unknown" and env:
            version = env.get("version", "unknown")
        last_used = disc.get("last_used") or disc.get("last_seen") or "unknown"
        status = collector_status(key, env, runs.get(key))
        if not detected:
            status = "skipped"
        # Per-tool evidence summary for cover-cell stats.
        extra = ""
        if env and detected:
            rules = env.get("rules") or []
            summary = env.get("summary") or {}
            permission_events = int(summary.get("permission_events") or summary.get("approval_requests") or 0)
            findings_n = len(env.get("findings") or [])
            if rules:
                extra = f"{len(rules)} permission rules"
            elif permission_events:
                extra = f"{permission_events} approval events"
            elif findings_n:
                extra = f"{findings_n} posture findings"
            elif key == "cursor":
                extra = "local state found"
            elif key == "grok":
                extra = "session metadata found"
            elif key == "copilot":
                extra = "settings found"
        rows.append(
            {
                "tool": label,
                "key": key,
                "detected": detected,
                "version": version if detected else "Tool not detected",
                "last_used": last_used if detected else "n/a",
                "status": status,
                "extra": extra,
            }
        )

    for key in ("chat-history", "secrets-scan", "git-posture"):
        env = envelopes.get(key)
        if not env:
            continue
        summary = env.get("summary") or {}
        # Per-collector extra count
        extra = ""
        if key == "chat-history":
            messages = int(summary.get("total_messages") or 0)
            files = int(summary.get("total_files") or 0)
            if messages:
                extra = f"{messages} chat messages"
            elif files:
                extra = f"{files} transcript files"
        elif key == "secrets-scan":
            n = int(summary.get("hits") or 0)
            extra = f"{n} secret hits" if n else ""
        elif key == "git-posture":
            n = int(summary.get("repos_scanned") or 0)
            extra = f"{n} git repos" if n else ""
        rows.append(
            {
                "tool": TOOL_LABELS.get(key, key),
                "key": key,
                "detected": bool(env.get("platform_detected", True)),
                "version": env.get("version", "unknown"),
                "last_used": (env.get("ran_at") or "")[:10] or "unknown",
                "status": collector_status(key, env, runs.get(key)),
                "extra": extra,
            }
        )
    return rows


def engagement_dates(evidence_root: Path, envelopes: dict[str, dict[str, Any]]) -> str:
    meta = read_frontmatter(evidence_root)
    start = meta.get("engagement_start", "")
    if start:
        start_date = start[:10]
    else:
        ran_times = [str(e.get("ran_at", ""))[:10] for e in envelopes.values() if e.get("ran_at")]
        start_date = min(ran_times) if ran_times else "unknown"
    end_times = [str(e.get("ran_at", ""))[:10] for e in envelopes.values() if e.get("ran_at")]
    end_date = max(end_times) if end_times else start_date
    if start_date == end_date:
        return start_date
    return f"{start_date} to {end_date}"


def detected_tool_names(
    envelopes: dict[str, dict[str, Any]],
    tools_rows: list[dict[str, Any]],
) -> list[str]:
    platform_labels = {TOOL_LABELS[k] for k in _visible_platform_collectors(envelopes)}
    names: list[str] = []
    for row in tools_rows:
        if row["detected"] and row["tool"] in platform_labels:
            names.append(row["tool"])
    if not names:
        for key in _visible_platform_collectors(envelopes):
            env = envelopes.get(key)
            if env and env.get("platform_detected"):
                names.append(TOOL_LABELS[key])
    return names


# ─────────────────────────────────────────────────────────────────────────────
# Hero / cover renderers
# ─────────────────────────────────────────────────────────────────────────────


def render_hero_lede(tool_names: list[str], counts: Counter[str]) -> str:
    n_tools = len(tool_names)
    crit = counts.get("critical", 0)
    high = counts.get("high", 0)

    if n_tools == 0:
        tool_part = "No coding agents were detected on this endpoint."
    elif n_tools == 1:
        tool_part = f"{tool_names[0]} is in use on the endpoint."
    else:
        n_word = {2: "Two", 3: "Three", 4: "Four"}.get(n_tools, str(n_tools))
        tool_part = f"{n_word} coding agents are in use on the endpoint."

    if crit:
        sev_part = (
            f"{crit} critical finding{'s' if crit != 1 else ''} need"
            f"{'' if crit != 1 else 's'} action this week."
        )
    elif high:
        sev_part = f"{high} high-severity findings need review."
    else:
        sev_part = "No critical findings — routine posture work only."

    return f"{tool_part} {sev_part}"


def render_executive_headline(counts: Counter[str]) -> str:
    total = sum(counts.values())
    crit = counts.get("critical", 0)
    high = counts.get("high", 0)
    if crit:
        return (
            f"{total} findings. "
            f"{crit} require{'s' if crit == 1 else ''} action this week."
        )
    if high:
        return f"{total} findings. {high} high-severity items to review."
    return f"{total} findings recorded. No critical exposure."


def render_executive_sub(envelopes: dict[str, dict[str, Any]], counts: Counter[str]) -> str:
    crit = counts.get("critical", 0)
    detected = [TOOL_LABELS[k] for k in _visible_platform_collectors(envelopes)
                if envelopes.get(k) and envelopes[k].get("platform_detected")]
    detected_list = ", ".join(detected[:-1]) + (" and " + detected[-1] if len(detected) > 1 else (detected[0] if detected else ""))
    if not detected_list:
        detected_list = "No coding agents"
    if crit:
        return (
            f"{detected_list} are in active use. The items below represent durable secret "
            f"exposure, persistent permission state with no prompt, and runtime configuration "
            f"that bypasses sandboxing."
        )
    return f"{detected_list} are in active use. Posture is largely clean — review the medium-tier items below."


def _tool_last_used(key: str, envelopes: dict[str, dict[str, Any]]) -> str:
    """Newest activity date for a tool, from chat-history's discovery block
    (per-data-path `newest` mtimes) or the tool's own summary."""
    disc = ((envelopes.get("chat-history") or {}).get("summary") or {}).get("discovery") or {}

    def newest(*names: str) -> str:
        return max(((disc.get(n) or {}).get("newest") or "" for n in names), default="")

    if key == "claude":
        return newest("claude_projects")
    if key == "codex":
        return newest("codex_sessions")
    if key == "cursor":
        return newest("cursor_projects", "cursor_db")
    if key == "grok":
        return newest("grok_sessions")
    if key == "cowork":
        return str(((envelopes.get(key) or {}).get("summary") or {}).get("newest_session") or "")
    return ""


def render_cover_status(
    envelopes: dict[str, dict[str, Any]],
    runs_map: dict[str, dict[str, Any]],
    counts: Counter[str],
) -> str:
    """Cover-right evidence status panel."""
    rows: list[tuple[str, str, str, str]] = []
    detected_tools = 0
    not_detected = 0

    for key in PLATFORM_COLLECTORS:
        env = envelopes.get(key)
        label = TOOL_LABELS.get(key, key)
        if not _is_detected(env):
            not_detected += 1
            rows.append((label, "not detected", "-", "-"))
            continue
        detected_tools += 1
        run = runs_map.get(key)
        dur = _duration_sec(run) if run else ""
        duration = dur if dur and dur != "unknown" else "-"
        rows.append((label, "detected", duration, _tool_last_used(key, envelopes) or "unknown"))

    # Claude Design is not a collector; its usage signal rides in the cowork
    # summary (design window file presence + last-open date).
    cowork_summary = (envelopes.get("cowork") or {}).get("summary") or {}
    if cowork_summary.get("design_used"):
        detected_tools += 1
        rows.append((
            "Claude Design",
            "detected",
            "-",
            cowork_summary.get("last_design_activity") or "unknown",
        ))

    crit = counts.get("critical", 0)
    high = counts.get("high", 0)
    med = counts.get("medium", 0)
    low = counts.get("low", 0)
    row_html = []
    for name, status, measure, detail in rows:
        status_class = "ok" if status in ("detected", "collected") else "muted"
        row_html.append(
            f"<tr><td><span class='status-dot {status_class}'></span>{_esc(name)}</td>"
            f"<td>{_esc(status)}</td>"
            f"<td>{_esc(measure)}</td>"
            f"<td>{_esc(detail)}</td></tr>"
        )

    return f"""      <div class="evidence-panel-body">
        <div class="evidence-metrics">
          <div><span>Detected tools</span><strong>{detected_tools}</strong></div>
          <div><span>Not detected</span><strong>{not_detected}</strong></div>
          <div><span>Findings</span><strong>{sum(counts.values())}</strong></div>
        </div>
        <div class="severity-inline">
          <span class="critical">critical {crit}</span>
          <span>high {high}</span>
          <span>medium {med}</span>
          <span>low {low}</span>
        </div>
        <table class="evidence-status-table">
          <thead><tr><th>Tool</th><th>Status</th><th>Duration</th><th>Last used</th></tr></thead>
          <tbody>{''.join(row_html)}</tbody>
        </table>
      </div>"""


def render_cover_terminal(
    envelopes: dict[str, dict[str, Any]],
    runs_map: dict[str, dict[str, Any]],
    customer: str,
    counts: Counter[str],
) -> str:
    """Cover-right terminal block. Whitespace preserved via <pre>."""
    lines: list[str] = []
    lines.append(
        f'<span class="pfx">$</span> .\\aiscan.ps1 all -Briefing'
        + (f' -Customer "{_esc(customer)}"' if customer and customer != "Unknown customer" else "")
    )

    rows: list[tuple[str, str, str]] = []  # (status_cls, name, note)

    # discover
    disc = envelopes.get("discovery")
    if disc:
        tools_n = len(disc.get("summary", {}).get("tools") or [])
        caps = disc.get("summary", {}).get("capabilities") or {}
        missing = sorted(k for k, v in caps.items() if not v)
        suffix = f" · {missing[0]}: missing" if missing else ""
        rows.append(("ok", "discover", f"{tools_n} collectors{suffix}" if tools_n else f"preflight only{suffix}"))

    # platform collectors
    for key in PLATFORM_COLLECTORS:
        env = envelopes.get(key)
        if not env or not env.get("platform_detected", True):
            rows.append(("com", key, "not detected"))
            continue
        rules_n = len(env.get("rules") or [])
        run = runs_map.get(key)
        dur = _duration_sec(run) if run else ""
        if rules_n:
            note = f"{rules_n} permission rules"
        elif dur and dur != "unknown":
            note = f"ran in {dur}"
        else:
            note = "local data found"
        rows.append(("ok", key, note))

    # chat-history
    env = envelopes.get("chat-history")
    if env:
        s = env.get("summary") or {}
        files = int(s.get("total_files") or 0)
        hits = int(s.get("secret_hit_files") or 0)
        rows.append(("ok", "chat", f"{files} transcript files; {hits} secret hit{'s' if hits != 1 else ''}"))

    # git-posture
    env = envelopes.get("git-posture")
    if env:
        s = env.get("summary") or {}
        repos = int(s.get("repos_scanned") or 0)
        rows.append(("ok", "git-posture", f"{repos} repos"))

    # secrets-scan
    env = envelopes.get("secrets-scan")
    if env:
        s = env.get("summary") or {}
        hits = int(s.get("hits") or 0)
        scanner = str(s.get("scanner") or "gitleaks")
        rows.append(("ok", "secrets", f"{scanner} · {hits} hits"))

    max_name = max((len(name) for _, name, _ in rows), default=0) + 1
    for status_cls, name, note in rows:
        icon = "✓" if status_cls == "ok" else "—"
        icon_cls = "ok" if status_cls == "ok" else "com"
        padded = name.ljust(max_name)
        lines.append(
            f'<span class="{icon_cls}">{icon}</span> {_esc(padded)}<span class="com">{_esc(note)}</span>'
        )

    lines.append("")
    lines.append('<span class="pfx">$</span> build-briefing.py')

    crit = counts.get("critical", 0)
    high = counts.get("high", 0)
    med = counts.get("medium", 0)
    low = counts.get("low", 0)
    sev_line = '<span class="acc">[severity]</span> '
    if crit:
        sev_line += f'<span class="red">crit:{crit}</span> · '
    else:
        sev_line += f'crit:{crit} · '
    sev_line += f'<span class="acc">high:{high}</span> · med:{med} · low:{low}'
    lines.append(sev_line)

    lines.append("")
    lines.append('<span class="pfx">$</span> <span class="term-cursor"></span>')

    body = "\n".join(lines)
    return (
        '<pre style="margin:0;font-family:var(--f-mono);'
        'font-size:12.5px;line-height:1.7;white-space:pre;color:var(--fg-2)">'
        f"{body}"
        "</pre>"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Severity strip + bar
# ─────────────────────────────────────────────────────────────────────────────


def render_severity_bar_segments(counts: Counter[str]) -> str:
    """Horizontal stacked bar — flex segments proportional to count."""
    out = []
    for sev, cls in (("critical", "crit"), ("high", "high"), ("medium", "med"), ("low", "low")):
        n = counts.get(sev, 0)
        if n <= 0:
            continue
        label = sev.upper()[:4] if sev != "medium" else "MED"
        out.append(
            f'        <div class="{cls}" style="flex: {n};">'
            f'<span class="n">{n}</span><span>{label}</span></div>'
        )
    return "\n".join(out) if out else (
        '        <div class="low" style="flex: 1;">'
        '<span class="n">0</span><span>NONE</span></div>'
    )


def render_severity_bar_note(counts: Counter[str], envelopes: dict[str, dict[str, Any]]) -> str:
    """Right-side annotation on the severity bar (e.g., gitleaks aggregation note)."""
    high = counts.get("high", 0)
    sec_env = envelopes.get("secrets-scan")
    gitleaks_hits = 0
    if sec_env:
        gitleaks_hits = int((sec_env.get("summary") or {}).get("hits") or 0)
    if high and gitleaks_hits and gitleaks_hits <= high:
        return f"{gitleaks_hits} / {high} high are gitleaks hits · grouped in appendix"
    return "see appendix for grouped evidence index"


# ─────────────────────────────────────────────────────────────────────────────
# Risk register (top critical findings as cases)
# ─────────────────────────────────────────────────────────────────────────────


def render_risk_register(findings: list[dict[str, Any]]) -> str:
    """Numbered case cards for the critical findings (all of them, so the count
    reconciles with the executive strip). When there are none, preview up to 4
    high-severity findings instead."""
    crits = [f for f in findings if str(f.get("severity")) == "critical"]
    pool = crits if crits else [f for f in findings if str(f.get("severity")) == "high"][:4]
    if not pool:
        return (
            '<article class="case">'
            '<p class="case-summary">No critical or high-severity findings recorded.</p>'
            "</article>"
        )

    # Group findings that are the same issue into one card with the affected
    # targets listed, instead of N near-identical cards. First-seen order.
    # Default key is the rule id; a few cross-tool classes (MCP config secrets)
    # collapse across differing ids into one canonical issue.
    CANON_TITLES = {"mcp.config_secret": "MCP server config contains secrets"}

    def _group_key(f: dict[str, Any]) -> str:
        fid = str(f.get("id") or "")
        if ".mcp." in fid and "secret" in fid:
            return "mcp.config_secret"
        return fid or str(f.get("title") or id(f))

    groups: dict[str, list[dict[str, Any]]] = {}
    for f in pool:
        groups.setdefault(_group_key(f), []).append(f)

    chunks: list[str] = []
    # Reconciliation caption when grouping collapsed anything, so the card count
    # is explained against the severity-strip finding count.
    if len(groups) != len(pool):
        sev0 = str(pool[0].get("severity", "critical"))
        n_issue = len(groups)
        chunks.append(
            f'<p class="cases-caption">{len(pool)} {sev0} finding'
            f'{"s" if len(pool) != 1 else ""} across {n_issue} issue'
            f'{"s" if n_issue != 1 else ""}.</p>'
        )

    for i, (gkey, members) in enumerate(groups.items(), start=1):
        f = members[0]
        occurrences = len(members)
        sev = str(f.get("severity", "low"))
        sev_label = sev.upper()
        category = str(f.get("category", "General"))
        title = CANON_TITLES.get(gkey, str(f.get("title", "")))
        sample = _display_redaction_tokens(f.get("sample_redacted") or "")

        # Per-member rows: (target, evidence ref). Target is the member's sample,
        # or its own title + tool when the sample is secret-suppressed.
        member_rows: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for m in members:
            loc = _display_redaction_tokens(m.get("sample_redacted") or "").strip()
            if not loc:
                mt = str(m.get("title", ""))
                mc = str(m.get("_collector", ""))
                # Trim the boilerplate the group's canonical title already carries.
                if mt.startswith("MCP server "):
                    mt = mt[len("MCP server "):]
                for suf in (" contains secrets", " contain secrets",
                            " contains secret", " contain secret"):
                    if mt.endswith(suf):
                        mt = mt[: -len(suf)]
                        break
                loc = f"{mt} ({mc})" if mc else mt
            if loc.startswith("project:"):
                loc = loc[len("project:"):]
            mref = str(m.get("raw_evidence_ref")
                       or (f"evidence/{m.get('_collector')}.json" if m.get("_collector") else ""))
            row = (loc, mref)
            if loc and row not in seen:
                seen.add(row)
                member_rows.append(row)

        # Column noun for the target, tuned to the group.
        if gkey == "mcp.config_secret":
            target_noun = "Server"
        elif "git" in category.lower():
            target_noun = "Project"
        else:
            target_noun = "Target"

        meta_parts = [category]
        if occurrences == 1 and f.get("_collector"):
            meta_parts.append(f"collector: {f.get('_collector')}")
        meta_html = "<span class='dot-sep'>·</span>".join(
            f"<span>{_esc(p)}</span>" for p in meta_parts
        )

        # A single finding shows its sample as a summary line; a group lists its
        # targets in a per-row table instead.
        if occurrences > 1:
            summary_text = ""
        elif sample and len(sample) < 220:
            summary_text = sample
        else:
            summary_text = f"Flagged under {category}."

        status_cls = "is-crit" if sev == "critical" else "is-active"
        tag_cls = "crit" if sev == "critical" else "high"
        tag_id = f"{sev_label[:4]}-{i:02d}"
        occ_tag = f'\n      <span class="tag {tag_cls}">×{occurrences}</span>' if occurrences > 1 else ""
        summary_html = f"\n  <p class=\"case-summary\">{_esc(summary_text)}</p>" if summary_text else ""

        if occurrences > 1:
            rows_html = "".join(
                f"<tr><td>{_esc(t)}</td><td class='mono'>{_esc(r) if r else 'n/a'}</td></tr>"
                for (t, r) in member_rows
            )
            detail_html = (
                '  <table class="case-rows">\n'
                f"    <thead><tr><th>{_esc(target_noun)}</th><th>Evidence</th></tr></thead>\n"
                f"    <tbody>{rows_html}</tbody>\n"
                "  </table>"
            )
        else:
            single_ref = member_rows[0][1] if member_rows else ""
            evn = int(f.get("evidence_count") or 1)
            detail_html = f"""  <div class="case-grid">
    <div>
      <div class="case-lbl">Category</div>
      <p>{_esc(category)}</p>
    </div>
    <div>
      <div class="case-lbl">Evidence count</div>
      <p>{evn} row{'s' if evn != 1 else ''}</p>
    </div>
    <div>
      <div class="case-lbl">Reference</div>
      <p class="mono">{_esc(single_ref) if single_ref else 'n/a'}</p>
    </div>
  </div>"""

        chunks.append(f"""<article class="case">
  <div class="case-head">
    <div class="case-num">/{i:02d}</div>
    <div>
      <h3 class="case-title">{_esc(title)}</h3>
      <div class="case-meta">{meta_html}</div>
    </div>
    <div class="status {status_cls}"><span class="status-dot"></span>{_esc(sev)}</div>
  </div>{summary_html}
{detail_html}
  <div class="case-foot">
    <div class="tags">
      <span class="tag {tag_cls}">{_esc(tag_id)}</span>
      <span class="tag">{_esc(category.lower())}</span>{occ_tag}
    </div>
  </div>
</article>""")
    return "\n".join(chunks)


# ─────────────────────────────────────────────────────────────────────────────
# Tools coverage cells
# ─────────────────────────────────────────────────────────────────────────────


def render_coverage_cells(rows: list[dict[str, Any]]) -> str:
    cells: list[str] = []
    for row in rows:
        skipped_cls = " skipped" if not row["detected"] else ""
        det_text = "Detected" if row["detected"] else "Not detected"
        det_cls = "" if row["detected"] else " no"
        status = row["status"]
        status_label = {"ok": "ok", "skipped": "skipped", "error": "error"}.get(status, status)
        if row.get("extra"):
            extra = row["extra"]
        elif not row["detected"]:
            extra = "no local data found"
        elif status == "error":
            extra = "collector error"
        else:
            extra = "local evidence found"
        cells.append(f"""      <div class="cell{skipped_cls}">
        <div class="name">{_esc(row['tool'].lower())}</div>
        <div class="det{det_cls}">{_esc(det_text)}</div>
        <span class="pill {status}">{_esc(status_label)}</span>
        <div class="evidence-label">found</div>
        <div class="ct">{_esc(extra)}</div>
      </div>""")
    return "\n".join(cells)


def render_collection_scope(rows: list[dict[str, Any]]) -> str:
    visible = [row for row in rows if row.get("detected")]
    if not visible:
        return ""
    row_html: list[str] = []
    for row in visible:
        status = str(row.get("status") or "ok")
        status_label = {"ok": "collected", "error": "error", "skipped": "skipped"}.get(status, status)
        evidence = str(row.get("extra") or "local evidence found")
        row_html.append(
            f"<tr><td><strong>{_esc(row.get('tool', ''))}</strong></td>"
            f"<td>{_esc(status_label)}</td>"
            f"<td>{_esc(str(row.get('version') or 'unknown'))}</td>"
            f"<td>{_esc(evidence)}</td></tr>"
        )
    return f"""    <div class="collection-scope">
      <div class="collection-scope-head">
        <h3>Collection scope</h3>
        <p>{len(visible)} collectors produced local evidence. Completion times are in Methodology.</p>
      </div>
      <table>
        <thead><tr><th>Collector</th><th>Status</th><th>Version</th><th>Evidence volume</th></tr></thead>
        <tbody>{''.join(row_html)}</tbody>
      </table>
    </div>"""


def render_tools_sub(rows: list[dict[str, Any]]) -> str:
    n_collectors = sum(1 for r in rows if r["status"] in ("ok", "error"))
    not_detected = [r["tool"] for r in rows if not r["detected"]]
    parts = [
        f"{n_collectors} collector{'s' if n_collectors != 1 else ''} ran against this endpoint.",
        "Each tile shows whether local tool data was found and the primary evidence volume collected.",
        "Collector versions are listed in Methodology."
    ]
    if not_detected:
        if len(not_detected) == 1:
            parts.append(f"{not_detected[0]} was not detected.")
        else:
            parts.append(f"Not detected: {', '.join(not_detected)}.")
    return " ".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# Findings (tabs + panels)
# ─────────────────────────────────────────────────────────────────────────────


def _finding_search_blob(f: dict[str, Any]) -> str:
    tags = " ".join(f.get("tags") or [])
    return " ".join(
        [
            str(f.get("title", "")),
            _display_redaction_tokens(f.get("sample_redacted", "")),
            tags,
            str(f.get("category", "")),
        ]
    ).lower()


def render_findings_section(findings: list[dict[str, Any]]) -> tuple[str, str]:
    by_category: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in findings:
        cat = str(f.get("category") or "General Tooling")
        by_category[cat].append(f)

    categories = [c for c in EXPOSURE_CATEGORIES if c in by_category]
    for cat in sorted(by_category.keys()):
        if cat not in categories:
            categories.append(cat)

    if not categories:
        return "", '<div class="panel"><p>No findings recorded.</p></div>'

    tabs = []
    panels = []
    for idx, cat in enumerate(categories):
        slug = re.sub(r"[^a-z0-9]+", "-", cat.lower()).strip("-")
        active = " active" if idx == 0 else ""
        count = len(by_category[cat])
        tabs.append(
            f'<button type="button" class="tab-btn{active}" data-tab="{slug}">'
            f'{_esc(cat)}<span class="ct">{count}</span></button>'
        )
        rows = []
        for f in by_category[cat]:
            sev = _esc(f.get("severity", "low"))
            blob = _esc(_finding_search_blob(f))
            sample = _display_redaction_tokens(f.get("sample_redacted") or "")
            sample_html = f"<code>{_esc(sample)}</code>" if sample else "<span class='mono' style='color:var(--fg-4)'>n/a</span>"
            last_seen = (f.get("last_seen") or "")[:10] or "n/a"
            rows.append(
                f'<tr class="frow" data-search="{blob}">'
                f'<td><span class="pill {sev}">{sev}</span></td>'
                f"<td>{_esc(f.get('title', ''))}</td>"
                f"<td class='num'>{int(f.get('evidence_count') or 1)}</td>"
                f"<td class='mono'>{_esc(last_seen)}</td>"
                f"<td>{sample_html}</td>"
                f"</tr>"
            )
        panels.append(
            f'<div class="tab-panel{active}" data-tab="{slug}">'
            f'<div class="table-wrap"><table>'
            f'<thead><tr><th style="width:90px">Severity</th><th>Title</th>'
            f'<th style="width:90px">Evidence</th><th style="width:110px">Last seen</th>'
            f"<th>Sample</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></div></div>"
        )
    return "\n".join(tabs), "\n".join(panels)


# ─────────────────────────────────────────────────────────────────────────────
# Permissions (per-platform: stat strip + rule group)
# ─────────────────────────────────────────────────────────────────────────────


def _rule_display(rule: dict[str, Any]) -> str:
    text = rule.get("rule") or rule.get("command_or_tool_redacted") or ""
    if text.startswith("Bash(") and text.endswith(")"):
        return _prefix_rule_display(rule, _compact_command_text(text[5:-1]))
    if text.startswith("PowerShell(") and text.endswith(")"):
        return _prefix_rule_display(rule, _compact_command_text(text[11:-1]))
    if text.startswith("[") and text.endswith("]"):
        try:
            parsed = ast.literal_eval(text)
        except (SyntaxError, ValueError):
            parsed = None
        if isinstance(parsed, list):
            parts = [str(part) for part in parsed if part not in (None, "")]
            if parts:
                return _prefix_rule_display(rule, _compact_command_text(" ".join(parts)))
    return _prefix_rule_display(rule, _compact_command_text(str(text)))


def _prefix_rule_display(rule: dict[str, Any], text: str) -> str:
    if rule.get("source_kind") not in ("session_event", "session_prefix"):
        return text
    if not text or text.endswith("*"):
        return text
    return f"{text} *"


def _compact_command_text(text: str, limit: int = 180) -> str:
    compact = str(text).replace("\\\\", "\\").strip()
    home = str(Path.home())
    if home:
        compact = compact.replace(home, "%USERPROFILE%")
    compact = re.sub(
        r"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1\.0\\powershell\.exe",
        "powershell.exe",
        compact,
        flags=re.I,
    )
    compact = re.sub(
        r"^<path#[0-9a-f]+>\s+-Command\b",
        "powershell.exe -Command",
        compact,
        flags=re.I,
    )
    compact = re.sub(
        r"%USERPROFILE%\\\.cache\\codex-runtimes\\\S*?\\node\\bin\\node(?:\.exe)?",
        "node.exe",
        compact,
        flags=re.I,
    )
    compact = re.sub(r"\s+", " ", compact)
    if len(compact) > limit:
        return compact[: limit - 3].rstrip() + "..."
    return compact


def _scope_list_items(
    rules: list[dict[str, Any]],
    limit: int = 16,
    trim_scope_prefix: bool = False,
) -> tuple[str, int]:
    labels = set()
    for rule in rules:
        label = _scope_label_display(
            str(rule.get("scope", "")),
            str(rule.get("scope_label_redacted", "")),
        )
        if trim_scope_prefix:
            label = re.sub(r"^(user|project|workspace):", "", label)
        labels.add(label)
    labels = sorted(labels)
    labels = [label for label in labels if label]
    shown = labels[:limit]
    return "".join(f"<li><code>{_esc(label)}</code></li>" for label in shown), max(0, len(labels) - len(shown))


def _render_codex_allow_rules_summary(platform: str, rules: list[dict[str, Any]]) -> str:
    allow_rules = [
        r for r in rules
        if r.get("decision") == "allow" and r.get("rule_type") != "mcp_tool"
    ]
    if not allow_rules:
        return ""

    trusted_rules = [r for r in allow_rules if str(r.get("rule")) == "trust_level=trusted"]
    session_rules = [
        r for r in allow_rules
        if r.get("source_kind") in ("session_event", "session_prefix")
    ]
    other_config_rules = [
        r for r in allow_rules
        if r not in trusted_rules and r not in session_rules
    ]

    cards: list[str] = []
    if trusted_rules:
        trust_lis, trust_overflow = _scope_list_items(trusted_rules, limit=18, trim_scope_prefix=True)
        more = f" +{trust_overflow} more" if trust_overflow else ""
        cards.append(f"""        <div class="codex-surface-card">
          <div class="allow-source-head">
            <h5>Trusted project workspaces</h5>
            <span>{len(trusted_rules)} entries - config.toml</span>
          </div>
          <p class="surface-note">Configured Codex projects with <code>trust_level=trusted</code>. This records workspace trust, not blanket command approval.</p>
          <ul class="rule-list compact">{trust_lis}</ul>
          <div class="more">evidence/{platform}.json{_esc(more)}</div>
        </div>""")

    if session_rules:
        by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for rule in session_rules:
            by_source[_rule_source_label(rule)].append(rule)
        session_blocks: list[str] = []
        for source, items in sorted(by_source.items(), key=lambda item: item[0].lower()):
            commands = sorted({_rule_display(r) for r in items if _rule_display(r)})
            shown = commands[:12]
            overflow = len(commands) - len(shown)
            command_lis = "".join(f"<li><code>{_esc(command)}</code></li>" for command in shown)
            more_parts = []
            if overflow > 0:
                more_parts.append(f"+{overflow} more")
            more_parts.append(f"{len(items)} entries")
            session_blocks.append(f"""            <div class="rule-subgroup">
              <div class="rule-subgroup-head"><h5>{_esc(source)}</h5><span>{_esc(' - '.join(more_parts))}</span></div>
              <ul class="rule-list compact">{command_lis}</ul>
            </div>""")
        cards.append(f"""        <div class="codex-surface-card">
          <div class="allow-source-head">
            <h5>Previously approved command prefixes</h5>
            <span>{len(session_rules)} entries - session history</span>
          </div>
          <p class="surface-note">Command prefixes observed in approval history or session snapshots. These show what has been permitted before; they are separate from project trust and MCP registration.</p>
          {''.join(session_blocks)}
          <div class="more">evidence/{platform}.json</div>
        </div>""")

    if other_config_rules:
        commands = sorted({_rule_display(r) for r in other_config_rules if _rule_display(r)})
        command_lis = "".join(f"<li><code>{_esc(command)}</code></li>" for command in commands[:12])
        overflow = max(0, len(commands) - 12)
        more = f" +{overflow} more" if overflow else ""
        cards.append(f"""        <div class="codex-surface-card">
          <div class="allow-source-head">
            <h5>Other config grants</h5>
            <span>{len(other_config_rules)} entries - config.toml</span>
          </div>
          <ul class="rule-list compact">{command_lis}</ul>
          <div class="more">evidence/{platform}.json{_esc(more)}</div>
        </div>""")

    return f"""<div class="allow-summary">
        <div class="rule-group-head">
          <h4>Codex permission surface</h4>
          <span class="meta">{len(allow_rules)} non-MCP entries</span>
        </div>
        <div class="codex-surface-grid">{''.join(cards)}</div>
      </div>"""


def _mcp_rule_parts(rule: dict[str, Any]) -> tuple[str, str | None]:
    text = str(rule.get("rule") or rule.get("command_or_tool_redacted") or "")
    if text.startswith("mcp__"):
        parts = text.split("__")
        server = parts[1] if len(parts) > 1 and parts[1] else text
        tool = parts[2] if len(parts) > 2 and parts[2] else None
        return server, tool
    return text, None


def _rule_source_label(rule: dict[str, Any]) -> str:
    settings_source = str(rule.get("settings_source") or "").strip()
    if settings_source:
        return settings_source
    source_kind = str(rule.get("source_kind") or "").strip()
    labels = {
        "user_config": "user config",
        "project_config": "project config",
        "session_event": "approval prompts",
        "session_prefix": "approved-prefix snapshot",
    }
    return labels.get(source_kind, "-")


def _mcp_scope_display(rule: dict[str, Any]) -> str:
    """Human scope for MCP table rows. Prefer settings_source over opaque IDs."""
    src = _rule_source_label(rule)
    by_source = {
        "shared mcp.json": "user (shared)",
        "user mcp.json": "user",
        "appdata mcp.json": "user (appdata)",
        "project mcp.json": "project",
        "state.vscdb approvedProjectMcpServers": "project approval",
        "state.vscdb knownServerIds": "runtime known",
        "events.jsonl mcp_config_resolved": "runtime",
        "config.toml mcp_servers": "user config",
        "config.toml permission": "user config",
        "project config.toml": "project",
    }
    if src in by_source:
        return by_source[src]
    scope = _scope_label_display(
        str(rule.get("scope", "")),
        str(rule.get("scope_label_redacted", "")),
    )
    return scope or "unknown scope"


def _render_mcp_summary(platform: str, rules: list[dict[str, Any]]) -> str:
    mcp_rules = [r for r in rules if r.get("rule_type") == "mcp_tool"]
    if not mcp_rules:
        return ""

    server_rows: dict[tuple[str, str], dict[str, Any]] = {}
    any_tools = False
    for rule in mcp_rules:
        server, tool = _mcp_rule_parts(rule)
        scope = _mcp_scope_display(rule)
        info = server_rows.setdefault(
            (server, scope),
            {
                "tools": set(),
                "registered": 0,
                "sources": set(),
            },
        )
        if tool:
            info["tools"].add(tool)
            any_tools = True
        else:
            info["registered"] += 1
        info["sources"].add(_rule_source_label(rule))

    rows = []
    unique_servers = {server for server, _scope in server_rows}
    for (server, scope), info in sorted(
        server_rows.items(),
        key=lambda item: (item[0][0].lower(), item[0][1].lower()),
    ):
        tool_count = len(info["tools"])
        registered = int(info["registered"])
        state_parts = []
        if tool_count:
            state_parts.append(f"{tool_count} explicit tool allow{'s' if tool_count != 1 else ''}")
        if registered:
            state_parts.append("server registered")
        state_text = " + ".join(state_parts) if state_parts else "recorded"
        sources = ", ".join(sorted(info["sources"]))
        tool_cell = (
            f"<td class='num'>{tool_count if tool_count else '-'}</td>"
            if any_tools
            else ""
        )
        rows.append(
            f"<tr><td><code>{_esc(server)}</code></td>"
            f"<td class='mono'>{_esc(scope)}</td>"
            f"{tool_cell}"
            f"<td>{_esc(state_text)}</td>"
            f"<td class='mono'>{_esc(sources)}</td>"
            f"</tr>"
        )

    tool_header = "<th>Explicit tool allows</th>" if any_tools else ""
    return f"""<div class="mcp-summary">
        <div class="rule-group-head">
          <h4>MCP servers and allowed tools</h4>
          <span class="meta">{len(unique_servers)} server{'s' if len(unique_servers) != 1 else ''} - {len(server_rows)} scoped row{'s' if len(server_rows) != 1 else ''}</span>
        </div>
        <table class="mcp-table">
          <thead><tr><th>Server</th><th>Scope</th>{tool_header}<th>Evidence</th><th>Source</th></tr></thead>
          <tbody>{''.join(rows)}</tbody>
        </table>
      </div>"""


def _render_allow_rules_summary(platform: str, rules: list[dict[str, Any]]) -> str:
    if platform == "codex":
        return _render_codex_allow_rules_summary(platform, rules)

    allow_rules = [
        r for r in rules
        if r.get("decision") == "allow" and r.get("rule_type") != "mcp_tool"
    ]
    if not allow_rules:
        return ""

    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for rule in allow_rules:
        scope = _scope_label_display(
            str(rule.get("scope", "")),
            str(rule.get("scope_label_redacted", "")),
        ) or "unknown scope"
        groups[(_rule_source_label(rule), scope)].append(rule)

    cards: list[str] = []
    for (source, scope), items in sorted(
        groups.items(),
        key=lambda item: (item[0][0].lower(), item[0][1].lower()),
    ):
        category_counts = Counter(str(r.get("exposure_category", "General Tooling")) for r in items)
        cat_html = "".join(
            f"<span>{_esc(cat)} <b>{count}</b></span>"
            for cat, count in category_counts.most_common()
        )
        commands = sorted({_rule_display(r) for r in items if _rule_display(r)})
        shown = commands[:12]
        overflow = len(commands) - len(shown)
        rule_lis = "".join(f"<li><code>{_esc(command)}</code></li>" for command in shown)
        more_parts = []
        if overflow > 0:
            more_parts.append(f"+{overflow} more")
        more_parts.append(f"evidence/{platform}.json")
        more_html = f"<div class='more'>{_esc(' - '.join(more_parts))}</div>"
        source_title = source if source != "-" else "Recorded source"
        cards.append(f"""        <div class="allow-source">
          <div class="allow-source-head">
            <h5>{_esc(source_title)}</h5>
            <span>{len(items)} allow rule{'s' if len(items) != 1 else ''} - {_esc(scope)}</span>
          </div>
          <div class="allow-cats">{cat_html}</div>
          <ul class="rule-list compact">{rule_lis}</ul>
          {more_html}
        </div>""")

    return f"""<div class="allow-summary">
        <div class="rule-group-head">
          <h4>Configured command allow rules</h4>
          <span class="meta">{len(allow_rules)} non-MCP allow rule{'s' if len(allow_rules) != 1 else ''}</span>
        </div>
        <div class="allow-source-grid">{''.join(cards)}</div>
      </div>"""


def _render_claude_mode_history(chat_sum: dict[str, Any]) -> str:
    mode_rows = [
        ("plan", "Plan mode"),
        ("auto", "Auto mode"),
        ("accept_edits", "Accept edits"),
        ("default", "Default"),
        ("bypass_permissions", "Bypass permissions"),
    ]
    cells: list[str] = []
    for key, label in mode_rows:
        count = int(chat_sum.get(f"claude_permission_mode_{key}") or 0)
        if count:
            cells.append(
                f"<div class='mode-chip'><span>{_esc(label)}</span><strong>{count}</strong></div>"
            )

    permission_responses = int(
        chat_sum.get("claude_granted_permission_responses")
        or chat_sum.get("claude_approval_events")
        or 0
    )
    if permission_responses:
        cells.append(
            f"<div class='mode-chip'><span>Granted permission responses</span><strong>{permission_responses}</strong></div>"
        )

    total = int(chat_sum.get("claude_permission_mode_events_total") or 0)
    if not cells and not total:
        return ""

    meta = f"{total} mode-tagged event{'s' if total != 1 else ''} - chat-history evidence"
    return f"""<div class="mode-summary">
        <div class="rule-group-head">
          <h4>Claude mode history</h4>
          <span class="meta">{_esc(meta)}</span>
        </div>
        <p class="surface-note">Mode tags are observed Claude session states in JSONL history. Local transcripts do not provide a reliable approval-click audit trail; use Claude Code OTEL <code>tool_decision</code> telemetry to distinguish user-click accepts, rejections, and config-rule decisions.</p>
        <div class="mode-grid">{''.join(cells)}</div>
      </div>"""


def _render_telemetry_summary(platform: str, summary: dict[str, Any]) -> str:
    """Telemetry-export card: what the tool's local config says it sends where."""
    if platform == "codex":
        if not summary.get("otel_log_user_prompt_configured"):
            return ""
        title = "Codex telemetry export"
        dest = str(summary.get("otel_exporter_destination") or "").strip()
        protocol = str(summary.get("otel_exporter_protocol") or "").strip()
        transport = "OTEL"
        if protocol:
            transport = f"OTEL/{protocol}"
        chips = [
            ("Source", "Codex OTEL (user prompts)"),
            ("Transport", transport),
            ("Status", "user-prompt export on"),
        ]
        if dest:
            chips.insert(2, ("Endpoint", dest))
        headers = bool(summary.get("otel_exporter_headers_configured"))
        meta = "from config.toml"
        if headers:
            meta = f"{meta} · headers configured"
        note = (
            "Codex is configured to export user prompts over OTEL. Prompt text leaves the "
            "endpoint for the configured destination; verify that destination is one you control."
        )
    elif platform == "claude":
        if not summary.get("otel_enabled"):
            return ""
        title = "Claude Code telemetry export"
        dest = str(summary.get("otel_destination") or "").strip()
        protocol = str(summary.get("otel_protocol") or "").strip()
        transport = "OTLP"
        if protocol:
            transport = f"OTLP/{protocol}"
        chips = [
            ("Source", "Claude Code OTLP"),
            ("Transport", transport),
            ("Status", "configured"),
        ]
        if dest:
            chips.insert(2, ("Endpoint", dest))
        headers = bool(summary.get("otel_headers_configured"))
        sources = summary.get("otel_sources") or []
        meta = ", ".join(str(s) for s in sources) or "local environment"
        if headers:
            meta = f"{meta} · headers configured"
        note = (
            "Claude Code native OTLP telemetry is enabled and pointed at the endpoint above. "
            "If you run a collector there, its tool_decision events are the reliable source for "
            "approval attribution: user-click accepts, rejections, and config-rule decisions."
        )
    else:
        return ""

    chip_parts = []
    for label, value in chips:
        value_text = str(value)
        chip_parts.append(
            f"<div class='mode-chip route-chip'><span>{_esc(label)}</span>"
            f"<strong>{_esc(value_text)}</strong></div>"
        )
    chip_html = "".join(chip_parts)
    return f"""<div class="telemetry-summary">
        <div class="rule-group-head">
          <h4>{_esc(title)}</h4>
          <span class="meta">{_esc(meta)}</span>
        </div>
        <p class="surface-note">{_esc(note)}</p>
        <div class="mode-grid">{chip_html}</div>
      </div>"""


def _render_cursor_state_summary(summary: dict[str, Any]) -> str:
    if not summary:
        return ""
    chips = [
        ("Registered MCP", str(int(summary.get("mcp_registered") or 0))),
        ("Approved project MCP", str(int(summary.get("approved_project_mcp_servers") or 0))),
        ("Known MCP (runtime)", str(int(summary.get("known_mcp_servers") or 0))),
        ("Unmatched known", str(int(summary.get("known_mcp_unmatched") or 0))),
        ("Approval-like events", str(int(summary.get("permission_events") or 0))),
        ("Auto-accept workspaces", str(int(summary.get("composer_auto_accept_workspaces") or 0))),
    ]
    if summary.get("agent_autorun_default_attempted"):
        chips.append(("Agent autorun default", "attempted"))
    chip_html = "".join(
        f"<div class='mode-chip'><span>{_esc(label)}</span><strong>{_esc(value)}</strong></div>"
        for label, value in chips
    )
    note = (
        "The MCP table lists registrations from mcp.json plus project approvals. "
        "Known (runtime) counts servers Cursor has seen in state.vscdb; unmatched known "
        "servers have no local mcp.json row. Local state cannot reconstruct every clicked "
        "approval as a reusable command allow-list."
    )
    return f"""<div class="telemetry-summary">
        <div class="rule-group-head">
          <h4>Cursor local permission state</h4>
          <span class="meta">mcp.json + state.vscdb + agent transcripts</span>
        </div>
        <p class="surface-note">{_esc(note)}</p>
        <div class="mode-grid">{chip_html}</div>
      </div>"""


def _format_byte_size(n: int) -> str:
    value = float(max(0, int(n or 0)))
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{int(n)} B"


def _render_grok_state_summary(summary: dict[str, Any]) -> str:
    if not summary:
        return ""
    mode = str(summary.get("permission_mode") or "unset")
    yolo = "yes" if summary.get("yolo") else "no"
    models = summary.get("model_distribution") or {}
    if isinstance(models, dict) and models:
        top = sorted(models.items(), key=lambda kv: (-int(kv[1] or 0), str(kv[0])))[:3]
        model_text = ", ".join(f"{name} ({count})" for name, count in top)
    else:
        model_text = "none"
    chips = [
        ("Permission mode", mode),
        ("Yolo", yolo),
        ("Sessions", str(int(summary.get("session_count") or 0))),
        ("Messages", str(int(summary.get("total_messages") or 0))),
        ("Tool calls", str(int(summary.get("total_tool_calls") or 0))),
        ("Transcript size", _format_byte_size(int(summary.get("transcript_bytes") or 0))),
        ("Models", model_text),
        ("Prompt-history cwds", str(int(summary.get("cwd_groups_with_prompt_history") or 0))),
        ("Runtime MCP", str(int(summary.get("mcp_runtime_servers") or 0))),
        ("Config MCP", str(int(summary.get("mcp_servers") or 0))),
    ]
    small_attr = ' class="small-value"'
    chip_html = "".join(
        f"<div class='mode-chip'><span>{_esc(label)}</span>"
        f"<strong{small_attr if len(str(value)) > 24 else ''}>{_esc(value)}</strong></div>"
        for label, value in chips
    )
    note = (
        "Inventory from config.toml, session summary/signals, and events.jsonl MCP "
        "resolution. Chat history and updates.jsonl content stay out of evidence. "
        "always-approve / yolo means tool use is not prompted."
    )
    return f"""<div class="telemetry-summary">
        <div class="rule-group-head">
          <h4>Grok Build local permission state</h4>
          <span class="meta">config.toml + sessions + events.jsonl</span>
        </div>
        <p class="surface-note">{_esc(note)}</p>
        <div class="mode-grid">{chip_html}</div>
      </div>"""


def render_permissions_section(envelopes: dict[str, dict[str, Any]]) -> str:
    chunks: list[str] = []
    chat_sum = (envelopes.get("chat-history") or {}).get("summary") or {}
    for platform in _visible_platform_collectors(envelopes):
        env = envelopes.get(platform)
        label = TOOL_LABELS.get(platform, platform)

        if not env:
            chunks.append(
                f'<div class="platform"><div class="platform-head">'
                f'<h3>{_esc(label)}</h3>'
                f'<div class="stats"><span>collector did not run</span></div></div></div>'
            )
            continue
        if not env.get("platform_detected", True):
            chunks.append(
                f'<div class="platform"><div class="platform-head">'
                f'<h3>{_esc(label)}</h3>'
                f'<div class="stats"><span>tool not detected on this endpoint</span></div></div></div>'
            )
            continue

        rules = [r for r in (env.get("rules") or []) if isinstance(r, dict)]
        state_early = ""
        if platform == "cursor":
            state_early = _render_cursor_state_summary(env.get("summary") or {})
        elif platform == "grok":
            state_early = _render_grok_state_summary(env.get("summary") or {})
        if not rules:
            posture_findings = [
                f for f in (env.get("findings") or [])
                if str(f.get("category", "")) in PERMISSION_CATEGORIES
            ]
            if posture_findings:
                finding_rows = []
                for f in posture_findings[:5]:
                    sev = str(f.get("severity", "low"))
                    sample = _display_redaction_tokens(f.get("sample_redacted") or "")
                    sample_html = f"<code>{_esc(sample)}</code>" if sample else "<span>configuration state</span>"
                    finding_rows.append(
                        f"<li><span class='pill {sev}'>{_esc(sev)}</span>"
                        f"<strong>{_esc(_display_finding_title(f))}</strong>{sample_html}</li>"
                    )
                more = len(posture_findings) - len(finding_rows)
                more_html = f"<div class='more'>+{more} more posture finding{'s' if more != 1 else ''}</div>" if more > 0 else ""
                chunks.append(f"""    <div class="platform">
      <div class="platform-head">
        <h3>{_esc(label)}</h3>
        <div class="stats"><span>no persistent allow-list rules</span><span>{len(posture_findings)} posture finding{'s' if len(posture_findings) != 1 else ''}</span></div>
      </div>
      {state_early}
      <div class="rule-group posture-findings">
        <div class="rule-group-head">
          <h4>Runtime permission posture</h4>
          <span class="meta">configuration finding</span>
        </div>
        <ul class="posture-list">{''.join(finding_rows)}</ul>
        {more_html}
      </div>
    </div>""")
                continue
            if state_early:
                chunks.append(f"""    <div class="platform">
      <div class="platform-head">
        <h3>{_esc(label)}</h3>
        <div class="stats"><span>no persistent permission rules recorded</span></div>
      </div>
      {state_early}
    </div>""")
                continue
            chunks.append(
                f'<div class="platform"><div class="platform-head">'
                f'<h3>{_esc(label)}</h3>'
                f'<div class="stats"><span>no persistent permission rules recorded</span></div></div></div>'
            )
            continue

        permission_findings = [
            f for f in (env.get("findings") or [])
            if str(f.get("category", "")) in PERMISSION_CATEGORIES
        ]

        # Counts
        n_total = len(rules)
        n_high = (
            sum(1 for r in rules if r.get("risk") == "high")
            + sum(1 for f in permission_findings if str(f.get("severity")) == "high")
        )
        n_medium = (
            sum(1 for r in rules if r.get("risk") == "medium")
            + sum(1 for f in permission_findings if str(f.get("severity")) == "medium")
        )
        n_crit = (
            sum(1 for r in rules if r.get("risk") == "critical")
            + sum(1 for f in permission_findings if str(f.get("severity")) == "critical")
        )
        warn_cls = " warn" if n_high else ""
        stats_html = (
            f'<div class="stats">'
            f'<span><b>{n_total}</b> rules</span>'
            f'<span><b class="{warn_cls.strip()}">{n_high}</b> high</span>'
            f'<span><b>{n_crit}</b> critical</span></div>'
        )

        # Exposure breakdown for the perm-summary strip
        exp_counts: Counter[str] = Counter()
        for r in rules:
            exp_counts[str(r.get("exposure_category", "General Tooling"))] += 1
        # Highest risk
        highest = "low"
        for r in rules:
            risk = str(r.get("risk", "low"))
            if SEVERITY_ORDER.get(risk, 9) < SEVERITY_ORDER.get(highest, 9):
                highest = risk
        for f in permission_findings:
            risk = str(f.get("severity", "low"))
            if SEVERITY_ORDER.get(risk, 9) < SEVERITY_ORDER.get(highest, 9):
                highest = risk
        highest_color = {
            "critical": "var(--red)",
            "high": "var(--accent)",
            "medium": "var(--yellow)",
            "low": "var(--green)",
        }.get(highest, "var(--fg-3)")
        highest_note = " - ".join(
            [f"{n_crit} critical", f"{n_high} high", f"{n_medium} medium"]
        )

        stored_allow_count = sum(
            1 for r in rules
            if r.get("decision") == "allow"
            and r.get("rule_type") != "mcp_tool"
            and r.get("source_kind") not in ("session_event", "session_prefix")
        )

        # Top 2 exposure categories + stored allow count + highest risk tile.
        top_exposures = exp_counts.most_common(2)
        ps_cells: list[str] = []
        for cat, n in top_exposures:
            ps_cells.append(
                f'<div class="ps"><div class="label">{_esc(cat)}</div>'
                f'<div class="n">{n}</div>'
                f'<div class="note">rule{"s" if n != 1 else ""}</div></div>'
            )
        ps_cells.append(
            f'<div class="ps"><div class="label">Stored allow rules</div>'
            f'<div class="n">{stored_allow_count}</div>'
            f'<div class="note">non-MCP rules</div></div>'
        )
        ps_cells.append(
            f'<div class="ps"><div class="label">Highest risk</div>'
            f'<div class="n risk-word" style="color: {highest_color};">{_esc(highest)}</div>'
            f'<div class="note">{_esc(highest_note)}</div></div>'
        )
        # Filler cards are intentionally disabled; every visible tile carries evidence.
        while False:
            ps_cells.append(
                '<div class="ps"><div class="label">—</div>'
                '<div class="n">0</div><div class="note">no data</div></div>'
            )
        ps_html = '<div class="perm-summary">' + "".join(ps_cells) + "</div>"
        telemetry_html = _render_telemetry_summary(platform, env.get("summary") or {})
        if platform == "cursor":
            state_html = _render_cursor_state_summary(env.get("summary") or {})
        elif platform == "grok":
            state_html = _render_grok_state_summary(env.get("summary") or {})
        else:
            state_html = ""
        mode_html = _render_claude_mode_history(chat_sum) if platform == "claude" else ""
        mcp_html = _render_mcp_summary(platform, rules)

        # Configured allow-rule sample.
        groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
        for r in rules:
            scope = str(r.get("scope", ""))
            scope_label = _scope_label_display(scope, str(r.get("scope_label_redacted", "")))
            key = (
                str(r.get("exposure_category", "General Tooling")),
                scope,
                scope_label,
                _rule_source_label(r),
            )
            groups[key].append(r)
        rg_html = ""
        if groups:
            group_rows = sorted(
                groups.items(),
                key=lambda kv: (-len(kv[1]), kv[0][0], kv[0][2]),
            )
            (exposure, scope, scope_label, settings_source), items = group_rows[0]
            display_scope_label = _scope_label_display(scope, scope_label)
            commands = sorted({_rule_display(r) for r in items if _rule_display(r)})
            other_rules = n_total - len(items)
            scope_text = (
                f"{_esc(exposure)} / <span style='color: var(--accent);'>{_esc(display_scope_label)}</span>"
                if display_scope_label
                else f"{_esc(exposure)} · {_esc(scope)}"
            )
            decision_counts = Counter(str(r.get("decision", "unknown")) for r in items)
            decision_meta = " - ".join(
                f"{count} {decision}" for decision, count in sorted(decision_counts.items())
            )
            source_meta = f"Source: {settings_source}" if settings_source != "-" else ""
            rule_lis = "".join(f"<li><code>{_esc(c)}</code></li>" for c in commands)
            more_text_parts = []
            if other_rules > 0:
                more_text_parts.append(f"{other_rules} rule{'s' if other_rules != 1 else ''} shown in other groups below")
            more_text_parts.append(f"evidence/{platform}.json")
            more_text = " · ".join(more_text_parts)
            subgroup_html_parts: list[str] = []
            for (sub_exposure, sub_scope, sub_scope_label, sub_settings_source), sub_items in group_rows[1:]:
                sub_display_scope_label = _scope_label_display(sub_scope, sub_scope_label)
                sub_scope_text = (
                    f"{_esc(sub_exposure)} / <span style='color: var(--accent);'>{_esc(sub_display_scope_label)}</span>"
                    if sub_display_scope_label
                    else f"{_esc(sub_exposure)} · {_esc(sub_scope)}"
                )
                sub_commands = sorted({_rule_display(r) for r in sub_items if _rule_display(r)})
                sub_decisions = Counter(str(r.get("decision", "unknown")) for r in sub_items)
                sub_decision_meta = " - ".join(
                    f"{count} {decision}" for decision, count in sorted(sub_decisions.items())
                )
                sub_meta_parts = [f"{len(sub_items)} rules", _esc(sub_decision_meta)]
                if sub_settings_source != "-":
                    sub_meta_parts.append(_esc(sub_settings_source))
                sub_meta = " - ".join(sub_meta_parts)
                sub_lis = "".join(f"<li><code>{_esc(c)}</code></li>" for c in sub_commands)
                subgroup_html_parts.append(f"""        <div class="rule-subgroup">
          <div class="rule-subgroup-head">
            <h5>{sub_scope_text}</h5>
            <span>{sub_meta}</span>
          </div>
          <ul class="rule-list compact">{sub_lis}</ul>
        </div>""")
            subgroup_html = (
                '<div class="other-rule-groups"><h5>Other rule groups</h5>'
                + "".join(subgroup_html_parts)
                + "</div>"
                if subgroup_html_parts
                else ""
            )

            rg_html = f"""<div class="rule-group">
        <div class="rule-group-head">
          <h4>Configured allow rules · {scope_text}</h4>
          <span class="meta">{len(items)} rules - {_esc(decision_meta)}</span>
        </div>
        {f'<div class="settings-source">{_esc(source_meta)}</div>' if source_meta else ''}
        <ul class="rule-list">{rule_lis}</ul>
        <div class="more">{more_text}</div>
        {subgroup_html}
      </div>"""

        rg_html = _render_allow_rules_summary(platform, rules)

        chunks.append(f"""    <div class="platform">
      <div class="platform-head">
        <h3>{_esc(label)}</h3>
        {stats_html}
      </div>
      {ps_html}
      {telemetry_html}
      {state_html}
      {mode_html}
      {mcp_html}
      {rg_html}
    </div>""")
    return "\n".join(chunks) if chunks else "<p>No permission collectors ran.</p>"


# ─────────────────────────────────────────────────────────────────────────────
# Chat exposure
# ─────────────────────────────────────────────────────────────────────────────


def _format_minutes_estimate(minutes: int) -> str:
    if minutes <= 0:
        return "0m"
    hours, mins = divmod(minutes, 60)
    if hours <= 0:
        return f"{mins}m"
    if mins == 0:
        return f"{hours}h"
    return f"{hours}h {mins}m"


def per_tool_chat_stats(chat_env: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not chat_env:
        return []
    summary = chat_env.get("summary") or {}
    pointers = chat_env.get("raw_pointers") or []
    by_tool: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"dates": [], "bytes": 0, "files": 0, "secret_hits": 0}
    )

    for ptr in pointers:
        if not isinstance(ptr, dict):
            continue
        path = str(ptr.get("path", ""))
        parts = path.replace("\\", "/").split("/")
        if len(parts) < 4 or parts[1] != "chat-history":
            continue
        tool = parts[2]
        date_part = parts[3].replace(".md", "")
        try:
            by_tool[tool]["dates"].append(datetime.strptime(date_part, "%Y-%m-%d"))
        except ValueError:
            pass
        by_tool[tool]["files"] += 1

    for key, val in summary.items():
        if key.endswith("_files") and isinstance(val, int):
            tool = key[: -len("_files")]
            by_tool[tool]["files"] = max(by_tool[tool]["files"], val)

    # Per-tool secret-hit file counts come from chat_history.secret.<tool>
    # evidence_count (files flagged), not the number of findings (usually 1).
    secret_hits: Counter[str] = Counter()
    for f in chat_env.get("findings") or []:
        fid = str(f.get("id", ""))
        if not fid.startswith("chat_history.secret."):
            continue
        tool = fid[len("chat_history.secret.") :]
        if not tool:
            continue
        secret_hits[tool] += int(f.get("evidence_count") or 0)

    tool_labels = {
        "claude": "claude",
        "codex": "codex",
        "cursor": "cursor",
        "cursor-composer": "composer",
        "grok": "grok",
    }
    rows: list[dict[str, Any]] = []
    for tool, label in tool_labels.items():
        info = by_tool.get(tool, {"dates": [], "files": 0})
        files = info["files"] or int(summary.get(f"{tool}_files") or 0)
        dates = info["dates"]
        oldest = min(dates).strftime("%Y-%m-%d") if dates else summary.get("oldest_date", "n/a")
        newest = max(dates).strftime("%Y-%m-%d") if dates else summary.get("newest_date", "n/a")
        retention = (datetime.now() - min(dates)).days if dates else summary.get("retention_days", 0)
        rows.append(
            {
                "tool_key": tool,
                "tool_label": label,
                "tool_display": tool.replace("-", " "),
                "oldest": oldest,
                "newest": newest,
                "files": files,
                "retention_days": int(retention or 0),
                "secret_hits": secret_hits.get(tool, 0),
                "active_minutes_estimated": int(summary.get(f"{tool}_active_minutes_estimated") or 0),
            }
        )
    return rows


def render_chat_section(chat_env: dict[str, Any] | None) -> str:
    if not chat_env:
        return "<p>Chat history collector did not run.</p>"
    if not chat_env.get("platform_detected", True):
        return "<p>Tool not detected. No chat transcripts found.</p>"

    summary = chat_env.get("summary") or {}
    rows = per_tool_chat_stats(chat_env)
    total_files = int(summary.get("total_files") or sum(r["files"] for r in rows))
    active_minutes = int(summary.get("active_minutes_estimated") or 0)
    active_gap_cap = int(summary.get("active_gap_cap_minutes") or 30)
    secret_files = int(summary.get("secret_hit_files") or 0)
    max_retention = int(summary.get("retention_days") or max((r["retention_days"] for r in rows), default=0))

    # Stat cards (left column)
    pct = round((secret_files / total_files) * 100, 1) if total_files else 0
    max_class = "red" if max_retention > 90 else "accent"
    max_over = max_retention - 90
    max_note = (
        f"{rows and max((r['tool_display'] for r in rows if r['retention_days'] == max_retention), default='—') or '—'}"
    )
    if max_over > 0:
        max_note += f" · {max_over}d over policy"

    stat_cards = f"""      <div class="side">
        <div class="stat">
          <div class="stat-num">{total_files}</div>
          <div class="stat-lbl">exported transcript files</div>
        </div>
        <div class="stat">
          <div class="stat-num">{_esc(_format_minutes_estimate(active_minutes))}</div>
          <div class="stat-lbl">estimated active conversation time</div>
        </div>
        <div class="stat">
          <div class="stat-num accent">{secret_files}<span>·files</span></div>
          <div class="stat-lbl">transcript files with secret patterns · ≈ {pct}% of all transcripts</div>
        </div>
        <div class="stat">
          <div class="stat-num {max_class}">{max_retention}<span>·days</span></div>
          <div class="stat-lbl">max retention · {_esc(max_note)}</div>
        </div>
      </div>"""

    # Retention rows
    scale = max(max_retention, 100)  # always show 100-day reference scale
    retention_rows: list[str] = []
    for r in rows:
        days = r["retention_days"]
        bar_pct = round((days / scale) * 100) if scale else 0
        over_cls = " over" if days > 90 else ""
        retention_rows.append(f"""        <div class="retention-row">
          <span class="name">{_esc(r['tool_display'])}</span>
          <div class="track"><div class="bar{over_cls}" style="width: {bar_pct}%;">{days}d</div><div class="ninety" style="left: {round((90/scale)*100)}%;"></div></div>
          <span class="right">{r['files']} files - {_esc(_format_minutes_estimate(r['active_minutes_estimated']))} active est.</span>
        </div>""")

    # Find which tool is over policy (if any) for the cap
    over_tool = next((r["tool_display"] for r in rows if r["retention_days"] > 90), None)
    over_days = max((r["retention_days"] - 90 for r in rows if r["retention_days"] > 90), default=0)
    cap = (
        f"▮ 90-day policy mark · {_esc(over_tool)} over by {over_days} days"
        if over_tool
        else "▮ 90-day policy mark"
    )

    retention_panel = f"""      <div class="retention">
        <h3>Retention by tool · days held on disk</h3>
{"".join(retention_rows)}
        <div class="ninety-cap">{cap}</div>
      </div>"""

    # Table
    table_rows = "\n".join(
        f"        <tr><td class='mono'>{_esc(r['tool_key'])}</td>"
        f"<td class='mono'>{_esc(r['oldest'])}</td>"
        f"<td class='mono'>{_esc(r['newest'])}</td>"
        f"<td class='num'>{r['files']}</td>"
        f"<td class='num'>{_esc(_format_minutes_estimate(r['active_minutes_estimated']))}</td>"
        f"<td class='num'>{r['secret_hits']}</td>"
        f"<td class='num{(' hot' if r['retention_days'] > 90 else '')}'>{r['retention_days']}d</td></tr>"
        for r in rows
    )

    return f"""    <div class="chat-grid">
{stat_cards}
{retention_panel}
    </div>

    <div class="table-wrap" style="margin-top: 24px;"><table>
      <thead><tr><th>Tool</th><th>Oldest</th><th>Newest</th><th>Files</th><th>Active estimate</th><th>Secret-hit files</th><th>Retention</th></tr></thead>
      <tbody>
{table_rows}
      </tbody>
    </table></div>
    <p class="posture-grid-caption">Active time is a capped-gap estimate from transcript timestamps: gaps between consecutive messages in the same session count up to {active_gap_cap} minutes. It is directional, not a timesheet, and tools with coarse timestamps may undercount.</p>"""


# ─────────────────────────────────────────────────────────────────────────────
# Secrets + git posture
# ─────────────────────────────────────────────────────────────────────────────


def render_secrets_section(secrets_env: dict[str, Any] | None) -> str:
    if not secrets_env:
        return "<p>Secrets scan did not run.</p>"
    summary = secrets_env.get("summary") or {}
    scanner = summary.get("scanner", "unknown")

    by_rule: list[tuple[str, int]] = []
    for key, val in sorted(summary.items()):
        if key.startswith("rule_") and isinstance(val, int):
            by_rule.append((key[5:], val))
    by_rule.sort(key=lambda kv: -kv[1])

    chat_hits = 0
    repo_hits = 0
    for f in secrets_env.get("findings") or []:
        sample = str(f.get("sample_redacted", ""))
        tags = f.get("tags") or []
        if "chat" in sample.lower() or "chat_plaintext" in tags:
            chat_hits += 1
        else:
            repo_hits += 1
    total = int(summary.get("hits") or 0)
    if total and not chat_hits and not repo_hits:
        repo_hits = total

    if by_rule:
        max_val = max(v for _, v in by_rule) or 1
        bars = "\n".join(
            f"""        <div class="secret-rules">
          <span class="name">{_esc(name)}</span>
          <div class="track"><div class="b" style="width: {round((val / max_val) * 100, 1)}%;"></div></div>
          <span class="v">{val}</span>
        </div>"""
            for name, val in by_rule[:12]
        )
    else:
        bars = "<p style='color: var(--fg-3);'>No rule breakdown recorded.</p>"

    note = (
        f'<p style="margin-top: 20px; font-family: var(--f-mono); font-size: 11.5px; '
        f'color: var(--fg-3); line-height: 1.6;">'
        f"// by location · chat: {chat_hits} · repos: {repo_hits}<br/>"
        f"// scanner: {_esc(scanner)}</p>"
    )
    return bars + "\n" + note


def render_git_section(git_env: dict[str, Any] | None) -> str:
    if not git_env:
        return "<p>Git posture collector did not run.</p>"
    if not git_env.get("platform_detected", True):
        return "<p>No git repositories found in scan scope.</p>"

    s = git_env.get("summary") or {}
    repos = int(s.get("repos_scanned") or 0)
    env_hist = int(s.get("env_in_history") or 0)
    no_hooks = int(s.get("no_pre_commit") or 0)
    no_prot = int(s.get("no_branch_protection") or 0)
    gh_checked = bool(s.get("gh_checked"))

    pre_commit_have = repos - no_hooks
    pre_commit_pct = round((pre_commit_have / repos) * 100) if repos else 0
    env_cls = "red" if env_hist > 0 else ""
    hooks_cls = "amber" if pre_commit_pct < 50 else ""

    cells: list[str] = []
    cells.append(f"""          <div>
            <div class="label">.env in history</div>
            <div class="v {env_cls}">{env_hist}<small>/ {repos}</small></div>
          </div>""")
    cells.append(f"""          <div>
            <div class="label">pre-commit coverage</div>
            <div class="v {hooks_cls}">{pre_commit_pct}%<small>{pre_commit_have} / {repos}</small></div>
          </div>""")
    cells.append(f"""          <div>
            <div class="label">repos scanned</div>
            <div class="v">{repos}</div>
          </div>""")
    if gh_checked:
        prot_have = repos - no_prot
        prot_pct = round((prot_have / repos) * 100) if repos else 0
        cells.append(f"""          <div>
            <div class="label">branch protection</div>
            <div class="v">{prot_pct}%<small>{prot_have} / {repos}</small></div>
          </div>""")
    else:
        cells.append("""          <div>
            <div class="label">branch protection</div>
            <div class="v" style="font-size: 22px; color: var(--fg-3); padding-top: 12px;">not checked</div>
            <div style="font-family: var(--f-mono); font-size: 11.5px; color: var(--fg-4);">(gh not enabled)</div>
          </div>""")

    return f"""        <div class="git-grid">
{chr(10).join(cells)}
        </div>"""


# ─────────────────────────────────────────────────────────────────────────────
# Methodology table
# ─────────────────────────────────────────────────────────────────────────────


def render_collectors_table(
    envelopes: dict[str, dict[str, Any]],
    runs: list[dict[str, Any]],
) -> str:
    run_map = {str(r.get("name", "")): r for r in runs}
    rows = []
    for name in sorted(envelopes.keys()):
        env = envelopes[name]
        if name == "copilot" and not _is_detected(env):
            continue
        run = run_map.get(name)
        version = env.get("version", run.get("version", "unknown") if run else "unknown")
        produced_at = _format_timestamp((run or {}).get("ended_at") or env.get("ran_at"))
        duration = _duration_sec(run) if run else "not recorded"
        status = collector_status(name, env, run)
        status_label = "ok"
        if not env.get("platform_detected", True):
            status_label = "tool not detected"
            status = "skipped"
        elif status == "skipped":
            status_label = "skipped"
        elif status == "error":
            status_label = "error"
        label, purpose = COLLECTOR_PURPOSES.get(name, (name, "Collector run"))
        rows.append(
            f"        <tr><td><strong>{_esc(label)}</strong><div class='mono'>{_esc(name)}</div></td>"
            f"<td>{_esc(purpose)}</td>"
            f"<td class='mono'>{_esc(produced_at)}</td>"
            f"<td class='mono'>{_esc(duration)}</td>"
            f"<td class='mono'>{_esc(version)}</td>"
            f"<td><span class='pill {status}'>{_esc(status_label)}</span></td></tr>"
        )
    return "\n".join(rows) if rows else "<tr><td colspan='6'>No collectors recorded.</td></tr>"


# ─────────────────────────────────────────────────────────────────────────────
# Appendix — KEY FIX: group identical findings by (severity, title, ref)
# ─────────────────────────────────────────────────────────────────────────────


def render_appendix_grouped(findings: list[dict[str, Any]]) -> tuple[str, str]:
    """Group identical-shape findings into single rows with a count badge.

    Returns (rows_html, note_html). The note appears above the table when
    aggregation actually collapsed something (e.g., 168 gitleaks rows → 4).
    """
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    raw_count = 0

    for f in findings:
        raw_count += 1
        collector = str(f.get("_collector", ""))
        # Prefer per-finding raw_evidence_ref; otherwise fall back to the
        # collector's primary evidence file so every finding has a pointer.
        ref = str(f.get("raw_evidence_ref") or (f"evidence/{collector}.json" if collector else "n/a"))
        sev = str(f.get("severity", "low"))
        title = str(f.get("title", ""))

        key = (sev, title, ref)
        if key not in groups:
            groups[key] = {"severity": sev, "title": title, "ref": ref, "count": 0}
        groups[key]["count"] += int(f.get("evidence_count") or 1)

    if not groups:
        return "<tr><td colspan='4'>No findings recorded.</td></tr>", ""

    sorted_groups = sorted(
        groups.values(),
        key=lambda g: (
            SEVERITY_ORDER.get(g["severity"], 9),
            -g["count"],
            g["title"].lower(),
        ),
    )

    row_html: list[str] = []
    for g in sorted_groups:
        sev = g["severity"]
        count = g["count"]
        count_cls = "count one" if count <= 1 else "count"
        row_html.append(
            f"          <tr>"
            f"<td><span class='pill {sev}'>{_esc(sev)}</span></td>"
            f"<td>{_esc(g['title'])}</td>"
            f"<td><span class='{count_cls}'>{count}</span></td>"
            f"<td class='mono'>{_esc(g['ref'])}</td></tr>"
        )

    # Aggregation note — only show if real collapsing happened
    collapsed = raw_count - len(groups)
    note_html = ""
    if collapsed > 10:
        # Find the largest collapsed rule for a concrete example
        biggest = max(sorted_groups, key=lambda g: g["count"])
        note_html = (
            '    <div class="appendix-note">\n'
            "      <strong>aggregation note · </strong>"
            f"{collapsed} individual findings collapsed into "
            f"{len(groups)} grouped rows. Largest group: "
            f"<span class='mono'>{_esc(biggest['title'])}</span> ({biggest['count']} hits) → "
            f"<span class='mono'>{_esc(biggest['ref'])}</span>. "
            "Per-row evidence (file path, line offset, redacted sample) lives in the linked CSV — "
            "the manifest hash is the integrity anchor.\n"
            "    </div>"
        )
    return "\n".join(row_html), note_html


# ─────────────────────────────────────────────────────────────────────────────
# Assemble & write
# ─────────────────────────────────────────────────────────────────────────────


def build_html(
    evidence_root: Path,
    *,
    customer: str | None,
    operator: str | None,
) -> str:
    envelopes = load_evidence(evidence_root)
    discovery = envelopes.get("discovery")
    runs_list = load_collectors_run(evidence_root)
    runs_map = {str(r.get("name", "")): r for r in runs_list}

    meta = read_frontmatter(evidence_root)
    customer_name = customer or meta.get("customer") or "Unknown customer"
    operator_name = operator or meta.get("operator") or "Unknown operator"
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    engagement_date = engagement_dates(evidence_root, envelopes)

    findings = aggregate_findings(envelopes)
    counts = severity_counts(findings)
    tools_rows = build_tools_table(envelopes, discovery, runs_map)
    posture_grid = render_posture_grid(envelopes)
    tool_names = detected_tool_names(envelopes, tools_rows)

    findings_tabs, findings_panels = render_findings_section(findings)
    appendix_rows, appendix_note = render_appendix_grouped(findings)

    secrets_env = envelopes.get("secrets-scan")
    total_secret_hits = int((secrets_env or {}).get("summary", {}).get("hits") or 0)
    git_env = envelopes.get("git-posture")
    git_repos = int((git_env or {}).get("summary", {}).get("repos_scanned") or 0)

    manifest_full = manifest_sha256(evidence_root)
    # 16-char fingerprint avoids tripping the secrets scanner's hex
    # threshold while preserving an integrity anchor; full hashes ship in
    # manifest.json itself.
    manifest_short = manifest_full[:16] if len(manifest_full) >= 16 else manifest_full

    css = (TEMPLATES_DIR / "briefing.css").read_text(encoding="utf-8")

    replacements = {
        "%%TITLE%%": f"{customer_name} · AI Coding Tool Exposure Review",
        "%%CSS%%": css,
        "%%CUSTOMER%%": _esc(customer_name),
        "%%ENGAGEMENT_DATE%%": _esc(engagement_date),
        "%%OPERATOR%%": _esc(operator_name),
        "%%GENERATED_AT%%": _esc(generated_at),
        "%%MANIFEST_HASH_SHORT%%": _esc(manifest_short),

        # Hero
        "%%HERO_LEDE%%": _esc(render_hero_lede(tool_names, counts)),
        "%%COVER_STATUS%%": render_cover_status(envelopes, runs_map, counts),

        # Executive
        "%%EXECUTIVE_HEADLINE%%": _esc(render_executive_headline(counts)),
        "%%EXECUTIVE_SUB%%": _esc(render_executive_sub(envelopes, counts)),
        "%%COUNT_CRITICAL%%": str(counts.get("critical", 0)),
        "%%COUNT_HIGH%%": str(counts.get("high", 0)),
        "%%COUNT_MEDIUM%%": str(counts.get("medium", 0)),
        "%%COUNT_LOW%%": str(counts.get("low", 0)),
        "%%FINDINGS_TOTAL%%": str(sum(counts.values())),
        "%%SEVERITY_BAR_SEGMENTS%%": render_severity_bar_segments(counts),
        "%%SEVERITY_BAR_NOTE%%": _esc(render_severity_bar_note(counts, envelopes)),
        "%%POSTURE_GRID%%": posture_grid,
        "%%RISK_REGISTER%%": render_risk_register(findings),

        # Collection scope
        "%%COLLECTION_SCOPE%%": render_collection_scope(tools_rows),

        # Findings
        "%%FINDINGS_CATEGORIES%%": str(len({f.get("category") for f in findings if f.get("category")})),
        "%%FINDINGS_TABS%%": findings_tabs,
        "%%FINDINGS_PANELS%%": findings_panels,

        # Permissions / chat / secrets / git
        "%%PERMISSIONS_SECTION%%": render_permissions_section(envelopes),
        "%%CHAT_SECTION%%": render_chat_section(envelopes.get("chat-history")),
        "%%SECRETS_SECTION%%": render_secrets_section(secrets_env),
        "%%GIT_SECTION%%": render_git_section(git_env),
        "%%SECRETS_TOTAL_HITS%%": str(total_secret_hits),
        "%%GIT_REPOS%%": str(git_repos),

        # Methodology
        "%%COLLECTORS_TABLE%%": render_collectors_table(envelopes, runs_list),

        # Appendix
        "%%APPENDIX_NOTE%%": appendix_note,
        "%%APPENDIX_GROUPED_ROWS%%": appendix_rows,
    }

    html_out = HTML_SHELL
    for token, value in replacements.items():
        html_out = html_out.replace(token, value)
    return html_out


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build executive HTML briefing from aiscan evidence.")
    parser.add_argument("--evidence-root", required=True, help="Engagement root directory")
    parser.add_argument("--out", required=True, help="Output HTML path")
    parser.add_argument("--customer", default=None, help="Customer name override")
    parser.add_argument("--operator", default=None, help="Operator name override")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    root = Path(args.evidence_root)
    out = Path(args.out)

    try:
        html_content = build_html(
            root,
            customer=args.customer,
            operator=args.operator,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html_content, encoding="utf-8", newline="\n")
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
