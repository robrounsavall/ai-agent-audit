"""
Grok Build (xAI) permission and session collector.

Usage:
    python grok.py --evidence-root ./audit-run [--repo-roots ...] [--dry-run]

Reads ~/.grok/config.toml for durable posture (permission_mode, yolo, MCP
servers, permission allow/deny/ask rules) and walks ~/.grok/sessions/**
for metadata inventory plus safe events.jsonl MCP resolution. Never reads
chat_history.jsonl or updates.jsonl content into evidence; auth.json is
detected, never opened.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

import paths
from common import (
    USERPROFILE,
    add_base_args,
    classify_rule,
    compute_scope_hash,
    finish_collector,
    load_json,
    make_envelope,
    make_finding,
    make_rule,
    parse_iso,
    secret_types_in,
    validate_evidence_root,
)

__version__ = "1.1.0"

COLLECTOR = "grok"

# Session/transcript volume above which we note it as a (low-severity) finding.
SESSION_HIGH_VOLUME_THRESHOLD = 100

WILDCARD_BASH_RE = re.compile(r"^Bash\([^)]*\*[^)]*\)$", re.I)
CURL_WGET_RE = re.compile(r"^Bash\((curl|wget)\s*[:*]", re.I)
SANDBOX_OFF_VALUES = frozenset({"off", "disabled", "none", "false", "0"})

MCP_EVENT_TYPES = frozenset(
    {
        "mcp_config_resolved",
        "mcp_server_starting",
        "mcp_server_ready",
        "mcp_server_failed",
        "mcp_server_error",
    }
)

DEFAULT_REPO_ROOTS = [
    USERPROFILE / "repos",
    USERPROFILE / "code",
    USERPROFILE / "src",
    USERPROFILE / "projects",
    USERPROFILE / "source",
]


def default_repo_roots() -> list[Path]:
    return [p for p in DEFAULT_REPO_ROOTS if p.exists()]


def _is_localhost(url: str) -> bool:
    if not url:
        return False
    lower = url.lower()
    return any(host in lower for host in ("localhost", "127.0.0.1", "::1"))


def _mcp_args_secret(server_id: str, server_config: dict) -> dict | None:
    """Finding when MCP command/args/url look like they embed secrets."""
    args = server_config.get("args")
    arg_blob = " ".join(str(a) for a in args) if isinstance(args, list) else ""
    command = str(server_config.get("command") or "")
    url = str(server_config.get("url") or "")
    auth_hint = bool(
        re.search(r"(?i)\bAuthorization\s*:|\bBearer\s+[A-Za-z0-9._\-+=/]{8,}", arg_blob)
    )
    for blob in (arg_blob, command, url):
        if (blob and secret_types_in(blob)) or (blob is arg_blob and auth_hint):
            return make_finding(
                "grok.mcp.args_secret",
                "critical",
                "Secrets Exposure",
                f"MCP server {server_id} command/args contain secrets",
                secret_redacted=True,
            )
    return None


def _permission_pattern_findings(pattern: str) -> list[dict]:
    findings: list[dict] = []
    if WILDCARD_BASH_RE.search(pattern):
        findings.append(
            make_finding(
                "grok.permission.bash_wildcard",
                "high",
                "Shell Execution",
                "Grok allow pattern grants a broad Bash wildcard",
                sample_redacted=pattern[:120],
                tags=["wildcard"],
            )
        )
    if CURL_WGET_RE.search(pattern):
        findings.append(
            make_finding(
                "grok.permission.bash_curl_wide",
                "high",
                "Network Egress",
                "Grok allow pattern grants wide curl/wget use",
                sample_redacted=pattern[:120],
                tags=["egress"],
            )
        )
    return findings


def parse_config_toml(data: dict) -> tuple[list[dict], list[dict], dict]:
    """
    Parse a Grok config.toml dict into (rules, findings, summary_extras).

    Rules are for genuine grants (MCP servers, permission allow/deny/ask),
    stamped source_kind="user_config". Everything else is a finding or a
    summary metric. No fabricated decisions, no path/secret leakage.
    """
    rules: list[dict] = []
    findings: list[dict] = []
    extras: dict = {}

    if not data:
        return ([], [], {})

    ui = data.get("ui", {})
    permission_mode = "unset"
    yolo = False
    if isinstance(ui, dict):
        permission_mode = ui.get("permission_mode", "unset")
        yolo = bool(ui.get("yolo", False))
        if permission_mode == "always-approve" or yolo:
            findings.append(
                make_finding(
                    "grok.permission.always_approve",
                    "critical",
                    "Shell Execution",
                    "Grok Build permission_mode is always-approve (no prompt on tool use)",
                    sample_redacted=f"permission_mode={permission_mode} yolo={yolo}",
                    tags=["auto_approve"],
                )
            )
    extras["permission_mode"] = permission_mode
    extras["yolo"] = yolo

    # MCP servers: same [mcp_servers.<name>] TOML shape as Codex.
    mcp_servers = data.get("mcp_servers", {})
    mcp_server_count = 0
    if isinstance(mcp_servers, dict):
        mcp_server_count = len(mcp_servers)
        for server_id, server_config in mcp_servers.items():
            if not isinstance(server_config, dict):
                continue
            rules.append(
                make_rule(
                    "grok",
                    "user",
                    server_id,
                    "mcp_tool",
                    f"mcp__{server_id}",
                    "allow",
                    command_or_tool=server_id,
                    source_kind="user_config",
                    settings_source="config.toml mcp_servers",
                    confidence="high",
                    risk="medium",
                )
            )

            url = server_config.get("url", "")
            if url and not _is_localhost(url):
                findings.append(
                    make_finding(
                        "grok.mcp.non_localhost",
                        "high",
                        "MCP Tooling",
                        f"Grok MCP server {server_id} has a non-localhost endpoint",
                    )
                )

            transport = str(
                server_config.get("transport") or server_config.get("type") or ""
            ).lower()
            if transport in ("http", "sse"):
                findings.append(
                    make_finding(
                        "grok.mcp.http_remote",
                        "medium",
                        "MCP Tooling",
                        f"Grok MCP server {server_id} uses {transport} transport",
                    )
                )

            env_vars = server_config.get("env", {})
            if isinstance(env_vars, dict):
                for env_val in env_vars.values():
                    if isinstance(env_val, str) and secret_types_in(env_val):
                        findings.append(
                            make_finding(
                                "grok.mcp.env_secret",
                                "critical",
                                "Secrets Exposure",
                                f"MCP server {server_id} env contains secrets",
                                secret_redacted=True,
                            )
                        )
                        break

            args_finding = _mcp_args_secret(str(server_id), server_config)
            if args_finding:
                findings.append(args_finding)
    extras["mcp_servers"] = mcp_server_count

    # [permission] allow/deny/ask pattern lists.
    permission = data.get("permission", {})
    allow_count = 0
    deny_count = 0
    ask_count = 0
    if isinstance(permission, dict):
        for decision, key in (("allow", "allow"), ("deny", "deny"), ("ask", "ask")):
            patterns = permission.get(key, [])
            if not isinstance(patterns, list):
                continue
            if decision == "allow":
                allow_count = len(patterns)
            elif decision == "deny":
                deny_count = len(patterns)
            else:
                ask_count = len(patterns)
            for pattern in patterns:
                if not isinstance(pattern, str) or not pattern:
                    continue
                rule_type, cmd, _ = classify_rule(pattern)
                rules.append(
                    make_rule(
                        "grok",
                        "user",
                        "permission",
                        rule_type,
                        pattern,
                        decision,
                        command_or_tool=cmd,
                        source_kind="user_config",
                        settings_source="config.toml permission",
                        confidence="high",
                    )
                )
                if decision == "allow":
                    findings.extend(_permission_pattern_findings(pattern))
    extras["permission_allow_rules"] = allow_count
    extras["permission_deny_rules"] = deny_count
    extras["permission_ask_rules"] = ask_count

    # Subagents / memory: presence only.
    subagents = data.get("subagents", {})
    extras["subagents_configured"] = bool(subagents)
    memory = data.get("memory", {})
    extras["memory_configured"] = bool(memory)

    return (rules, findings, extras)


def _session_dirs(grok_sessions: Path):
    if not grok_sessions.exists():
        return
    for summary_path in grok_sessions.rglob("summary.json"):
        yield summary_path.parent


def _scan_events_mcp(events_path: Path) -> tuple[dict[str, str], int]:
    """Return ({server_name: transport}, event_hit_count). Never stores target paths."""
    servers: dict[str, str] = {}
    hits = 0
    if not events_path.exists():
        return servers, hits
    try:
        with events_path.open("r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if not isinstance(obj, dict):
                    continue
                etype = str(obj.get("type") or "")
                if etype not in MCP_EVENT_TYPES:
                    continue
                hits += 1
                if etype == "mcp_config_resolved":
                    for entry in obj.get("servers") or []:
                        if not isinstance(entry, dict):
                            continue
                        name = str(entry.get("name") or "").strip()
                        if not name:
                            continue
                        transport = str(entry.get("transport") or "unknown").lower()
                        servers.setdefault(name, transport)
                else:
                    name = str(obj.get("server_name") or "").strip()
                    if name:
                        transport = str(obj.get("transport") or servers.get(name) or "unknown").lower()
                        servers.setdefault(name, transport)
    except OSError:
        pass
    return servers, hits


def collect_session_inventory(grok_sessions: Path) -> tuple[dict, list[dict], list[dict]]:
    """
    Walk grok_sessions/**/summary.json (+ sibling files).

    Reads events.jsonl only for controlled MCP event types (name + transport).
    Never reads chat_history.jsonl or updates.jsonl content.
    Returns (summary_dict, findings, runtime_mcp_rules).
    """
    findings: list[dict] = []
    rules: list[dict] = []
    session_count = 0
    model_counts: dict[str, int] = {}
    sandbox_counts: dict[str, int] = {}
    tools_used: dict[str, int] = {}
    total_messages = 0
    dates: list[str] = []
    transcript_files = 0
    transcript_bytes = 0
    cwd_groups_with_prompt_history: set[str] = set()
    total_context_tokens = 0
    total_tool_calls = 0
    sandbox_off_sessions = 0
    runtime_servers: dict[str, str] = {}
    mcp_runtime_events = 0

    for session_dir in _session_dirs(grok_sessions):
        session_count += 1
        summary = load_json(session_dir / "summary.json") or {}
        model_id = summary.get("current_model_id")
        if model_id:
            model_counts[str(model_id)] = model_counts.get(str(model_id), 0) + 1
        num_messages = summary.get("num_messages")
        if isinstance(num_messages, int):
            total_messages += num_messages
        created_at = parse_iso(summary.get("created_at"))
        if created_at:
            dates.append(created_at)

        sandbox = str(summary.get("sandbox_profile") or "").strip().lower()
        if sandbox:
            sandbox_counts[sandbox] = sandbox_counts.get(sandbox, 0) + 1
            if sandbox in SANDBOX_OFF_VALUES:
                sandbox_off_sessions += 1
        else:
            sandbox_counts["unset"] = sandbox_counts.get("unset", 0) + 1
            sandbox_off_sessions += 1

        for name in ("chat_history.jsonl", "updates.jsonl", "events.jsonl"):
            f = session_dir / name
            if f.exists():
                transcript_files += 1
                try:
                    transcript_bytes += f.stat().st_size
                except OSError:
                    pass

        event_servers, event_hits = _scan_events_mcp(session_dir / "events.jsonl")
        mcp_runtime_events += event_hits
        for name, transport in event_servers.items():
            runtime_servers.setdefault(name, transport)

        signals = load_json(session_dir / "signals.json")
        if isinstance(signals, dict):
            tokens = signals.get("contextTokensUsed")
            if isinstance(tokens, int):
                total_context_tokens += tokens
            calls = signals.get("toolCallCount")
            if isinstance(calls, int):
                total_tool_calls += calls
            used = signals.get("toolsUsed")
            if isinstance(used, list):
                for tool in used:
                    if isinstance(tool, str) and tool.strip():
                        # Controlled short tool names only (no paths/args).
                        # Lowercase so summary JSON stays PowerShell-safe
                        # (ConvertFrom-Json rejects case-only duplicate keys).
                        key = tool.strip()[:64].lower()
                        tools_used[key] = tools_used.get(key, 0) + 1

        cwd_dir = session_dir.parent
        if (cwd_dir / "prompt_history.jsonl").exists():
            cwd_groups_with_prompt_history.add(str(cwd_dir))

    for name, transport in sorted(runtime_servers.items()):
        rules.append(
            make_rule(
                "grok",
                "user",
                "runtime",
                "mcp_tool",
                f"mcp__{name}",
                "allow",
                command_or_tool=name,
                source_kind="session_event",
                settings_source="events.jsonl mcp_config_resolved",
                confidence="medium",
                risk="medium",
            )
        )
        # Transport is summary-only; http/sse already covered by config findings
        # when registered in config.toml. Runtime transport noted in summary.

    summary_out = {
        "session_count": session_count,
        "total_messages": total_messages,
        "model_distribution": model_counts,
        "oldest_session": min(dates) if dates else "",
        "newest_session": max(dates) if dates else "",
        "transcript_files": transcript_files,
        "transcript_bytes": transcript_bytes,
        "cwd_groups_with_prompt_history": len(cwd_groups_with_prompt_history),
        "total_context_tokens_used": total_context_tokens,
        "total_tool_calls": total_tool_calls,
        "sandbox_profile_distribution": sandbox_counts,
        "sandbox_off_sessions": sandbox_off_sessions,
        "tools_used_distribution": tools_used,
        "mcp_runtime_servers": len(runtime_servers),
        "mcp_runtime_events": mcp_runtime_events,
        "mcp_runtime_transports": {
            name: transport for name, transport in sorted(runtime_servers.items())
        },
    }

    if session_count > SESSION_HIGH_VOLUME_THRESHOLD:
        findings.append(
            make_finding(
                "grok.session.high_volume",
                "low",
                "Cross-Agent Visibility",
                f"Grok has {session_count} local session directories",
                evidence_count=session_count,
            )
        )

    if sandbox_off_sessions:
        findings.append(
            make_finding(
                "grok.sandbox.off",
                "high",
                "Shell Execution",
                f"Grok sessions with sandbox_profile off/disabled: {sandbox_off_sessions}",
                evidence_count=sandbox_off_sessions,
                tags=["sandbox"],
            )
        )

    return summary_out, findings, rules


def collect_log_metadata(grok_logs: Path) -> dict:
    """Count log files/bytes under grok_logs. Does not parse content."""
    log_files = 0
    log_bytes = 0
    if not grok_logs.exists():
        return {"log_files": 0, "log_bytes": 0}
    candidates: list[Path] = []
    unified = grok_logs / "unified.jsonl"
    if unified.exists():
        candidates.append(unified)
    mcp_dir = grok_logs / "mcp"
    if mcp_dir.exists():
        candidates.extend(mcp_dir.glob("*.log"))
        candidates.extend(mcp_dir.glob("*.jsonl"))
    for path in candidates:
        if not path.is_file():
            continue
        log_files += 1
        try:
            log_bytes += path.stat().st_size
        except OSError:
            pass
    return {"log_files": log_files, "log_bytes": log_bytes}


def discover_project_configs(repo_roots: list[Path]) -> list[Path]:
    """Find <repo>/.grok/config.toml under repo roots (direct children + root)."""
    found: list[Path] = []
    seen: set[str] = set()
    for root in repo_roots:
        if not root.exists():
            continue
        candidates: list[Path] = []
        if (root / ".git").exists():
            candidates.append(root)
        try:
            for child in root.iterdir():
                if child.is_dir() and (child / ".git").exists():
                    candidates.append(child)
        except OSError:
            continue
        for repo in candidates:
            cfg = repo / ".grok" / "config.toml"
            key = str(cfg.resolve()) if cfg.exists() else str(cfg)
            if key in seen:
                continue
            seen.add(key)
            if cfg.exists():
                found.append(cfg)
    return found


def collect(tp: paths.ToolPaths, repo_roots: list[Path] | None = None) -> dict:
    roots = repo_roots if repo_roots is not None else default_repo_roots()
    grok_sessions = tp.grok_sessions
    config_toml = tp.grok_config
    auth_json = tp.grok_auth
    project_config = tp.grok_project_config
    project_configs = discover_project_configs(roots)
    if project_config is not None and project_config.exists():
        key = str(project_config.resolve())
        if key not in {str(p.resolve()) for p in project_configs}:
            project_configs.append(project_config)

    scanned = [str(grok_sessions), str(config_toml), str(auth_json), str(tp.grok_logs)]
    scanned.extend(str(p) for p in project_configs)
    scope_hash = compute_scope_hash(scanned)
    platform_detected = tp.grok_home.exists() or grok_sessions.exists()

    envelope = make_envelope(
        COLLECTOR,
        __version__,
        scope_hash,
        platform_detected=platform_detected,
    )

    if not platform_detected:
        envelope["summary"] = {
            "session_count": 0,
            "rules": 0,
            "mcp_runtime_servers": 0,
            "mcp_servers": 0,
        }
        return envelope

    rules: list[dict] = []
    findings: list[dict] = []
    seen_finding_ids: set[str] = set()

    def _add_findings(items: list[dict]) -> None:
        for f in items:
            fid = str(f.get("id") or "")
            if fid and fid in seen_finding_ids:
                continue
            if fid:
                seen_finding_ids.add(fid)
            findings.append(f)

    config_toml_parsed = False
    config_extras: dict = {}
    if config_toml.exists():
        try:
            with open(config_toml, "rb") as f:
                config_data = tomllib.load(f)
            config_rules, config_findings, config_extras = parse_config_toml(config_data)
            rules.extend(config_rules)
            _add_findings(config_findings)
            config_toml_parsed = True
        except (tomllib.TOMLDecodeError, OSError):
            pass

    project_config_parsed = 0
    for pcfg in project_configs:
        try:
            with open(pcfg, "rb") as f:
                project_data = tomllib.load(f)
            project_rules, project_findings, _ = parse_config_toml(project_data)
            for r in project_rules:
                r["scope"] = "project"
                if not r.get("settings_source"):
                    r["settings_source"] = "project config.toml"
            rules.extend(project_rules)
            _add_findings(project_findings)
            project_config_parsed += 1
        except (tomllib.TOMLDecodeError, OSError):
            continue

    session_summary, session_findings, runtime_mcp_rules = collect_session_inventory(
        grok_sessions
    )
    _add_findings(session_findings)
    rules.extend(runtime_mcp_rules)

    config_mcp = int(config_extras.get("mcp_servers") or 0)
    runtime_mcp = int(session_summary.get("mcp_runtime_servers") or 0)
    if runtime_mcp and not config_mcp:
        _add_findings(
            [
                make_finding(
                    "grok.mcp.runtime_only",
                    "medium",
                    "MCP Tooling",
                    f"Grok resolved {runtime_mcp} MCP server(s) at runtime with none in config.toml",
                    evidence_count=runtime_mcp,
                    tags=["mcp_runtime"],
                )
            ]
        )

    if auth_json.exists():
        _add_findings(
            [
                make_finding(
                    "grok.auth.present_excluded",
                    "low",
                    "Identity & SSO",
                    "Grok auth.json present (contents excluded from collection)",
                    tags=["auth_excluded"],
                )
            ]
        )

    log_meta = collect_log_metadata(tp.grok_logs)

    envelope["rules"] = rules
    envelope["findings"] = findings
    envelope["summary"] = {
        "config_toml_exists": config_toml.exists(),
        "config_toml_parsed": config_toml_parsed,
        "project_config_present": bool(project_configs),
        "project_config_parsed": project_config_parsed > 0,
        "project_configs_scanned": len(project_configs),
        "permission_mode": config_extras.get("permission_mode", "unset"),
        "yolo": config_extras.get("yolo", False),
        "mcp_servers": config_mcp,
        "permission_allow_rules": config_extras.get("permission_allow_rules", 0),
        "permission_deny_rules": config_extras.get("permission_deny_rules", 0),
        "permission_ask_rules": config_extras.get("permission_ask_rules", 0),
        "subagents_configured": config_extras.get("subagents_configured", False),
        "memory_configured": config_extras.get("memory_configured", False),
        "auth_json_exists": auth_json.exists(),
        "rules": len(rules),
        "findings": len(findings),
        **session_summary,
        **log_meta,
    }
    return envelope


def main() -> None:
    parser = argparse.ArgumentParser(description="Grok Build permission collector")
    add_base_args(parser)
    paths.add_path_args(parser)
    parser.add_argument(
        "--repo-roots",
        default=None,
        help="Comma-separated repo scan roots for project .grok/config.toml "
        "(default: ~/repos,~/code,~/src,~/projects,~/source)",
    )
    args = parser.parse_args()
    evidence_root = validate_evidence_root(args.evidence_root)
    tp = paths.resolve_from_args(args)

    if args.repo_roots:
        repo_roots = [Path(p.strip()) for p in args.repo_roots.split(",") if p.strip()]
    else:
        repo_roots = default_repo_roots()

    envelope = collect(tp, repo_roots=repo_roots)
    if not envelope["platform_detected"]:
        finish_collector(envelope, evidence_root, dry_run=args.dry_run)
        sys.exit(2)

    finish_collector(envelope, evidence_root, dry_run=args.dry_run)
    sys.exit(0)


if __name__ == "__main__":
    main()
