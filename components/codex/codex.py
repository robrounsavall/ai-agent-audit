"""
Codex permission and session collector.

Usage:
    python codex.py --evidence-root ./audit-run [--dry-run]

Reads ~/.codex/sessions JSONL rollouts for approval requests and approved prefixes.
Checks config.toml and auth.json for presence (not token values).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import paths
from common import (
    add_base_args,
    classify_rule,
    compute_scope_hash,
    finish_collector,
    iter_jsonl,
    make_envelope,
    make_finding,
    make_rule,
    nested_text,
    parse_iso,
    secret_types_in,
    sha256_short,
    validate_evidence_root,
)

__version__ = "1.1.0"

COLLECTOR = "codex"

NETWORK_RE = re.compile(r"network|curl|wget|fetch|http", re.I)
SANDBOX_BYPASS_RE = re.compile(r"require_escalated|sandbox.?bypass|no.?sandbox", re.I)
WRITE_OUTSIDE_RE = re.compile(r"\.\./|/(tmp|etc|home|users)/", re.I)


def safe_url(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parts = urlsplit(text)
    except ValueError:
        return text[:160]
    if not parts.scheme or not parts.netloc:
        return text[:160]
    host = parts.hostname or parts.netloc
    if parts.port:
        host = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, host, parts.path.rstrip("/"), "", ""))


def _find_endpoint(value) -> str:
    if isinstance(value, str):
        return safe_url(value) if value.lower().startswith(("http://", "https://", "grpc://")) else ""
    if isinstance(value, dict):
        for key in ("endpoint", "url", "otlp_endpoint", "trace_endpoint", "traces_endpoint"):
            endpoint = _find_endpoint(value.get(key))
            if endpoint:
                return endpoint
        for key, child in value.items():
            if str(key).lower() in ("headers", "authorization", "token", "api_key"):
                continue
            endpoint = _find_endpoint(child)
            if endpoint:
                return endpoint
    return ""


def otel_exporter_summary(otel: dict) -> dict[str, str | bool]:
    exporter = otel.get("exporter", {}) if isinstance(otel, dict) else {}
    destination = _find_endpoint(exporter)
    protocol = str(
        otel.get("protocol")
        or (exporter.get("protocol") if isinstance(exporter, dict) else "")
        or ""
    )
    exporter_type = ""
    if isinstance(exporter, dict):
        explicit_type = exporter.get("type") or exporter.get("kind")
        if explicit_type:
            exporter_type = str(explicit_type)
        else:
            exporter_type = ",".join(sorted(str(k) for k in exporter.keys() if str(k).lower() != "headers"))
    return {
        "destination": destination,
        "protocol": protocol,
        "exporter_type": exporter_type,
        "headers_configured": "headers" in exporter if isinstance(exporter, dict) else False,
    }


def parse_approved_prefixes(text: str) -> list[str]:
    """
    Extract approved command prefixes from structured JSON array only.

    Finds "Approved command prefixes" marker (case-insensitive), then expects
    a JSON array. Uses balanced-bracket extraction to handle arrays with
    quoted strings and nesting. Returns structured prefixes, de-duplicated,
    with empties filtered. A JSON array of argv tokens such as
    ["docker", "compose"] is one prefix, rendered as "docker compose *".
    A JSON array of full string prefixes such as ["git status", "npm test"]
    remains two prefixes. Returns [] if no valid JSON array is found.
    Deliberately does NOT promote prose, markdown, or line-by-line fallback
    into rules.
    """
    prefixes: list[str] = []

    # Find the marker (case-insensitive)
    marker_match = re.search(r"Approved command prefixes", text, re.I)
    if not marker_match:
        return []

    # Start searching after the marker for the opening bracket
    search_start = marker_match.end()
    after_marker = text[search_start:]

    # Skip past optional : or = and whitespace
    after_marker_stripped = re.sub(r'^[\s:=]*', '', after_marker)
    bracket_pos = after_marker_stripped.find('[')

    if bracket_pos == -1:
        # No opening bracket found; return empty instead of falling back to prose
        return []

    # Extract balanced bracket JSON array
    open_bracket_pos = search_start + len(after_marker) - len(after_marker_stripped) + bracket_pos
    json_str = extract_balanced_array(text, open_bracket_pos)

    if not json_str:
        return []

    try:
        arr = json.loads(json_str)
        if isinstance(arr, list):
            prefixes = normalize_prefix_array(arr)
    except json.JSONDecodeError:
        # Invalid JSON; return empty
        pass

    return prefixes


def normalize_prefix_array(arr: list) -> list[str]:
    """Normalize structured approved-prefix JSON into displayable prefixes."""
    prefixes: list[str] = []
    seen: set[str] = set()

    def add(prefix: str) -> None:
        prefix = prefix.strip()
        if prefix and prefix not in seen:
            prefixes.append(prefix)
            seen.add(prefix)

    def argv_prefix(items: list[str]) -> str:
        return " ".join(item.strip() for item in items if item.strip()) + " *"

    def looks_like_argv_prefix(items: list[str]) -> bool:
        if len(items) <= 1:
            return False
        first = items[0].strip().lower()
        if "\\" in first or "/" in first or first.endswith(".exe"):
            return True
        if any(item.strip().startswith("-") for item in items[1:]):
            return True
        return all(not re.search(r"\s", item) for item in items)

    string_items = [item for item in arr if isinstance(item, str) and item.strip()]
    list_items = [item for item in arr if isinstance(item, list)]

    if list_items:
        for item in list_items:
            parts = [part for part in item if isinstance(part, str) and part.strip()]
            if parts:
                add(argv_prefix(parts))
        for item in string_items:
            add(item)
        return prefixes

    if string_items and len(string_items) == len(arr):
        # ["docker", "compose"] and ["powershell.exe", "-Command", "..."]
        # are argv prefixes; ["git status", "npm test"] is a list of
        # already-rendered prefix strings.
        if looks_like_argv_prefix(string_items):
            add(argv_prefix(string_items))
        else:
            for item in string_items:
                add(item)
        return prefixes

    for item in string_items:
        add(item)
    return prefixes


def extract_balanced_array(text: str, start_pos: int) -> str:
    """
    Extract a balanced JSON array starting at start_pos.

    Scans from text[start_pos] (should be '[') to find the matching ']',
    handling nested structures and quoted strings correctly.
    Returns the substring from '[' to ']' inclusive, or empty string if
    the closing bracket is not found.
    """
    if start_pos >= len(text) or text[start_pos] != '[':
        return ""

    depth = 0
    in_string = False
    escape_next = False

    for i in range(start_pos, len(text)):
        char = text[i]

        if escape_next:
            escape_next = False
            continue

        if char == '\\':
            escape_next = True
            continue

        if char == '"' and not escape_next:
            in_string = not in_string
            continue

        if in_string:
            continue

        if char == '[':
            depth += 1
        elif char == ']':
            depth -= 1
            if depth == 0:
                return text[start_pos:i+1]

    # Closing bracket not found
    return ""


def _is_localhost(url: str) -> bool:
    """Check if URL is localhost or loopback."""
    if not url:
        return False
    lower = url.lower()
    return any(
        host in lower
        for host in ["localhost", "127.0.0.1", "::1"]
    )


def parse_config_toml(data: dict) -> tuple[list[dict], list[dict]]:
    """
    Parse config.toml dict into rules and findings.

    Returns (rules, findings) tuples. Rules are only for genuine grants
    (trusted projects, MCP servers, auto-approve apps). All other posture
    is findings. Every rule stamped source_kind="user_config".
    """
    rules: list[dict] = []
    findings: list[dict] = []

    if not data:
        return ([], [])

    # Sandbox mode
    sandbox_mode = data.get("sandbox_mode", "")
    if sandbox_mode == "danger-full-access":
        findings.append(
            make_finding(
                "codex.sandbox.full_access",
                "critical",
                "Shell Execution",
                "Codex sandbox_mode set to danger-full-access",
            )
        )

    # Approval policy
    approval_policy = data.get("approval_policy")
    if approval_policy == "never":
        findings.append(
            make_finding(
                "codex.approval.never",
                "critical",
                "Shell Execution",
                "Codex approval_policy set to never",
            )
        )
    elif isinstance(approval_policy, dict):
        request_perms = approval_policy.get("request_permissions", True)
        sandbox_approval = approval_policy.get("sandbox_approval", True)
        if not request_perms or not sandbox_approval:
            findings.append(
                make_finding(
                    "codex.approval.never",
                    "critical",
                    "Shell Execution",
                    "Codex approval_policy granular disables permission gate",
                )
            )

    # Workspace write network access
    if sandbox_mode == "workspace-write":
        workspace_write = data.get("sandbox_workspace_write", {})
        if isinstance(workspace_write, dict):
            if workspace_write.get("network_access"):
                findings.append(
                    make_finding(
                        "codex.network.workspace_write",
                        "high",
                        "Network Egress",
                        "Codex sandbox_workspace_write has network_access enabled",
                    )
                )

    # Shell environment policy
    shell_env = data.get("shell_environment_policy", {})
    if isinstance(shell_env, dict):
        if shell_env.get("inherit") == "all":
            findings.append(
                make_finding(
                    "codex.env.inherit_all",
                    "high",
                    "Secrets Exposure",
                    "Codex shell_environment_policy inherits all environment variables",
                )
            )
        if shell_env.get("ignore_default_excludes"):
            findings.append(
                make_finding(
                    "codex.env.ignore_excludes",
                    "high",
                    "Secrets Exposure",
                    "Codex shell_environment_policy ignores default secret exclusions",
                )
            )

    # Trusted projects
    projects = data.get("projects", {})
    if isinstance(projects, dict):
        trusted_count = 0
        for project_path, project_config in projects.items():
            if isinstance(project_config, dict):
                trust_level = project_config.get("trust_level")
                if trust_level == "trusted":
                    trusted_count += 1
                    rules.append(
                        make_rule(
                            "codex",
                            "user",
                            project_path,
                            "other",
                            "trust_level=trusted",
                            "allow",
                            source_kind="user_config",
                            confidence="high",
                            risk="medium",
                        )
                    )
        if trusted_count > 3:
            findings.append(
                make_finding(
                    "codex.trust.broad",
                    "medium",
                    "General Tooling",
                    f"Codex has {trusted_count} trusted projects",
                    evidence_count=trusted_count,
                )
            )

    # MCP servers
    mcp_servers = data.get("mcp_servers", {})
    if isinstance(mcp_servers, dict):
        for server_id, server_config in mcp_servers.items():
            if isinstance(server_config, dict):
                # Always emit a rule for the server
                rules.append(
                    make_rule(
                        "codex",
                        "user",
                        server_id,
                        "mcp_tool",
                        f"mcp__{server_id}",
                        "allow",
                        command_or_tool=server_id,
                        source_kind="user_config",
                        confidence="high",
                        risk="medium",
                    )
                )

                # External server finding
                url = server_config.get("url", "")
                if url and not _is_localhost(url):
                    findings.append(
                        make_finding(
                            "codex.mcp.external_server",
                            "high",
                            "MCP Tooling",
                            f"MCP server {server_id} has external URL",
                        )
                    )

                # Environment variable secrets
                env_vars = server_config.get("env", {})
                if isinstance(env_vars, dict):
                    for env_key, env_val in env_vars.items():
                        if isinstance(env_val, str):
                            secret_types = secret_types_in(env_val)
                            if secret_types:
                                findings.append(
                                    make_finding(
                                        "codex.mcp.env_secret",
                                        "critical",
                                        "Secrets Exposure",
                                        f"MCP server {server_id} env contains secrets",
                                        secret_redacted=True,
                                    )
                                )

    # Apps
    apps = data.get("apps", {})
    if isinstance(apps, dict):
        for app_id, app_config in apps.items():
            if isinstance(app_config, dict):
                # Auto-approve finding and rule
                if app_config.get("default_tools_approval_mode") == "auto":
                    findings.append(
                        make_finding(
                            "codex.apps.auto_approve",
                            "high",
                            "General Tooling",
                            f"App {app_id} has auto approval mode",
                        )
                    )
                    rules.append(
                        make_rule(
                            "codex",
                            "user",
                            app_id,
                            "other",
                            f"app__{app_id}__auto_approve",
                            "allow",
                            command_or_tool=app_id,
                            source_kind="user_config",
                            confidence="high",
                            risk="medium",
                        )
                    )

                # Destructive enabled finding
                if app_config.get("destructive_enabled"):
                    findings.append(
                        make_finding(
                            "codex.apps.destructive",
                            "high",
                            "General Tooling",
                            f"App {app_id} has destructive_enabled",
                        )
                    )

                # Open world enabled finding
                if app_config.get("open_world_enabled"):
                    findings.append(
                        make_finding(
                            "codex.apps.open_world",
                            "high",
                            "General Tooling",
                            f"App {app_id} has open_world_enabled",
                        )
                    )

    # OpenTelemetry
    otel = data.get("otel", {})
    if isinstance(otel, dict):
        if otel.get("log_user_prompt"):
            exporter = otel.get("exporter", {})
            if isinstance(exporter, dict) and exporter:
                otel_summary = otel_exporter_summary(otel)
                destination = otel_summary.get("destination") or "destination not recorded"
                findings.append(
                    make_finding(
                        "codex.telemetry.log_user_prompt_configured",
                        "high",
                        "Telemetry Configuration",
                        "Codex configured to export user prompts via telemetry",
                        sample_redacted=f"destination={destination}",
                    )
                )

    # Hooks
    hooks = data.get("hooks", {})
    if isinstance(hooks, dict):
        for hook_key, hook_list in hooks.items():
            if isinstance(hook_list, list) and hook_list:
                severity = "high" if hook_key in ("PreToolUse", "PermissionRequest") else "medium"
                findings.append(
                    make_finding(
                        "codex.hooks.lifecycle_command",
                        severity,
                        "Shell Execution",
                        f"Codex hook {hook_key} configured with command",
                    )
                )

    return (rules, findings)


def detect_auth_method(auth_json: Path) -> str:
    if not auth_json.exists():
        return "unknown"
    data = None
    try:
        data = json.loads(auth_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "present"
    if isinstance(data, dict):
        if "tokens" in data or "access_token" in data:
            return "oauth_or_pat"
        if "api_key" in data:
            return "api_key"
    return "present"


def collect(tp: paths.ToolPaths) -> dict:
    codex_sessions = tp.codex_sessions
    config_toml = tp.codex_config
    auth_json = tp.codex_auth
    scanned = [str(codex_sessions), str(config_toml), str(auth_json)]
    scope_hash = compute_scope_hash(scanned)
    platform_detected = tp.codex_home.exists() or codex_sessions.exists()

    envelope = make_envelope(
        COLLECTOR,
        __version__,
        scope_hash,
        platform_detected=platform_detected,
    )

    if not platform_detected:
        envelope["summary"] = {"session_files": 0, "rules": 0}
        return envelope

    rules: list[dict] = []
    findings: list[dict] = []
    seen_rules: set[str] = set()
    approval_count = 0
    session_files = 0
    seen_prefix_blocks: set[str] = set()

    # Repeated session approval events collapse into one finding per id, with
    # evidence_count and a first/last span, so the briefing stays readable.
    event_findings: dict[str, dict] = {}

    def add_event(finding_id, severity, category, title, sample, ts, tags):
        agg = event_findings.get(finding_id)
        if agg is None:
            event_findings[finding_id] = {
                "severity": severity,
                "category": category,
                "title": title,
                "sample": sample,
                "tags": tags,
                "count": 1,
                "first": ts,
                "last": ts,
            }
            return
        agg["count"] += 1
        if ts:
            if not agg["first"] or ts < agg["first"]:
                agg["first"] = ts
            if not agg["last"] or ts > agg["last"]:
                agg["last"] = ts

    if codex_sessions.exists():
        for jsonl in codex_sessions.rglob("*.jsonl"):
            session_files += 1
            for line_no, obj in iter_jsonl(jsonl):
                ts = parse_iso(obj.get("timestamp"))
                payload = obj.get("payload", {})

                if isinstance(payload, dict) and payload.get("type") == "function_call":
                    args_raw = payload.get("arguments", "")
                    args: dict = {}
                    if isinstance(args_raw, str):
                        try:
                            args = json.loads(args_raw)
                        except json.JSONDecodeError:
                            args = {}
                    elif isinstance(args_raw, dict):
                        args = args_raw

                    sandbox = str(args.get("sandbox_permissions", ""))
                    prefix_rule = args.get("prefix_rule", "")
                    command = str(args.get("command", payload.get("name", "")))

                    if sandbox == "require_escalated" or prefix_rule:
                        approval_count += 1
                        if SANDBOX_BYPASS_RE.search(sandbox + command):
                            add_event(
                                "codex.sandbox.require_escalated",
                                "high",
                                "Shell Execution",
                                "Codex approval request escalated sandbox permissions",
                                command[:80] if command else "require_escalated",
                                ts,
                                ["unbounded_glob"],
                            )
                        if prefix_rule and str(prefix_rule) not in seen_rules:
                            seen_rules.add(str(prefix_rule))
                            rule_type, cmd, _ = classify_rule(str(prefix_rule))
                            rules.append(
                                make_rule(
                                    "codex",
                                    "user",
                                    "session",
                                    rule_type,
                                    str(prefix_rule),
                                    "allow",
                                    command_or_tool=cmd,
                                    source_kind="session_event",
                                    confidence="observed_event",
                                )
                            )
                        if NETWORK_RE.search(command):
                            add_event(
                                "codex.network.escalated",
                                "high",
                                "Network Egress",
                                "Codex escalated approval for network command",
                                command[:80],
                                ts,
                                ["network_egress"],
                            )
                        if WRITE_OUTSIDE_RE.search(command):
                            add_event(
                                "codex.write.outside_root",
                                "high",
                                "Data Access",
                                "Codex command may write outside project root",
                                command[:80],
                                ts,
                                ["env_read"],
                            )

                text = nested_text(obj)
                if "Approved command prefixes" in text:
                    block_key = sha256_short(text[:500]) if len(text) > 500 else text[:200]
                    if block_key in seen_prefix_blocks:
                        continue
                    seen_prefix_blocks.add(block_key)
                    for prefix in parse_approved_prefixes(text):
                        if prefix in seen_rules:
                            continue
                        seen_rules.add(prefix)
                        rule_type, cmd, _ = classify_rule(prefix)
                        rules.append(
                            make_rule(
                                "codex",
                                "user",
                                "session_snapshot",
                                rule_type,
                                prefix,
                                "allow",
                                command_or_tool=cmd,
                                source_kind="session_prefix",
                                confidence="medium",
                            )
                        )

    # Flush aggregated session events: one finding per id with evidence_count.
    for finding_id, agg in event_findings.items():
        findings.append(
            make_finding(
                finding_id,
                agg["severity"],
                agg["category"],
                agg["title"],
                evidence_count=agg["count"],
                first_seen=agg["first"],
                last_seen=agg["last"],
                sample_redacted=agg["sample"],
                tags=agg["tags"],
            )
        )

    # Parse config.toml if present
    config_toml_parsed = False
    trusted_projects = 0
    mcp_servers = 0
    sandbox_mode = "unset"
    approval_policy = "unset"
    otel_log_user_prompt_configured = False
    otel_exporter_destination = ""
    otel_exporter_protocol = ""
    otel_exporter_type = ""
    otel_exporter_headers_configured = False

    if config_toml.exists():
        try:
            with open(config_toml, "rb") as f:
                config_data = tomllib.load(f)
            config_rules, config_findings = parse_config_toml(config_data)
            rules.extend(config_rules)
            findings.extend(config_findings)
            config_toml_parsed = True

            # Extract summary stats from config
            projects = config_data.get("projects", {})
            if isinstance(projects, dict):
                trusted_projects = sum(
                    1 for p in projects.values()
                    if isinstance(p, dict) and p.get("trust_level") == "trusted"
                )

            mcp = config_data.get("mcp_servers", {})
            if isinstance(mcp, dict):
                mcp_servers = len(mcp)

            sandbox_mode = config_data.get("sandbox_mode", "unset")
            approval_policy = config_data.get("approval_policy", "unset")
            if isinstance(approval_policy, dict):
                approval_policy = "granular"

            otel = config_data.get("otel", {})
            if isinstance(otel, dict):
                if otel.get("log_user_prompt"):
                    exporter = otel.get("exporter", {})
                    if isinstance(exporter, dict) and exporter:
                        otel_log_user_prompt_configured = True
                        otel_summary = otel_exporter_summary(otel)
                        otel_exporter_destination = str(otel_summary.get("destination") or "")
                        otel_exporter_protocol = str(otel_summary.get("protocol") or "")
                        otel_exporter_type = str(otel_summary.get("exporter_type") or "")
                        otel_exporter_headers_configured = bool(
                            otel_summary.get("headers_configured")
                        )
        except (tomllib.TOMLDecodeError, OSError):
            # Skip on parse error or file access error
            pass

    auth_method = detect_auth_method(auth_json)
    envelope["rules"] = rules
    envelope["findings"] = findings
    envelope["summary"] = {
        "session_files": session_files,
        "rules": len(rules),
        "approval_requests": approval_count,
        "findings": len(findings),
        "config_toml_parsed": config_toml_parsed,
        "trusted_projects": trusted_projects,
        "mcp_servers": mcp_servers,
        "sandbox_mode": sandbox_mode,
        "approval_policy": approval_policy,
        "otel_log_user_prompt_configured": otel_log_user_prompt_configured,
        "otel_exporter_destination": otel_exporter_destination,
        "otel_exporter_protocol": otel_exporter_protocol,
        "otel_exporter_type": otel_exporter_type,
        "otel_exporter_headers_configured": otel_exporter_headers_configured,
        "config_toml_exists": config_toml.exists(),
        "auth_json_exists": auth_json.exists(),
        "auth_method": auth_method,
    }
    return envelope


def main() -> None:
    parser = argparse.ArgumentParser(description="Codex permission collector")
    add_base_args(parser)
    paths.add_path_args(parser)
    args = parser.parse_args()
    evidence_root = validate_evidence_root(args.evidence_root)
    tp = paths.resolve_from_args(args)

    envelope = collect(tp)
    if not envelope["platform_detected"]:
        finish_collector(envelope, evidence_root, dry_run=args.dry_run)
        sys.exit(2)

    finish_collector(envelope, evidence_root, dry_run=args.dry_run)
    sys.exit(0)


if __name__ == "__main__":
    main()
