"""
Claude permission and settings collector.

Usage:
    python claude.py --evidence-root ./audit-run [--scope all] [--dry-run]

Reads ~/.claude/settings.json, settings.local.json, and project-level
.claude/settings.local.json files. Emits permission rules and security findings.

Also reads the Claude desktop app MCP registry (%APPDATA%/Claude/
claude_desktop_config.json) and flags ~/.claude side artifacts that persist
user content outside the transcript store: history.jsonl (global prompt
history), file-history/ (pre-edit file snapshots), bash-audit.log (shell
command log).
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

try:
    import winreg
except ImportError:  # pragma: no cover - non-Windows fallback
    winreg = None

import paths
from common import (
    APPDATA,
    add_base_args,
    classify_rule,
    compute_scope_hash,
    finish_collector,
    load_json,
    make_envelope,
    make_finding,
    make_rule,
    secret_types_in,
    validate_evidence_root,
)

__version__ = "1.1.0"

COLLECTOR = "claude"

LOCALHOST_RE = re.compile(r"localhost|127\.0\.0\.1|::1", re.I)
WILDCARD_BASH_RE = re.compile(r"^Bash\([^)]*\*[^)]*\)$", re.I)
CURL_WGET_RE = re.compile(r"^Bash\((curl|wget)\s*[:*]", re.I)
OTEL_KEYS = {
    "CLAUDE_CODE_ENABLE_TELEMETRY",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_EXPORTER_OTLP_PROTOCOL",
    "OTEL_SERVICE_NAME",
}


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


def truthy(value: object) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def read_registry_env(root, path: str) -> dict[str, str]:
    if winreg is None:
        return {}
    found: dict[str, str] = {}
    try:
        with winreg.OpenKey(root, path) as key:
            for name in OTEL_KEYS | {"OTEL_EXPORTER_OTLP_HEADERS"}:
                try:
                    value, _ = winreg.QueryValueEx(key, name)
                    found[name] = str(value)
                except OSError:
                    continue
    except OSError:
        return {}
    return found


def local_otel_env_sources(settings_envs: list[tuple[str, dict]]) -> list[tuple[str, dict[str, str]]]:
    sources: list[tuple[str, dict[str, str]]] = []
    process = {
        key: os.environ.get(key, "")
        for key in OTEL_KEYS | {"OTEL_EXPORTER_OTLP_HEADERS"}
        if os.environ.get(key)
    }
    if process:
        sources.append(("process env", process))

    if winreg is not None and sys.platform == "win32":
        user_env = read_registry_env(winreg.HKEY_CURRENT_USER, "Environment")
        if user_env:
            sources.append(("user env", user_env))
        machine_env = read_registry_env(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        )
        if machine_env:
            sources.append(("machine env", machine_env))

    for label, env in settings_envs:
        scoped = {
            key: str(value)
            for key, value in env.items()
            if key in OTEL_KEYS or key == "OTEL_EXPORTER_OTLP_HEADERS"
        }
        if scoped:
            sources.append((label, scoped))
    return sources


def claude_otel_summary(settings_envs: list[tuple[str, dict]]) -> dict[str, object]:
    enabled = False
    destination = ""
    protocol = ""
    service_name = ""
    headers_configured = False
    source_labels: list[str] = []

    for label, env in local_otel_env_sources(settings_envs):
        source_labels.append(label)
        enabled = enabled or truthy(env.get("CLAUDE_CODE_ENABLE_TELEMETRY"))
        destination = destination or safe_url(
            str(env.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") or env.get("OTEL_EXPORTER_OTLP_ENDPOINT") or "")
        )
        protocol = protocol or str(env.get("OTEL_EXPORTER_OTLP_PROTOCOL") or "")
        service_name = service_name or str(env.get("OTEL_SERVICE_NAME") or "")
        headers_configured = headers_configured or bool(env.get("OTEL_EXPORTER_OTLP_HEADERS"))

    return {
        "enabled": enabled,
        "destination": destination,
        "protocol": protocol,
        "service_name": service_name,
        "headers_configured": headers_configured,
        "sources": sorted(set(source_labels)),
    }


def scope_matches(scope_filter: str, scope: str) -> bool:
    if scope_filter == "all":
        return True
    if scope_filter == "user":
        return scope in ("user", "global")
    if scope_filter == "workspace":
        return scope in ("workspace", "project")
    return True


def discover_settings(
    scope_filter: str, claude_home: Path, claude_projects: Path
) -> list[tuple[str, str, Path]]:
    """Return (scope, scope_label, path) tuples."""
    found: list[tuple[str, str, Path]] = []
    for name, scope in (("settings.json", "user"), ("settings.local.json", "user")):
        path = claude_home / name
        if path.exists() and scope_matches(scope_filter, scope):
            found.append((scope, "global", path))

    if claude_projects.exists() and scope_matches(scope_filter, "workspace"):
        for path in claude_projects.rglob("settings.local.json"):
            if ".claude" not in path.parts:
                continue
            try:
                rel = path.relative_to(claude_projects)
                label = rel.parts[0] if rel.parts else "project"
            except ValueError:
                label = "project"
            found.append(("project", label, path))
    return found


def extract_rules_from_settings(
    scope: str,
    scope_label: str,
    data: dict,
    source_path: Path,
) -> tuple[list[dict], list[dict]]:
    rules: list[dict] = []
    findings: list[dict] = []
    if scope == "project":
        settings_source = "project settings.local.json"
        source_kind = "project_config"
    else:
        settings_source = source_path.name
        source_kind = "user_config"

    permissions = data.get("permissions", {})
    if isinstance(permissions, dict):
        for decision in ("allow", "deny", "ask"):
            items = permissions.get(decision, [])
            if not isinstance(items, list):
                continue
            for rule in items:
                if not isinstance(rule, str):
                    continue
                rule_type, command, _ = classify_rule(rule)
                rules.append(
                    make_rule(
                        "claude",
                        scope,
                        scope_label,
                        rule_type,
                        rule,
                        decision,
                        command_or_tool=command,
                        source_kind=source_kind,
                        settings_source=settings_source,
                        confidence="high",
                    )
                )
                if decision == "allow" and WILDCARD_BASH_RE.match(rule):
                    findings.append(
                        make_finding(
                            "claude.permission.bash_wildcard",
                            "high",
                            "Shell Execution",
                            "Claude has wildcard bash allow rule",
                            sample_redacted=rule,
                            tags=["unbounded_glob"],
                        )
                    )
                if decision == "allow" and CURL_WGET_RE.match(rule):
                    findings.append(
                        make_finding(
                            "claude.permission.bash_curl_wide",
                            "high",
                            "Network Egress",
                            "Claude has unrestricted curl/wget approval",
                            sample_redacted=rule,
                            tags=["network_egress"],
                        )
                    )

    default_mode = data.get("defaultMode") or data.get("permissionMode") or ""
    if str(default_mode).lower() in ("bypasspermissions", "bypass"):
        findings.append(
            make_finding(
                "claude.permission.bypass_mode",
                "critical",
                "Shell Execution",
                "Claude default permission mode bypasses prompts",
                sample_redacted=f"defaultMode={default_mode}",
                tags=["unbounded_glob"],
            )
        )

    if data.get("skipDangerousModePermissionPrompt") is True:
        findings.append(
            make_finding(
                "claude.permission.skip_dangerous_prompt",
                "high",
                "Shell Execution",
                "Claude dangerous-mode confirmation prompt is disabled",
                sample_redacted="skipDangerousModePermissionPrompt=true",
                tags=["dangerous_mode_prompt_disabled"],
            )
        )

    env = data.get("env", {})
    if isinstance(env, dict):
        for key, value in env.items():
            val_str = str(value)
            if secret_types_in(val_str):
                findings.append(
                    make_finding(
                        "claude.env.secret_value",
                        "critical",
                        "Secrets Exposure",
                        "Claude env var appears to contain a secret",
                        sample_redacted=f"{key}=${'{'}VAR{'}'}",
                        secret_redacted=True,
                        tags=["env_read"],
                    )
                )

    mcp_servers = data.get("mcpServers") or data.get("enabledMcpjsonServers") or {}
    if isinstance(mcp_servers, dict):
        for server_name, config in mcp_servers.items():
            config_text = str(config)
            if config_text and not LOCALHOST_RE.search(config_text):
                if "url" in config_text.lower() or "http" in config_text.lower():
                    findings.append(
                        make_finding(
                            "claude.mcp.external_server",
                            "high",
                            "MCP Tooling",
                            "Claude MCP server may point outside localhost",
                            sample_redacted=f"mcpServers.{server_name}",
                            tags=["mcp_external"],
                        )
                    )
            if isinstance(config, dict):
                rules.append(
                    make_rule(
                        "claude",
                        scope,
                        scope_label,
                        "mcp_tool",
                        f"mcp__{server_name}",
                        "allow",
                        command_or_tool=server_name,
                        risk="medium",
                        source_kind=source_kind,
                        settings_source=settings_source,
                        confidence="high",
                    )
                )
    elif isinstance(mcp_servers, list):
        for server in mcp_servers:
            if isinstance(server, str):
                rules.append(
                    make_rule(
                        "claude",
                        scope,
                        scope_label,
                        "mcp_tool",
                        server,
                        "allow",
                        command_or_tool=server,
                        risk="medium",
                        source_kind=source_kind,
                        settings_source=settings_source,
                        confidence="high",
                    )
                )

    return rules, findings


def desktop_config_path() -> Path:
    return APPDATA / "Claude" / "claude_desktop_config.json"


def collect_desktop_mcp(config_path: Path) -> tuple[list[dict], list[dict], int]:
    """Parse mcpServers from the Claude desktop app config, if present."""
    if not config_path.exists():
        return [], [], 0
    data = load_json(config_path)
    servers = (data or {}).get("mcpServers")
    if not isinstance(servers, dict) or not servers:
        return [], [], 0
    rules, findings = extract_rules_from_settings(
        "user", "desktop", {"mcpServers": servers}, config_path
    )
    return rules, findings, len(servers)


def scan_side_artifacts(claude_home: Path) -> list[dict]:
    """Flag ~/.claude artifacts that persist user content outside transcripts."""
    findings: list[dict] = []

    history = claude_home / "history.jsonl"
    try:
        history_kb = history.stat().st_size // 1024 if history.exists() else 0
    except OSError:
        history_kb = 0
    if history_kb > 0:
        findings.append(
            make_finding(
                "claude.history.global_prompt_log",
                "medium",
                "Cross-Agent Visibility",
                "Global prompt history persists in ~/.claude/history.jsonl",
                sample_redacted=f"size_kb={history_kb}",
                tags=["history_retention"],
            )
        )

    file_history = claude_home / "file-history"
    snapshot_count = 0
    snapshot_bytes = 0
    if file_history.exists():
        for p in file_history.rglob("*"):
            if p.is_file():
                snapshot_count += 1
                try:
                    snapshot_bytes += p.stat().st_size
                except OSError:
                    continue
    if snapshot_count > 0:
        findings.append(
            make_finding(
                "claude.file_history.snapshots",
                "medium",
                "Cross-Agent Visibility",
                "Pre-edit file snapshots persist under ~/.claude/file-history",
                evidence_count=snapshot_count,
                sample_redacted=f"files={snapshot_count}; size_mb={snapshot_bytes // (1024 * 1024)}",
                tags=["history_retention"],
            )
        )

    bash_audit = claude_home / "bash-audit.log"
    try:
        audit_kb = bash_audit.stat().st_size // 1024 if bash_audit.exists() else 0
    except OSError:
        audit_kb = 0
    if audit_kb > 0:
        findings.append(
            make_finding(
                "claude.shell_audit.log_present",
                "low",
                "Cross-Agent Visibility",
                "Shell command audit log persists in ~/.claude/bash-audit.log",
                sample_redacted=f"size_kb={audit_kb}",
                tags=["history_retention"],
            )
        )

    return findings


def collect(scope_filter: str, tp: paths.ToolPaths) -> dict:
    settings_files = discover_settings(scope_filter, tp.claude_home, tp.claude_projects)
    desktop_config = desktop_config_path()
    scanned_paths = [str(p) for _, _, p in settings_files]
    if desktop_config.exists():
        scanned_paths.append(str(desktop_config))
    scope_hash = compute_scope_hash(scanned_paths or [str(tp.claude_home)])

    platform_detected = tp.claude_home.exists()
    envelope = make_envelope(
        COLLECTOR,
        __version__,
        scope_hash,
        platform_detected=platform_detected,
    )

    if not platform_detected:
        envelope["summary"] = {"settings_files": 0, "rules": 0, "findings": 0}
        return envelope

    all_rules: list[dict] = []
    all_findings: list[dict] = []
    seen_finding_ids: set[str] = set()
    settings_envs: list[tuple[str, dict]] = []

    for scope, scope_label, path in settings_files:
        data = load_json(path)
        if not data:
            continue
        env = data.get("env", {})
        if isinstance(env, dict):
            settings_envs.append((f"{scope} {path.name}", env))
        rules, findings = extract_rules_from_settings(scope, scope_label, data, path)
        all_rules.extend(rules)
        for finding in findings:
            if finding["id"] not in seen_finding_ids:
                seen_finding_ids.add(finding["id"])
                all_findings.append(finding)

    desktop_rules, desktop_findings, desktop_servers = collect_desktop_mcp(desktop_config)
    all_rules.extend(desktop_rules)
    for finding in desktop_findings:
        if finding["id"] not in seen_finding_ids:
            seen_finding_ids.add(finding["id"])
            all_findings.append(finding)

    for finding in scan_side_artifacts(tp.claude_home):
        if finding["id"] not in seen_finding_ids:
            seen_finding_ids.add(finding["id"])
            all_findings.append(finding)

    otel = claude_otel_summary(settings_envs)
    if otel["enabled"]:
        destination = str(otel.get("destination") or "destination not recorded")
        source_text = ", ".join(otel.get("sources") or [])
        all_findings.append(
            make_finding(
                "claude.telemetry.otel_configured",
                "low",
                "Telemetry Configuration",
                "Claude Code OTEL telemetry configured",
                sample_redacted=f"destination={destination}; source={source_text or 'local env'}",
                tags=["otel"],
            )
        )

    envelope["rules"] = all_rules
    envelope["findings"] = all_findings
    envelope["summary"] = {
        "settings_files": len(settings_files),
        "rules": len(all_rules),
        "findings": len(all_findings),
        "allow_rules": sum(1 for r in all_rules if r["decision"] == "allow"),
        "deny_rules": sum(1 for r in all_rules if r["decision"] == "deny"),
        "ask_rules": sum(1 for r in all_rules if r["decision"] == "ask"),
        "desktop_mcp_servers": desktop_servers,
        "otel_enabled": bool(otel.get("enabled")),
        "otel_destination": str(otel.get("destination") or ""),
        "otel_protocol": str(otel.get("protocol") or ""),
        "otel_service_name": str(otel.get("service_name") or ""),
        "otel_headers_configured": bool(otel.get("headers_configured")),
        "otel_sources": otel.get("sources") or [],
    }
    return envelope


def main() -> None:
    parser = argparse.ArgumentParser(description="Claude permission collector")
    add_base_args(parser)
    paths.add_path_args(parser)
    args = parser.parse_args()
    evidence_root = validate_evidence_root(args.evidence_root)
    tp = paths.resolve_from_args(args)

    envelope = collect(args.scope, tp)
    if not envelope["platform_detected"]:
        finish_collector(envelope, evidence_root, dry_run=args.dry_run)
        sys.exit(2)

    finish_collector(envelope, evidence_root, dry_run=args.dry_run)
    sys.exit(0)


if __name__ == "__main__":
    main()
