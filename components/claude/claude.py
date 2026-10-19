"""
Claude permission and settings collector.

Usage:
    python claude.py --evidence-root ./audit-run [--scope all] [--dry-run]

Reads ~/.claude/settings.json and settings.local.json, plus
<repo>/.claude/settings.json and settings.local.json under the repo roots.
Project settings live in the repo, not under ~/.claude/projects (that folder
is transcripts). Emits permission rules and security findings, including the
effective start permission mode (permissions.defaultMode, or the implicit
auto default) and the Claude Code version seen in transcripts.

Also reads the Claude desktop app MCP registry (%APPDATA%/Claude/
claude_desktop_config.json) and flags ~/.claude side artifacts that persist
user content outside the transcript store: history.jsonl (global prompt
history), file-history/ (pre-edit file snapshots), bash-audit.log (shell
command log).
"""

from __future__ import annotations

import argparse
import json
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
    config_has_remote_url,
    default_repo_roots,
    finish_collector,
    make_envelope,
    make_finding,
    make_rule,
    read_json_object,
    sanitize_text,
    secret_types_in,
    validate_evidence_root,
)

__version__ = "1.4.0"

COLLECTOR = "claude"

WILDCARD_BASH_RE = re.compile(r"^Bash\([^)]*\*[^)]*\)$", re.I)
CURL_WGET_RE = re.compile(r"^Bash\((curl|wget)\s*[:*]", re.I)
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+")
AUTO_DEFAULT_MIN_VERSION = (2, 1, 283)
MODE_ALIASES = {
    "manual": "default",
    "default": "default",
    "bypass": "bypassPermissions",
    "bypasspermissions": "bypassPermissions",
    "acceptedits": "acceptEdits",
    "dontask": "dontAsk",
    "auto": "auto",
    "plan": "plan",
}
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
        if not parts.scheme or not parts.netloc:
            return text[:160]
        # hostname and port can raise ValueError (bad IPv6, port above 65535).
        host = parts.hostname or parts.netloc
        port = parts.port
        if port:
            host = f"{host}:{port}"
        return urlunsplit((parts.scheme, host, parts.path.rstrip("/"), "", ""))
    except ValueError:
        return "invalid-endpoint"


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
        "destination": sanitize_text(destination),
        "protocol": sanitize_text(protocol),
        "service_name": sanitize_text(service_name),
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


def _repo_candidates(repo_roots: list[Path]) -> list[Path]:
    """Git repos that are a root or a direct child of a root. Same walk as cursor."""
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
            try:
                key = str(repo.resolve()).lower()
            except OSError:
                key = str(repo).lower()
            if key in seen:
                continue
            seen.add(key)
            found.append(repo)
    return found


def discover_settings(
    scope_filter: str,
    claude_home: Path,
    repo_roots: list[Path],
) -> list[tuple[str, str, Path]]:
    """Return (scope, scope_label, path) for user and project Claude settings.

    Project files are <repo>/.claude/settings.json and settings.local.json.
    ~/.claude/projects is the transcript store and is not searched.
    """
    found: list[tuple[str, str, Path]] = []
    seen: set[str] = set()

    def add(scope: str, label: str, path: Path) -> None:
        if not path.is_file() or not scope_matches(scope_filter, scope):
            return
        try:
            key = str(path.resolve()).lower()
        except OSError:
            key = str(path).lower()
        if key in seen:
            return
        seen.add(key)
        found.append((scope, label, path))

    for name in ("settings.json", "settings.local.json"):
        add("user", "global", claude_home / name)

    if scope_matches(scope_filter, "project"):
        for repo in _repo_candidates(repo_roots):
            label = repo.name or "project"
            for name in ("settings.json", "settings.local.json"):
                add("project", label, repo / ".claude" / name)
    return found


def permission_mode_from_settings(data: dict) -> tuple[str, str]:
    """Return (normalized_mode, key_path) for the start permission mode."""
    permissions = data.get("permissions")
    candidates = []
    if isinstance(permissions, dict):
        candidates.append(("permissions.defaultMode", permissions.get("defaultMode")))
    candidates.append(("defaultMode", data.get("defaultMode")))
    candidates.append(("permissionMode", data.get("permissionMode")))
    for key_path, raw in candidates:
        if not isinstance(raw, str) or not raw.strip():
            continue
        value = raw.strip()
        return MODE_ALIASES.get(value.lower(), value), key_path
    return "", ""


def _raw_mode(data: dict, key_path: str) -> str:
    if key_path == "permissions.defaultMode":
        return str(data["permissions"]["defaultMode"]).strip()
    return str(data.get(key_path, "")).strip()


def _setting_disabled(data: dict, key: str) -> bool:
    permissions = data.get("permissions")
    if not isinstance(permissions, dict):
        return False
    value = permissions.get(key)
    return isinstance(value, str) and value.strip().lower() == "disable"


def _version_tuple(value: str) -> tuple[int, ...]:
    match = VERSION_RE.match(value)
    return tuple(int(p) for p in match.group(0).split(".")) if match else ()


def detect_claude_code_version(claude_projects: Path) -> str:
    """Highest Claude Code version recorded in the newest transcripts, or ""."""
    try:
        files = sorted(
            claude_projects.rglob("*.jsonl"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )[:5]
    except OSError:
        return ""
    best: tuple[int, ...] = ()
    for path in files:
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for _ in range(50):
                    line = handle.readline()
                    if not line:
                        break
                    try:
                        record = json.loads(line)
                    except ValueError:
                        continue
                    version = record.get("version") if isinstance(record, dict) else None
                    if isinstance(version, str) and VERSION_RE.match(version):
                        found = _version_tuple(version)
                        if found > best:
                            best = found
                        break
        except OSError:
            continue
    return ".".join(str(p) for p in best)


def extract_rules_from_settings(
    scope: str,
    scope_label: str,
    data: dict,
    source_path: Path,
) -> tuple[list[dict], list[dict]]:
    rules: list[dict] = []
    findings: list[dict] = []
    if scope == "project":
        settings_source = f"project {source_path.name}"
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

    mode, mode_key = permission_mode_from_settings(data)
    raw_mode = _raw_mode(data, mode_key) if mode_key else ""
    is_local = scope == "project" or source_path.name == "settings.local.json"
    if mode in ("auto", "bypassPermissions") and is_local:
        findings.append(
            make_finding(
                "claude.permission.mode_not_applied",
                "low",
                "Shell Execution",
                "Claude auto/bypass mode set in project or local settings, which Claude Code ignores",
                sample_redacted=(
                    f"{mode_key}={raw_mode}; file={source_path.name}; "
                    "ignored by Claude Code 2.1.257+ (older versions may honor bypass)"
                ),
                tags=["mode_not_applied"],
            )
        )
    elif mode == "bypassPermissions":
        findings.append(
            make_finding(
                "claude.permission.bypass_mode",
                "critical",
                "Shell Execution",
                "Claude default permission mode bypasses prompts",
                sample_redacted=f"{mode_key}={raw_mode}",
                tags=["unbounded_glob"],
            )
        )
    elif mode == "auto":
        findings.append(
            make_finding(
                "claude.permission.auto_mode",
                "medium",
                "Shell Execution",
                "Claude default permission mode is auto: actions run without prompts after a classifier check",
                sample_redacted=f"{mode_key}=auto",
                tags=["auto_mode"],
            )
        )
    elif mode == "acceptEdits":
        findings.append(
            make_finding(
                "claude.permission.accept_edits_mode",
                "low",
                "Data Access",
                "Claude default permission mode auto-accepts file edits",
                sample_redacted=f"{mode_key}=acceptEdits",
                tags=["auto_accept_edits"],
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
            if config_has_remote_url(config):
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


def _read_settings_object(path: Path) -> tuple[dict | None, str | None]:
    """(data, None) parsed, (None, None) missing, (None, reason) unusable."""
    return read_json_object(path)


def collect_desktop_mcp(config_path: Path) -> tuple[list[dict], list[dict], int]:
    """Parse mcpServers from the Claude desktop app config, if present."""
    data, err = _read_settings_object(config_path)
    if err:
        return [], [
            make_finding(
                "claude.config.parse_error",
                "low",
                "General Tooling",
                "Claude desktop config is present but could not be parsed",
                sample_redacted=err,
                tags=["config_parse_error"],
            )
        ], 0
    if not data:
        return [], [], 0
    servers = data.get("mcpServers")
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


def collect(
    scope_filter: str,
    tp: paths.ToolPaths,
    repo_roots: list[Path] | None = None,
) -> dict:
    roots = list(repo_roots) if repo_roots is not None else default_repo_roots()
    settings_files = discover_settings(scope_filter, tp.claude_home, roots)
    desktop_config = desktop_config_path()
    desktop_present = desktop_config.is_file()
    code_home = tp.claude_home.exists()
    scanned_paths = [str(p) for _, _, p in settings_files]
    if desktop_present:
        scanned_paths.append(str(desktop_config))
    scope_hash = compute_scope_hash(scanned_paths or [str(tp.claude_home)])

    # A Desktop-only install has no Claude Code home. Project settings in a
    # repo also count, so a missing home does not skip the scan.
    platform_detected = code_home or desktop_present or bool(settings_files)
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
    parse_reasons: list[str] = []
    user_mode = ""
    user_mode_key = ""
    auto_disabled = False
    bypass_disabled = False

    for scope, scope_label, path in settings_files:
        data, err = _read_settings_object(path)
        if err:
            parse_reasons.append(err)
            continue
        if not data:
            continue
        if scope == "user" and path.name == "settings.json":
            user_mode, user_mode_key = permission_mode_from_settings(data)
        auto_disabled = auto_disabled or _setting_disabled(data, "disableAutoMode")
        bypass_disabled = bypass_disabled or _setting_disabled(
            data, "disableBypassPermissionsMode"
        )
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
        if finding["id"] == "claude.config.parse_error":
            reason = str(finding.get("sample_redacted") or "unreadable")
            parse_reasons.append(reason)
            continue
        if finding["id"] not in seen_finding_ids:
            seen_finding_ids.add(finding["id"])
            all_findings.append(finding)

    if parse_reasons:
        unique: list[str] = []
        for reason in parse_reasons:
            if reason not in unique:
                unique.append(reason)
        seen_finding_ids.add("claude.config.parse_error")
        all_findings.append(
            make_finding(
                "claude.config.parse_error",
                "low",
                "General Tooling",
                "Claude settings file is present but could not be parsed",
                evidence_count=len(parse_reasons),
                sample_redacted="; ".join(unique)[:180],
                tags=["config_parse_error"],
            )
        )

    for finding in scan_side_artifacts(tp.claude_home):
        if finding["id"] not in seen_finding_ids:
            seen_finding_ids.add(finding["id"])
            all_findings.append(finding)

    def drop_as_not_applied(finding_id: str, note: str) -> None:
        nonlocal all_findings
        if finding_id not in seen_finding_ids:
            return
        all_findings = [f for f in all_findings if f["id"] != finding_id]
        seen_finding_ids.discard(finding_id)
        if "claude.permission.mode_not_applied" in seen_finding_ids:
            for existing in all_findings:
                if existing["id"] == "claude.permission.mode_not_applied":
                    prior = existing.get("sample_redacted") or ""
                    existing["sample_redacted"] = f"{prior}; {note}" if prior else note
                    break
            return
        seen_finding_ids.add("claude.permission.mode_not_applied")
        all_findings.append(
            make_finding(
                "claude.permission.mode_not_applied",
                "low",
                "Shell Execution",
                "Claude auto/bypass mode is set but disabled, so Claude Code does not apply it",
                sample_redacted=note,
                tags=["mode_not_applied"],
            )
        )

    if bypass_disabled:
        drop_as_not_applied(
            "claude.permission.bypass_mode",
            "bypassPermissions disabled by permissions.disableBypassPermissionsMode",
        )
    if auto_disabled:
        drop_as_not_applied(
            "claude.permission.auto_mode",
            "auto disabled by permissions.disableAutoMode",
        )

    version = detect_claude_code_version(tp.claude_projects)
    user_in_scope = scope_matches(scope_filter, "user")
    # The implicit auto default is a Claude Code behavior. Desktop-only
    # installs have no Claude Code home and must not be reported as auto.
    if user_in_scope and code_home and not user_mode and not auto_disabled:
        sample = (
            "permissions.defaultMode=unset; implicit default=auto "
            f"(Claude Code 2.1.283+); version={version or 'unknown'}"
        )
        old_version = bool(version) and _version_tuple(version) < AUTO_DEFAULT_MIN_VERSION
        if old_version:
            title = (
                "No Claude permission mode is set, so interactive sessions may start in auto mode "
                "(default on Pro/Max/Team plans before 2.1.283)"
            )
        else:
            title = (
                "No Claude permission mode is set, so interactive sessions start in auto mode "
                "(no routine prompts; a classifier reviews actions)"
            )
        seen_finding_ids.add("claude.permission.auto_mode_default")
        all_findings.append(
            make_finding(
                "claude.permission.auto_mode_default",
                "medium",
                "Shell Execution",
                title,
                sample_redacted=sample,
                tags=["auto_mode"],
            )
        )

    if not user_in_scope:
        mode_label, mode_source = "", "not scanned (scope)"
    elif not code_home:
        mode_label, mode_source = "", "not scanned (no Claude Code home)"
    elif user_mode:
        mode_label = user_mode
        if user_mode == "auto" and auto_disabled:
            mode_label = "default (auto disabled)"
        elif user_mode == "bypassPermissions" and bypass_disabled:
            mode_label = "default (bypass disabled)"
        mode_source = (
            "settings.json permissions.defaultMode"
            if user_mode_key == "permissions.defaultMode"
            else f"settings.json {user_mode_key} (legacy)"
        )
    elif auto_disabled:
        mode_label, mode_source = "default (auto disabled)", "built-in default"
    else:
        mode_label, mode_source = "auto (implicit default)", "built-in default"

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
        "permission_mode": mode_label,
        "permission_mode_source": mode_source,
        "claude_code_version": version,
        "auto_mode_disabled": auto_disabled,
        "bypass_mode_disabled": bypass_disabled,
    }
    return envelope


def main() -> None:
    parser = argparse.ArgumentParser(description="Claude permission collector")
    add_base_args(parser)
    paths.add_path_args(parser)
    parser.add_argument(
        "--repo-roots",
        default=None,
        help="Comma-separated repo scan roots for project .claude/settings.json "
        "and settings.local.json (default: common code dirs under the user profile)",
    )
    args = parser.parse_args()
    evidence_root = validate_evidence_root(args.evidence_root)
    tp = paths.resolve_from_args(args)

    if args.repo_roots:
        repo_roots = [Path(p.strip()) for p in args.repo_roots.split(",") if p.strip()]
    else:
        repo_roots = default_repo_roots()

    envelope = collect(args.scope, tp, repo_roots=repo_roots)
    if not envelope["platform_detected"]:
        finish_collector(envelope, evidence_root, dry_run=args.dry_run)
        sys.exit(2)

    finish_collector(envelope, evidence_root, dry_run=args.dry_run)
    sys.exit(0)


if __name__ == "__main__":
    main()
