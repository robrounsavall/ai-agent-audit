"""
VS Code surface collector (Copilot Chat, agent mode, MCP, AI extensions).

Usage:
    python vscode.py --evidence-root ./audit-run [--vscode-root DIR] [--repo-roots a,b] [--dry-run]

Audits the VS Code surface as a host for AI harnesses:
  - Copilot enable/exclude/public-code/telemetry settings (v1 lineage)
  - Copilot SKU/auth signals from globalStorage and the Copilot Chat log channel
  - Agent-mode posture: chat.agent.*, chat.tools auto-approve, chat.mcp.*
  - Workspace trust
  - Installed AI extensions (Copilot, Claude Code, Cline, Continue, ...)
  - Copilot chat-session inventory (metadata only: counts, modes, models,
    permission levels; never prompt text or account identity)
  - Workspace-scoped .vscode/settings.json and .vscode/mcp.json (hashed repo identity)
  - JetBrains Copilot config (minor unit, v1 lineage)

Replaces the v1 `copilot` collector; evidence key is now `vscode`.
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from common import (
    APPDATA,
    USERPROFILE,
    add_base_args,
    classify_rule,
    compute_scope_hash,
    finish_collector,
    make_envelope,
    make_finding,
    make_rule,
    read_json_object,
    sha256_short,
    validate_evidence_root,
)
import paths as toolpaths

# Envelope schema major stays 1 (briefing validates major == 1); this collector
# supersedes copilot.py 1.0.0.
__version__ = "1.2.0"

COLLECTOR = "vscode"
JETBRAINS_ROOT = APPDATA / "JetBrains"
EXTENSIONS_DIR = USERPROFILE / ".vscode" / "extensions"

DEFAULT_REPO_ROOTS = [
    USERPROFILE / "repos",
    USERPROFILE / "code",
    USERPROFILE / "src",
    USERPROFILE / "projects",
    USERPROFILE / "source",
    USERPROFILE / "cursor-projects",
]

# Known AI-assistant extension id prefixes -> safe short-vocab label.
AI_EXTENSION_VOCAB = {
    "github.copilot": "copilot",
    "github.copilot-chat": "copilot-chat",
    "anthropic.claude-code": "claude-code",
    "saoudrizwan.claude-dev": "cline",
    "continue.continue": "continue",
    "codeium.codeium": "codeium",
    "sourcegraph.cody-ai": "cody",
    "google.geminicodeassist": "gemini",
    "openai.chatgpt": "chatgpt",
    "amazonwebservices.amazon-q-vscode": "amazon-q",
    "tabnine.tabnine-vscode": "tabnine",
}

_SKU_LOG_RE = re.compile(r"copilot token sku:\s*(\S+)")
_LOGIN_LOG_RE = re.compile(r"\bLogged in as\b")

# Fixed labels only. organizationLogin and any other free-text field stay out
# of the summary; an unrecognized sku/plan is ignored rather than copied.
_SKU_ALIASES = {
    "free": "free",
    "individual": "individual",
    "pro": "individual",
    "pro_plus": "individual",
    "individual_or_business": "individual_or_business",
    "business": "business",
    "team": "business",
    "enterprise": "enterprise",
    "signed_in": "signed_in",
    "unknown": "unknown",
}


def _sku_alias(value: object) -> str:
    if not isinstance(value, str):
        return ""
    token = value.strip().lower().replace("-", "_").replace(" ", "_")
    return _SKU_ALIASES.get(token, "")


def _sku_from_object(data: dict) -> str:
    mapped = _sku_alias(data.get("sku")) or _sku_alias(data.get("plan"))
    if mapped:
        return mapped
    if data.get("enterprise"):
        return "enterprise"
    # Presence of an org login means Business. The login string itself is not a sku.
    if data.get("organizationLogin"):
        return "business"
    return ""


def _as_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    return None


# --------------------------------------------------------------------------- #
# SKU / auth detection
# --------------------------------------------------------------------------- #
def detect_sku(global_storage: Path) -> str:
    """Probe both Copilot globalStorage dirs (v1 only probed github.copilot)."""
    for dirname in ("github.copilot", "github.copilot-chat"):
        storage = global_storage / dirname
        if not storage.exists():
            continue
        for name in ("copilot-token", "copilot-chat-token"):
            if (storage / name).exists():
                return "individual_or_business"
        try:
            storage_files = list(storage.rglob("*.json"))
        except OSError:
            storage_files = []
        for path in storage_files:
            try:
                if path.stat().st_size > 1_000_000:
                    continue
            except OSError:
                continue
            data, err = read_json_object(path)
            if err or not data:
                continue
            mapped = _sku_from_object(data)
            if mapped:
                return mapped
        if (storage / "copilot-user").exists():
            return "signed_in"
    return "unknown"


def sku_from_logs(logs_root: Path, max_windows: int = 3) -> tuple[str | None, bool]:
    """Scan recent Copilot Chat log channels for the token SKU line.

    Returns (sku, signed_in). Reads only the extension's own log channel; the
    username on the login line is never captured.
    """
    if not logs_root.exists():
        return None, False
    sku: str | None = None
    signed_in = False
    try:
        log_dirs = sorted(
            (d for d in logs_root.iterdir() if d.is_dir()), key=lambda d: d.name, reverse=True
        )[:max_windows]
    except OSError:
        return None, False
    for log_dir in log_dirs:
        for log_file in log_dir.rglob("GitHub Copilot Chat.log"):
            try:
                text = log_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            m = _SKU_LOG_RE.search(text)
            if m:
                mapped = _sku_alias(m.group(1))
                if mapped:
                    sku = mapped
            if _LOGIN_LOG_RE.search(text):
                signed_in = True
        if sku:
            break
    return sku, signed_in


# --------------------------------------------------------------------------- #
# Settings parsing (user or workspace scope)
# --------------------------------------------------------------------------- #
def parse_vscode_settings(
    data: dict,
    scope: str = "user",
    scope_label: str = "vscode",
    sku: str = "",
) -> tuple[list[dict], list[dict], dict]:
    rules: list[dict] = []
    findings: list[dict] = []
    summary: dict = {}
    prefix = "" if scope == "user" else "workspace_"

    enabled = data.get("github.copilot.enable")
    lang_map: dict[str, bool] = {}
    # VS Code stores this as {"*": true, "markdown": false}, not a bool.
    # bool({"*": false}) is True, which used to report a disabled install as on.
    if isinstance(enabled, dict):
        for key, value in enabled.items():
            if not isinstance(key, str):
                continue
            parsed = _as_bool(value)
            if parsed is not None:
                lang_map[key] = parsed
        summary[prefix + "copilot_enabled"] = lang_map["*"] if "*" in lang_map else "unset"
    elif isinstance(enabled, bool):
        summary[prefix + "copilot_enabled"] = enabled
    else:
        summary[prefix + "copilot_enabled"] = "unset"

    for key, value in data.items():
        if not isinstance(key, str) or not key.startswith("github.copilot.enable."):
            continue
        lang = key.split(".")[-1]
        parsed = _as_bool(value)
        if parsed is None:
            continue
        lang_map[lang] = parsed

    for lang, value in lang_map.items():
        rules.append(
            make_rule(
                "vscode",
                scope,
                scope_label,
                "other",
                f"github.copilot.enable.{lang}",
                "allow" if value else "deny",
                command_or_tool=lang,
                risk="low",
                exposure_category="General Tooling",
            )
        )
    summary[prefix + "language_overrides"] = len(lang_map)

    excludes = data.get("github.copilot.advanced.exclude", [])
    if isinstance(excludes, list):
        summary[prefix + "exclude_patterns"] = len(excludes)
        for pattern in excludes:
            if isinstance(pattern, str):
                rules.append(
                    make_rule(
                        "vscode",
                        scope,
                        scope_label,
                        "other",
                        f"exclude:{pattern}",
                        "deny",
                        command_or_tool=pattern,
                        risk="low",
                        exposure_category="Data Access",
                    )
                )
        if not excludes and scope == "user":
            findings.append(
                make_finding(
                    "vscode.copilot.exclude.none_configured",
                    "medium",
                    "Source Code Egress",
                    "Copilot has no file exclusion patterns configured",
                    tags=["chat_plaintext"],
                )
            )

    public_code = data.get("github.copilot.advanced.publicCodeSuggestions")
    if public_code is None:
        public_code = data.get("github.copilot.advanced.publicCodeSuggestions.enabled")
    summary[prefix + "public_code_suggestions"] = (
        str(public_code) if public_code is not None else "unset"
    )
    if public_code is True or str(public_code).lower() == "enabled":
        findings.append(
            make_finding(
                "vscode.copilot.public_code.enabled",
                "medium",
                "Source Code Egress",
                "Copilot public code suggestions are allowed",
                tags=["chat_plaintext"],
            )
        )

    telemetry = data.get("telemetry.telemetryLevel") or data.get("telemetry.enableTelemetry")
    summary[prefix + "telemetry"] = str(telemetry) if telemetry is not None else "unset"
    if (
        scope == "user"
        and telemetry
        and str(telemetry).lower() not in ("off", "false", "none")
        and sku in ("business", "enterprise", "signed_in")
    ):
        findings.append(
            make_finding(
                "vscode.copilot.telemetry.enabled",
                "low",
                "Telemetry Configuration",
                "Copilot telemetry enabled on Business or Enterprise SKU",
                tags=["chat_plaintext"],
            )
        )

    # --- Agent mode / chat.tools auto-approve (key names drift across versions;
    # match any chat.tools*autoApprove* variant) ---
    agent_enabled = _as_bool(data.get("chat.agent.enabled"))
    summary[prefix + "agent_enabled"] = agent_enabled if agent_enabled is not None else "unset"
    max_requests = data.get("chat.agent.maxRequests")
    if isinstance(max_requests, (int, float)):
        summary[prefix + "agent_max_requests"] = int(max_requests)
        if max_requests >= 100:
            findings.append(
                make_finding(
                    "vscode.copilot.agent.max_requests_raised",
                    "low",
                    "General Tooling",
                    "Copilot agent maxRequests raised, long unattended agent runs allowed",
                    tags=["agent_autonomy"],
                )
            )

    auto_approve_on = False
    for key, value in data.items():
        if not isinstance(key, str) or not key.startswith("chat.tools"):
            continue
        if "autoapprove" not in key.lower():
            continue
        if isinstance(value, bool):
            if value:
                auto_approve_on = True
                rules.append(
                    make_rule(
                        "vscode",
                        scope,
                        scope_label,
                        "approval_event",
                        key,
                        "allow",
                        command_or_tool="*",
                        risk="high",
                        exposure_category="Shell Execution",
                    )
                )
        elif isinstance(value, dict):
            # terminal auto-approve map: {"pattern": true/false}
            for pattern, allowed in value.items():
                if allowed:
                    auto_approve_on = True
                rules.append(
                    make_rule(
                        "vscode",
                        scope,
                        scope_label,
                        "approval_event",
                        key,
                        "allow" if allowed else "deny",
                        command_or_tool=str(pattern),
                        risk="high" if allowed else "low",
                        exposure_category="Shell Execution",
                    )
                )
    if auto_approve_on:
        findings.append(
            make_finding(
                "vscode.copilot.tools.auto_approve",
                "high",
                "Shell Execution",
                "Copilot agent tool auto-approve is enabled",
                tags=["agent_autonomy", "approval_bypass"],
            )
        )
    summary[prefix + "tools_auto_approve"] = auto_approve_on

    mcp_enabled = _as_bool(data.get("chat.mcp.enabled"))
    mcp_discovery = _as_bool(data.get("chat.mcp.discovery.enabled"))
    summary[prefix + "mcp_enabled"] = mcp_enabled if mcp_enabled is not None else "unset"
    summary[prefix + "mcp_discovery"] = mcp_discovery if mcp_discovery is not None else "unset"

    trust = _as_bool(data.get("security.workspace.trust.enabled"))
    if trust is False:
        findings.append(
            make_finding(
                "vscode.workspace_trust.disabled",
                "medium",
                "General Tooling",
                "VS Code workspace trust is disabled",
                tags=["agent_autonomy"],
            )
        )
    summary[prefix + "workspace_trust"] = trust if trust is not None else "unset"

    return rules, findings, summary


# --------------------------------------------------------------------------- #
# Agent host (globalStorage/agent-host-config.json + agent-host.db)
# --------------------------------------------------------------------------- #
AGENT_HOST_CONFIG = "agent-host-config.json"
AGENT_HOST_DB = "agent-host.db"
_SAFE_TOKEN_RE = re.compile(r"^[a-z0-9_.-]{1,32}$")
_SANDBOX_OFF_VALUES = {"off", "false", "disabled", "none", "0"}


def _safe_token(value: object) -> str:
    text = str(value or "").strip().lower()
    return text if _SAFE_TOKEN_RE.match(text) else ""


def parse_agent_host_config(data: dict) -> tuple[list[dict], list[dict], dict]:
    """Parse VS Code's agent-host config (the Agents window / Copilot CLI host).

    Returns (rules, findings, summary). Summary keys are prefixed agent_host_.
    Trusted folder paths, shell paths and free-text instructions are counted,
    never copied.
    """
    rules: list[dict] = []
    findings: list[dict] = []
    summary: dict = {"agent_host_config": True}
    label = "vscode-agent-host"

    perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
    counts = {}
    for decision in ("allow", "ask", "deny"):
        entries = perms.get(decision) if isinstance(perms.get(decision), list) else []
        counts[decision] = 0
        for entry in entries:
            if not isinstance(entry, str) or not entry.strip():
                continue
            counts[decision] += 1
            rule_type, tool, _inner = classify_rule(entry)
            rules.append(
                make_rule(
                    "vscode",
                    "user",
                    label,
                    rule_type,
                    entry,
                    decision,
                    command_or_tool=tool,
                    source_kind="user_config",
                    settings_source=AGENT_HOST_CONFIG,
                    confidence="high",
                )
            )
    summary["agent_host_allow_rules"] = counts["allow"]
    summary["agent_host_ask_rules"] = counts["ask"]
    summary["agent_host_deny_rules"] = counts["deny"]
    if counts["allow"]:
        findings.append(
            make_finding(
                "vscode.agent_host.allow_rules",
                "low",
                "General Tooling",
                "VS Code agent host has standing allow rules",
                evidence_count=counts["allow"],
                tags=["agent_autonomy"],
            )
        )

    def flag(key: str) -> bool | None:
        return _as_bool(data.get(key))

    global_auto = flag("globalAutoApproveEnabled")
    terminal_auto = flag("terminalAutoApproveEnabled")
    summary["agent_host_global_auto_approve"] = global_auto if global_auto is not None else "unset"
    summary["agent_host_terminal_auto_approve_rules"] = (
        terminal_auto if terminal_auto is not None else "unset"
    )
    if global_auto:
        findings.append(
            make_finding(
                "vscode.agent_host.global_auto_approve",
                "high",
                "Shell Execution",
                "VS Code agent host auto-approves every tool call",
                tags=["agent_autonomy", "approval_bypass"],
            )
        )

    edit_patterns = data.get("editAutoApprovePatterns")
    edit_all = False
    protected = 0
    if isinstance(edit_patterns, dict):
        edit_all = _as_bool(edit_patterns.get("**/*")) is True
        protected = sum(1 for k, v in edit_patterns.items() if k != "**/*" and _as_bool(v) is False)
    summary["agent_host_edit_auto_approve_all"] = edit_all
    summary["agent_host_edit_protected_patterns"] = protected
    if edit_all:
        findings.append(
            make_finding(
                "vscode.agent_host.edit_auto_approve",
                "low",
                "Data Access",
                "VS Code agent file edits are auto-approved outside protected paths",
                evidence_count=protected or 1,
                sample_redacted=f"**/* auto-approved; {protected} protected pattern(s)",
                tags=["agent_autonomy"],
            )
        )

    sandbox = data.get("sandbox") if isinstance(data.get("sandbox"), dict) else {}
    mode = str(sandbox.get("enabled", "")).strip().lower() if sandbox else ""
    if isinstance(sandbox.get("enabled"), bool):
        mode = "on" if sandbox["enabled"] else "off"
    summary["agent_host_sandbox"] = _safe_token(mode) or ("unset" if not mode else "other")
    sandbox_off = mode in _SANDBOX_OFF_VALUES
    for key, out in (
        ("allowNetwork", "agent_host_sandbox_allow_network"),
        ("allowUnsandboxedCommands", "agent_host_sandbox_allow_unsandboxed"),
        ("authenticateGit", "agent_host_sandbox_git_auth"),
        ("authenticateGh", "agent_host_sandbox_gh_auth"),
    ):
        val = _as_bool(sandbox.get(key))
        summary[out] = val if val is not None else "unset"
    if sandbox_off:
        findings.append(
            make_finding(
                "vscode.agent_host.sandbox_off",
                "medium",
                "Shell Execution",
                "VS Code agent terminal sandbox is off; commands run with your full user rights",
                sample_redacted="sandbox=disabled",
                tags=["agent_autonomy"],
            )
        )
    elif _as_bool(sandbox.get("allowUnsandboxedCommands")):
        findings.append(
            make_finding(
                "vscode.agent_host.unsandboxed_commands",
                "medium",
                "Shell Execution",
                "VS Code agent sandbox lets commands escape to unsandboxed execution",
                tags=["agent_autonomy"],
            )
        )

    for key, out in (
        ("computerUseEnabled", "agent_host_computer_use"),
        ("codexAgentEnabled", "agent_host_codex_agent"),
        ("githubMcpServerEnabled", "agent_host_github_mcp"),
        ("mcpConnectorsEnabled", "agent_host_mcp_connectors"),
        ("byokModelsEnabled", "agent_host_byok_models"),
        ("imageGeneration", "agent_host_image_generation"),
    ):
        val = flag(key)
        summary[out] = val if val is not None else "unset"
    if summary["agent_host_computer_use"] is True:
        findings.append(
            make_finding(
                "vscode.agent_host.computer_use",
                "medium",
                "General Tooling",
                "VS Code agents may control the desktop (computer use enabled)",
                tags=["agent_autonomy"],
            )
        )
    if summary["agent_host_github_mcp"] is True or summary["agent_host_mcp_connectors"] is True:
        bits = [
            name
            for name, on in (
                ("GitHub MCP server", summary["agent_host_github_mcp"] is True),
                ("MCP connectors", summary["agent_host_mcp_connectors"] is True),
            )
            if on
        ]
        findings.append(
            make_finding(
                "vscode.agent_host.remote_mcp",
                "low",
                "MCP Tooling",
                "VS Code agents can call hosted MCP services",
                evidence_count=len(bits),
                sample_redacted=", ".join(bits),
                tags=["mcp_external"],
            )
        )

    merge = data.get("agentMerge") if isinstance(data.get("agentMerge"), dict) else {}
    merge_on = _as_bool(merge.get("enabled")) is True
    summary["agent_host_agent_merge"] = merge_on
    if merge_on:
        findings.append(
            make_finding(
                "vscode.agent_host.agent_merge",
                "medium",
                "General Tooling",
                "VS Code agents may push fixes and merge pull requests",
                sample_redacted=_safe_token(merge.get("mergePullRequest")) or "enabled",
                tags=["agent_autonomy"],
            )
        )

    trust = data.get("workspaceTrust") if isinstance(data.get("workspaceTrust"), dict) else {}
    trust_on = _as_bool(trust.get("enabled"))
    uris = trust.get("trustedUris")
    summary["agent_host_workspace_trust"] = trust_on if trust_on is not None else "unset"
    summary["agent_host_trusted_folders"] = len(uris) if isinstance(uris, list) else 0
    if trust_on is False:
        findings.append(
            make_finding(
                "vscode.workspace_trust.disabled",
                "medium",
                "General Tooling",
                "VS Code agent host workspace trust is disabled",
                tags=["agent_autonomy"],
            )
        )

    telemetry = _safe_token(data.get("telemetryLevel"))
    if telemetry:
        summary["agent_host_telemetry"] = telemetry
    return rules, findings, summary


def _epoch_ms_to_date(value: object) -> str:
    if not isinstance(value, (int, float)) or value <= 0:
        return ""
    try:
        return datetime.fromtimestamp(value / 1000, tz=timezone.utc).date().isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


def inventory_agent_host_sessions(db_path: Path) -> dict:
    """Session metadata from agent-host.db: counts per provider, chat count,
    deleted (tombstoned) sessions, newest activity date. No titles, paths or
    payloads are read."""
    out: dict = {}
    if not db_path.is_file():
        return out
    uri = "file:" + db_path.resolve().as_posix() + "?mode=ro"
    try:
        con = sqlite3.connect(uri, uri=True, timeout=2)
    except (sqlite3.Error, OSError, ValueError):
        return {"agent_host_db_error": True}
    try:
        tables = {r[0] for r in con.execute("select name from sqlite_master where type='table'")}
        providers: dict[str, int] = {}
        newest = 0
        if "sessions" in tables:
            for provider, start, modified in con.execute(
                "select provider, start_time, modified_time from sessions"
            ):
                name = _safe_token(provider) or "other"
                providers[name] = providers.get(name, 0) + 1
                for ts in (start, modified):
                    if isinstance(ts, (int, float)) and ts > newest:
                        newest = ts
        out["agent_host_sessions"] = sum(providers.values())
        out["agent_host_providers"] = providers
        if "chats_v2" in tables:
            out["agent_host_chats"] = con.execute("select count(*) from chats_v2").fetchone()[0]
        if "metadata" in tables:
            out["agent_host_deleted_sessions"] = con.execute(
                "select count(*) from metadata where key like 'sessionTombstone:%'"
            ).fetchone()[0]
        date = _epoch_ms_to_date(newest)
        if date:
            out["agent_host_last_activity"] = date
    except sqlite3.Error:
        out["agent_host_db_error"] = True
    finally:
        con.close()
    return out


# --------------------------------------------------------------------------- #
# AI extension inventory
# --------------------------------------------------------------------------- #
def inventory_extensions(ext_dir: Path, global_storage: Path) -> tuple[list[dict], dict]:
    """Enumerate installed AI extensions. Built-in Copilot Chat is detected via
    globalStorage since it ships inside VS Code with no extensions-dir entry."""
    findings: list[dict] = []
    found: set[str] = set()
    total = 0
    if ext_dir.exists():
        try:
            entries = list(ext_dir.iterdir())
        except OSError:
            entries = []
        for entry in entries:
            if not entry.is_dir():
                continue
            total += 1
            name = entry.name.lower()
            for ext_id, label in AI_EXTENSION_VOCAB.items():
                if name.startswith(ext_id):
                    found.add(label)
    if (global_storage / "github.copilot-chat").exists():
        found.add("copilot-chat")
    if (global_storage / "github.copilot").exists():
        found.add("copilot")

    summary = {
        "extensions_total": total,
        "ai_extensions": sorted(found),
        "ai_extensions_count": len(found),
    }
    non_copilot = sorted(f for f in found if not f.startswith("copilot"))
    if non_copilot:
        findings.append(
            make_finding(
                "vscode.ai_extension.present",
                "low",
                "Cross-Agent Visibility",
                "AI assistant extensions installed beyond Copilot",
                evidence_count=len(non_copilot),
                sample_redacted=", ".join(non_copilot),
                tags=["multi_harness"],
            )
        )
    return findings, summary


# --------------------------------------------------------------------------- #
# Copilot chat-session inventory (metadata only)
# --------------------------------------------------------------------------- #
def parse_session_lines(lines: list[str]) -> dict:
    """Parse one chatSessions JSONL into safe metadata. Pure function.

    Returns {requests, modes, models, permission_levels}. Never returns prompt
    text, response text, workspace paths, or account labels.
    """
    out = {"requests": 0, "modes": set(), "models": set(), "permission_levels": set()}
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        kind = obj.get("kind")
        v = obj.get("v")
        if kind == 0 and isinstance(v, dict):
            state = v.get("inputState") or {}
            mode = ((state.get("mode") or {}).get("id"))
            if mode:
                out["modes"].add(str(mode))
            level = state.get("permissionLevel")
            if level:
                out["permission_levels"].add(str(level))
            model = ((state.get("selectedModel") or {}).get("metadata") or {}).get("family")
            if model:
                out["models"].add(str(model))
            reqs = v.get("requests")
            if isinstance(reqs, list):
                out["requests"] += len(reqs)
                _harvest_requests(reqs, out)
        elif kind == 2 and obj.get("k") == ["requests"] and isinstance(v, list):
            out["requests"] += len(v)
            _harvest_requests(v, out)
    return out


def _harvest_requests(reqs: list, out: dict) -> None:
    for req in reqs:
        if not isinstance(req, dict):
            continue
        resolved = ((req.get("result") or {}).get("metadata") or {}).get("resolvedModel")
        if resolved:
            out["models"].add(str(resolved))
        agent = req.get("agent") or {}
        for mode in agent.get("modes") or []:
            out["modes"].add(str(mode))


def inventory_chat_sessions(
    workspace_storage: Path, global_storage: Path | None = None
) -> tuple[list[dict], dict, list[str]]:
    """Walk workspaceStorage/*/chatSessions/*.jsonl plus the no-folder
    globalStorage/emptyWindowChatSessions/*.jsonl. Returns (findings, summary,
    scanned_paths). Workspace identity is hashed, prompt text never read into
    the envelope."""
    findings: list[dict] = []
    scanned: list[str] = []
    sessions = 0
    empty_window = 0
    workspaces: set[str] = set()
    requests_total = 0
    modes: dict[str, int] = {}
    models: set[str] = set()
    levels: dict[str, int] = {}
    newest_mtime = 0.0

    files: list[tuple[Path, str | None]] = []
    if workspace_storage.exists():
        files.extend(
            (f, f.parent.parent.name) for f in workspace_storage.glob("*/chatSessions/*.jsonl")
        )
    if global_storage is not None and (global_storage / "emptyWindowChatSessions").is_dir():
        files.extend(
            (f, None) for f in (global_storage / "emptyWindowChatSessions").glob("*.jsonl")
        )

    if files:
        for session_file, workspace_id in files:
            scanned.append(str(session_file))
            sessions += 1
            if workspace_id is None:
                empty_window += 1
            else:
                workspaces.add(sha256_short(workspace_id))
            try:
                newest_mtime = max(newest_mtime, session_file.stat().st_mtime)
            except OSError:
                pass
            try:
                lines = session_file.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            meta = parse_session_lines(lines)
            requests_total += meta["requests"]
            for m in meta["modes"]:
                modes[m] = modes.get(m, 0) + 1
            models.update(meta["models"])
            for lv in meta["permission_levels"]:
                levels[lv] = levels.get(lv, 0) + 1

    relaxed = {lv: n for lv, n in levels.items() if lv != "default"}
    if relaxed:
        findings.append(
            make_finding(
                "vscode.copilot.permission_level_relaxed",
                "medium",
                "Shell Execution",
                "Copilot chat sessions with non-default permission level",
                evidence_count=sum(relaxed.values()),
                sample_redacted=", ".join(sorted(relaxed)),
                tags=["agent_autonomy", "approval_bypass"],
            )
        )

    summary = {
        "chat_sessions": sessions,
        "chat_empty_window_sessions": empty_window,
        "chat_workspaces": len(workspaces),
        "chat_requests": requests_total,
        "chat_modes": modes,
        "chat_models": sorted(models),
        "chat_permission_levels": levels,
    }
    if newest_mtime:
        summary["chat_last_activity"] = (
            datetime.fromtimestamp(newest_mtime, tz=timezone.utc).date().isoformat()
        )
    return findings, summary, scanned


# --------------------------------------------------------------------------- #
# Workspace-scoped .vscode/ scan
# --------------------------------------------------------------------------- #
def parse_workspace_mcp(data: dict, repo_hash: str) -> tuple[list[dict], list[dict], int]:
    """Parse a .vscode/mcp.json server inventory. Returns (rules, findings, count)."""
    rules: list[dict] = []
    findings: list[dict] = []
    servers = data.get("servers") or data.get("mcpServers") or {}
    non_local = 0
    for name, cfg in servers.items() if isinstance(servers, dict) else []:
        if not isinstance(cfg, dict):
            continue
        url = str(cfg.get("url", ""))
        transport = "http" if url else ("stdio" if cfg.get("command") else "unknown")
        remote = bool(url) and not any(
            h in url for h in ("localhost", "127.0.0.1", "[::1]")
        )
        if remote:
            non_local += 1
        rules.append(
            make_rule(
                "vscode",
                "workspace",
                f"workspace#{repo_hash}",
                "mcp_tool",
                f"mcp:{transport}",
                "allow",
                command_or_tool=sha256_short(str(name)),
                risk="medium" if remote else "low",
                exposure_category="MCP Tooling",
            )
        )
    if non_local:
        findings.append(
            make_finding(
                "vscode.mcp.non_local_server",
                "medium",
                "MCP Tooling",
                "Workspace MCP config points at non-localhost servers",
                evidence_count=non_local,
                tags=["mcp_external"],
            )
        )
    count = len(servers) if isinstance(servers, dict) else 0
    return rules, findings, count


def scan_workspace_repos(repo_roots: list[Path]) -> tuple[list[dict], list[dict], dict, list[str]]:
    rules: list[dict] = []
    findings: list[dict] = []
    scanned: list[str] = []
    ws_with_settings = 0
    ws_with_mcp = 0
    mcp_servers_total = 0

    vscode_dirs: list[Path] = []
    for root in repo_roots:
        if not root.exists():
            continue
        if (root / ".vscode").is_dir():
            vscode_dirs.append(root / ".vscode")
        try:
            children = list(root.iterdir())
        except OSError:
            children = []
        for child in children:
            if child.is_dir() and (child / ".vscode").is_dir():
                vscode_dirs.append(child / ".vscode")

    for vs_dir in vscode_dirs:
        repo_hash = sha256_short(str(vs_dir.parent.resolve()).replace("\\", "/").lower())
        settings_path = vs_dir / "settings.json"
        if settings_path.exists():
            scanned.append(str(settings_path))
            data, err = read_json_object(settings_path)
            if err or data is None:
                findings.append(
                    make_finding(
                        "vscode.config.parse_error",
                        "low",
                        "General Tooling",
                        "A workspace settings.json is present but could not be parsed",
                        sample_redacted=err or "unreadable",
                        tags=["config_parse_error"],
                    )
                )
            else:
                ws_rules, ws_findings, _ = parse_vscode_settings(
                    data, scope="workspace", scope_label=f"workspace#{repo_hash}"
                )
                rules.extend(ws_rules)
                findings.extend(ws_findings)
                ws_with_settings += 1
        mcp_path = vs_dir / "mcp.json"
        if mcp_path.exists():
            scanned.append(str(mcp_path))
            data, err = read_json_object(mcp_path)
            if err or data is None:
                findings.append(
                    make_finding(
                        "vscode.config.parse_error",
                        "low",
                        "General Tooling",
                        "A workspace mcp.json is present but could not be parsed",
                        sample_redacted=err or "unreadable",
                        tags=["config_parse_error"],
                    )
                )
            else:
                mcp_rules, mcp_findings, count = parse_workspace_mcp(data, repo_hash)
                rules.extend(mcp_rules)
                findings.extend(mcp_findings)
                ws_with_mcp += 1
                mcp_servers_total += count

    if ws_with_mcp:
        findings.append(
            make_finding(
                "vscode.mcp.workspace_servers_present",
                "low",
                "MCP Tooling",
                "Workspace-scoped MCP server configs present",
                evidence_count=ws_with_mcp,
                tags=["mcp_external"],
            )
        )
    summary = {
        "workspaces_with_settings": ws_with_settings,
        "workspaces_with_mcp": ws_with_mcp,
        "workspace_mcp_servers": mcp_servers_total,
    }
    return rules, findings, summary, scanned


# --------------------------------------------------------------------------- #
# JetBrains (minor unit, v1 lineage)
# --------------------------------------------------------------------------- #
def parse_jetbrains_xml(path: Path) -> tuple[list[dict], dict]:
    rules: list[dict] = []
    summary: dict = {"jetbrains_config": str(path.name)}
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except (OSError, ET.ParseError, UnicodeDecodeError):
        return rules, summary

    for elem in root.iter():
        tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
        value = elem.text or elem.get("value", "")
        if tag.lower() in ("enabled", "enable") or "copilot" in tag.lower():
            rules.append(
                make_rule(
                    "vscode",
                    "user",
                    "jetbrains",
                    "other",
                    f"{tag}={value}",
                    "allow" if str(value).lower() in ("true", "1", "yes") else "ask",
                    command_or_tool=tag,
                    risk="low",
                )
            )
    return rules, summary


# --------------------------------------------------------------------------- #
# Collect
# --------------------------------------------------------------------------- #
def collect(p: toolpaths.ToolPaths, repo_roots: list[Path]) -> dict:
    scanned: list[str] = []
    if p.vscode_settings.exists():
        scanned.append(str(p.vscode_settings))
    if p.vscode_global_storage.exists():
        scanned.append(str(p.vscode_global_storage))
    try:
        jetbrains_configs = (
            list(JETBRAINS_ROOT.glob("*/options/github-copilot.xml"))
            if JETBRAINS_ROOT.exists()
            else []
        )
    except OSError:
        jetbrains_configs = []
    scanned.extend(str(c) for c in jetbrains_configs)

    vscode_exists = p.vscode_root.exists()
    platform_detected = vscode_exists or bool(jetbrains_configs)

    all_rules: list[dict] = []
    all_findings: list[dict] = []
    summary: dict = {"platforms_found": 0}

    if vscode_exists:
        summary["platforms_found"] += 1

        storage_sku = detect_sku(p.vscode_global_storage)
        log_sku, signed_in = sku_from_logs(p.vscode_logs)
        summary["sku"] = log_sku or storage_sku
        summary["signed_in"] = signed_in or storage_sku not in ("unknown",)

        if p.vscode_settings.is_file():
            data, err = read_json_object(p.vscode_settings)
            if err or data is None:
                all_findings.append(
                    make_finding(
                        "vscode.config.parse_error",
                        "low",
                        "General Tooling",
                        "VS Code settings.json is present but could not be parsed",
                        sample_redacted=err or "unreadable",
                        tags=["config_parse_error"],
                    )
                )
            else:
                rules, findings, vs_summary = parse_vscode_settings(data, sku=summary["sku"])
                all_rules.extend(rules)
                all_findings.extend(findings)
                summary.update(vs_summary)
        else:
            rules, findings, vs_summary = parse_vscode_settings({}, sku=summary["sku"])
            all_rules.extend(rules)
            all_findings.extend(findings)
            summary.update(vs_summary)

        ext_findings, ext_summary = inventory_extensions(
            EXTENSIONS_DIR, p.vscode_global_storage
        )
        all_findings.extend(ext_findings)
        summary.update(ext_summary)
        if EXTENSIONS_DIR.exists():
            scanned.append(str(EXTENSIONS_DIR))

        chat_findings, chat_summary, chat_scanned = inventory_chat_sessions(
            p.vscode_workspace_storage, p.vscode_global_storage
        )
        all_findings.extend(chat_findings)
        summary.update(chat_summary)
        scanned.extend(chat_scanned)

        host_cfg = p.vscode_global_storage / AGENT_HOST_CONFIG
        if host_cfg.is_file():
            scanned.append(str(host_cfg))
            data, err = read_json_object(host_cfg)
            if err or data is None:
                all_findings.append(
                    make_finding(
                        "vscode.config.parse_error",
                        "low",
                        "General Tooling",
                        "VS Code agent-host-config.json is present but could not be parsed",
                        sample_redacted=err or "unreadable",
                        tags=["config_parse_error"],
                    )
                )
            else:
                host_rules, host_findings, host_summary = parse_agent_host_config(data)
                all_rules.extend(host_rules)
                all_findings.extend(host_findings)
                summary.update(host_summary)
                # One switch for the access map: either surface auto-approving
                # every tool call means shell runs without a prompt.
                if host_summary.get("agent_host_global_auto_approve") is True:
                    summary["tools_auto_approve"] = True
        else:
            summary["agent_host_config"] = False
        host_db = p.vscode_global_storage / AGENT_HOST_DB
        if host_db.is_file():
            scanned.append(str(host_db))
            summary.update(inventory_agent_host_sessions(host_db))

        last = max(
            str(summary.get("chat_last_activity") or ""),
            str(summary.get("agent_host_last_activity") or ""),
        )
        if last:
            summary["last_activity"] = last

        ws_rules, ws_findings, ws_summary, ws_scanned = scan_workspace_repos(repo_roots)
        all_rules.extend(ws_rules)
        all_findings.extend(ws_findings)
        summary.update(ws_summary)
        scanned.extend(ws_scanned)
    else:
        summary["sku"] = "unknown"

    for jb_path in jetbrains_configs:
        summary["platforms_found"] += 1
        rules, _jb_summary = parse_jetbrains_xml(jb_path)
        all_rules.extend(rules)
        summary.setdefault("jetbrains_products", []).append(jb_path.parent.parent.name)

    scope_hash = compute_scope_hash(scanned or [str(p.vscode_root)])
    envelope = make_envelope(
        COLLECTOR,
        __version__,
        scope_hash,
        platform_detected=platform_detected,
    )
    if not platform_detected:
        envelope["summary"] = {"platforms_found": 0}
        return envelope

    envelope["rules"] = all_rules
    envelope["findings"] = all_findings
    envelope["summary"] = summary
    envelope["summary"]["rules"] = len(all_rules)
    envelope["summary"]["findings"] = len(all_findings)
    return envelope


def main() -> None:
    parser = argparse.ArgumentParser(description="VS Code surface collector (Copilot, agent mode, MCP, AI extensions)")
    add_base_args(parser)
    toolpaths.add_path_args(parser)
    parser.add_argument(
        "--repo-roots",
        default=None,
        help="Comma-separated repo roots for workspace .vscode scans (default: common roots)",
    )
    args = parser.parse_args()
    evidence_root = validate_evidence_root(args.evidence_root)
    p = toolpaths.resolve_from_args(args)

    if args.repo_roots:
        repo_roots = [Path(r.strip()) for r in args.repo_roots.split(",") if r.strip()]
    else:
        repo_roots = [r for r in DEFAULT_REPO_ROOTS if r.exists()]

    envelope = collect(p, repo_roots)
    finish_collector(envelope, evidence_root, dry_run=args.dry_run)
    sys.exit(0 if envelope["platform_detected"] else 2)


if __name__ == "__main__":
    main()
