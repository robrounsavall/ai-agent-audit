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
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from common import (
    APPDATA,
    USERPROFILE,
    add_base_args,
    compute_scope_hash,
    finish_collector,
    load_json,
    make_envelope,
    make_finding,
    make_rule,
    sha256_short,
    validate_evidence_root,
)
import paths as toolpaths

# Envelope schema major stays 1 (briefing validates major == 1); this collector
# supersedes copilot.py 1.0.0.
__version__ = "1.1.0"

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
        for path in storage.rglob("*.json"):
            if path.stat().st_size > 1_000_000:
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError, UnicodeDecodeError):
                continue
            if isinstance(data, dict):
                sku = data.get("sku") or data.get("plan")
                if sku:
                    return str(sku)
                if data.get("enterprise"):
                    return "enterprise"
                if data.get("organizationLogin"):
                    return "business"
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
    log_dirs = sorted(
        (d for d in logs_root.iterdir() if d.is_dir()), key=lambda d: d.name, reverse=True
    )[:max_windows]
    for log_dir in log_dirs:
        for log_file in log_dir.rglob("GitHub Copilot Chat.log"):
            try:
                text = log_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            m = _SKU_LOG_RE.search(text)
            if m:
                sku = m.group(1)
            if _LOGIN_LOG_RE.search(text):
                signed_in = True
        if sku:
            break
    return sku, signed_in


# --------------------------------------------------------------------------- #
# Settings parsing (user or workspace scope)
# --------------------------------------------------------------------------- #
def parse_vscode_settings(data: dict, scope: str = "user", scope_label: str = "vscode") -> tuple[list[dict], list[dict], dict]:
    rules: list[dict] = []
    findings: list[dict] = []
    summary: dict = {}
    prefix = "" if scope == "user" else "workspace_"

    enabled = data.get("github.copilot.enable")
    summary[prefix + "copilot_enabled"] = bool(enabled) if enabled is not None else "unset"

    lang_map: dict[str, bool] = {}
    for key, value in data.items():
        if key.startswith("github.copilot.enable."):
            lang = key.split(".")[-1]
            lang_map[lang] = bool(value)
            rules.append(
                make_rule(
                    "vscode",
                    scope,
                    scope_label,
                    "other",
                    key,
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

    # --- Agent mode / chat.tools auto-approve (key names drift across versions;
    # match any chat.tools*autoApprove* variant) ---
    agent_enabled = data.get("chat.agent.enabled")
    summary[prefix + "agent_enabled"] = (
        bool(agent_enabled) if agent_enabled is not None else "unset"
    )
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
        if not key.startswith("chat.tools"):
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

    mcp_enabled = data.get("chat.mcp.enabled")
    mcp_discovery = data.get("chat.mcp.discovery.enabled")
    summary[prefix + "mcp_enabled"] = bool(mcp_enabled) if mcp_enabled is not None else "unset"
    summary[prefix + "mcp_discovery"] = (
        bool(mcp_discovery) if mcp_discovery is not None else "unset"
    )

    trust = data.get("security.workspace.trust.enabled")
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
    summary[prefix + "workspace_trust"] = bool(trust) if trust is not None else "unset"

    return rules, findings, summary


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
        for entry in ext_dir.iterdir():
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


def inventory_chat_sessions(workspace_storage: Path) -> tuple[list[dict], dict, list[str]]:
    """Walk workspaceStorage/*/chatSessions/*.jsonl. Returns (findings, summary,
    scanned_paths). Workspace identity is hashed, prompt text never read into
    the envelope."""
    findings: list[dict] = []
    scanned: list[str] = []
    sessions = 0
    workspaces: set[str] = set()
    requests_total = 0
    modes: dict[str, int] = {}
    models: set[str] = set()
    levels: dict[str, int] = {}

    if workspace_storage.exists():
        for session_file in workspace_storage.glob("*/chatSessions/*.jsonl"):
            scanned.append(str(session_file))
            sessions += 1
            workspaces.add(sha256_short(session_file.parent.parent.name))
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
        "chat_workspaces": len(workspaces),
        "chat_requests": requests_total,
        "chat_modes": modes,
        "chat_models": sorted(models),
        "chat_permission_levels": levels,
    }
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
        for child in root.iterdir():
            if child.is_dir() and (child / ".vscode").is_dir():
                vscode_dirs.append(child / ".vscode")

    for vs_dir in vscode_dirs:
        repo_hash = sha256_short(str(vs_dir.parent.resolve()).replace("\\", "/").lower())
        settings_path = vs_dir / "settings.json"
        if settings_path.exists():
            scanned.append(str(settings_path))
            data = load_json(settings_path) or {}
            ws_rules, ws_findings, _ = parse_vscode_settings(
                data, scope="workspace", scope_label=f"workspace#{repo_hash}"
            )
            rules.extend(ws_rules)
            findings.extend(ws_findings)
            ws_with_settings += 1
        mcp_path = vs_dir / "mcp.json"
        if mcp_path.exists():
            scanned.append(str(mcp_path))
            data = load_json(mcp_path) or {}
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
    except (OSError, ET.ParseError):
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
    jetbrains_configs = (
        list(JETBRAINS_ROOT.glob("*/options/github-copilot.xml"))
        if JETBRAINS_ROOT.exists()
        else []
    )
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

        data = load_json(p.vscode_settings) or {}
        rules, findings, vs_summary = parse_vscode_settings(data)
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
            p.vscode_workspace_storage
        )
        all_findings.extend(chat_findings)
        summary.update(chat_summary)
        scanned.extend(chat_scanned)

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
