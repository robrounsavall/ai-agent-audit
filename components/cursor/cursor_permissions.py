"""
Cursor permission-file parsing.

Reads run mode, allow/deny lists, sandbox and hook settings from where Cursor
3.2x keeps them: cli-config.json / cli.json, permissions.json, sandbox.json,
hooks.json, product.json, and two targeted state.vscdb rows. Only whitelisted
fields are read; instruction text, tokens, emails and chat content are never
copied into evidence.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from pathlib import Path
from typing import Any

import configfmt
from common import USERPROFILE, make_finding, make_rule, mask_secrets, redact_paths, redaction_disabled

APPLICATION_USER_KEY = (
    "src.vs.platform.reactivestorage.browser.reactiveStorageServiceImpl."
    "persistentStorage.applicationUser"
)
ADMIN_SETTINGS_KEY = "adminSettings.cached"

# ItemTable keys that must never be fetched by the legacy permission-key scan.
SKIP_KEY_PREFIXES = (
    "cursorAuth/", "mcpOAuth", "secret://", "agentKv:", "bubbleId:",
    "composerData:", "ofsContent:", "checkpointId:",
)
SKIP_KEYS = {APPLICATION_USER_KEY, ADMIN_SETTINGS_KEY}

COMPOSER_BOOL_KEYS = (
    "useYoloMode", "yoloEnableRunEverything", "smartAllowlistEnabled",
    "yoloMcpToolsDisabled", "yoloDeleteFileDisabled", "yoloDotFilesDisabled",
    "yoloOutsideWorkspaceDisabled", "autoAcceptWebSearchTool",
    "playwrightProtection", "mcpAuthBlocking",
)

INTERPRETERS = {
    "powershell", "pwsh", "cmd", "bash", "sh", "zsh", "wsl", "python",
    "python3", "py", "node", "deno", "ruby", "perl", "start-process",
    "invoke-expression", "iex",
}
NETWORK_TOOLS = {
    "curl", "wget", "invoke-webrequest", "iwr", "invoke-restmethod", "irm",
    "ssh", "scp",
}
DESTRUCTIVE = {"rm", "del", "erase", "remove-item", "rmdir", "rd"}

SANDBOX_OFF_MODES = {"disabled", "off", "none"}
NETWORK_ALLOW_ALL = {"allow_all", "allowall", "all"}
BROAD_WRITE_ROOTS = {"/", "~", "~/", "~\\"}
DRIVE_ROOT_RE = re.compile(r"^[A-Za-z]:[\\/]?$")
TOKEN_RE = re.compile(r"^\s*(\w+)\((.*)\)\s*$", re.S)

# kind -> severity for wildcard allow entries
WILDCARD_SEVERITY = {
    "shell": "critical", "write": "high", "mcp": "high",
    "webfetch": "medium", "read": "medium",
}

MAX_LABEL = 80


def evidence_text(text: str) -> str:
    """Permission evidence never carries emails or credentials.

    Paths follow aiscan's usual policy: shown on a local run, redacted with
    -Redact / AISCAN_REDACT=1. Under redaction, allowlist entries can hold a
    fragment of a profile path split at a space ("Name\\AppData\\..."), so each
    part of the account name is masked too.
    """
    text = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "<email>", text)
    if redaction_disabled():
        return mask_secrets(text)
    text = redact_paths(text)
    for part in USERPROFILE.name.split():
        if len(part) >= 3:
            text = re.sub(r"(?<![A-Za-z0-9])" + re.escape(part) + r"(?![A-Za-z0-9])",
                          "<user>", text, flags=re.IGNORECASE)
    return mask_secrets(text)


def _clean(text: Any, limit: int = MAX_LABEL) -> str:
    return evidence_text(str(text)).replace("\r", " ").replace("\n", " ")[:limit]


def _str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_clean(v, 200) for v in value if isinstance(v, str) and v.strip()]


def _bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _count(value: Any) -> int:
    return len(value) if isinstance(value, (list, dict)) else 0


# --------------------------------------------------------------------------
# state.vscdb targeted reads
# --------------------------------------------------------------------------

def _row_json(con: sqlite3.Connection, key: str) -> Any:
    try:
        row = con.execute("SELECT value FROM ItemTable WHERE key=? AND length(value)<=?",
                          (key, configfmt.MAX_CONFIG_BYTES)).fetchone()
    except sqlite3.Error:
        return None
    if not row or row[0] is None:
        return None
    value = row[0]
    try:
        if isinstance(value, (bytes, bytearray)):
            value = bytes(value).decode("utf-8", errors="ignore")
        return json.loads(value)
    except (ValueError, TypeError, RecursionError):
        return None


def read_ide_state(con: sqlite3.Connection) -> dict | None:
    """Whitelisted composerState fields, or None when unavailable/not JSON."""
    blob = _row_json(con, APPLICATION_USER_KEY)
    if not isinstance(blob, dict):
        return None
    composer = blob.get("composerState")
    if not isinstance(composer, dict):
        composer = {}
    state: dict[str, Any] = {k: _bool(composer.get(k)) for k in COMPOSER_BOOL_KEYS}
    state["yoloCommandAllowlist"] = _str_list(composer.get("yoloCommandAllowlist"))
    state["yoloCommandDenylist"] = _str_list(composer.get("yoloCommandDenylist"))
    state["webFetchDomainAllowlist"] = _str_list(composer.get("webFetchDomainAllowlist"))
    default_mode = composer.get("defaultMode2")
    state["defaultMode2"] = _clean(default_mode) if isinstance(default_mode, str) else ""
    modes = []
    raw_modes = composer.get("modes4")
    for mode in raw_modes if isinstance(raw_modes, list) else []:
        if not isinstance(mode, dict):
            continue
        name = mode.get("name") if isinstance(mode.get("name"), str) else mode.get("id")
        modes.append({
            "name": _clean(name) if isinstance(name, str) and name else "unnamed",
            "autoRun": mode.get("autoRun") is True,
            "fullAutoRun": mode.get("fullAutoRun") is True,
        })
    state["modes"] = modes
    return state


def read_admin_state(con: sqlite3.Connection) -> dict | None:
    """Counts/booleans from the cached team policy; never instruction text."""
    data = _row_json(con, ADMIN_SETTINGS_KEY)
    if not isinstance(data, dict):
        return None
    review = data.get("autoReview") if isinstance(data.get("autoReview"), dict) else {}
    local_path = data.get("localPermissionsFilePath")
    remote = data.get("remotePermissionsFilePaths")
    remote_ctl = data.get("remoteControlV2Policy")
    projects = data.get("projectsSettings")
    return {
        "auto_review_rules": _count(review.get("allowInstructions"))
        + _count(review.get("blockInstructions")),
        "permissions_file_set": (isinstance(local_path, str) and bool(local_path.strip()))
        or _count(remote) > 0,
        "permissions_file_overrides_autorun": data.get("permissionsFileOverridesAutoRun") is True,
        "network_allowlist": _count(data.get("networkAllowlist")),
        "network_denylist": _count(data.get("networkDenylist")),
        "dot_cursor_protection": data.get("dotCursorProtection") is True,
        "enforce_hooks_readiness": data.get("enforceHooksReadiness") is True,
        "remote_control_enabled": isinstance(remote_ctl, dict) and remote_ctl.get("enabled") is True,
        "projects_settings_enabled": isinstance(projects, dict) and projects.get("enabled") is True,
    }


def read_permission_state(db_path: Path) -> tuple[dict | None, dict | None]:
    """Read the two policy rows independently of the legacy search summary."""
    try:
        con = sqlite3.connect(Path(db_path).resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
    except (sqlite3.Error, OSError, ValueError):
        return None, None
    try:
        return read_ide_state(con), read_admin_state(con)
    finally:
        con.close()


def legacy_permission_keys(con: sqlite3.Connection, permission_key_re, extra_skip=()) -> list[str]:
    """ItemTable keys (never values) worth a legacy allow-list parse."""
    try:
        keys = [str(r[0]) for r in con.execute("SELECT key FROM ItemTable")]
    except sqlite3.Error:
        return []
    return [
        k for k in keys
        if permission_key_re.search(k)
        and not k.startswith(SKIP_KEY_PREFIXES)
        and k not in SKIP_KEYS
        and k not in extra_skip
    ]


def fetch_value_text(con: sqlite3.Connection, key: str) -> str:
    try:
        row = con.execute("SELECT value FROM ItemTable WHERE key=? AND length(value)<=?",
                          (key, configfmt.MAX_CONFIG_BYTES)).fetchone()
    except sqlite3.Error:
        return ""
    if not row or row[0] is None:
        return ""
    value = row[0]
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", errors="ignore")
    return str(value)


# --------------------------------------------------------------------------
# result accumulator
# --------------------------------------------------------------------------

class _Result:
    def __init__(self) -> None:
        self.rules: list[dict] = []
        self.findings: list[dict] = []
        self.summary: dict[str, Any] = {}
        # (source, command name) for every allow entry
        self.allowed: list[tuple[str, str]] = []
        self.wildcards: dict[tuple[str, str], list[str]] = {}
        self.run_mode_finding = False
        self.has_allowlist = False
        self.auto_review_cli = 0
        self.hook_handlers = 0

    def add_finding(self, *args, **kwargs) -> None:
        self.findings.append(make_finding(*args, **kwargs))


def _load(path: Path, label: str, res: _Result) -> dict | None:
    try:
        data, err = configfmt.load_jsonc(path)
    except (RecursionError, ValueError):
        data, err = None, "invalid or excessively nested JSON"
    if err is None and path.is_file() and not isinstance(data, dict):
        err = "unexpected top-level type"
    if err:
        res.add_finding(
            "cursor.config.parse_error", "low", "General Tooling",
            f"Cursor {label} is present but could not be parsed",
            sample_redacted=err, tags=["config_parse_error"],
        )
        return None
    return data


def _command_name(inner: str) -> str:
    first = inner.split(":", 1)[0].strip()
    return first


def _basename(command: str) -> str:
    tokens = command.strip().split()
    first = tokens[0] if tokens else ""
    base = re.split(r"[\\/]", first)[-1].lower()
    return base[:-4] if base.endswith(".exe") else base


def _note_wildcard(res: _Result, source: str, kind: str, token: str) -> None:
    res.wildcards.setdefault((source, kind), []).append(_clean(token, 60))


# --------------------------------------------------------------------------
# CLI config
# --------------------------------------------------------------------------

def _cli_rule(res: _Result, token: str, decision: str, scope: str, source_kind: str,
              settings_source: str) -> None:
    token = evidence_text(token)
    match = TOKEN_RE.match(token)
    if not match:
        return
    kind, inner = match.group(1), match.group(2).strip()
    low = kind.lower()
    if low == "shell":
        rule_type, tool = "bash", _command_name(inner)
    elif low == "write":
        rule_type, tool = "edit", inner
    elif low == "webfetch":
        rule_type, tool = "web_fetch", inner
    elif low == "mcp":
        rule_type, tool = "mcp_tool", inner.split(":", 1)[0]
    elif low == "read":
        rule_type, tool = "other", inner
    else:
        return
    res.rules.append(make_rule(
        "cursor", scope, "global" if scope == "user" else "project", rule_type, token,
        decision, command_or_tool=tool or token, source_kind=source_kind,
        settings_source=settings_source, confidence="high",
    ))
    if decision != "allow":
        return
    if rule_type == "bash":
        res.has_allowlist = True
    if low == "shell":
        res.allowed.append((settings_source, tool))
        if tool in ("*", "**"):
            _note_wildcard(res, settings_source, "shell", token)
    elif low == "write" and inner in ("*", "**", "/**"):
        _note_wildcard(res, settings_source, "write", token)
    elif low == "mcp" and inner in ("*", "*:*"):
        _note_wildcard(res, settings_source, "mcp", token)
    elif low == "webfetch" and inner in ("*", "**"):
        _note_wildcard(res, settings_source, "webfetch", token)
    elif low == "read" and inner in ("*", "**", "/**"):
        _note_wildcard(res, settings_source, "read", token)


def _parse_cli(data: dict, *, scope: str, source_kind: str, label: str, res: _Result) -> dict:
    info = {"approval": "", "allow": 0, "deny": 0, "sandbox_mode": "", "network": "", "boundary": ""}
    approval = data.get("approvalMode")
    if isinstance(approval, str):
        info["approval"] = _clean(approval)
        if approval == "unrestricted":
            res.run_mode_finding = True
            title = (
                "Cursor Agent CLI approvalMode is unrestricted (Run Everything)"
                if scope == "user"
                else "Cursor project cli.json approvalMode is unrestricted (Run Everything)"
            )
            res.add_finding(
                "cursor.run_mode.unrestricted", "critical", "Shell Execution", title,
                sample_redacted=f"approvalMode: unrestricted ({label})",
                tags=["approval_bypass"],
            )
        elif approval == "auto-review":
            res.auto_review_cli += 1
            res.add_finding(
                "cursor.run_mode.auto_review", "low", "Shell Execution",
                f"Cursor Agent CLI uses auto-review approvals ({label})",
                sample_redacted="approvalMode: auto-review", tags=["approval_mode"],
            )
    perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
    for decision, field in (("allow", "allow"), ("deny", "deny")):
        tokens = [t for t in perms.get(field, []) if isinstance(t, str)] \
            if isinstance(perms.get(field), list) else []
        info[field] = len(tokens)
        for token in tokens:
            _cli_rule(res, token, decision, scope, source_kind, label)
    sandbox = data.get("sandbox") if isinstance(data.get("sandbox"), dict) else {}
    mode = sandbox.get("mode")
    if isinstance(mode, str):
        info["sandbox_mode"] = _clean(mode)
        if mode.strip().lower() in SANDBOX_OFF_MODES:
            res.add_finding(
                "cursor.sandbox.disabled", "medium", "Shell Execution",
                f"Cursor Agent CLI sandbox is disabled ({label})",
                sample_redacted=f"sandbox.mode: {_clean(mode)}", tags=["sandbox_off"],
            )
    network = sandbox.get("networkAccess")
    if isinstance(network, str):
        info["network"] = _clean(network)
        if (network.strip().lower() in NETWORK_ALLOW_ALL
                or "allow_all" in network.lower() or "allowall" in network.lower()
                or network.strip().lower() == "allow-all"):
            res.add_finding(
                "cursor.sandbox.network_allow_all", "high", "Network Egress",
                f"Cursor Agent CLI sandbox allows all network access ({label})",
                sample_redacted=f"sandbox.networkAccess: {_clean(network)}",
                tags=["sandbox_network"],
            )
    boundary = sandbox.get("readBoundary")
    if isinstance(boundary, str):
        info["boundary"] = _clean(boundary)
    return info


# --------------------------------------------------------------------------
# permissions.json / sandbox.json / hooks.json
# --------------------------------------------------------------------------

def _instruction_count(src: dict, *names: str) -> int:
    for name in names:
        if isinstance(src.get(name), list):
            return len(src[name])
    return 0


def _parse_permissions_json(data: dict, res: _Result) -> tuple[int, int]:
    src = data.get("autoRun") if isinstance(data.get("autoRun"), dict) else data
    return (
        _instruction_count(src, "allow_instructions", "allowInstructions"),
        _instruction_count(src, "block_instructions", "blockInstructions"),
    )


def _parse_sandbox_json(data: dict, label: str, res: _Result) -> None:
    sb_type = data.get("type")
    if isinstance(sb_type, str) and sb_type == "insecure_none":
        res.add_finding(
            "cursor.sandbox.disabled", "high", "Shell Execution",
            f"Cursor {label} sets sandbox type insecure_none",
            sample_redacted="type: insecure_none", tags=["sandbox_off"],
        )
    policy = data.get("networkPolicy") if isinstance(data.get("networkPolicy"), dict) else {}
    allow = _str_list(policy.get("allow"))
    if policy.get("default") in ("allow", "*") or "*" in allow:
        res.add_finding(
            "cursor.sandbox.network_allow_all", "high", "Network Egress",
            f"Cursor {label} sandbox allows all network access",
            sample_redacted="networkPolicy: allow all", tags=["sandbox_network"],
        )
    rw = _str_list(data.get("additionalReadwritePaths"))
    broad = [p for p in rw if p.strip() in BROAD_WRITE_ROOTS or DRIVE_ROOT_RE.match(p.strip())]
    if broad:
        res.add_finding(
            "cursor.sandbox.broad_write", "high", "Data Access",
            f"Cursor {label} sandbox grants write access to a filesystem or home root",
            evidence_count=len(broad), sample_redacted=", ".join(broad[:5]),
            tags=["sandbox_write"],
        )


def _hook_commands(entries: Any) -> list[str]:
    cmds: list[str] = []
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        if isinstance(entry.get("command"), str) and entry["command"].strip():
            cmds.append(entry["command"].strip())
        cmds.extend(_hook_commands(entry.get("hooks")))
    return cmds


def _parse_hooks_json(data: dict, label: str, res: _Result) -> None:
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return
    for event, entries in hooks.items():
        cmds = _hook_commands(entries)
        if not cmds:
            continue
        res.hook_handlers += len(cmds)
        sample = evidence_text(cmds[0])[:80]
        res.add_finding(
            "cursor.hooks.command", "medium", "Shell Execution",
            f"Cursor hook {_clean(event)} runs a command ({label})",
            evidence_count=len(cmds), sample_redacted=sample, tags=["hook"],
        )


# --------------------------------------------------------------------------
# IDE state
# --------------------------------------------------------------------------

def _ide_rule(res: _Result, rule_type: str, token: str, tool: str, decision: str, source: str) -> None:
    res.rules.append(make_rule(
        "cursor", "user", "global", rule_type, token, decision, command_or_tool=tool,
        source_kind="user_config", settings_source=source, confidence="high",
    ))


def _apply_ide_state(state: dict, res: _Result) -> None:
    cmd_src = "state.vscdb composerState.yoloCommandAllowlist"
    for cmd in state["yoloCommandAllowlist"]:
        _ide_rule(res, "bash", f"Shell({cmd})", cmd, "allow", cmd_src)
        res.allowed.append(("IDE state", cmd))
        res.has_allowlist = True
        if cmd in ("*", "**"):
            _note_wildcard(res, "IDE state", "shell", f"Shell({cmd})")
    for cmd in state["yoloCommandDenylist"]:
        _ide_rule(res, "bash", f"Shell({cmd})", cmd, "deny",
                  "state.vscdb composerState.yoloCommandDenylist")
    for domain in state["webFetchDomainAllowlist"]:
        _ide_rule(res, "web_fetch", f"WebFetch({domain})", domain, "allow",
                  "state.vscdb composerState.webFetchDomainAllowlist")
        if domain in ("*", "**"):
            _note_wildcard(res, "IDE state", "webfetch", f"WebFetch({domain})")

    if state.get("useYoloMode") and state.get("yoloEnableRunEverything"):
        res.run_mode_finding = True
        res.add_finding(
            "cursor.run_mode.unrestricted", "critical", "Shell Execution",
            "Cursor IDE Run Mode is Run Everything",
            sample_redacted="useYoloMode and yoloEnableRunEverything are on",
            tags=["approval_bypass"],
        )
    full = [m["name"] for m in state["modes"] if m["fullAutoRun"]]
    if full:
        res.run_mode_finding = True
        noun = "mode runs" if len(full) == 1 else "modes run"
        res.add_finding(
            "cursor.run_mode.full_auto_mode", "high", "Shell Execution",
            f"Cursor {', '.join(full)} {noun} every tool call automatically (fullAutoRun)",
            evidence_count=len(full), sample_redacted="modes: " + ", ".join(full[:5]),
            tags=["approval_bypass"],
        )
    auto_modes = [m["name"] for m in state["modes"] if m["autoRun"]]
    if (state.get("useYoloMode") or auto_modes) and state.get("yoloOutsideWorkspaceDisabled") is False:
        res.add_finding(
            "cursor.autorun.outside_workspace", "medium", "Data Access",
            "Cursor IDE auto-run may act outside the workspace",
            sample_redacted="yoloOutsideWorkspaceDisabled: false", tags=["autorun_scope"],
        )

    if state.get("useYoloMode") and state.get("yoloEnableRunEverything"):
        run_mode = "run-everything"
    elif state.get("useYoloMode"):
        run_mode = "auto-run (allowlist)"
    elif state.get("useYoloMode") is False:
        run_mode = "ask"
    else:
        run_mode = "unknown"
    res.summary.update({
        "ide_run_mode": run_mode,
        "ide_full_auto_modes": full,
        "ide_auto_run_modes": auto_modes,
        "ide_allowlist_count": len(state["yoloCommandAllowlist"]),
        "ide_denylist_count": len(state["yoloCommandDenylist"]),
        "ide_web_fetch_allowlist_count": len(state["webFetchDomainAllowlist"]),
        "ide_outside_workspace_disabled": state.get("yoloOutsideWorkspaceDisabled"),
        "ide_delete_file_disabled": state.get("yoloDeleteFileDisabled"),
        "ide_mcp_tools_autorun_disabled": state.get("yoloMcpToolsDisabled"),
    })


# --------------------------------------------------------------------------
# install / version
# --------------------------------------------------------------------------

def default_install_dirs() -> list[tuple[str, Path]]:
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    local = os.environ.get("LOCALAPPDATA")
    dirs = [("system", Path(program_files) / "Cursor")]
    if local:
        dirs.append(("user", Path(local) / "Programs" / "cursor"))
    return dirs


def detect_install(install_dirs) -> tuple[str, str]:
    """Return (version, scope) from the first product.json carrying a version."""
    candidates = default_install_dirs() if install_dirs is None else list(install_dirs)
    for index, item in enumerate(candidates):
        if isinstance(item, tuple):
            scope, path = item
        else:
            path, scope = item, ("system" if index == 0 else "user")
        try:
            data, err = configfmt.load_jsonc(Path(path) / "resources" / "app" / "product.json")
        except (RecursionError, ValueError):
            continue
        if err is None and isinstance(data, dict) and isinstance(data.get("version"), str):
            return _clean(data["version"], 40), scope
    return "", ""


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------

def project_repos(roots) -> list[Path]:
    """Repo roots themselves plus direct git-repo children (as for mcp.json)."""
    seen: set[str] = set()
    repos: list[Path] = []
    for root in roots or []:
        if not root.exists():
            continue
        candidates = [root] if (root / ".git").exists() else []
        try:
            candidates += [c for c in root.iterdir() if c.is_dir() and (c / ".git").exists()]
        except OSError:
            continue
        for repo in candidates:
            key = str(repo.resolve())
            if key not in seen:
                seen.add(key)
                repos.append(repo)
    return repos


def collect_permission_sources(
    cursor_home: Path,
    roots,
    ide_state: dict | None,
    admin_state: dict | None,
    install_dirs=None,
) -> dict:
    """Return {"rules", "findings", "summary", "has_allowlist", "run_mode_finding",
    "cli_present"} for all non-vscdb-legacy permission sources."""
    res = _Result()
    cursor_home = Path(cursor_home)

    # --- CLI config (global + project)
    cli_path = cursor_home / "cli-config.json"
    cli_present = cli_path.is_file()
    cli = {"approval": "", "allow": 0, "deny": 0, "sandbox_mode": "", "network": "", "boundary": ""}
    data = _load(cli_path, "cli-config.json", res)
    if data is not None:
        cli = _parse_cli(data, scope="user", source_kind="user_config",
                         label="cli-config.json", res=res)
    repos = project_repos(roots)
    project_cli = 0
    allow_total, deny_total = cli["allow"], cli["deny"]
    for repo in repos:
        path = repo / ".cursor" / "cli.json"
        if not path.is_file():
            continue
        project_cli += 1
        pdata = _load(path, "project .cursor/cli.json", res)
        if pdata is not None:
            info = _parse_cli(pdata, scope="project", source_kind="project_config",
                              label="project .cursor/cli.json", res=res)
            allow_total += info["allow"]
            deny_total += info["deny"]

    # --- permissions.json / sandbox.json / hooks.json
    perm_files = sandbox_files = 0
    allow_instr = block_instr = 0
    sources = [("user", cursor_home, "")] + [("project", r / ".cursor", ".cursor/") for r in repos]
    for scope, base, sub in sources:
        for name in ("permissions.json", "sandbox.json", "hooks.json"):
            path = base / name
            if not path.is_file():
                continue
            pdata = _load(path, f"{scope} {sub}{name}", res)
            if name == "permissions.json":
                perm_files += 1
                if pdata is not None:
                    a, b = _parse_permissions_json(pdata, res)
                    allow_instr += a
                    block_instr += b
            elif name == "sandbox.json":
                sandbox_files += 1
                if pdata is not None:
                    _parse_sandbox_json(pdata, f"{scope} sandbox.json", res)
            elif pdata is not None:
                _parse_hooks_json(pdata, f"{scope} hooks.json", res)

    # --- IDE state
    if ide_state is not None:
        _apply_ide_state(ide_state, res)

    # --- cross-source allow-list findings
    for (source, kind), tokens in res.wildcards.items():
        res.add_finding(
            "cursor.allowlist.wildcard", WILDCARD_SEVERITY[kind], "Shell Execution",
            f"Cursor {source} allow-list contains wildcard {kind} entries",
            evidence_count=len(tokens), sample_redacted=", ".join(tokens[:5]),
            tags=["allowlist_wildcard"],
        )
    for fid, sev, cat, names, title in (
        ("cursor.allowlist.interpreter", "high", "Shell Execution", INTERPRETERS,
         "Cursor auto-runs interpreters without asking ({n} allowlisted)"),
        ("cursor.allowlist.network_tools", "medium", "Network Egress", NETWORK_TOOLS,
         "Cursor auto-runs network tools without asking ({n} allowlisted)"),
        ("cursor.allowlist.destructive", "medium", "Data Access", DESTRUCTIVE,
         "Cursor auto-runs file-deleting commands without asking ({n} allowlisted)"),
    ):
        hits = sorted({_basename(cmd) for _, cmd in res.allowed if _basename(cmd) in names})
        if hits:
            res.add_finding(
                fid, sev, cat, title.format(n=len(hits)), evidence_count=len(hits),
                sample_redacted=", ".join(hits[:5]), tags=["allowlist"],
            )

    # --- summary
    summary = {
        "ide_state_read": ide_state is not None,
        "ide_run_mode": "unknown",
        "ide_full_auto_modes": [],
        "ide_auto_run_modes": [],
        "ide_allowlist_count": 0,
        "ide_denylist_count": 0,
        "ide_web_fetch_allowlist_count": 0,
        "ide_outside_workspace_disabled": None,
        "ide_delete_file_disabled": None,
        "ide_mcp_tools_autorun_disabled": None,
        "cli_config_present": cli_present,
        "cli_approval_mode": cli["approval"] or "unset",
        "cli_allow_count": allow_total,
        "cli_deny_count": deny_total,
        "cli_sandbox_mode": cli["sandbox_mode"] or "unset",
        "cli_sandbox_network": cli["network"] or "unset",
        "cli_read_boundary": cli["boundary"] or "unset",
        "project_cli_configs": project_cli,
        "permissions_json_files": perm_files,
        "auto_review_allow_instructions": allow_instr,
        "auto_review_block_instructions": block_instr,
        "sandbox_json_files": sandbox_files,
        "hooks_json_handlers": res.hook_handlers,
        "admin_policy_cached": admin_state is not None,
        "admin_auto_review_rules": 0,
        "admin_network_allowlist": 0,
        "admin_network_denylist": 0,
        "admin_permissions_file_set": False,
        "admin_permissions_file_overrides_autorun": False,
    }
    summary.update(res.summary)
    if admin_state is not None:
        summary.update({
            "admin_auto_review_rules": admin_state["auto_review_rules"],
            "admin_network_allowlist": admin_state["network_allowlist"],
            "admin_network_denylist": admin_state["network_denylist"],
            "admin_permissions_file_set": admin_state["permissions_file_set"],
            "admin_permissions_file_overrides_autorun":
                admin_state["permissions_file_overrides_autorun"],
            "admin_dot_cursor_protection": admin_state["dot_cursor_protection"],
            "admin_enforce_hooks_readiness": admin_state["enforce_hooks_readiness"],
            "admin_remote_control_enabled": admin_state["remote_control_enabled"],
            "admin_projects_settings_enabled": admin_state["projects_settings_enabled"],
        })
    version, scope = detect_install(install_dirs)
    summary["cursor_version"] = version
    summary["cursor_install_scope"] = scope

    return {
        "rules": res.rules,
        "findings": res.findings,
        "summary": summary,
        "has_allowlist": res.has_allowlist,
        "run_mode_finding": res.run_mode_finding,
        "cli_present": cli_present,
    }
