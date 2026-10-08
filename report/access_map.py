"""Cross-agent access map derived only from evidence envelopes.

``build_access_map`` is pure and stdlib-only. It does not read the filesystem.
A later integration step should call it from the briefing renderer.

Cells are ``yes``, ``no``, ``partial``, or ``unknown``. ``unknown`` means the
evidence cannot tell. Product behavior that no collector records stays unknown
on purpose.

Some agent/column pairs are uncaptured: no field in that collector's envelope
can move them off ``unknown``. They are listed in ``UNCAPTURED``.
"""

from __future__ import annotations

import re
from typing import Any

Cell = dict[str, Any]

AGENTS: tuple[tuple[str, str, str], ...] = (
    ("claude", "Claude Code", "claude"),
    ("cowork", "Claude Cowork", "cowork"),
    ("cursor", "Cursor", "cursor"),
    ("codex", "Codex", "codex"),
    ("copilot", "Copilot/VS Code", "copilot"),
    ("grok", "Grok Build", "grok"),
    ("grok-bot", "Grok Bot", "grok-bot"),
    ("cloud-agents", "Cursor cloud agents", "cloud-agents"),
)

COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("shell", "Runs shell commands", "Shell"),
    ("files", "Writes files", "Files"),
    ("network", "Network or MCP access", "Network / MCP"),
    ("secrets", "Can read secrets", "Secrets"),
    ("git", "Pushes to git/GitHub", "Git push"),
    ("remote", "Runs remotely", "Remote"),
    ("approval", "Approval mode", "Approval"),
)

# Agent/column pairs whose collector schema has no signal. The map always
# returns unknown for these, including when neighboring fields look alarming.
UNCAPTURED: dict[tuple[str, str], str] = {
    ("claude", "remote"): (
        "Claude Code evidence is local settings; remote execution is not recorded."
    ),
    ("cowork", "shell"): (
        "Cowork evidence counts sessions and files; shell commands are not recorded."
    ),
    ("cowork", "secrets"): (
        "Cowork evidence does not record secret stores or env grants."
    ),
    ("cowork", "git"): (
        "Cowork evidence does not record git or GitHub pushes."
    ),
    ("cowork", "approval"): (
        "Cowork evidence does not record an approval mode."
    ),
    ("cursor", "remote"): (
        "Cursor IDE evidence is local; remote agents are a separate inventory."
    ),
    ("codex", "remote"): (
        "Codex evidence is local config and sessions; remote execution is not recorded."
    ),
    ("copilot", "shell"): (
        "Copilot settings evidence does not record shell or terminal access."
    ),
    ("copilot", "files"): (
        "Copilot settings evidence does not record file writes."
    ),
    ("copilot", "secrets"): (
        "Copilot settings evidence does not record secret stores or env grants."
    ),
    ("copilot", "git"): (
        "Copilot settings evidence does not record git or GitHub pushes."
    ),
    ("copilot", "approval"): (
        "Copilot settings evidence does not record an approval mode."
    ),
    ("grok", "remote"): (
        "Grok Build evidence is local config and sessions; remote execution is not recorded."
    ),
    ("grok-bot", "files"): (
        "Grok Bot evidence is presence and size only; file writes are not recorded."
    ),
    ("grok-bot", "network"): (
        "Grok Bot evidence does not record network grants or MCP servers."
    ),
    ("grok-bot", "git"): (
        "Grok Bot evidence has no git or GitHub grant. "
        "box-secrets push state is a secrets file, not a git push."
    ),
    ("grok-bot", "remote"): (
        "Whether Grok Bot work runs on a hosted computer is not in this evidence."
    ),
    ("grok-bot", "approval"): (
        "Grok Bot approval mode is not stored on this computer."
    ),
    ("cloud-agents", "shell"): (
        "The Cloud Agents API inventory does not record shell or tool use."
    ),
    ("cloud-agents", "secrets"): (
        "The Cloud Agents API inventory does not record secret stores or env grants."
    ),
    ("cloud-agents", "approval"): (
        "The Cloud Agents API inventory does not record an approval mode."
    ),
}

_MCP_TRACKED = {"claude", "cursor", "codex", "grok"}
_SHELL_TYPES = {"bash", "powershell"}
_SHELL_TOOLS = {
    "run_terminal_command",
    "bash",
    "shell",
    "terminal",
    "powershell",
    "execute_command",
    "run_command",
}
_FILE_TOOLS = {
    "write_file",
    "edit_file",
    "apply_patch",
    "str_replace",
    "search_replace",
    "create_file",
    "delete_file",
}
_SANDBOX_OFF = {"danger-full-access", "disabled", "off", "none", "bypass"}
_SANDBOX_LIMITED = {"read-only", "workspace-write", "workspace_write"}
_ASK_POLICIES = {"on-request", "untrusted", "on-failure", "on-request-rule"}
_PROMPT_MODES = {"default", "prompt", "ask", "standard"}

_SHELL_RULE_RE = re.compile(r"^(Bash|PowerShell)\((.*)\)\s*$", re.I)
_GIT_RE = re.compile(r"\b(git|gh|hub)\b", re.I)
_NET_CMD_RE = re.compile(r"\b(curl|wget|ssh|nc|ncat)\b", re.I)


def build_access_map(envelopes: dict[str, dict]) -> dict[str, Any]:
    """Build the cross-agent access grid from collector envelopes.

    ``envelopes`` maps a collector id (``claude``, ``grok-bot``, ...) to its
    evidence object. Missing collectors are skipped in the sense that their
    cells stay ``unknown`` with a not-collected reason; the eight agent rows
    are always returned so the grid stays stable.

    Returns ``rows``, ``columns``, ``cells`` (each cell has ``value``,
    ``reason``, ``anchor``, and ``evidence``), ``headline``, and
    ``uncaptured``.
    """
    envelopes = envelopes or {}
    rows: list[dict[str, Any]] = []
    cells: dict[str, dict[str, Cell]] = {}

    for agent_id, label, collector in AGENTS:
        env = envelopes.get(collector)
        present, absent = _presence(collector, env if isinstance(env, dict) else None)
        rows.append(
            {
                "id": agent_id,
                "label": label,
                "collector": collector,
                "present": present,
            }
        )
        if not present or not isinstance(env, dict):
            cells[agent_id] = {
                column_id: _make_cell(
                    agent_id,
                    column_id,
                    "unknown",
                    absent or "Not collected.",
                    "none",
                    ["not collected"],
                    mcp_count=None,
                )
                for column_id, _label, _short in COLUMNS
            }
            continue
        view = _View(agent_id, collector, env)
        built = {
            "shell": _shell(view),
            "files": _files(view),
            "network": _network(view),
            "secrets": _secrets(view),
            "git": _git(view),
            "remote": _remote(view),
            "approval": _approval(view),
        }
        cells[agent_id] = built

    shell_yes = sum(1 for row in cells.values() if row["shell"]["value"] == "yes")
    git_yes = sum(1 for row in cells.values() if row["git"]["value"] == "yes")
    return {
        "rows": rows,
        "columns": [
            {"id": column_id, "label": label, "short": short}
            for column_id, label, short in COLUMNS
        ],
        "cells": cells,
        "headline": _headline(shell_yes, git_yes),
        "counts": {"shell_yes": shell_yes, "git_yes": git_yes},
        "uncaptured": [
            {"agent_id": agent_id, "column_id": column_id, "reason": reason}
            for (agent_id, column_id), reason in UNCAPTURED.items()
        ],
    }


def _headline(shell_yes: int, git_yes: int) -> str:
    shell_bit = "1 agent can" if shell_yes == 1 else f"{shell_yes} agents can"
    git_bit = "1 can" if git_yes == 1 else f"{git_yes} can"
    return f"{shell_bit} run shell commands; {git_bit} push to GitHub."


class _View:
    def __init__(self, agent_id: str, collector: str, env: dict[str, Any]) -> None:
        self.agent_id = agent_id
        self.collector = collector
        self.env = env
        summary = env.get("summary")
        self.summary = summary if isinstance(summary, dict) else {}
        self.rules = [r for r in (env.get("rules") or []) if isinstance(r, dict)]
        self.findings = [f for f in (env.get("findings") or []) if isinstance(f, dict)]
        self.finding_ids = {str(f.get("id") or "") for f in self.findings}
        self.source = f"evidence/{collector}.json"
        self.agents = [a for a in (env.get("agents") or []) if isinstance(a, dict)]

    def has_id(self, *ids: str) -> bool:
        return any(i in self.finding_ids for i in ids)

    def has_category(self, category: str) -> bool:
        return any(str(f.get("category") or "") == category for f in self.findings)

    def has_tag(self, tag: str) -> bool:
        for finding in self.findings:
            tags = finding.get("tags") or []
            if isinstance(tags, list) and tag in tags:
                return True
        return False

    def secret_findings(self) -> bool:
        if self.has_category("Secrets Exposure") or self.has_tag("env_read"):
            return True
        return any(bool(f.get("secret_redacted")) for f in self.findings)


def _presence(collector: str, env: dict[str, Any] | None) -> tuple[bool, str]:
    if not isinstance(env, dict):
        return False, f"Not collected (no {collector}.json)."
    if env.get("platform_detected") is False:
        if collector == "cloud-agents":
            summary = env.get("summary") if isinstance(env.get("summary"), dict) else {}
            if summary.get("key_configured") is False:
                return False, "Not collected (CURSOR_API_KEY was not configured)."
        return False, "Not detected on this machine."
    return True, ""


def _make_cell(
    agent_id: str,
    column_id: str,
    value: str,
    reason: str,
    evidence: str,
    sources: list[str],
    mcp_count: int | None,
) -> Cell:
    cell: Cell = {
        "value": value,
        "reason": reason,
        "anchor": f"access-evidence-{agent_id}-{column_id}",
        "evidence": evidence,
        "sources": sources,
    }
    if column_id == "network":
        cell["mcp_count"] = mcp_count
    return cell


def _cell(
    view: _View,
    column_id: str,
    value: str,
    reason: str,
    evidence: str,
    extra_sources: list[str] | None = None,
    mcp_count: int | None = None,
) -> Cell:
    sources = [view.source]
    for item in extra_sources or []:
        if item not in sources:
            sources.append(item)
    return _make_cell(view.agent_id, column_id, value, reason, evidence, sources, mcp_count)


def _forced(view: _View, column_id: str, mcp_count: int | None = None) -> Cell | None:
    reason = UNCAPTURED.get((view.agent_id, column_id))
    if reason is None:
        return None
    return _cell(view, column_id, "unknown", reason, "none", mcp_count=mcp_count)


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _flag_on(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"true", "1", "yes", "enabled", "on"}


def _shell_inner(rule: dict[str, Any]) -> str:
    text = str(rule.get("rule") or "").strip()
    match = _SHELL_RULE_RE.match(text)
    if match:
        return match.group(2).strip()
    return str(rule.get("command_or_tool_redacted") or "").strip()


def _is_allow(rule: dict[str, Any]) -> bool:
    return str(rule.get("decision") or "").lower() == "allow"


def _effective_type(rule: dict[str, Any]) -> str:
    """Prefer the declared type, but honor Bash/Edit/WebFetch text.

    The Cursor collector stores durable allow-list entries as rule_type
    ``other`` and puts the original pattern in ``rule``.
    """
    declared = str(rule.get("rule_type") or "")
    if declared in _SHELL_TYPES or declared in {"edit", "web_fetch", "mcp_tool"}:
        return declared
    text = str(rule.get("rule") or "").strip()
    if text.startswith("Bash("):
        return "bash"
    if text.startswith("PowerShell("):
        return "powershell"
    if text.startswith("Edit("):
        return "edit"
    if text.startswith("WebFetch("):
        return "web_fetch"
    if text.startswith("mcp__"):
        return "mcp_tool"
    return declared


def _shell_allows(view: _View) -> list[dict[str, Any]]:
    return [rule for rule in view.rules if _is_allow(rule) and _effective_type(rule) in _SHELL_TYPES]


def _is_unrestricted_shell(rule: dict[str, Any]) -> bool:
    inner = _shell_inner(rule)
    cmd = str(rule.get("command_or_tool_redacted") or "").strip()
    return inner in {"*", ""} or cmd == "*"


def _rule_blob(rule: dict[str, Any]) -> str:
    return f"{rule.get('command_or_tool_redacted') or ''} {_shell_inner(rule)} {rule.get('rule') or ''}"


def _git_allows(view: _View) -> list[dict[str, Any]]:
    return [rule for rule in view.rules if _is_allow(rule) and _GIT_RE.search(_rule_blob(rule))]


def _edit_allows(view: _View) -> list[dict[str, Any]]:
    return [rule for rule in view.rules if _is_allow(rule) and _effective_type(rule) == "edit"]


def _web_fetch_allows(view: _View) -> list[dict[str, Any]]:
    return [rule for rule in view.rules if _is_allow(rule) and _effective_type(rule) == "web_fetch"]


def _network_shell_allows(view: _View) -> list[dict[str, Any]]:
    return [rule for rule in _shell_allows(view) if _NET_CMD_RE.search(_rule_blob(rule))]


def _mcp_names(view: _View) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for rule in view.rules:
        if _effective_type(rule) != "mcp_tool":
            continue
        name = str(rule.get("command_or_tool_redacted") or rule.get("rule") or "").strip()
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    return names


def _tool_hits(view: _View, names: set[str]) -> list[str]:
    dist = view.summary.get("tools_used_distribution")
    if not isinstance(dist, dict):
        return []
    hits: list[str] = []
    for key, count in dist.items():
        if str(key).strip().lower() in names and (_as_int(count) or 0) > 0:
            hits.append(str(key))
    return hits


def _sandbox_mode(view: _View) -> str:
    return str(view.summary.get("sandbox_mode") or "").strip().lower()


def _sandbox_off(view: _View) -> bool:
    if _sandbox_mode(view) in _SANDBOX_OFF:
        return True
    if view.has_id("codex.sandbox.full_access", "codex.sandbox.bypass", "grok.sandbox.off"):
        return True
    if (_as_int(view.summary.get("sandbox_off_sessions")) or 0) > 0:
        return True
    for finding in view.findings:
        sample = str(finding.get("sample_redacted") or "").lower()
        if "sandbox=disabled" in sample or "danger-full-access" in sample:
            return True
    return False


def _approval_never(view: _View) -> bool:
    policy = view.summary.get("approval_policy")
    if isinstance(policy, str) and policy.strip().lower() == "never":
        return True
    return view.has_id("codex.approval.never")


def _bypass(view: _View) -> bool:
    return view.has_id("claude.permission.bypass_mode")


def _unrestricted_execution(view: _View) -> bool:
    """True when a recorded grant lets the agent run arbitrary commands."""
    if any(_is_unrestricted_shell(rule) for rule in _shell_allows(view)):
        return True
    if _sandbox_off(view) or _approval_never(view) or _bypass(view):
        return True
    if view.has_id("claude.permission.bash_wildcard"):
        return True
    return False


def _mcp_count(view: _View) -> int | None:
    if view.agent_id not in _MCP_TRACKED:
        return None
    names = _mcp_names(view)
    summary_vals: list[int] = []
    for key in (
        "mcp_servers",
        "mcp_runtime_servers",
        "mcp_registered",
        "known_mcp_servers",
        "desktop_mcp_servers",
        "mcp_rules",
    ):
        if key in view.summary:
            parsed = _as_int(view.summary.get(key))
            if parsed is not None:
                summary_vals.append(parsed)
    if names or summary_vals:
        return max([len(names), *summary_vals])
    if "rules" in view.env or view.summary:
        return 0
    return None


def _mcp_phrase(view: _View, count: int | None) -> str:
    if count is None:
        return "MCP servers are not in this evidence"
    names = _mcp_names(view)
    if count == 0:
        return "0 MCP servers recorded"
    config_n = _as_int(view.summary.get("mcp_servers")) if "mcp_servers" in view.summary else None
    runtime_n = (
        _as_int(view.summary.get("mcp_runtime_servers"))
        if "mcp_runtime_servers" in view.summary
        else None
    )
    if (
        view.agent_id == "grok"
        and config_n is not None
        and runtime_n is not None
        and config_n != runtime_n
    ):
        config_noun = "server" if config_n == 1 else "servers"
        return f"{config_n} MCP {config_noun} in config and {runtime_n} resolved at runtime"
    if len(names) == 1 and count == 1:
        return f"1 MCP server ({names[0]})"
    if 1 < len(names) <= 3 and len(names) == count:
        return f"{count} MCP servers ({', '.join(names)})"
    noun = "server" if count == 1 else "servers"
    return f"{count} MCP {noun}"


def _quoted_rule(rule: dict[str, Any]) -> str:
    text = str(rule.get("rule") or rule.get("command_or_tool_redacted") or "allow")
    return text if len(text) <= 80 else text[:77] + "..."


def _shell(view: _View) -> Cell:
    forced = _forced(view, "shell")
    if forced:
        return forced
    if view.agent_id == "grok-bot":
        return _grok_bot_shell(view)

    allows = _shell_allows(view)
    unrestricted = [rule for rule in allows if _is_unrestricted_shell(rule)]
    specific = [rule for rule in allows if not _is_unrestricted_shell(rule)]
    tool_hits = _tool_hits(view, _SHELL_TOOLS)

    if unrestricted:
        return _cell(
            view,
            "shell",
            "yes",
            f"Allow rule {_quoted_rule(unrestricted[0])} grants unrestricted shell.",
            "high",
            [f"rule {_quoted_rule(unrestricted[0])}"],
        )
    if _sandbox_off(view):
        return _cell(
            view,
            "shell",
            "yes",
            "Sandbox is disabled, so shell commands are not contained.",
            "high" if view.has_id("codex.sandbox.full_access", "codex.sandbox.bypass", "grok.sandbox.off") else "moderate",
            ["sandbox off"],
        )
    if tool_hits:
        shown = ", ".join(tool_hits[:3])
        return _cell(
            view,
            "shell",
            "yes",
            f"Session metadata records shell tool use ({shown}).",
            "moderate",
            [f"tool {shown}"],
        )
    if view.has_id("claude.permission.bash_wildcard"):
        return _cell(
            view,
            "shell",
            "yes",
            "A wildcard bash allow finding is recorded.",
            "moderate",
            ["finding claude.permission.bash_wildcard"],
        )
    if view.has_id("claude.shell_audit.log_present"):
        return _cell(
            view,
            "shell",
            "yes",
            "A shell audit log is present, so commands have been run.",
            "moderate",
            ["finding claude.shell_audit.log_present"],
        )
    if _bypass(view) or _approval_never(view):
        return _cell(
            view,
            "shell",
            "yes",
            "Permission prompts are bypassed, so shell commands can run unattended.",
            "moderate",
            ["approval bypass"],
        )
    if specific:
        shown = ", ".join(_quoted_rule(rule) for rule in specific[:3])
        return _cell(
            view,
            "shell",
            "partial",
            f"Shell is allowed only for specific commands ({shown}).",
            "moderate",
            [f"rule {shown}"],
        )
    mode = _sandbox_mode(view)
    if mode in _SANDBOX_LIMITED:
        return _cell(
            view,
            "shell",
            "partial",
            f"Shell runs inside sandbox_mode {mode}.",
            "moderate",
            [f"sandbox_mode {mode}"],
        )
    if view.has_id("cursor.permissions.no_durable_allowlist"):
        return _cell(
            view,
            "shell",
            "unknown",
            "No durable command allow-list was found; shell use is not recorded.",
            "low",
            ["finding cursor.permissions.no_durable_allowlist"],
        )
    return _cell(
        view,
        "shell",
        "unknown",
        "No shell allow rule or shell finding is in this evidence.",
        "none",
    )


def _grok_bot_shell(view: _View) -> Cell:
    lexical = str(view.summary.get("local_execution") or "unknown").strip().lower()
    reason_code = str(view.summary.get("local_execution_reason") or "not_determinable_offline")
    if lexical == "unknown":
        return _cell(
            view,
            "shell",
            "unknown",
            (
                "Local execution is unknown. This offline scan cannot tell."
                if reason_code == "not_determinable_offline"
                else f"Local execution is unknown ({reason_code.replace('_', ' ')})."
            ),
            "none",
            ["summary.local_execution"],
        )
    if lexical in {"on", "enabled", "local", "true", "always"}:
        return _cell(
            view,
            "shell",
            "yes",
            f"local_execution is {lexical}.",
            "moderate",
            ["summary.local_execution"],
        )
    if lexical in {"off", "disabled", "never", "false"}:
        return _cell(
            view,
            "shell",
            "no",
            f"local_execution is {lexical}.",
            "moderate",
            ["summary.local_execution"],
        )
    return _cell(
        view,
        "shell",
        "unknown",
        f"local_execution value {lexical} is not a known signal.",
        "low",
        ["summary.local_execution"],
    )


def _files(view: _View) -> Cell:
    forced = _forced(view, "files")
    if forced:
        return forced
    mode = _sandbox_mode(view)
    if mode == "read-only":
        return _cell(
            view,
            "files",
            "no",
            "sandbox_mode is read-only, so workspace writes are blocked.",
            "high",
            ["sandbox_mode read-only"],
        )
    edits = _edit_allows(view)
    if edits:
        return _cell(
            view,
            "files",
            "yes",
            f"Edit allow rule {_quoted_rule(edits[0])} grants file writes.",
            "high",
            [f"rule {_quoted_rule(edits[0])}"],
        )
    if view.has_id("claude.file_history.snapshots"):
        return _cell(
            view,
            "files",
            "yes",
            "Pre-edit file snapshots are stored, so this agent writes files.",
            "moderate",
            ["finding claude.file_history.snapshots"],
        )
    file_tools = _tool_hits(view, _FILE_TOOLS)
    if file_tools:
        shown = ", ".join(file_tools[:3])
        return _cell(
            view,
            "files",
            "yes",
            f"Session metadata records file-write tool use ({shown}).",
            "moderate",
            [f"tool {shown}"],
        )
    output_files = _as_int(view.summary.get("output_files")) if "output_files" in view.summary else None
    if output_files and output_files > 0:
        return _cell(
            view,
            "files",
            "yes",
            (
                f"{output_files} Cowork session output file is on disk."
                if output_files == 1
                else f"{output_files} Cowork session output files are on disk."
            ),
            "moderate",
            ["summary.output_files"],
        )
    if mode == "workspace-write":
        return _cell(
            view,
            "files",
            "partial",
            "sandbox_mode workspace-write allows writes inside the workspace.",
            "moderate",
            ["sandbox_mode workspace-write"],
        )
    if view.agent_id == "cloud-agents":
        return _cloud_files(view)
    if _unrestricted_execution(view):
        return _cell(
            view,
            "files",
            "partial",
            "Unrestricted command execution could write files; no edit grant was recorded.",
            "low",
            ["unrestricted execution"],
        )
    return _cell(
        view,
        "files",
        "unknown",
        "No edit grant, file snapshot, or write-tool record is in this evidence.",
        "none",
    )


def _cloud_files(view: _View) -> Cell:
    if _cloud_writes_repo(view):
        return _cell(
            view,
            "files",
            "yes",
            "A branch or pull request is recorded, so the agent writes repository files.",
            "moderate",
            ["agent branch or pr"],
        )
    if _cloud_has_repos(view):
        return _cell(
            view,
            "files",
            "partial",
            "Repositories are attached; file writes are not shown.",
            "low",
            ["agent repos"],
        )
    if _cloud_inventory_empty(view):
        return _cell(
            view,
            "files",
            "no",
            "No cloud agents were returned for this account.",
            "moderate",
            ["summary.total_agents"],
        )
    return _cell(
        view,
        "files",
        "unknown",
        "No branch, pull request, or repository write is recorded.",
        "none",
    )


def _network(view: _View) -> Cell:
    forced = _forced(view, "network", mcp_count=None)
    if forced:
        return forced
    count = _mcp_count(view)
    phrase = _mcp_phrase(view, count)
    direct_bits: list[str] = []
    if count and count > 0:
        direct_bits.append(phrase)
    if _web_fetch_allows(view) or _network_shell_allows(view):
        direct_bits.append("a network command or WebFetch grant is allowed")
    if view.has_category("Network Egress") or view.has_tag("network_egress") or view.has_tag("mcp_external"):
        direct_bits.append("a network-egress finding is recorded")
    if view.has_id("codex.network.workspace_write"):
        direct_bits.append("sandbox workspace-write has network_access")
    if view.agent_id == "cowork" and _cowork_bridged(view):
        direct_bits.append(f"{_cowork_bridge_count(view)} session(s) bridged off the machine")

    if direct_bits:
        evidence = "high" if count and count > 0 and len(direct_bits) > 1 else "moderate"
        if count and count > 0 and len(direct_bits) == 1:
            evidence = "high" if "mcp_servers" in view.summary or _mcp_names(view) else "moderate"
        return _cell(
            view,
            "network",
            "yes",
            _sentence(direct_bits, prefix=None if (count and count > 0) else phrase),
            evidence,
            ["network grant"],
            mcp_count=count,
        )
    if view.agent_id == "copilot":
        return _copilot_network(view)
    if view.agent_id == "cloud-agents":
        return _cloud_network(view, count)
    if _unrestricted_execution(view):
        return _cell(
            view,
            "network",
            "partial",
            f"Unrestricted command execution could reach the network; {phrase}.",
            "low",
            ["unrestricted execution"],
            mcp_count=count,
        )
    if count == 0:
        return _cell(
            view,
            "network",
            "unknown",
            f"{phrase}; other network use is not recorded.",
            "low" if view.summary else "none",
            mcp_count=count,
        )
    return _cell(
        view,
        "network",
        "unknown",
        "Network grants and MCP servers are not in this evidence.",
        "none",
        mcp_count=count,
    )


def _sentence(bits: list[str], prefix: str | None) -> str:
    parts = []
    if prefix:
        parts.append(prefix)
    parts.extend(bits)
    text = "; ".join(parts)
    if not text.endswith("."):
        text += "."
    return text[0].upper() + text[1:]


def _copilot_network(view: _View) -> Cell:
    public = view.summary.get("public_code_suggestions")
    telemetry = view.summary.get("telemetry") if "telemetry" in view.summary else None
    bits: list[str] = []
    if _flag_on(public):
        bits.append("public code suggestions are enabled")
    if telemetry is not None and str(telemetry).strip().lower() not in {"", "unset", "off", "false", "none", "0"}:
        bits.append(f"telemetry is {telemetry}")
    if not bits:
        return _cell(
            view,
            "network",
            "unknown",
            "Copilot evidence does not record MCP servers or network grants.",
            "none",
            mcp_count=None,
        )
    return _cell(
        view,
        "network",
        "partial",
        _sentence(bits, "data can leave the machine") + " MCP servers are not in this evidence.",
        "low",
        ["copilot egress setting"],
        mcp_count=None,
    )


def _cloud_network(view: _View, count: int | None) -> Cell:
    if _cloud_has_repos(view) or _cloud_has_pr(view):
        return _cell(
            view,
            "network",
            "partial",
            "Repository hosts are in the inventory; MCP server count is not in the Cloud Agents API.",
            "moderate",
            ["agent repos"],
            mcp_count=None,
        )
    if _cloud_inventory_empty(view):
        return _cell(
            view,
            "network",
            "unknown",
            "No cloud agents were returned; MCP servers are not in the API.",
            "low",
            ["summary.total_agents"],
            mcp_count=None,
        )
    return _cell(
        view,
        "network",
        "unknown",
        "No repository host is recorded, and MCP servers are not in the Cloud Agents API.",
        "none",
        mcp_count=count,
    )


def _secrets(view: _View) -> Cell:
    forced = _forced(view, "secrets")
    if forced:
        return forced
    if view.agent_id == "grok-bot":
        sand = bool(view.summary.get("sand_secrets_present"))
        box = bool(view.summary.get("box_secrets_push_state_present"))
        if sand or box or view.has_id("grok_bot.secrets.store_present"):
            parts = []
            if sand:
                parts.append("sand-secrets.json")
            if box:
                parts.append("box-secrets-push-state")
            listed = " and ".join(parts) if parts else "a secrets store"
            return _cell(
                view,
                "secrets",
                "yes",
                f"Secrets store is present ({listed}). Contents were not read.",
                "high" if sand or box else "moderate",
                ["summary secrets store"],
            )
        if "sand_secrets_present" in view.summary:
            return _cell(
                view,
                "secrets",
                "unknown",
                "Local secrets files are absent; cloud-side secrets are not in this evidence.",
                "low",
                ["summary.sand_secrets_present"],
            )
    if view.secret_findings() or view.has_id(
        "claude.env.secret_value",
        "codex.env.inherit_all",
        "codex.env.ignore_excludes",
        "codex.mcp.env_secret",
        "grok.mcp.env_secret",
        "grok.mcp.args_secret",
        "grok.auth.present_excluded",
    ):
        return _cell(
            view,
            "secrets",
            "yes",
            "A secret store or an env/credential exposure is recorded for this agent.",
            "high",
            ["secrets finding"],
        )
    if view.summary.get("auth_json_exists") is True:
        return _cell(
            view,
            "secrets",
            "yes",
            "auth.json is present, so this agent holds credentials. Contents were not read.",
            "moderate",
            ["summary.auth_json_exists"],
        )
    return _cell(
        view,
        "secrets",
        "unknown",
        "No secret store or env-exposure grant is in this evidence.",
        "none",
    )


def _git(view: _View) -> Cell:
    forced = _forced(view, "git")
    if forced:
        return forced
    git_rules = _git_allows(view)
    if git_rules:
        return _cell(
            view,
            "git",
            "yes",
            f"Allow rule {_quoted_rule(git_rules[0])} covers git or GitHub.",
            "high",
            [f"rule {_quoted_rule(git_rules[0])}"],
        )
    if view.agent_id == "cloud-agents":
        return _cloud_git(view)
    if _unrestricted_execution(view):
        return _cell(
            view,
            "git",
            "partial",
            "Unrestricted command execution could run git push; no git or GitHub grant was recorded.",
            "low",
            ["unrestricted execution"],
        )
    return _cell(
        view,
        "git",
        "unknown",
        "No git or GitHub push grant is in this evidence.",
        "none",
    )


def _cloud_git(view: _View) -> Cell:
    if _cloud_has_pr(view) or _cloud_auto_push(view) or view.has_id(
        "cloud_agents.active_current_branch",
        "cloud_agents.active_repo_write",
    ):
        if view.has_id("cloud_agents.active_current_branch") or any(
            agent.get("work_on_current_branch") is True for agent in view.agents
        ):
            reason = "An agent can push to the repository current branch or has opened a pull request."
        else:
            reason = "A pull request or repository write is recorded for a cloud agent."
        return _cell(view, "git", "yes", reason, "high", ["cloud agent git"])
    if _cloud_has_branch(view):
        return _cell(
            view,
            "git",
            "partial",
            "A git branch is recorded; a pull request URL is not.",
            "moderate",
            ["agent branch"],
        )
    if _cloud_has_repos(view):
        return _cell(
            view,
            "git",
            "partial",
            "Repositories are attached; no branch or pull request is recorded.",
            "low",
            ["agent repos"],
        )
    if _cloud_inventory_empty(view):
        return _cell(
            view,
            "git",
            "no",
            "No cloud agents were returned for this account.",
            "moderate",
            ["summary.total_agents"],
        )
    return _cell(
        view,
        "git",
        "unknown",
        "No branch, pull request, or repository write is recorded.",
        "none",
    )


def _remote(view: _View) -> Cell:
    forced = _forced(view, "remote")
    if forced:
        return forced
    if view.agent_id == "cloud-agents":
        return _cloud_remote(view)
    if view.agent_id == "cowork":
        if _cowork_bridged(view):
            count = _cowork_bridge_count(view)
            return _cell(
                view,
                "remote",
                "yes",
                f"{count} Cowork session(s) are bridged to a remote cloud environment.",
                "high",
                ["cowork bridge"],
            )
        if view.summary.get("design_used") is True or view.has_id("cowork.design.in_use"):
            return _cell(
                view,
                "remote",
                "partial",
                "Claude Design has been opened; whether that work runs in the cloud is not recorded.",
                "low",
                ["summary.design_used"],
            )
        return _cell(
            view,
            "remote",
            "unknown",
            "No Cowork cloud bridge is recorded.",
            "none",
        )
    if view.agent_id == "copilot" and _flag_on(view.summary.get("public_code_suggestions")):
        return _cell(
            view,
            "remote",
            "partial",
            "Public code suggestions are enabled, so completions leave the machine; a remote agent runtime is not recorded.",
            "low",
            ["summary.public_code_suggestions"],
        )
    return _cell(
        view,
        "remote",
        "unknown",
        "Remote execution is not recorded for this agent.",
        "none",
    )


def _cloud_remote(view: _View) -> Cell:
    if not view.agents:
        if _cloud_inventory_empty(view):
            return _cell(
                view,
                "remote",
                "no",
                "No cloud agents were returned for this account.",
                "moderate",
                ["summary.total_agents"],
            )
        return _cell(
            view,
            "remote",
            "unknown",
            "No cloud agent records are in this evidence.",
            "none",
        )
    types = sorted(
        {
            str(agent.get("env_type") or "").strip()
            for agent in view.agents
            if str(agent.get("env_type") or "").strip()
        }
    )
    if types == ["local"]:
        return _cell(
            view,
            "remote",
            "partial",
            "Inventoried agents report env_type local, not a hosted environment.",
            "moderate",
            ["env_type local"],
        )
    shown = ", ".join(types) if types else "unspecified"
    local_too = "local" in types
    if local_too:
        return _cell(
            view,
            "remote",
            "partial",
            f"Agents report env types {shown}; at least one is local.",
            "moderate",
            ["env_type"],
        )
    return _cell(
        view,
        "remote",
        "yes",
        f"Agents run on Cursor infrastructure (env_type {shown}).",
        "high",
        ["env_type"],
    )


def _approval(view: _View) -> Cell:
    forced = _forced(view, "approval")
    if forced:
        return forced
    if view.agent_id == "grok":
        return _grok_approval(view)
    if view.agent_id == "codex":
        return _codex_approval(view)
    if view.agent_id == "claude":
        return _claude_approval(view)
    if view.agent_id == "cursor":
        return _cursor_approval(view)
    return _cell(
        view,
        "approval",
        "unknown",
        "Approval mode is not recorded for this agent.",
        "none",
    )


def _grok_approval(view: _View) -> Cell:
    mode = str(view.summary.get("permission_mode") or "").strip().lower()
    yolo = view.summary.get("yolo")
    yolo_on = yolo is True or (isinstance(yolo, str) and yolo.strip().lower() in {"true", "1", "yes"})
    if mode == "always-approve" or yolo_on or view.has_id("grok.permission.always_approve"):
        bits = []
        if mode:
            bits.append(f"permission_mode is {mode}")
        if yolo_on:
            bits.append("yolo is on")
        if not bits:
            bits.append("always-approve was recorded")
        return _cell(
            view,
            "approval",
            "yes",
            "Auto-approve: " + " and ".join(bits) + ".",
            "high",
            ["summary.permission_mode"],
        )
    if mode in _PROMPT_MODES:
        return _cell(
            view,
            "approval",
            "no",
            f"Ask: permission_mode is {mode}.",
            "high",
            ["summary.permission_mode"],
        )
    if (_as_int(view.summary.get("sandbox_off_sessions")) or 0) > 0 or view.has_id("grok.sandbox.off"):
        return _cell(
            view,
            "approval",
            "partial",
            "Sandbox: sessions ran with the sandbox off; permission_mode is not recorded.",
            "moderate",
            ["sandbox off"],
        )
    return _cell(
        view,
        "approval",
        "unknown",
        "permission_mode is not recorded.",
        "none",
    )


def _codex_approval(view: _View) -> Cell:
    policy = view.summary.get("approval_policy")
    policy_text = policy.strip().lower() if isinstance(policy, str) else ""
    mode = _sandbox_mode(view)
    if _approval_never(view) or _sandbox_off(view):
        bits = []
        if policy_text == "never" or view.has_id("codex.approval.never"):
            bits.append("approval_policy is never")
        if _sandbox_off(view):
            bits.append(f"sandbox is {mode or 'disabled'}")
        return _cell(
            view,
            "approval",
            "yes",
            "Auto-approve: " + " and ".join(bits) + ".",
            "high",
            ["codex approval"],
        )
    if policy_text == "granular":
        return _cell(
            view,
            "approval",
            "partial",
            "Approval policy is granular.",
            "moderate",
            ["summary.approval_policy"],
        )
    if policy_text in _ASK_POLICIES and mode in _SANDBOX_LIMITED:
        return _cell(
            view,
            "approval",
            "partial",
            f"Ask: approval_policy is {policy_text}. Sandbox: sandbox_mode is {mode}.",
            "high",
            ["summary.approval_policy"],
        )
    if policy_text in _ASK_POLICIES:
        return _cell(
            view,
            "approval",
            "no",
            f"Ask: approval_policy is {policy_text}.",
            "high",
            ["summary.approval_policy"],
        )
    if mode in _SANDBOX_LIMITED:
        return _cell(
            view,
            "approval",
            "partial",
            f"Sandbox: sandbox_mode is {mode}.",
            "moderate",
            ["summary.sandbox_mode"],
        )
    return _cell(
        view,
        "approval",
        "unknown",
        "approval_policy and sandbox_mode are not recorded.",
        "none",
    )


def _claude_approval(view: _View) -> Cell:
    if _bypass(view):
        return _cell(
            view,
            "approval",
            "yes",
            "Auto-approve: the default permission mode bypasses prompts.",
            "high",
            ["finding claude.permission.bypass_mode"],
        )
    if view.has_id("claude.permission.skip_dangerous_prompt"):
        return _cell(
            view,
            "approval",
            "partial",
            "Dangerous-mode confirmation is disabled; the default permission mode is not recorded.",
            "moderate",
            ["finding claude.permission.skip_dangerous_prompt"],
        )
    ask_rules = _as_int(view.summary.get("ask_rules")) or 0
    allow_rules = [
        rule
        for rule in view.rules
        if _is_allow(rule) and str(rule.get("rule_type") or "") != "mcp_tool"
    ]
    summary_allows = _as_int(view.summary.get("allow_rules")) or 0
    if ask_rules and not allow_rules and not summary_allows:
        return _cell(
            view,
            "approval",
            "no",
            "Ask: settings have ask rules and no allow rules or bypass.",
            "moderate",
            ["summary.ask_rules"],
        )
    if allow_rules or summary_allows:
        return _cell(
            view,
            "approval",
            "partial",
            "Stored allow rules exist; the default permission mode is not recorded.",
            "low",
            ["allow rules"],
        )
    return _cell(
        view,
        "approval",
        "unknown",
        "Approval mode is not recorded in Claude settings.",
        "none",
    )


def _cursor_approval(view: _View) -> Cell:
    workspaces = _as_int(view.summary.get("composer_auto_accept_workspaces")) or 0
    if workspaces > 0:
        return _cell(
            view,
            "approval",
            "partial",
            f"Auto-accept was recorded for {workspaces} workspace(s); a global approval mode is not stored.",
            "moderate",
            ["summary.composer_auto_accept_workspaces"],
        )
    if view.summary.get("agent_autorun_default_attempted") is True:
        return _cell(
            view,
            "approval",
            "partial",
            "An autorun default was attempted; the current approval mode is not stored.",
            "low",
            ["summary.agent_autorun_default_attempted"],
        )
    events = _as_int(view.summary.get("permission_events")) or 0
    if events > 0 or view.has_id("cursor.permissions.events_observed"):
        return _cell(
            view,
            "approval",
            "unknown",
            "Permission events were observed, but the approval mode is not stored.",
            "low",
            ["permission events"],
        )
    return _cell(
        view,
        "approval",
        "unknown",
        "Approval mode is not recorded in Cursor local state.",
        "none",
    )


def _cowork_bridge_count(view: _View) -> int:
    count = _as_int(view.summary.get("bridge_synced_sessions")) or 0
    if count:
        return count
    for finding in view.findings:
        if finding.get("id") == "cowork.bridge.remote_sync":
            return _as_int(finding.get("evidence_count")) or 1
    return 0


def _cowork_bridged(view: _View) -> bool:
    return _cowork_bridge_count(view) > 0 or view.has_id("cowork.bridge.remote_sync")


def _cloud_inventory_empty(view: _View) -> bool:
    total = view.summary.get("total_agents")
    if total is None:
        return False
    return (_as_int(total) or 0) == 0 and not view.agents


def _cloud_has_repos(view: _View) -> bool:
    for agent in view.agents:
        for repo in agent.get("repos") or []:
            if isinstance(repo, dict) and str(repo.get("url") or "").strip():
                return True
    return False


def _cloud_has_pr(view: _View) -> bool:
    if (_as_int(view.summary.get("agents_with_prs")) or 0) > 0:
        return True
    for agent in view.agents:
        for repo in agent.get("repos") or []:
            if isinstance(repo, dict) and str(repo.get("pr_url") or "").strip():
                return True
        for branch in agent.get("branches") or []:
            if isinstance(branch, dict) and str(branch.get("pr_url") or "").strip():
                return True
    return False


def _cloud_auto_push(view: _View) -> bool:
    return any(
        agent.get("auto_create_pr") is True or agent.get("work_on_current_branch") is True
        for agent in view.agents
    )


def _cloud_has_branch(view: _View) -> bool:
    for agent in view.agents:
        for branch in agent.get("branches") or []:
            if isinstance(branch, dict) and str(branch.get("branch") or "").strip():
                return True
    return False


def _cloud_writes_repo(view: _View) -> bool:
    return _cloud_has_pr(view) or _cloud_has_branch(view) or _cloud_auto_push(view) or view.has_id(
        "cloud_agents.active_current_branch",
        "cloud_agents.active_repo_write",
    )
