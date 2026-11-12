"""Synthetic scan history for trying the hub without scanning anything.

Three made-up machines, a few months of weekly scans. Every name, rule and
sample here is invented. Nothing is read from this machine.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any

import hub_paths  # noqa: F401

from hub_bundle import BUNDLE_VERSION

HOSTS = ("DEMO-LAPTOP", "DEMO-WORKSTATION", "DEMO-BUILD")

# (collector, id, severity, category, title, sample)
_FINDINGS = (
    ("claude", "claude.permission.skip_dangerous_prompt", "critical", "Shell Execution",
     "Claude skips dangerous-mode permission prompt", "skipDangerousModePermissionPrompt=true"),
    ("claude", "claude.permission.bash_curl_wide", "high", "Network Egress",
     "Claude has unrestricted curl approval", "Bash(curl:*)"),
    ("claude", "claude.retention.history", "low", "Data Access",
     "Claude prompt history is kept on disk", ""),
    ("cursor", "cursor.mcp.remote_server", "medium", "MCP Tooling",
     "Cursor has a remote MCP server configured", "mcp: demo-tracker"),
    ("cursor", "cursor.permission.allowlist_wide", "high", "Shell Execution",
     "Cursor allow-list contains a wildcard command", "npm run *"),
    ("codex", "codex.sandbox.bypass", "critical", "Shell Execution",
     "Codex sandbox is set to danger-full-access", "sandbox_mode=danger-full-access"),
    ("codex", "codex.trust.projects", "medium", "Data Access",
     "Codex trusts 4 projects without prompting", ""),
    ("grok", "grok.permission.always_approve", "critical", "Shell Execution",
     "Grok Build approves every action", "permission_mode=always-approve"),
    ("vscode", "vscode.copilot.agent_auto_approve", "high", "Shell Execution",
     "Copilot agent mode auto-approves terminal commands", "chat.tools.autoApprove=true"),
    ("chat-history", "chat_history.secret_hit", "medium", "Secrets Exposure",
     "Chat transcripts contain secret-shaped strings", ""),
    ("chat-history", "chat_history.retention.long", "low", "Data Access",
     "Chat history older than 90 days is kept locally", ""),
    ("git-posture", "git.env.in_history", "critical", "Git Posture",
     ".env file found in git commit history (2 repos)", ""),
    ("git-posture", "git.hooks.pre_commit_missing", "low", "Git Posture",
     "No pre-commit hook in 5 repos", ""),
    ("secrets-scan", "secrets-scan.hit.generic-api-key", "high", "Secrets Exposure",
     "Secret detected by betterleaks: generic-api-key (6 hit(s) across 3 file(s))", "demo...mple (generic-api-key)"),
    ("pii-scan", "pii.email", "low", "Data Access",
     "Email addresses in chat transcripts (41 hit(s) across 9 file(s))", ""),
    ("accounts", "accounts.identity.multiple", "medium", "Identity & SSO",
     "Tools are signed in with 2 different accounts", ""),
)

_RULES = (
    ("claude", "bash", "Bash(curl:*)", "allow", "high", "Network Egress"),
    ("claude", "bash", "Bash(git status)", "allow", "low", "Shell Execution"),
    ("claude", "bash", "Bash(npm run test:*)", "allow", "medium", "Shell Execution"),
    ("claude", "mcp_tool", "mcp__playwright", "allow", "medium", "MCP Tooling"),
    ("claude", "bash", "Bash(rm -rf:*)", "deny", "high", "Shell Execution"),
    ("claude", "web_fetch", "WebFetch(domain:docs.example.com)", "ask", "low", "Network Egress"),
    ("cursor", "bash", "npm run *", "allow", "medium", "Shell Execution"),
    ("cursor", "mcp_tool", "mcp__demo-tracker", "allow", "medium", "MCP Tooling"),
    ("codex", "bash", "docker compose *", "allow", "high", "Shell Execution"),
    ("codex", "bash", "pytest", "allow", "low", "Shell Execution"),
    ("grok", "mcp_tool", "mcp__filesystem", "allow", "medium", "MCP Tooling"),
)

_ACCOUNTS = (
    ("claude-code", "dev@example.com", "Demo Org", "max", "oauth", "~/.claude.json"),
    ("cursor", "dev@example.com", "", "pro", "oauth", "%APPDATA%/Cursor/User/globalStorage/state.vscdb"),
    ("codex", "builds@example.com", "Demo Org", "team", "oauth", "~/.codex/auth.json"),
    ("git", "dev@example.com", "", "", "git_config", "~/.gitconfig"),
)

_ALL = ("claude", "cursor", "codex", "grok", "vscode", "chat-history", "git-posture",
        "secrets-scan", "pii-scan", "accounts")


def _envelope(collector: str, host: str, when: datetime) -> dict[str, Any]:
    return {
        "collector": collector, "version": "1.0.0", "aiscan_version": "0.2.0-demo",
        "ran_at": when.isoformat(), "host": host, "platform_detected": True,
        "scope_hash": "demo", "summary": {}, "findings": [], "rules": [],
    }


def demo_bundles(weeks: int = 12, *, end: datetime | None = None) -> list[dict[str, Any]]:
    """Normalized-shape bundles, oldest first. Same output for the same end time."""
    rng = random.Random(13)
    end = end or datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    bundles = []
    for host_index, host in enumerate(HOSTS):
        # Each machine starts with its own subset and drifts week to week:
        # some findings get fixed, a few new ones appear.
        active = {index for index in range(len(_FINDINGS)) if rng.random() < 0.55 + 0.1 * host_index}
        tools = set(_ALL) - ({"grok"} if host_index == 2 else set()) - ({"vscode"} if host_index == 1 else set())
        for week in range(weeks, -1, -1):
            if host_index == 2 and week % 2:
                continue  # the build machine scans every other week
            when = end - timedelta(days=7 * week, hours=host_index * 3)
            for index in range(len(_FINDINGS)):
                roll = rng.random()
                if index in active and roll < 0.09:
                    active.discard(index)
                elif index not in active and roll < 0.05:
                    active.add(index)
            collectors = {name: _envelope(name, host, when) for name in sorted(tools)}
            for index in sorted(active):
                name, fid, severity, category, title, sample = _FINDINGS[index]
                if name not in collectors:
                    continue
                collectors[name]["findings"].append({
                    "id": fid, "severity": severity, "category": category, "title": title,
                    "evidence_count": 1 + (index * 7 + week) % 9, "first_seen": "", "last_seen": "",
                    "sample_redacted": sample, "secret_redacted": False, "tags": ["demo_data"],
                })
            for position, (name, rule_type, rule, decision, risk, exposure) in enumerate(_RULES):
                if name not in collectors or (position + host_index + week // 5) % 5 == 0:
                    continue
                collectors[name]["rules"].append({
                    "platform": name, "scope": "user", "scope_label_redacted": "user:global",
                    "rule_type": rule_type, "rule": rule, "decision": decision,
                    "command_or_tool_redacted": rule.split("(", 1)[0], "risk": risk,
                    "exposure_category": exposure, "source_kind": "user_config",
                })
            for name, env in collectors.items():
                env["summary"] = {"findings": len(env["findings"]), "rules": len(env["rules"])}
            collectors["chat-history"]["summary"].update(
                {"total_files": 40 + 3 * (weeks - week), "total_messages": 900 + 120 * (weeks - week)}
            )
            collectors["accounts"]["accounts"] = [
                {"tool": tool, "signed_in": "yes", "account": account, "organization": org, "plan": plan,
                 "auth_method": auth, "source": source, "last_sign_in": ""}
                for tool, account, org, plan, auth, source in _ACCOUNTS[: 4 - host_index]
            ]
            bundles.append({
                "bundle_version": BUNDLE_VERSION, "share_safe": False, "created_at": when.isoformat(),
                "source_label": when.strftime("%Y-%m-%d"), "host": host, "aiscan_version": "0.2.0-demo",
                "run_origin": {"launched_by": "demo data", "started": when.isoformat(), "reason": "weekly scan"},
                "collector_status": {}, "collector_errors": [], "collectors": collectors,
            })
    bundles.sort(key=lambda bundle: bundle["created_at"])
    return bundles
