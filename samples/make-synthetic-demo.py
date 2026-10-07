#!/usr/bin/env python3
"""
Generate a fully synthetic demo evidence bundle for the public scanner.

- User: "Test User"
- Host: "DEMO-ENDPOINT"
- No real paths, no real secrets, no real identities.
- Produces evidence/*.json for all standard collectors so that
  `python report/build-briefing.py --evidence-root samples/synthetic-demo`
  renders a complete briefing.

Run:
    python samples/make-synthetic-demo.py
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
OUT = HERE / "synthetic-demo" / "evidence"
OUT.mkdir(parents=True, exist_ok=True)

NOW = datetime.now(timezone.utc).isoformat()


def short_hash(s: str) -> str:
    import hashlib
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:12]


def envelope(collector: str, summary: dict[str, Any], findings: list[dict], rules: list[dict]) -> dict:
    return {
        "collector": collector,
        "version": "1.0.0",
        "ran_at": NOW,
        "host": "DEMO-ENDPOINT",
        "platform_detected": True,
        "scope_hash": short_hash(collector + "demo"),
        "summary": summary,
        "findings": findings,
        "rules": rules,
        "raw_pointers": [],
    }


def write(name: str, data: dict) -> None:
    p = OUT / f"{name}.json"
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {p}")


def main() -> None:
    # discovery
    write("discovery", {
        "collector": "discovery",
        "version": "1.0.0",
        "ran_at": NOW,
        "host": "DEMO-ENDPOINT",
        "platform_detected": True,
        "scope_hash": short_hash("disc"),
        "summary": {
            "tools_detected": 5,
            "claude_version": "2.x (demo)",
            "cursor_version": "0.50 (demo)",
            "codex_version": "26.x (demo)",
            "copilot_version": "1.x (demo)",
            "grok_version": "1.x (demo)",
        },
        "findings": [],
        "rules": [],
        "raw_pointers": [],
    })

    # claude (with one bypass finding + mcp allow)
    claude_rules = [
        {"platform": "claude", "scope": "user", "scope_label_redacted": "user#abc123", "rule_type": "mcp_tool", "rule": "mcp__playwright", "decision": "allow", "command_or_tool_redacted": "playwright", "risk": "medium", "exposure_category": "MCP Tooling"},
        {"platform": "claude", "scope": "user", "scope_label_redacted": "user#abc123", "rule_type": "bash", "rule": "Bash(*)", "decision": "allow", "command_or_tool_redacted": "*", "risk": "high", "exposure_category": "Shell Execution"},
    ]
    claude_findings = [
        {"id": "claude.permission.skip_dangerous_prompt", "severity": "critical", "category": "Shell Execution", "title": "Claude skips dangerous-mode permission prompt", "evidence_count": 1, "first_seen": "", "last_seen": "", "sample_redacted": "skipDangerousModePermissionPrompt=${ENABLED}", "secret_redacted": False, "tags": ["unbounded_glob"]},
    ]
    write("claude", envelope("claude", {"settings_files": 1, "rules": len(claude_rules), "findings": len(claude_findings), "allow_rules": 2, "deny_rules": 0, "ask_rules": 0}, claude_findings, claude_rules))

    # cursor (simple)
    cursor_rules: list[dict] = []
    write("cursor", envelope("cursor", {"rules": 0, "findings": 0}, [], cursor_rules))

    # codex (one critical approval)
    codex_rules = [{"platform": "codex", "scope": "user", "scope_label_redacted": "user#def456", "rule_type": "other", "rule": "prefix:demo", "decision": "allow", "command_or_tool_redacted": "demo", "risk": "low", "exposure_category": "General Tooling"}]
    codex_findings = [{"id": "codex.sandbox.bypass", "severity": "critical", "category": "Shell Execution", "title": "Codex sandbox bypass observed", "evidence_count": 1, "sample_redacted": "sandbox=disabled", "tags": []}]
    write("codex", envelope("codex", {"sessions": 4, "rules": 1, "findings": 1}, codex_findings, codex_rules))

    # copilot
    write("copilot", envelope("copilot", {"enabled": True, "findings": 0}, [], []))

    # grok (always-approve + mcp)
    grok_rules = [
        {"platform": "grok", "scope": "user", "scope_label_redacted": "user#mcp1", "rule_type": "mcp_tool", "rule": "mcp__demo", "decision": "allow", "command_or_tool_redacted": "demo", "risk": "medium", "exposure_category": "MCP Tooling"},
    ]
    grok_findings = [{"id": "grok.permission.always_approve", "severity": "critical", "category": "Shell Execution", "title": "Grok Build permission_mode is always-approve", "evidence_count": 1, "sample_redacted": "permission_mode=always-approve yolo=true", "tags": ["auto_approve"]}]
    write("grok", envelope("grok", {"permission_mode": "always-approve", "yolo": True, "mcp_servers": 1, "rules": 1}, grok_findings, grok_rules))

    # grok-bot (real AppData names; local execution is not on disk)
    grok_bot_findings = [
        {"id": "grok_bot.desktop.present", "severity": "low", "category": "Cross-Agent Visibility", "title": "Grok Bot desktop app data is present on this endpoint", "evidence_count": 1, "sample_redacted": "files=40; newest=2026-07-07", "tags": ["desktop_app"]},
        {"id": "grok_bot.secrets.store_present", "severity": "medium", "category": "Secrets Exposure", "title": "Grok Bot secrets store is present on this endpoint (contents excluded)", "evidence_count": 2, "sample_redacted": "sand-secrets.json present; box-secrets-push-state.v1.json present", "tags": ["auth_excluded"]},
        {"id": "grok_bot.lockfile.present", "severity": "low", "category": "Cross-Agent Visibility", "title": "Grok Bot lockfile is present (app is running or ran recently)", "evidence_count": 1, "sample_redacted": "lockfile present", "tags": ["desktop_app"]},
        {"id": "grok_bot.state.local_stores_present", "severity": "low", "category": "Cross-Agent Visibility", "title": "Grok Bot keeps browser and client state on disk (contents excluded)", "evidence_count": 4, "sample_redacted": "Local Storage present; Session Storage present; Network present; sand-client-persistence present", "tags": ["chat_history"]},
    ]
    write("grok-bot", envelope("grok-bot", {
        "app_present": True,
        "local_execution": "unknown",
        "local_execution_reason": "not_determinable_offline",
        "file_count": 40,
        "dir_count": 19,
        "total_bytes": 120000,
        "newest_local_activity": "2026-07-07",
        "known_files_present": 14,
        "known_dirs_present": 19,
        "sand_secrets_present": True,
        "sand_secrets_bytes": 256,
        "box_secrets_push_state_present": True,
        "box_secrets_push_state_bytes": 128,
        "lockfile_present": True,
        "lockfile_bytes": 0,
        "browser_state_present": True,
        "client_persistence_present": True,
        "findings": len(grok_bot_findings),
    }, grok_bot_findings, []))

    # chat-history (per-tool file counts mirror real collector summary shape)
    chat_sum = {
        "total_files": 12,
        "total_messages": 340,
        "total_bytes": 128000,
        "retention_days": 45,
        "secret_hit_files": 1,
        "claude_files": 3,
        "codex_files": 2,
        "cursor_files": 4,
        "cursor-composer_files": 2,
        "grok_files": 1,
    }
    chat_findings = [{"id": "chat_history.secret_hit", "severity": "medium", "category": "Secrets Exposure", "title": "Secret-like value observed in chat export", "evidence_count": 1, "sample_redacted": "ghp_****REDACTED****", "secret_redacted": True, "tags": []}]
    write("chat-history", envelope("chat-history", chat_sum, chat_findings, []))

    # git-posture
    git_sum = {"repos_scanned": 5, "env_in_history": 1, "no_pre_commit": 5, "no_branch_protection": 3, "large_blobs": 0, "gh_checked": False}
    git_findings = [{"id": "git.env.in_history", "severity": "critical", "category": "Git Posture", "title": ".env file found in git commit history", "evidence_count": 1, "sample_redacted": "project#demo", "tags": []}]
    write("git-posture", envelope("git-posture", git_sum, git_findings, []))

    # secrets-scan
    sec_sum = {"scanner": "gitleaks", "hits": 1, "targets": 3}
    sec_findings = [{"id": "secrets-scan.hit", "severity": "high", "category": "Secrets Exposure", "title": "Potential secret in chat export", "evidence_count": 1, "sample_redacted": "ghp_****", "secret_redacted": True, "tags": []}]
    write("secrets-scan", envelope("secrets-scan", sec_sum, sec_findings, []))

    # Write a tiny README for the bundle
    readme = HERE / "synthetic-demo" / "README.md"
    readme.write_text(
        "# Synthetic Demo Evidence\n\n"
        "Fully synthetic data generated by `make-synthetic-demo.py`.\n"
        "User = Test User, Host = DEMO-ENDPOINT.\n"
        "Use with:\n\n"
        "    python report\\build-briefing.py --evidence-root samples\\synthetic-demo --out demo-briefing.html\n\n"
        "Contains no real paths, identities, or credentials.\n",
        encoding="utf-8",
    )
    print(f"Wrote {readme}")


if __name__ == "__main__":
    main()
