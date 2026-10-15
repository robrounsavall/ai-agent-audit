"""
Tests for vscode.py settings parsing and workspace MCP parsing.

Run:
    python -m unittest discover -s phase1-audit/tests -v
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

os.environ["USERPROFILE"] = "C:\\Users\\Test User"
import bootstrap  # noqa: E402,F401

import vscode  # noqa: E402


def ids(findings):
    return {f["id"] for f in findings}


class TestParseVscodeSettings(unittest.TestCase):
    def test_empty_settings_flags_missing_excludes(self):
        rules, findings, summary = vscode.parse_vscode_settings({})
        self.assertIn("vscode.copilot.exclude.none_configured", ids(findings))
        self.assertEqual(summary["copilot_enabled"], "unset")
        self.assertFalse(summary["tools_auto_approve"])

    def test_excludes_present_no_finding(self):
        rules, findings, summary = vscode.parse_vscode_settings(
            {"github.copilot.advanced.exclude": ["**/*.env"]}
        )
        self.assertNotIn("vscode.copilot.exclude.none_configured", ids(findings))
        self.assertEqual(summary["exclude_patterns"], 1)
        self.assertTrue(any(r["decision"] == "deny" for r in rules))

    def test_global_auto_approve_is_high_finding(self):
        rules, findings, _ = vscode.parse_vscode_settings(
            {"chat.tools.autoApprove": True}
        )
        f = next(f for f in findings if f["id"] == "vscode.copilot.tools.auto_approve")
        self.assertEqual(f["severity"], "high")
        self.assertTrue(any(r["rule_type"] == "approval_event" and r["decision"] == "allow" for r in rules))

    def test_auto_approve_variant_key_names_match(self):
        for key in ("chat.tools.global.autoApprove", "chat.tools.terminal.enableAutoApprove"):
            _, findings, summary = vscode.parse_vscode_settings({key: True})
            self.assertIn("vscode.copilot.tools.auto_approve", ids(findings), key)
            self.assertTrue(summary["tools_auto_approve"], key)

    def test_terminal_auto_approve_map_rules(self):
        rules, findings, _ = vscode.parse_vscode_settings(
            {"chat.tools.terminal.autoApprove": {"git status": True, "rm": False}}
        )
        decisions = {r["command_or_tool_redacted"]: r["decision"] for r in rules}
        self.assertEqual(decisions["git status"], "allow")
        self.assertEqual(decisions["rm"], "deny")
        self.assertIn("vscode.copilot.tools.auto_approve", ids(findings))

    def test_auto_approve_false_no_finding(self):
        _, findings, summary = vscode.parse_vscode_settings(
            {"chat.tools.autoApprove": False}
        )
        self.assertNotIn("vscode.copilot.tools.auto_approve", ids(findings))
        self.assertFalse(summary["tools_auto_approve"])

    def test_workspace_trust_disabled(self):
        _, findings, summary = vscode.parse_vscode_settings(
            {"security.workspace.trust.enabled": False}
        )
        self.assertIn("vscode.workspace_trust.disabled", ids(findings))
        self.assertFalse(summary["workspace_trust"])

    def test_max_requests_raised(self):
        _, findings, summary = vscode.parse_vscode_settings(
            {"chat.agent.maxRequests": 500}
        )
        self.assertIn("vscode.copilot.agent.max_requests_raised", ids(findings))
        self.assertEqual(summary["agent_max_requests"], 500)

    def test_public_code_enabled_finding(self):
        _, findings, _ = vscode.parse_vscode_settings(
            {"github.copilot.advanced.publicCodeSuggestions": True}
        )
        self.assertIn("vscode.copilot.public_code.enabled", ids(findings))

    def test_workspace_scope_prefixes_summary(self):
        _, findings, summary = vscode.parse_vscode_settings(
            {}, scope="workspace", scope_label="workspace#abc123"
        )
        self.assertIn("workspace_copilot_enabled", summary)
        # missing-excludes finding is user-scope only
        self.assertNotIn("vscode.copilot.exclude.none_configured", ids(findings))


class TestParseWorkspaceMcp(unittest.TestCase):
    def test_non_localhost_server_flagged(self):
        rules, findings, count = vscode.parse_workspace_mcp(
            {"servers": {"corp": {"url": "https://mcp.example.com/sse"}}}, "abc123"
        )
        self.assertIn("vscode.mcp.non_local_server", ids(findings))
        self.assertEqual(count, 1)
        self.assertTrue(all(r["scope_label_redacted"].startswith("workspace") for r in rules))

    def test_localhost_server_not_flagged(self):
        _, findings, _ = vscode.parse_workspace_mcp(
            {"servers": {"local": {"url": "http://localhost:8000/mcp"}}}, "abc123"
        )
        self.assertNotIn("vscode.mcp.non_local_server", ids(findings))

    def test_stdio_server_counts(self):
        rules, findings, count = vscode.parse_workspace_mcp(
            {"mcpServers": {"tool": {"command": "python", "args": ["server.py"]}}}, "abc123"
        )
        self.assertEqual(count, 1)
        self.assertNotIn("vscode.mcp.non_local_server", ids(findings))

    def test_no_raw_server_names_in_rules(self):
        rules, _, _ = vscode.parse_workspace_mcp(
            {"servers": {"secret-project-server": {"url": "https://mcp.example.com"}}}, "abc123"
        )
        for r in rules:
            self.assertNotIn("secret-project-server", str(r))


if __name__ == "__main__":
    unittest.main()
