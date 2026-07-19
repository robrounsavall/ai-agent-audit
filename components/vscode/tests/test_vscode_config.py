"""
Tests for vscode.py settings parsing and workspace MCP parsing.

Run:
    python -m unittest discover -s phase1-audit/tests -v
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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

    def test_enable_object_uses_wildcard(self):
        data = {"github.copilot.enable": {"*": False, "python": True, "markdown": False}}
        rules, _findings, summary = vscode.parse_vscode_settings(data)
        self.assertIs(summary["copilot_enabled"], False)
        by_lang = {r["command_or_tool_redacted"]: r["decision"] for r in rules}
        self.assertEqual(by_lang["*"], "deny")
        self.assertEqual(by_lang["python"], "allow")
        self.assertEqual(by_lang["markdown"], "deny")

    def test_enable_object_without_wildcard_is_unset(self):
        data = {"github.copilot.enable": {"markdown": False}}
        _rules, _findings, summary = vscode.parse_vscode_settings(data)
        self.assertEqual(summary["copilot_enabled"], "unset")

    def test_non_string_setting_key_is_skipped(self):
        rules, findings, summary = vscode.parse_vscode_settings(
            {1: True, "github.copilot.enable": {"*": False}}
        )
        self.assertIs(summary["copilot_enabled"], False)
        self.assertTrue(rules)
        self.assertNotIn("vscode.config.parse_error", ids(findings))


def _tool_paths(root: Path):
    dummy = root / "unused"
    code = root / "Code"
    return vscode.toolpaths.ToolPaths(
        claude_home=dummy,
        claude_projects=dummy,
        codex_home=dummy,
        codex_sessions=dummy,
        codex_config=dummy,
        codex_auth=dummy,
        cursor_projects=dummy,
        cursor_db=dummy,
        cursor_user_mcp=dummy,
        cursor_appdata_mcp=dummy,
        shared_mcp=dummy,
        grok_home=dummy,
        grok_sessions=dummy,
        grok_config=dummy,
        grok_logs=dummy,
        grok_auth=dummy,
        grok_project_config=None,
        vscode_root=code,
        vscode_settings=code / "User" / "settings.json",
        vscode_global_storage=code / "User" / "globalStorage",
        vscode_workspace_storage=code / "User" / "workspaceStorage",
        vscode_logs=code / "logs",
    )


class TestSkuAndConfigFiles(unittest.TestCase):
    def _collect(self, root: Path):
        code = root / "Code"
        code.mkdir(parents=True, exist_ok=True)
        with mock.patch.object(vscode, "JETBRAINS_ROOT", root / "missing-jb"), mock.patch.object(
            vscode, "EXTENSIONS_DIR", root / "missing-ext"
        ):
            return vscode.collect(_tool_paths(root), [])

    def test_org_login_maps_to_business_without_leaking(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = root / "Code"
            settings = code / "User" / "settings.json"
            settings.parent.mkdir(parents=True)
            settings.write_text(
                json.dumps(
                    {
                        "github.copilot.enable": {"*": False},
                        "telemetry.telemetryLevel": "all",
                    }
                ),
                encoding="utf-8",
            )
            storage = code / "User" / "globalStorage" / "github.copilot"
            storage.mkdir(parents=True)
            (storage / "state.json").write_text(
                json.dumps({"organizationLogin": "secret-org-name"}),
                encoding="utf-8",
            )
            env = self._collect(root)
        self.assertEqual(env["summary"]["sku"], "business")
        self.assertIs(env["summary"]["copilot_enabled"], False)
        self.assertIn("vscode.copilot.telemetry.enabled", ids(env["findings"]))
        self.assertNotIn("secret-org-name", json.dumps(env))

    def test_unrecognized_sku_is_not_copied(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = Path(tmp) / "github.copilot"
            storage.mkdir()
            (storage / "state.json").write_text(
                json.dumps({"sku": "secret-org-name"}),
                encoding="utf-8",
            )
            self.assertEqual(vscode.detect_sku(Path(tmp)), "unknown")

    def test_jsonc_bom_settings_and_bad_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = root / "Code"
            settings = code / "User" / "settings.json"
            settings.parent.mkdir(parents=True)
            settings.write_bytes(
                b'\xef\xbb\xbf{\n  // comment\n  "github.copilot.enable": {"*": false},\n}\n'
            )
            env = self._collect(root)
            self.assertIs(env["summary"]["copilot_enabled"], False)
            self.assertNotIn("vscode.config.parse_error", ids(env["findings"]))

            settings.write_bytes(b"\xff")
            env = self._collect(root)
        self.assertIn("vscode.config.parse_error", ids(env["findings"]))
        self.assertNotIn("vscode.copilot.exclude.none_configured", ids(env["findings"]))
        self.assertNotIn(str(settings), json.dumps(env))


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
