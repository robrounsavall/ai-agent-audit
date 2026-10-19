"""
Tests for grok.py config.toml posture parsing.

Mirrors test_codex_config.py's shape:

    parse_config_toml(data: dict) -> tuple[list[rule], list[finding], dict]

`data` is an already-parsed config.toml (tomllib). Rules are emitted only for
genuine grants (MCP servers, permission allow patterns), stamped
source_kind="user_config". Everything else is a finding or summary metric.

Run:
    scripts/test-component.ps1 -Name <component>
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"
import bootstrap  # noqa: E402,F401

import grok  # noqa: E402

AWS_KEY = "AKIA" + "C" * 16


def ids(findings):
    return {f["id"] for f in findings}


class TestParseConfigToml(unittest.TestCase):
    def parse(self, data):
        return grok.parse_config_toml(data)

    def test_empty_config(self):
        rules, findings, extras = self.parse({})
        self.assertEqual(rules, [])
        self.assertEqual(findings, [])
        self.assertEqual(extras, {})

    def test_always_approve_is_critical(self):
        _, findings, extras = self.parse({"ui": {"permission_mode": "always-approve"}})
        f = next(f for f in findings if f["id"] == "grok.permission.always_approve")
        self.assertEqual(f["severity"], "critical")
        self.assertEqual(extras["permission_mode"], "always-approve")

    def test_yolo_true_is_critical_even_if_mode_unset(self):
        _, findings, _ = self.parse({"ui": {"yolo": True}})
        self.assertIn("grok.permission.always_approve", ids(findings))

    def test_default_mode_no_finding(self):
        _, findings, extras = self.parse({"ui": {"permission_mode": "default", "yolo": False}})
        self.assertNotIn("grok.permission.always_approve", ids(findings))
        self.assertEqual(extras["permission_mode"], "default")

    def test_mcp_server_emits_allow_rule(self):
        data = {"mcp_servers": {"local-tool": {"command": "node"}}}
        rules, _, extras = self.parse(data)
        self.assertTrue(any(r["rule_type"] == "mcp_tool" for r in rules))
        self.assertEqual(extras["mcp_servers"], 1)
        for r in rules:
            self.assertEqual(r["source_kind"], "user_config")

    def test_mcp_non_localhost_finding(self):
        data = {"mcp_servers": {"remote": {"url": "https://evil.example.com/mcp"}}}
        _, findings, _ = self.parse(data)
        self.assertIn("grok.mcp.non_localhost", ids(findings))

    def test_mcp_localhost_no_non_localhost_finding(self):
        for url in ("http://localhost:9000", "http://127.0.0.1:9", "http://[::1]:8080"):
            _, findings, _ = self.parse({"mcp_servers": {"local": {"url": url}}})
            self.assertNotIn("grok.mcp.non_localhost", ids(findings), url)

    def test_mcp_lookalike_host_is_non_localhost(self):
        for url in (
            "http://localhost.evil.example/mcp",
            "https://evil.example/mcp?h=127.0.0.1",
        ):
            _, findings, _ = self.parse({"mcp_servers": {"remote": {"url": url}}})
            self.assertIn("grok.mcp.non_localhost", ids(findings), url)

    def test_mcp_non_string_url_does_not_raise(self):
        _, findings, _ = self.parse({"mcp_servers": {"x": {"url": 5}}})
        self.assertNotIn("grok.mcp.non_localhost", ids(findings))

    def test_mcp_http_transport_finding(self):
        data = {"mcp_servers": {"x": {"url": "http://localhost:9000", "transport": "sse"}}}
        _, findings, _ = self.parse(data)
        self.assertIn("grok.mcp.http_remote", ids(findings))

    def test_mcp_env_secret_masked(self):
        data = {"mcp_servers": {"x": {"command": "node", "env": {"TOKEN": AWS_KEY}}}}
        rules, findings, _ = self.parse(data)
        self.assertIn("grok.mcp.env_secret", ids(findings))
        blob = str(rules) + str(findings)
        self.assertNotIn(AWS_KEY, blob)

    def test_permission_allow_patterns_become_rules(self):
        data = {"permission": {"allow": ["Bash(curl:*)", "Bash(git:*)"]}}
        rules, _, extras = self.parse(data)
        allow_rules = [r for r in rules if r["decision"] == "allow"]
        self.assertEqual(len(allow_rules), 2)
        self.assertEqual(extras["permission_allow_rules"], 2)
        for r in allow_rules:
            self.assertEqual(r["source_kind"], "user_config")

    def test_all_rules_are_user_config(self):
        data = {
            "mcp_servers": {"x": {"command": "node"}},
            "permission": {"allow": ["Bash(ls:*)"]},
        }
        rules, _, _ = self.parse(data)
        self.assertTrue(rules)
        for r in rules:
            self.assertEqual(r.get("source_kind"), "user_config")

    def test_subagents_and_memory_presence(self):
        data = {"subagents": {"plan": {}}, "memory": {"enabled": True}}
        _, _, extras = self.parse(data)
        self.assertTrue(extras["subagents_configured"])
        self.assertTrue(extras["memory_configured"])


class TestConfigFileTolerance(unittest.TestCase):
    def collect(self, root: Path):
        grok_home = root / "grok"
        grok_home.mkdir(exist_ok=True)
        tp = grok.paths.ToolPaths(
            claude_home=root / ".claude",
            claude_projects=root / ".claude" / "projects",
            codex_home=root / ".codex",
            codex_sessions=root / ".codex" / "sessions",
            codex_config=root / ".codex" / "config.toml",
            codex_auth=root / ".codex" / "auth.json",
            cursor_projects=root / ".cursor" / "projects",
            cursor_db=root / "state.vscdb",
            cursor_user_mcp=root / ".cursor" / "mcp.json",
            cursor_appdata_mcp=root / "Cursor" / "mcp.json",
            shared_mcp=root / ".mcp.json",
            grok_home=grok_home,
            grok_sessions=grok_home / "sessions",
            grok_config=grok_home / "config.toml",
            grok_logs=grok_home / "logs",
            grok_auth=grok_home / "auth.json",
            grok_project_config=None,
        )
        return grok.collect(tp, repo_roots=[])

    def test_bom_toml_is_parsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "grok").mkdir()
            (root / "grok" / "config.toml").write_bytes(
                b'\xef\xbb\xbf[ui]\npermission_mode = "always-approve"\n'
            )
            env = self.collect(root)
        self.assertIn("grok.permission.always_approve", ids(env["findings"]))
        self.assertNotIn("grok.config.parse_error", ids(env["findings"]))

    def test_bad_byte_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "grok").mkdir()
            (root / "grok" / "config.toml").write_bytes(b"\xff")
            env = self.collect(root)
        self.assertIn("grok.config.parse_error", ids(env["findings"]))
        self.assertNotIn(str(root), json.dumps(env["findings"]))


if __name__ == "__main__":
    unittest.main()
