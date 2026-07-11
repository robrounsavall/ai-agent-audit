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

import os
import sys
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
        data = {"mcp_servers": {"local": {"url": "http://localhost:9000"}}}
        _, findings, _ = self.parse(data)
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


if __name__ == "__main__":
    unittest.main()
