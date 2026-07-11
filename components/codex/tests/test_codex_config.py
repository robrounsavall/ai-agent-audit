"""
Contract for codex.py config.toml posture parsing (Step 3 target).

Defines the interface and behavior the Haiku implementation must satisfy:

    parse_config_toml(data: dict) -> tuple[list[rule], list[finding]]

`data` is an already-parsed config.toml (the collector reads the file with
tomllib and passes the dict, so this stays pure and testable). Rules are
emitted only for genuine grants (trusted projects, MCP servers, auto-approve
apps), stamped source_kind="user_config". All other posture is findings.
No fabricated decisions, no path/secret leakage.

Schema confirmed from openai/codex codex-rs/core/config.schema.json.

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

import codex  # noqa: E402

AWS_KEY = "AKIA" + "C" * 16


def ids(findings):
    return {f["id"] for f in findings}


class TestParseConfigToml(unittest.TestCase):
    def parse(self, data):
        rules, findings = codex.parse_config_toml(data)
        return rules, findings

    def test_empty_config(self):
        rules, findings = self.parse({})
        self.assertEqual(rules, [])
        self.assertEqual(findings, [])

    def test_sandbox_full_access_critical(self):
        _, findings = self.parse({"sandbox_mode": "danger-full-access"})
        f = next(f for f in findings if f["id"] == "codex.sandbox.full_access")
        self.assertEqual(f["severity"], "critical")

    def test_sandbox_readonly_no_finding(self):
        _, findings = self.parse({"sandbox_mode": "read-only"})
        self.assertNotIn("codex.sandbox.full_access", ids(findings))

    def test_approval_never_critical(self):
        _, findings = self.parse({"approval_policy": "never"})
        self.assertIn("codex.approval.never", ids(findings))

    def test_approval_granular_disables_prompts(self):
        # Granular object that turns off the permission gate must still fire.
        _, findings = self.parse(
            {"approval_policy": {"request_permissions": False, "sandbox_approval": False}}
        )
        self.assertIn("codex.approval.never", ids(findings))

    def test_workspace_write_network_access(self):
        _, findings = self.parse(
            {"sandbox_mode": "workspace-write",
             "sandbox_workspace_write": {"network_access": True}}
        )
        self.assertIn("codex.network.workspace_write", ids(findings))

    def test_shell_env_inherit_all_and_ignore_excludes(self):
        _, findings = self.parse(
            {"shell_environment_policy": {"inherit": "all", "ignore_default_excludes": True}}
        )
        got = ids(findings)
        self.assertTrue({"codex.env.inherit_all", "codex.env.ignore_excludes"} & got)

    def test_trusted_projects_become_allow_rules_no_path_leak(self):
        data = {
            "projects": {
                r"c:\users\test user\cursor-projects\acme-app": {"trust_level": "trusted"},
                r"c:\users\test user\cursor-projects\widget-api": {"trust_level": "trusted"},
            }
        }
        rules, _ = self.parse(data)
        trust_rules = [r for r in rules if r["decision"] == "allow"
                       and "trust" in r["rule"].lower()]
        self.assertEqual(len(trust_rules), 2)
        for r in trust_rules:
            self.assertEqual(r["source_kind"], "user_config")
            # path lives only in the hashed scope label, never raw
            blob = " ".join(str(v) for v in r.values())
            self.assertNotIn("Test User", blob)
            self.assertNotIn("cursor-projects", blob)

    def test_broad_trust_finding(self):
        data = {"projects": {f"p{i}": {"trust_level": "trusted"} for i in range(5)}}
        _, findings = self.parse(data)
        f = next(f for f in findings if f["id"] == "codex.trust.broad")
        self.assertEqual(f["evidence_count"], 5)

    def test_untrusted_project_not_a_rule(self):
        data = {"projects": {"p1": {"trust_level": "untrusted"}}}
        rules, _ = self.parse(data)
        self.assertEqual([r for r in rules if "trust" in r["rule"].lower()], [])

    def test_mcp_external_server(self):
        data = {"mcp_servers": {"remote": {"url": "https://evil.example.com/mcp"}}}
        rules, findings = self.parse(data)
        self.assertIn("codex.mcp.external_server", ids(findings))
        self.assertTrue(any(r["rule_type"] == "mcp_tool" for r in rules))

    def test_mcp_localhost_no_external_finding(self):
        data = {"mcp_servers": {"local": {"url": "http://localhost:9000"}}}
        _, findings = self.parse(data)
        self.assertNotIn("codex.mcp.external_server", ids(findings))

    def test_mcp_env_secret_masked(self):
        data = {"mcp_servers": {"x": {"command": "node", "env": {"TOKEN": AWS_KEY}}}}
        rules, findings = self.parse(data)
        self.assertIn("codex.mcp.env_secret", ids(findings))
        blob = str(rules) + str(findings)
        self.assertNotIn(AWS_KEY, blob)

    def test_otel_log_user_prompt(self):
        data = {"otel": {"log_user_prompt": True,
                         "exporter": {"otlp-http": {"endpoint": "http://localhost:14318"}}}}
        _, findings = self.parse(data)
        self.assertIn("codex.telemetry.log_user_prompt_configured", ids(findings))

    def test_apps_auto_approve(self):
        data = {"apps": {"gmail": {"enabled": True,
                                   "default_tools_approval_mode": "auto",
                                   "destructive_enabled": True}}}
        rules, findings = self.parse(data)
        got = ids(findings)
        self.assertTrue({"codex.apps.auto_approve", "codex.apps.destructive"} & got)
        self.assertTrue(any(r["decision"] == "allow" and "gmail" in str(r).lower()
                            for r in rules))

    def test_hooks_pretooluse_high(self):
        data = {"hooks": {"PreToolUse": [{"command": "powershell -c notify"}]}}
        _, findings = self.parse(data)
        f = next(f for f in findings if f["id"] == "codex.hooks.lifecycle_command")
        self.assertEqual(f["severity"], "high")

    def test_all_rules_are_user_config(self):
        data = {
            "projects": {"p1": {"trust_level": "trusted"}},
            "mcp_servers": {"x": {"command": "node"}},
        }
        rules, _ = self.parse(data)
        self.assertTrue(rules)
        for r in rules:
            self.assertEqual(r.get("source_kind"), "user_config")


if __name__ == "__main__":
    unittest.main()
