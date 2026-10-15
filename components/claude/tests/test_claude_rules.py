"""Unit tests for Claude settings rule extraction."""

from __future__ import annotations

import os
import unittest
from pathlib import Path

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"

import bootstrap  # noqa: E402,F401
import claude  # noqa: E402


def ids(findings):
    return {f["id"] for f in findings}


class TestExtractRules(unittest.TestCase):
    def test_allow_deny_ask(self):
        settings = {
            "permissions": {
                "allow": ["Bash(git status)", "Bash(curl *)"],
                "deny": ["Bash(rm *)"],
                "ask": ["Edit(*)"],
            }
        }
        rules, findings = claude.extract_rules_from_settings(
            "user", "global", settings, Path("settings.json")
        )
        decisions = {r["decision"] for r in rules}
        self.assertEqual(decisions, {"allow", "deny", "ask"})
        for r in rules:
            self.assertEqual(r["platform"], "claude")
            self.assertIn(r["decision"], ("allow", "deny", "ask"))
        self.assertIn("claude.permission.bash_curl_wide", ids(findings))

    def test_bypass_mode_finding(self):
        settings = {"permissions": {"defaultMode": "bypassPermissions"}}
        findings = self.mode_findings(settings)
        self.assertIn("claude.permission.bypass_mode", ids(findings))
        critical = [f for f in findings if f["severity"] == "critical"]
        self.assertTrue(critical)
        self.assertIn("permissions.defaultMode", critical[0]["sample_redacted"])

    def mode_findings(self, settings, scope="user", name="settings.json"):
        _rules, findings = claude.extract_rules_from_settings(
            scope, "global", settings, Path(name)
        )
        return findings

    def test_legacy_top_level_bypass(self):
        findings = self.mode_findings({"defaultMode": "bypassPermissions"})
        self.assertIn("claude.permission.bypass_mode", ids(findings))
        self.assertIn("defaultMode=", findings[0]["sample_redacted"])

    def test_safe_modes_have_no_finding(self):
        for mode in ("manual", "default", "dontAsk", "plan"):
            findings = self.mode_findings({"permissions": {"defaultMode": mode}})
            self.assertEqual(findings, [], mode)

    def test_auto_mode_user(self):
        findings = self.mode_findings({"permissions": {"defaultMode": "auto"}})
        self.assertEqual(ids(findings), {"claude.permission.auto_mode"})
        self.assertEqual(findings[0]["severity"], "medium")

    def test_accept_edits_mode(self):
        findings = self.mode_findings({"permissions": {"defaultMode": "acceptEdits"}})
        self.assertEqual(ids(findings), {"claude.permission.accept_edits_mode"})
        self.assertEqual(findings[0]["severity"], "low")

    def test_bypass_in_local_or_project_not_applied(self):
        settings = {"permissions": {"defaultMode": "bypassPermissions"}}
        for scope, name in (("user", "settings.local.json"), ("project", "settings.json")):
            found = ids(self.mode_findings(settings, scope, name))
            self.assertEqual(found, {"claude.permission.mode_not_applied"})

    def test_permission_mode_from_settings(self):
        self.assertEqual(
            claude.permission_mode_from_settings({"permissions": {"defaultMode": "Manual"}}),
            ("default", "permissions.defaultMode"),
        )
        self.assertEqual(
            claude.permission_mode_from_settings({"permissionMode": "bypass"}),
            ("bypassPermissions", "permissionMode"),
        )
        self.assertEqual(
            claude.permission_mode_from_settings({"permissions": {"defaultMode": 3}}),
            ("", ""),
        )

    def test_wildcard_bash_finding(self):
        settings = {"permissions": {"allow": ["Bash(*)"]}}
        _rules, findings = claude.extract_rules_from_settings(
            "user", "global", settings, Path("settings.json")
        )
        self.assertIn("claude.permission.bash_wildcard", ids(findings))


if __name__ == "__main__":
    unittest.main()
