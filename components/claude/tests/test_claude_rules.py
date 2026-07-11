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
        settings = {"defaultMode": "bypassPermissions"}
        _rules, findings = claude.extract_rules_from_settings(
            "user", "global", settings, Path("settings.json")
        )
        self.assertIn("claude.permission.bypass_mode", ids(findings))
        critical = [f for f in findings if f["severity"] == "critical"]
        self.assertTrue(critical)

    def test_wildcard_bash_finding(self):
        settings = {"permissions": {"allow": ["Bash(*)"]}}
        _rules, findings = claude.extract_rules_from_settings(
            "user", "global", settings, Path("settings.json")
        )
        self.assertIn("claude.permission.bash_wildcard", ids(findings))


if __name__ == "__main__":
    unittest.main()
