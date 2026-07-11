"""Unit tests for Copilot VS Code settings parsing."""

from __future__ import annotations

import os
import unittest

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"

import bootstrap  # noqa: E402,F401
import copilot  # noqa: E402


def ids(findings):
    return {f["id"] for f in findings}


class TestParseVscodeSettings(unittest.TestCase):
    def test_no_excludes_finding(self):
        data = {"github.copilot.enable": True}
        rules, findings, summary = copilot.parse_vscode_settings(data)
        self.assertIn("copilot.exclude.none_configured", ids(findings))
        self.assertEqual(summary.get("vscode_copilot_enabled"), True)

    def test_exclude_patterns_as_deny_rules(self):
        data = {
            "github.copilot.enable": True,
            "github.copilot.advanced.exclude": ["**/.env", "**/secrets/**"],
        }
        rules, findings, summary = copilot.parse_vscode_settings(data)
        self.assertEqual(summary.get("exclude_patterns"), 2)
        deny = [r for r in rules if r["decision"] == "deny"]
        self.assertGreaterEqual(len(deny), 2)
        self.assertNotIn("copilot.exclude.none_configured", ids(findings))

    def test_public_code_enabled(self):
        data = {
            "github.copilot.advanced.exclude": ["**/.env"],
            "github.copilot.advanced.publicCodeSuggestions": True,
        }
        _rules, findings, summary = copilot.parse_vscode_settings(data)
        self.assertIn("copilot.public_code.enabled", ids(findings))
        self.assertEqual(summary.get("public_code_suggestions"), "True")

    def test_decisions_legal(self):
        data = {
            "github.copilot.enable.markdown": False,
            "github.copilot.advanced.exclude": ["a"],
        }
        rules, _findings, _summary = copilot.parse_vscode_settings(data)
        for r in rules:
            self.assertIn(r["decision"], ("allow", "deny", "ask"))


if __name__ == "__main__":
    unittest.main()
