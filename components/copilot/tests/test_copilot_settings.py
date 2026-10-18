"""Unit tests for Copilot VS Code settings parsing."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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

    def test_enable_object_uses_wildcard(self):
        data = {"github.copilot.enable": {"*": False, "python": True, "markdown": False}}
        rules, _findings, summary = copilot.parse_vscode_settings(data)
        self.assertIs(summary["vscode_copilot_enabled"], False)
        by_lang = {r["command_or_tool_redacted"]: r["decision"] for r in rules}
        self.assertEqual(by_lang["*"], "deny")
        self.assertEqual(by_lang["python"], "allow")
        self.assertEqual(by_lang["markdown"], "deny")

    def test_enable_object_without_wildcard_is_unset(self):
        data = {"github.copilot.enable": {"markdown": False}}
        _rules, _findings, summary = copilot.parse_vscode_settings(data)
        self.assertEqual(summary["vscode_copilot_enabled"], "unset")


class TestSkuAndConfigFiles(unittest.TestCase):
    def test_org_login_maps_to_business_without_leaking(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = root / "settings.json"
            settings.write_text(
                json.dumps(
                    {
                        "github.copilot.enable": {"*": False},
                        "telemetry.telemetryLevel": "all",
                    }
                ),
                encoding="utf-8",
            )
            storage = root / "storage"
            storage.mkdir()
            (storage / "state.json").write_text(
                json.dumps({"organizationLogin": "secret-org-name"}),
                encoding="utf-8",
            )
            with mock.patch.object(copilot, "VSCODE_SETTINGS", settings), mock.patch.object(
                copilot, "JETBRAINS_ROOT", root / "missing-jb"
            ), mock.patch.object(copilot, "COPILOT_STORAGE", storage):
                env = copilot.collect()
        self.assertEqual(env["summary"]["sku"], "business")
        self.assertIs(env["summary"]["vscode_copilot_enabled"], False)
        self.assertIn("copilot.telemetry.enabled", ids(env["findings"]))
        self.assertNotIn("secret-org-name", json.dumps(env))

    def test_unrecognized_sku_is_not_copied(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = Path(tmp)
            (storage / "state.json").write_text(
                json.dumps({"sku": "secret-org-name"}),
                encoding="utf-8",
            )
            with mock.patch.object(copilot, "COPILOT_STORAGE", storage):
                self.assertEqual(copilot.detect_sku(), "unknown")

    def test_jsonc_bom_settings_and_bad_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = root / "settings.json"
            settings.write_bytes(
                b'\xef\xbb\xbf{\n  // comment\n  "github.copilot.enable": {"*": false},\n}\n'
            )
            with mock.patch.object(copilot, "VSCODE_SETTINGS", settings), mock.patch.object(
                copilot, "JETBRAINS_ROOT", root / "missing-jb"
            ), mock.patch.object(copilot, "COPILOT_STORAGE", root / "storage"):
                env = copilot.collect()
            self.assertIs(env["summary"]["vscode_copilot_enabled"], False)
            self.assertNotIn("copilot.config.parse_error", ids(env["findings"]))

            settings.write_bytes(b"\xff")
            with mock.patch.object(copilot, "VSCODE_SETTINGS", settings), mock.patch.object(
                copilot, "JETBRAINS_ROOT", root / "missing-jb"
            ), mock.patch.object(copilot, "COPILOT_STORAGE", root / "storage"):
                env = copilot.collect()
        self.assertIn("copilot.config.parse_error", ids(env["findings"]))
        self.assertNotIn("copilot.exclude.none_configured", ids(env["findings"]))
        self.assertNotIn(str(settings), json.dumps(env))


if __name__ == "__main__":
    unittest.main()
