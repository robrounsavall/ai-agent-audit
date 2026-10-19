"""Project settings, Desktop-only installs, and unreadable Claude configs."""

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
import claude  # noqa: E402


def ids(findings):
    return {f["id"] for f in findings}


def tool_paths(root: Path, home: Path) -> claude.paths.ToolPaths:
    projects = home / "projects"
    return claude.paths.ToolPaths(
        claude_home=home,
        claude_projects=projects,
        codex_home=root / "codex",
        codex_sessions=root / "codex" / "sessions",
        codex_config=root / "codex" / "config.toml",
        codex_auth=root / "codex" / "auth.json",
        cursor_projects=root / "cursor",
        cursor_db=root / "cursor.db",
        cursor_user_mcp=root / "cursor_mcp.json",
        cursor_appdata_mcp=root / "cursor_appdata_mcp.json",
        shared_mcp=root / "shared_mcp.json",
        grok_home=root / "grok",
        grok_sessions=root / "grok" / "sessions",
        grok_config=root / "grok" / "config.toml",
        grok_logs=root / "grok" / "logs",
        grok_auth=root / "grok" / "auth.json",
        grok_project_config=None,
    )


class TestProjectSettings(unittest.TestCase):
    def test_repo_settings_found_transcripts_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "claude_home"
            (home / "projects").mkdir(parents=True)
            repo = root / "repos" / "demo"
            (repo / ".git").mkdir(parents=True)
            (repo / ".claude").mkdir()
            (repo / ".claude" / "settings.json").write_text(
                json.dumps({"permissions": {"allow": ["Bash(git status)"]}}),
                encoding="utf-8",
            )
            (repo / ".claude" / "settings.local.json").write_text(
                json.dumps({"permissions": {"deny": ["Bash(rm *)"]}}),
                encoding="utf-8",
            )
            decoy = home / "projects" / "encoded" / ".claude"
            decoy.mkdir(parents=True)
            (decoy / "settings.local.json").write_text(
                json.dumps({"permissions": {"allow": ["Bash(curl *)"]}}),
                encoding="utf-8",
            )
            tp = tool_paths(root, home)
            with mock.patch.object(claude, "desktop_config_path", return_value=root / "missing.json"):
                env = claude.collect("all", tp, repo_roots=[root / "repos"])
                user_only = claude.collect("user", tp, repo_roots=[root / "repos"])

        rules = env["rules"]
        self.assertTrue(any("git status" in r["rule"] and r["scope"] == "project" for r in rules))
        self.assertTrue(any(r["decision"] == "deny" and r["scope"] == "project" for r in rules))
        self.assertFalse(any("curl" in r["rule"] for r in rules))
        self.assertTrue(any(r["settings_source"] == "project settings.json" for r in rules))
        self.assertTrue(any(r["settings_source"] == "project settings.local.json" for r in rules))
        self.assertFalse(any(r["scope"] == "project" for r in user_only["rules"]))

    def test_jsonc_bom_project_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "claude_home"
            home.mkdir()
            repo = root / "repos" / "demo"
            (repo / ".git").mkdir(parents=True)
            (repo / ".claude").mkdir()
            (repo / ".claude" / "settings.json").write_bytes(
                b'\xef\xbb\xbf{\n  // kept\n  "permissions": {"allow": ["Bash(git status)"]},\n}\n'
            )
            tp = tool_paths(root, home)
            with mock.patch.object(claude, "desktop_config_path", return_value=root / "missing.json"):
                env = claude.collect("all", tp, repo_roots=[root / "repos"])
        self.assertTrue(any("git status" in r["rule"] for r in env["rules"]))
        self.assertNotIn("claude.config.parse_error", ids(env["findings"]))

    def test_bad_byte_reports_and_keeps_sibling(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "claude_home"
            home.mkdir()
            (home / "settings.json").write_bytes(b"\xff")
            (home / "settings.local.json").write_text(
                json.dumps({"permissions": {"allow": ["Bash(git status)"]}}),
                encoding="utf-8",
            )
            tp = tool_paths(root, home)
            with mock.patch.object(claude, "desktop_config_path", return_value=root / "missing.json"):
                env = claude.collect("all", tp, repo_roots=[])
        self.assertIn("claude.config.parse_error", ids(env["findings"]))
        self.assertTrue(any("git status" in r["rule"] for r in env["rules"]))
        blob = json.dumps(env)
        self.assertNotIn(str(home), blob)


class TestDesktopOnly(unittest.TestCase):
    def test_desktop_without_code_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "missing-home"
            desktop = root / "claude_desktop_config.json"
            desktop.write_text(
                json.dumps({"mcpServers": {"local-tool": {"command": "python", "args": ["srv.py"]}}}),
                encoding="utf-8",
            )
            tp = tool_paths(root, home)
            with mock.patch.object(claude, "desktop_config_path", return_value=desktop):
                env = claude.collect("all", tp, repo_roots=[])
        self.assertTrue(env["platform_detected"])
        self.assertEqual(env["summary"]["desktop_mcp_servers"], 1)
        self.assertEqual(len(env["rules"]), 1)
        self.assertNotIn("claude.permission.auto_mode_default", ids(env["findings"]))
        self.assertEqual(env["summary"]["permission_mode"], "")

    def test_nothing_installed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tp = tool_paths(root, root / "missing-home")
            with mock.patch.object(claude, "desktop_config_path", return_value=root / "missing.json"):
                env = claude.collect("all", tp, repo_roots=[])
        self.assertFalse(env["platform_detected"])
        self.assertEqual(env["summary"], {"settings_files": 0, "rules": 0, "findings": 0})


class TestMcpHost(unittest.TestCase):
    def findings_for(self, config):
        _rules, findings = claude.extract_rules_from_settings(
            "user", "global", {"mcpServers": {"srv": config}}, Path("settings.json")
        )
        return ids(findings)

    def test_lookalike_and_query_are_external(self):
        self.assertIn(
            "claude.mcp.external_server",
            self.findings_for({"url": "http://localhost.evil.example/mcp", "note": "localhost"}),
        )
        self.assertIn(
            "claude.mcp.external_server",
            self.findings_for({"url": "https://evil.example/mcp?h=127.0.0.1"}),
        )

    def test_loopback_and_stdio_are_not_external(self):
        for config in (
            {"url": "http://localhost:9000"},
            {"url": "http://127.0.0.1:9"},
            {"url": "http://[::1]:8080"},
            {"command": "python", "args": ["srv.py"]},
            {"url": 5},
        ):
            self.assertNotIn("claude.mcp.external_server", self.findings_for(config), config)


class TestSafeUrl(unittest.TestCase):
    def test_out_of_range_port_is_a_marker(self):
        self.assertEqual(claude.safe_url("http://otel.example:99999/v1"), "invalid-endpoint")
        self.assertEqual(claude.safe_url("http://[::1"), "invalid-endpoint")

    def test_normal_endpoint_keeps_host_and_port(self):
        self.assertEqual(
            claude.safe_url("https://otel.example:4318/v1/traces?token=sekret"),
            "https://otel.example:4318/v1/traces",
        )


if __name__ == "__main__":
    unittest.main()
