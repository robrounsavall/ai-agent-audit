"""Unit tests for desktop MCP config parsing and ~/.claude side artifacts."""

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


class TestCollectPermissionMode(unittest.TestCase):
    def run_collect(self, settings=None, version=None, local_settings=None, scope="all"):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "claude_home"
            projects = home / "projects"
            projects.mkdir(parents=True)
            if settings is not None:
                (home / "settings.json").write_text(json.dumps(settings), encoding="utf-8")
            if local_settings is not None:
                (home / "settings.local.json").write_text(
                    json.dumps(local_settings), encoding="utf-8"
                )
            if version:
                (projects / "t.jsonl").write_text(
                    json.dumps({"type": "user", "version": version}) + "\n",
                    encoding="utf-8",
                )
            tp = claude.paths.ToolPaths(
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
            env = {
                k: v
                for k, v in os.environ.items()
                if not k.startswith(("OTEL_", "CLAUDE_CODE_"))
            }
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(
                claude, "desktop_config_path", return_value=root / "missing.json"
            ), mock.patch.object(claude, "read_registry_env", return_value={}):
                return claude.collect(scope, tp, repo_roots=[])

    def by_id(self, envelope):
        return {f["id"]: f for f in envelope["findings"]}

    def test_no_settings_implies_auto(self):
        env = self.run_collect()
        found = self.by_id(env)
        self.assertEqual(found["claude.permission.auto_mode_default"]["severity"], "medium")
        self.assertEqual(env["summary"]["permission_mode"], "auto (implicit default)")
        self.assertEqual(env["summary"]["permission_mode_source"], "built-in default")

    def test_disable_auto_mode(self):
        env = self.run_collect({"permissions": {"disableAutoMode": "disable"}})
        self.assertNotIn("claude.permission.auto_mode_default", self.by_id(env))
        self.assertTrue(env["summary"]["auto_mode_disabled"])
        self.assertEqual(env["summary"]["permission_mode"], "default (auto disabled)")

    def test_disable_bypass_mode(self):
        env = self.run_collect(
            {
                "permissions": {
                    "defaultMode": "bypassPermissions",
                    "disableBypassPermissionsMode": "disable",
                }
            }
        )
        found = self.by_id(env)
        self.assertNotIn("claude.permission.bypass_mode", found)
        self.assertIn("claude.permission.mode_not_applied", found)
        self.assertTrue(env["summary"]["bypass_mode_disabled"])

    def test_explicit_auto_with_disable_flag(self):
        env = self.run_collect(
            {"permissions": {"defaultMode": "auto", "disableAutoMode": "disable"}}
        )
        self.assertEqual(env["summary"]["permission_mode"], "default (auto disabled)")
        self.assertEqual(
            env["summary"]["permission_mode_source"], "settings.json permissions.defaultMode"
        )

    def test_explicit_bypass_with_disable_flag(self):
        env = self.run_collect(
            {
                "permissions": {
                    "defaultMode": "bypassPermissions",
                    "disableBypassPermissionsMode": "disable",
                }
            }
        )
        self.assertEqual(env["summary"]["permission_mode"], "default (bypass disabled)")
        self.assertEqual(
            env["summary"]["permission_mode_source"], "settings.json permissions.defaultMode"
        )

    def test_not_applied_evidence_merged(self):
        env = self.run_collect(
            {
                "permissions": {
                    "defaultMode": "bypassPermissions",
                    "disableBypassPermissionsMode": "disable",
                }
            },
            local_settings={"permissions": {"defaultMode": "auto"}},
        )
        found = [f for f in env["findings"] if f["id"] == "claude.permission.mode_not_applied"]
        self.assertEqual(len(found), 1)
        self.assertIn("disableBypassPermissionsMode", found[0]["sample_redacted"])

    def test_workspace_scope_skips_implicit_default(self):
        env = self.run_collect(scope="workspace")
        self.assertNotIn("claude.permission.auto_mode_default", self.by_id(env))
        self.assertEqual(env["summary"]["permission_mode"], "")
        self.assertEqual(env["summary"]["permission_mode_source"], "not scanned (scope)")

    def test_explicit_mode_suppresses_implicit(self):
        env = self.run_collect({"permissions": {"defaultMode": "plan"}})
        self.assertNotIn("claude.permission.auto_mode_default", self.by_id(env))
        self.assertEqual(env["summary"]["permission_mode"], "plan")
        self.assertEqual(
            env["summary"]["permission_mode_source"], "settings.json permissions.defaultMode"
        )

    def test_version_detected(self):
        env = self.run_collect(version="2.1.301")
        self.assertEqual(env["summary"]["claude_code_version"], "2.1.301")
        sample = self.by_id(env)["claude.permission.auto_mode_default"]["sample_redacted"]
        self.assertIn("version=2.1.301", sample)

    def test_old_version_wording(self):
        env = self.run_collect(version="2.1.200")
        title = self.by_id(env)["claude.permission.auto_mode_default"]["title"]
        self.assertIn("may start", title)


class TestCollectDesktopMcp(unittest.TestCase):
    def test_missing_file(self):
        rules, findings, count = claude.collect_desktop_mcp(Path(r"C:\nope\none.json"))
        self.assertEqual((rules, findings, count), ([], [], 0))

    def test_servers_become_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "claude_desktop_config.json"
            cfg.write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "local-tool": {"command": "python", "args": ["srv.py"]},
                            "remote-tool": {"url": "https://mcp.example.com/sse"},
                        }
                    }
                ),
                encoding="utf-8",
            )
            rules, findings, count = claude.collect_desktop_mcp(cfg)
        self.assertEqual(count, 2)
        self.assertEqual(len(rules), 2)
        for rule in rules:
            self.assertEqual(rule["rule_type"], "mcp_tool")
            self.assertEqual(rule["settings_source"], "claude_desktop_config.json")
        self.assertIn("claude.mcp.external_server", ids(findings))

    def test_empty_servers(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "claude_desktop_config.json"
            cfg.write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")
            rules, findings, count = claude.collect_desktop_mcp(cfg)
        self.assertEqual((rules, findings, count), ([], [], 0))


class TestScanSideArtifacts(unittest.TestCase):
    def test_empty_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(claude.scan_side_artifacts(Path(tmp)), [])

    def test_all_artifacts_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / "history.jsonl").write_text("{}\n" * 1000, encoding="utf-8")
            fh = home / "file-history" / "proj"
            fh.mkdir(parents=True)
            (fh / "snap1.txt").write_text("old contents", encoding="utf-8")
            (fh / "snap2.txt").write_text("older contents", encoding="utf-8")
            (home / "bash-audit.log").write_text("cmd\n" * 500, encoding="utf-8")

            findings = claude.scan_side_artifacts(home)

        found = ids(findings)
        self.assertIn("claude.history.global_prompt_log", found)
        self.assertIn("claude.file_history.snapshots", found)
        self.assertIn("claude.shell_audit.log_present", found)
        snaps = next(f for f in findings if f["id"] == "claude.file_history.snapshots")
        self.assertEqual(snaps["evidence_count"], 2)

    def test_zero_byte_files_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / "history.jsonl").write_bytes(b"")
            (home / "bash-audit.log").write_bytes(b"")
            (home / "file-history").mkdir()
            self.assertEqual(claude.scan_side_artifacts(home), [])


if __name__ == "__main__":
    unittest.main()
