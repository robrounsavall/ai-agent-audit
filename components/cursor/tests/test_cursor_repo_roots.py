"""Regression tests for shared default repository roots."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import bootstrap  # noqa: F401

import cursor
import paths


class TestCursorRepoRoots(unittest.TestCase):
    def test_default_roots_discover_project_mcp_and_respect_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / ".cursor" / "projects").mkdir(parents=True)
            repo_root = home / "cursor-projects"
            project = repo_root / "demo-proj"
            (project / ".git").mkdir(parents=True)
            config = project / ".cursor" / "mcp.json"
            config.parent.mkdir()
            config.write_text(json.dumps({
                "mcpServers": {"project-only": {"command": "node", "args": ["server.js"]}}
            }), encoding="utf-8")
            tp = paths.ToolPaths(
                claude_home=home / ".claude",
                claude_projects=home / ".claude" / "projects",
                codex_home=home / ".codex",
                codex_sessions=home / ".codex" / "sessions",
                codex_config=home / ".codex" / "config.toml",
                codex_auth=home / ".codex" / "auth.json",
                cursor_projects=home / ".cursor" / "projects",
                cursor_db=home / "state.vscdb",
                cursor_user_mcp=home / ".cursor" / "mcp.json",
                cursor_appdata_mcp=home / "AppData" / "Cursor" / "mcp.json",
                shared_mcp=home / ".mcp.json",
                grok_home=home / ".grok",
                grok_sessions=home / ".grok" / "sessions",
                grok_config=home / ".grok" / "config.toml",
                grok_logs=home / ".grok" / "logs",
                grok_auth=home / ".grok" / "auth.json",
                grok_project_config=None,
                sources={},
            )
            with mock.patch.dict(os.environ, {"USERPROFILE": str(home)}):
                self.assertIn(repo_root, cursor.default_repo_roots())
                envelope = cursor.collect(tp, repo_roots=None)
                explicit = cursor.collect(tp, repo_roots=[])

            project_servers = [
                rule for rule in envelope["rules"]
                if rule["rule_type"] == "mcp_tool"
                and rule["settings_source"] == "project mcp.json"
                and rule["command_or_tool_redacted"] == "project-only"
            ]
            self.assertEqual(len(project_servers), 1)
            self.assertEqual(project_servers[0]["source_kind"], "project_config")
            self.assertFalse(any(
                rule["rule_type"] == "mcp_tool"
                for rule in explicit["rules"]
            ))


if __name__ == "__main__":
    unittest.main()
