"""
Tests for Grok session inventory: events.jsonl MCP, sandbox_profile, signals.

Run:
    python -m unittest discover -s tests -p test_grok_sessions.py -v
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"

import bootstrap  # noqa: E402,F401

import grok  # noqa: E402
import paths  # noqa: E402

SECRET_TARGET = r"C:\Users\Test User\cursor-projects\acme-mcp\mcp-server.py"


def ids(findings):
    return {f["id"] for f in findings}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_json(path: Path, data: dict) -> None:
    _write(path, json.dumps(data))


class TestScanEventsMcp(unittest.TestCase):
    def test_resolves_servers_without_target_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            events = Path(tmp) / "events.jsonl"
            lines = [
                {
                    "ts": "2026-06-20T23:53:25.961Z",
                    "type": "mcp_config_resolved",
                    "servers": [
                        {"name": "acme-mcp", "transport": "stdio", "source": "local"},
                        {"name": "splunk-mcp-server", "transport": "stdio"},
                    ],
                    "disabled": [],
                },
                {
                    "ts": "2026-06-20T23:53:26.299Z",
                    "type": "mcp_server_starting",
                    "server_name": "acme-mcp",
                    "transport": "stdio",
                    "target": f"python {SECRET_TARGET}",
                },
                {"ts": "x", "type": "other_noise", "payload": "ignore"},
            ]
            _write(events, "\n".join(json.dumps(x) for x in lines) + "\n")
            servers, hits = grok._scan_events_mcp(events)
            self.assertEqual(hits, 2)
            self.assertEqual(servers["acme-mcp"], "stdio")
            self.assertEqual(servers["splunk-mcp-server"], "stdio")
            blob = json.dumps(servers)
            self.assertNotIn(SECRET_TARGET, blob)
            self.assertNotIn("cursor-projects", blob)


class TestCollectSessionInventory(unittest.TestCase):
    def test_sandbox_off_and_runtime_mcp_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "sessions"
            session = root / "cwd-slug" / "sess-1"
            _write_json(
                session / "summary.json",
                {
                    "current_model_id": "grok-build",
                    "num_messages": 10,
                    "created_at": "2026-06-20T23:53:25.497286+00:00",
                    "sandbox_profile": "off",
                },
            )
            _write_json(
                session / "signals.json",
                {
                    "contextTokensUsed": 100,
                    "toolCallCount": 5,
                    "toolsUsed": ["run_terminal_command", "read_file"],
                },
            )
            _write(
                session / "events.jsonl",
                json.dumps(
                    {
                        "type": "mcp_config_resolved",
                        "servers": [
                            {"name": "acme-mcp", "transport": "stdio"},
                            {"name": "notebooklm-mcp", "transport": "stdio"},
                        ],
                    }
                )
                + "\n"
                + json.dumps(
                    {
                        "type": "mcp_server_starting",
                        "server_name": "acme-mcp",
                        "target": SECRET_TARGET,
                    }
                )
                + "\n",
            )
            _write(session / "chat_history.jsonl", '{"text":"secret prompt"}\n')
            _write(session / "updates.jsonl", '{"method":"session/update"}\n')

            summary, findings, rules = grok.collect_session_inventory(root)
            self.assertEqual(summary["session_count"], 1)
            self.assertEqual(summary["mcp_runtime_servers"], 2)
            self.assertEqual(summary["sandbox_off_sessions"], 1)
            self.assertEqual(summary["sandbox_profile_distribution"].get("off"), 1)
            self.assertIn("run_terminal_command", summary["tools_used_distribution"])
            self.assertIn("grok.sandbox.off", ids(findings))

            mcp_rules = [r for r in rules if r["rule_type"] == "mcp_tool"]
            self.assertEqual(len(mcp_rules), 2)
            names = {r.get("command_or_tool_redacted") for r in mcp_rules}
            self.assertEqual(names, {"acme-mcp", "notebooklm-mcp"})
            for r in mcp_rules:
                self.assertEqual(r["settings_source"], "events.jsonl mcp_config_resolved")
                self.assertEqual(r["source_kind"], "session_event")

            blob = json.dumps(summary) + json.dumps(findings) + json.dumps(rules)
            self.assertNotIn(SECRET_TARGET, blob)
            self.assertNotIn("secret prompt", blob)


class TestCollectIntegration(unittest.TestCase):
    def test_runtime_only_finding_when_config_has_no_mcp(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            grok_home = root / ".grok"
            sessions = grok_home / "sessions"
            config = grok_home / "config.toml"
            logs = grok_home / "logs"
            auth = grok_home / "auth.json"
            logs.mkdir(parents=True)
            _write(logs / "unified.jsonl", '{"msg":"x"}\n')
            _write(
                config,
                '[ui]\npermission_mode = "always-approve"\nyolo = false\n',
            )
            _write(auth, '{"token":"x"}')

            session = sessions / "cwd" / "s1"
            _write_json(
                session / "summary.json",
                {
                    "current_model_id": "grok-build",
                    "num_messages": 3,
                    "created_at": "2026-07-01T00:00:00+00:00",
                    "sandbox_profile": "off",
                },
            )
            _write(
                session / "events.jsonl",
                json.dumps(
                    {
                        "type": "mcp_config_resolved",
                        "servers": [{"name": "acme-mcp", "transport": "stdio"}],
                    }
                )
                + "\n",
            )

            tp = paths.ToolPaths(
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
                grok_sessions=sessions,
                grok_config=config,
                grok_logs=logs,
                grok_auth=auth,
                grok_project_config=None,
                sources={},
            )

            with mock.patch.dict(os.environ, {"USERPROFILE": str(root)}):
                envelope = grok.collect(tp, repo_roots=[])

            self.assertTrue(envelope["platform_detected"])
            self.assertEqual(envelope["version"], "1.1.0")
            got = ids(envelope["findings"])
            self.assertIn("grok.permission.always_approve", got)
            self.assertIn("grok.sandbox.off", got)
            self.assertIn("grok.mcp.runtime_only", got)
            self.assertIn("grok.auth.present_excluded", got)
            self.assertEqual(envelope["summary"]["mcp_servers"], 0)
            self.assertEqual(envelope["summary"]["mcp_runtime_servers"], 1)
            self.assertGreaterEqual(envelope["summary"]["log_files"], 1)
            mcp_rules = [r for r in envelope["rules"] if r["rule_type"] == "mcp_tool"]
            self.assertEqual(len(mcp_rules), 1)
            blob = json.dumps(envelope)
            self.assertNotIn(SECRET_TARGET, blob)


if __name__ == "__main__":
    unittest.main()
