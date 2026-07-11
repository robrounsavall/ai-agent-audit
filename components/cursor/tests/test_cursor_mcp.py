"""
Tests for Cursor MCP registration + known/approved enrichment.

Run:
    python -m unittest scripts/test-component.ps1 -Name cursor
    # or from scripts/test-component.ps1 -Name cursor
    python -m unittest discover -s tests -p test_cursor_mcp.py -v
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"

import bootstrap  # noqa: E402,F401

import cursor  # noqa: E402
import paths  # noqa: E402

AWS_KEY = "AKIA" + "C" * 16
BEARER = (
    "YSDqVxDYh22ZVpr5GcQ0bUHXiWmK6Z87lcDNYuxnntWiktYOV/"
    "rQftpOP06Rjex9f2qXkCwTaI/YL/gisT4sogBwGIadp/Elq9s2WlRsyVORvWo9"
)


def ids(findings):
    return {f["id"] for f in findings}


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _make_vscdb(path: Path, items: dict[str, object], *, both_tables: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    try:
        con.execute("CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value BLOB)")
        con.execute("CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value BLOB)")
        for key, value in items.items():
            blob = json.dumps(value)
            con.execute("INSERT INTO ItemTable (key, value) VALUES (?, ?)", (key, blob))
            if both_tables:
                con.execute(
                    "INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)", (key, blob)
                )
        con.commit()
    finally:
        con.close()


class TestParseMcpJson(unittest.TestCase):
    def test_registered_servers_and_secret_in_args(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mcp.json"
            _write_json(
                path,
                {
                    "mcpServers": {
                        "acme-mcp": {"command": "python", "args": ["mcp-server.py"]},
                        "splunk-mcp-server": {
                            "command": "npx",
                            "args": [
                                "-y",
                                "mcp-remote",
                                "http://localhost:8001/mcp",
                                "--header",
                                f"Authorization: Bearer {BEARER}",
                            ],
                        },
                        "remote-evil": {"url": "https://evil.example.com/mcp"},
                    }
                },
            )
            rules, findings, names = cursor.parse_mcp_json_file(
                path,
                scope="user",
                scope_label="global",
                source_kind="user_config",
                settings_source="shared mcp.json",
            )
            self.assertEqual(names, {"acme-mcp", "splunk-mcp-server", "remote-evil"})
            self.assertEqual(len(rules), 3)
            self.assertTrue(all(r["rule_type"] == "mcp_tool" for r in rules))
            self.assertTrue(all(r["source_kind"] == "user_config" for r in rules))
            got = ids(findings)
            self.assertIn("cursor.mcp.args_secret", got)
            self.assertIn("cursor.mcp.external_server", got)
            blob = json.dumps(rules) + json.dumps(findings)
            self.assertNotIn(BEARER, blob)

    def test_env_secret_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mcp.json"
            _write_json(
                path,
                {"mcpServers": {"x": {"command": "node", "env": {"TOKEN": AWS_KEY}}}},
            )
            _, findings, _ = cursor.parse_mcp_json_file(
                path,
                scope="user",
                scope_label="global",
                source_kind="user_config",
                settings_source="user mcp.json",
            )
            self.assertIn("cursor.mcp.env_secret", ids(findings))
            self.assertNotIn(AWS_KEY, json.dumps(findings))

    def test_localhost_no_external(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mcp.json"
            _write_json(
                path,
                {"mcpServers": {"local": {"url": "http://localhost:9000"}}},
            )
            _, findings, _ = cursor.parse_mcp_json_file(
                path,
                scope="user",
                scope_label="global",
                source_kind="user_config",
                settings_source="user mcp.json",
            )
            self.assertNotIn("cursor.mcp.external_server", ids(findings))


class TestVscdbMcp(unittest.TestCase):
    def test_known_enrichment_and_approved(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "state.vscdb"
            _make_vscdb(
                db,
                {
                    "cursor/approvedProjectMcpServers": [
                        "project-0-0-04-acme-mcp-acme-mcp"
                    ],
                    "mcpService.knownServerIds": [
                        "acme-mcp",
                        "02-content-production-system-notebooklm-mcp",
                        "mystery-server",
                    ],
                },
            )
            rules, _, _, summary = cursor.search_vscdb(
                db, registered_names={"acme-mcp", "notebooklm-mcp"}
            )
            self.assertEqual(summary["approved_project_mcp_servers"], 1)
            self.assertEqual(summary["known_mcp_servers"], 3)
            self.assertEqual(summary["known_mcp_matched"], 2)
            self.assertEqual(summary["known_mcp_unmatched"], 1)
            mcp_rules = [r for r in rules if r["rule_type"] == "mcp_tool"]
            # 1 approved (resolved to acme-mcp) + 1 unmatched known
            self.assertEqual(len(mcp_rules), 2)
            approved = [
                r for r in mcp_rules
                if r.get("settings_source") == "state.vscdb approvedProjectMcpServers"
            ]
            self.assertEqual(len(approved), 1)
            self.assertEqual(approved[0]["rule"], "mcp__acme-mcp")
            self.assertEqual(approved[0]["command_or_tool_redacted"], "acme-mcp")
            # Scope label must not leak the mangled Cursor project id.
            # With redaction on it is project#hash; with AISCAN_NO_REDACT it is
            # project:approval (controlled vocab from the collector).
            label = approved[0]["scope_label_redacted"]
            self.assertTrue(
                "approval" in label or label.startswith("project#"),
                f"unexpected scope_label_redacted: {label}",
            )
            self.assertNotIn("04-acme-mcp-acme-mcp", json.dumps(approved))
            sources = {r.get("settings_source") for r in mcp_rules}
            self.assertIn("state.vscdb approvedProjectMcpServers", sources)
            self.assertIn("state.vscdb knownServerIds", sources)

    def test_resolve_registered_name_prefers_longest_suffix(self):
        self.assertEqual(
            cursor._resolve_registered_name(
                "04-acme-mcp-acme-mcp", {"acme-mcp", "ai"}
            ),
            "acme-mcp",
        )
        self.assertEqual(
            cursor._resolve_registered_name(
                "02-content-production-system-notebooklm-mcp",
                {"acme-mcp", "notebooklm-mcp"},
            ),
            "notebooklm-mcp",
        )
        self.assertIsNone(
            cursor._resolve_registered_name("mystery-server", {"acme-mcp"})
        )

    def test_project_slug_known_matches_registered(self):
        self.assertTrue(
            cursor._known_matches_registered(
                "02-content-production-system-acme-mcp", {"acme-mcp"}
            )
        )
        self.assertTrue(
            cursor._known_matches_registered("04-acme-mcp-acme-mcp", {"acme-mcp"})
        )
        self.assertFalse(
            cursor._known_matches_registered("mystery-server", {"acme-mcp"})
        )

    def test_no_double_count_across_tables(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "state.vscdb"
            _make_vscdb(
                db,
                {
                    "mcpService.knownServerIds": ["a", "b"],
                    "cursor/approvedProjectMcpServers": ["proj-server"],
                },
                both_tables=True,
            )
            rules, _, _, summary = cursor.search_vscdb(db, registered_names=set())
            self.assertEqual(summary["known_mcp_servers"], 2)
            self.assertEqual(summary["approved_project_mcp_servers"], 1)
            # Without registered names, both known become unmatched rules + 1 approved
            mcp_rules = [r for r in rules if r["rule_type"] == "mcp_tool"]
            self.assertEqual(len(mcp_rules), 3)


class TestCollectIntegration(unittest.TestCase):
    def test_collect_merges_mcp_json_and_vscdb(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            user_mcp = root / ".cursor" / "mcp.json"
            shared = root / ".mcp.json"
            appdata_mcp = root / "AppData" / "Roaming" / "Cursor" / "mcp.json"
            db = root / "AppData" / "Roaming" / "Cursor" / "User" / "globalStorage" / "state.vscdb"
            projects = root / ".cursor" / "projects"
            projects.mkdir(parents=True)

            _write_json(user_mcp, {"mcpServers": {}})
            _write_json(
                shared,
                {
                    "mcpServers": {
                        "acme-mcp": {"command": "python"},
                        "notebooklm-mcp": {"command": "notebooklm-mcp"},
                        "splunk-mcp-server": {
                            "command": "npx",
                            "args": [
                                "--header",
                                f"Authorization: Bearer {BEARER}",
                            ],
                        },
                    }
                },
            )
            _make_vscdb(
                db,
                {
                    "cursor/approvedProjectMcpServers": ["project-1-2-acme-mcp"],
                    "mcpService.knownServerIds": [
                        "acme-mcp",
                        "notebooklm-mcp",
                        "splunk-mcp-server",
                    ],
                },
            )

            # Project mcp.json under a fake repo root
            repo_root = root / "repos"
            proj = repo_root / "demo-proj"
            (proj / ".git").mkdir(parents=True)
            _write_json(
                proj / ".cursor" / "mcp.json",
                {"mcpServers": {"project-only": {"command": "node"}}},
            )

            tp = paths.ToolPaths(
                claude_home=root / ".claude",
                claude_projects=root / ".claude" / "projects",
                codex_home=root / ".codex",
                codex_sessions=root / ".codex" / "sessions",
                codex_config=root / ".codex" / "config.toml",
                codex_auth=root / ".codex" / "auth.json",
                cursor_projects=projects,
                cursor_db=db,
                cursor_user_mcp=user_mcp,
                cursor_appdata_mcp=appdata_mcp,
                shared_mcp=shared,
                grok_home=root / ".grok",
                grok_sessions=root / ".grok" / "sessions",
                grok_config=root / ".grok" / "config.toml",
                grok_logs=root / ".grok" / "logs",
                grok_auth=root / ".grok" / "auth.json",
                grok_project_config=None,
                sources={},
            )

            with mock.patch.dict(
                os.environ,
                {
                    "USERPROFILE": str(root),
                    "APPDATA": str(root / "AppData" / "Roaming"),
                },
            ):
                envelope = cursor.collect(tp, repo_roots=[repo_root])

            self.assertTrue(envelope["platform_detected"])
            summary = envelope["summary"]
            self.assertEqual(summary["mcp_registered"], 4)  # 3 shared + 1 project
            self.assertEqual(summary["known_mcp_servers"], 3)
            self.assertEqual(summary["known_mcp_matched"], 3)
            self.assertEqual(summary["known_mcp_unmatched"], 0)
            self.assertEqual(summary["approved_project_mcp_servers"], 1)

            mcp_rules = [r for r in envelope["rules"] if r["rule_type"] == "mcp_tool"]
            # 3 shared + 1 project + 1 approved (known all matched → no unmatched rules)
            self.assertGreaterEqual(len(mcp_rules), 5)
            names = {r.get("command_or_tool_redacted") or r.get("rule") for r in mcp_rules}
            self.assertTrue(any("acme-mcp" in str(n) for n in names))
            self.assertTrue(any("splunk" in str(n) for n in names))
            self.assertTrue(any("project-only" in str(n) for n in names))

            self.assertIn("cursor.mcp.args_secret", ids(envelope["findings"]))
            blob = json.dumps(envelope)
            self.assertNotIn(BEARER, blob)
            for r in mcp_rules:
                src = str(r.get("settings_source") or "")
                self.assertNotIn("\\", src)
                self.assertNotIn("/", src)


class TestCursorMcpServerName(unittest.TestCase):
    def test_strips_project_prefix(self):
        self.assertEqual(
            cursor._cursor_mcp_server_name("project-0-0-04-acme-mcp-acme-mcp"),
            "04-acme-mcp-acme-mcp",
        )

    def test_strips_host_port(self):
        self.assertEqual(cursor._cursor_mcp_server_name("host:1234:myserver"), "host")


if __name__ == "__main__":
    unittest.main()
