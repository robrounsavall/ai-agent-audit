"""
Tests for the VS Code agent host (agent-host-config.json + agent-host.db),
empty-window chat sessions, and last-activity dating.

Run:
    scripts/test-component.ps1 -Name vscode
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

os.environ["USERPROFILE"] = r"C:\Users\Test User"
import bootstrap  # noqa: E402,F401

import paths as toolpaths  # noqa: E402
import vscode  # noqa: E402

TRUSTED = "C:/Users/Test User/secret-client-repo"

CONFIG = {
    "permissions": {"allow": ["WebFetch(docs.example.com)", "WebFetch(github.com/org/*)"], "ask": [], "deny": []},
    "telemetryLevel": "all",
    "globalAutoApproveEnabled": False,
    "terminalAutoApproveEnabled": True,
    "editAutoApprovePatterns": {"**/*": True, "**/.git/**": False, "**/.claude/settings.json": False},
    "sandbox": {
        "enabled": "off",
        "allowNetwork": True,
        "allowUnsandboxedCommands": True,
        "authenticateGit": True,
        "authenticateGh": True,
    },
    "computerUseEnabled": True,
    "codexAgentEnabled": True,
    "githubMcpServerEnabled": True,
    "mcpConnectorsEnabled": False,
    "agentMerge": {"enabled": False, "mergePullRequest": "never"},
    "workspaceTrust": {"enabled": True, "trustedUris": [TRUSTED, "C:/x"]},
    "defaultShell": r"C:\WINDOWS\System32\wsl.exe",
    "assistedApprovalInstructions": "never approve rm on prod-db-7",
}


def ids(findings):
    return {f["id"] for f in findings}


class TestParseAgentHostConfig(unittest.TestCase):
    def test_posture_summary_and_findings(self):
        rules, findings, summary = vscode.parse_agent_host_config(CONFIG)
        self.assertEqual(summary["agent_host_allow_rules"], 2)
        self.assertEqual({r["rule_type"] for r in rules}, {"web_fetch"})
        self.assertTrue(all(r["decision"] == "allow" for r in rules))
        self.assertEqual(summary["agent_host_sandbox"], "off")
        self.assertTrue(summary["agent_host_edit_auto_approve_all"])
        self.assertEqual(summary["agent_host_edit_protected_patterns"], 2)
        self.assertEqual(summary["agent_host_trusted_folders"], 2)
        self.assertTrue(summary["agent_host_computer_use"])
        self.assertFalse(summary["agent_host_agent_merge"])
        self.assertEqual(
            ids(findings),
            {
                "vscode.agent_host.allow_rules",
                "vscode.agent_host.edit_auto_approve",
                "vscode.agent_host.sandbox_off",
                "vscode.agent_host.computer_use",
                "vscode.agent_host.remote_mcp",
            },
        )

    def test_no_paths_or_free_text_leak(self):
        rules, findings, summary = vscode.parse_agent_host_config(CONFIG)
        blob = json.dumps([rules, findings, summary])
        for leak in ("secret-client-repo", "wsl.exe", "prod-db-7"):
            self.assertNotIn(leak, blob)

    def test_global_auto_approve_is_high(self):
        _, findings, summary = vscode.parse_agent_host_config({"globalAutoApproveEnabled": True})
        self.assertTrue(summary["agent_host_global_auto_approve"])
        high = [f for f in findings if f["id"] == "vscode.agent_host.global_auto_approve"]
        self.assertEqual(high[0]["severity"], "high")

    def test_sandbox_on_with_escape_hatch(self):
        _, findings, summary = vscode.parse_agent_host_config(
            {"sandbox": {"enabled": "on", "allowUnsandboxedCommands": True}}
        )
        self.assertEqual(summary["agent_host_sandbox"], "on")
        self.assertIn("vscode.agent_host.unsandboxed_commands", ids(findings))
        self.assertNotIn("vscode.agent_host.sandbox_off", ids(findings))

    def test_empty_config_is_quiet(self):
        rules, findings, summary = vscode.parse_agent_host_config({})
        self.assertEqual(rules, [])
        self.assertEqual(findings, [])
        self.assertEqual(summary["agent_host_sandbox"], "unset")


def make_agent_host_db(path: Path) -> None:
    con = sqlite3.connect(path)
    con.execute(
        "create table sessions (session_uri text, provider text, start_time int, external int,"
        " registration_source text, modified_time int)"
    )
    con.execute("create table chats_v2 (chat_uri text, owner_session_uri text)")
    con.execute("create table metadata (key text, value text)")
    con.executemany(
        "insert into sessions values (?,?,?,?,?,?)",
        [
            ("copilotcli:/a", "copilotcli", 1793538907839, 0, "explicit", 1793538944518),
            ("x:/b", "Weird Provider/With Path", 1794403574007, 0, "explicit", 1794403574007),
        ],
    )
    con.executemany("insert into chats_v2 values (?,?)", [("c1", "a"), ("c2", "a"), ("c3", "b")])
    con.executemany(
        "insert into metadata values (?,?)",
        [("sessionTombstone:copilotcli:/z", "1"), ("sessionTombstone:copilotcli:/y", "1"), ("other", "1")],
    )
    con.commit()
    con.close()


class TestAgentHostSessions(unittest.TestCase):
    def test_counts_and_newest_date(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "agent-host.db"
            make_agent_host_db(db)
            out = vscode.inventory_agent_host_sessions(db)
        self.assertEqual(out["agent_host_sessions"], 2)
        self.assertEqual(out["agent_host_providers"], {"copilotcli": 1, "other": 1})
        self.assertEqual(out["agent_host_chats"], 3)
        self.assertEqual(out["agent_host_deleted_sessions"], 2)
        self.assertEqual(out["agent_host_last_activity"], "2026-11-11")

    def test_missing_db(self):
        self.assertEqual(vscode.inventory_agent_host_sessions(Path("nope/agent-host.db")), {})

    def test_corrupt_db(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "agent-host.db"
            db.write_bytes(b"not a database" * 100)
            out = vscode.inventory_agent_host_sessions(db)
        self.assertTrue(out.get("agent_host_db_error"))


class TestCollectWithAgentHost(unittest.TestCase):
    def test_collect_reads_agent_host_and_empty_window_chats(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "Code"
            gs = root / "User" / "globalStorage"
            (gs / "emptyWindowChatSessions").mkdir(parents=True)
            (root / "User" / "workspaceStorage").mkdir(parents=True)
            (gs / "agent-host-config.json").write_text(json.dumps(CONFIG), encoding="utf-8")
            make_agent_host_db(gs / "agent-host.db")
            (gs / "emptyWindowChatSessions" / "s.jsonl").write_text(
                json.dumps({"kind": 0, "v": {"requests": [{}], "inputState": {"mode": {"id": "ask"}}}}),
                encoding="utf-8",
            )
            p = toolpaths.resolve_tool_paths(cli_overrides={"vscode_root": str(root)})
            env = vscode.collect(p, [])
        s = env["summary"]
        self.assertEqual(s["chat_sessions"], 1)
        self.assertEqual(s["chat_empty_window_sessions"], 1)
        self.assertEqual(s["chat_workspaces"], 0)
        self.assertEqual(s["agent_host_sessions"], 2)
        self.assertEqual(s["agent_host_allow_rules"], 2)
        self.assertEqual(s["last_activity"], max(s["chat_last_activity"], "2026-11-11"))
        self.assertIn("vscode.agent_host.sandbox_off", ids(env["findings"]))
        self.assertEqual(len(env["rules"]), 2)


if __name__ == "__main__":
    unittest.main()
