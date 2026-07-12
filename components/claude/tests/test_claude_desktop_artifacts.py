"""Unit tests for desktop MCP config parsing and ~/.claude side artifacts."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"

import bootstrap  # noqa: E402,F401
import claude  # noqa: E402


def ids(findings):
    return {f["id"] for f in findings}


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
