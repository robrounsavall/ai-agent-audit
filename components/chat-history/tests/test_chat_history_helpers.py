"""Unit tests for chat-history pure helpers."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"

import bootstrap  # noqa: E402,F401

_mod_path = Path(__file__).resolve().parent.parent / "chat-history.py"
_spec = importlib.util.spec_from_file_location("chat_history_mod", _mod_path)
ch = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(ch)


class TestHelpers(unittest.TestCase):
    def test_escape_md_fence(self):
        out = ch.escape_md_fence("a ``` b")
        self.assertIsInstance(out, str)
        self.assertNotEqual(out, "")

    def test_parse_iso(self):
        self.assertTrue(ch.parse_iso("2026-01-01T00:00:00Z") or ch.parse_iso("2026-01-01T00:00:00+00:00"))

    def test_get_content_text_string(self):
        self.assertEqual(ch.get_content_text("hello"), "hello")

    def test_bad_byte_does_not_abort(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            good = root / "proj" / "ok.jsonl"
            good.parent.mkdir(parents=True)
            good.write_text(
                json.dumps(
                    {
                        "type": "user",
                        "timestamp": "2026-01-02T00:00:00Z",
                        "message": {"role": "user", "content": "hello"},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "proj" / "bad.jsonl").write_bytes(b"\xff\xfe")
            buckets = defaultdict(list)
            problems: list[str] = []
            ch.collect_claude(buckets, False, root, problems=problems)
        self.assertTrue(problems)
        self.assertTrue(buckets)
        self.assertNotIn(str(root), " ".join(problems))

    def test_parse_problem_becomes_a_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tp = ch.paths.ToolPaths(
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
                grok_home=root / "grok",
                grok_sessions=root / "grok" / "sessions",
                grok_config=root / "grok" / "config.toml",
                grok_logs=root / "grok" / "logs",
                grok_auth=root / "grok" / "auth.json",
                grok_project_config=None,
            )
            env = ch.build_evidence([], root, tp, parse_problems=["unreadable", "unreadable"])
        found = [f for f in env["findings"] if f["id"] == "chat_history.parse_error"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["evidence_count"], 2)
        self.assertNotIn(str(root), json.dumps(found))


if __name__ == "__main__":
    unittest.main()
