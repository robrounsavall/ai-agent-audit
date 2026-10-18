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

    def test_non_object_json_does_not_abort(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            claude_file = root / "proj" / "mix.jsonl"
            claude_file.parent.mkdir(parents=True)
            claude_file.write_text(
                "[]\n"
                + json.dumps(
                    {
                        "type": "user",
                        "timestamp": "2026-01-02T00:00:00Z",
                        "message": "hello from a string",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            codex_root = root / "codex"
            codex_file = codex_root / "sess.jsonl"
            codex_file.parent.mkdir(parents=True)
            codex_file.write_text(
                json.dumps({"type": "event_msg", "payload": "not-an-object"})
                + "\n"
                + json.dumps(
                    {
                        "type": "event_msg",
                        "timestamp": "2026-01-02T00:00:00Z",
                        "payload": {"type": "user_message", "message": "codex kept"},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            grok_file = root / "grok" / "cwd" / "s1" / "chat_history.jsonl"
            grok_file.parent.mkdir(parents=True)
            grok_file.write_text(
                "[]\n"
                + json.dumps({"type": "user", "content": "grok kept"})
                + "\n",
                encoding="utf-8",
            )
            cursor_file = (
                root
                / "cursor"
                / "cursor-projects-demo"
                / "agent-transcripts"
                / "sess"
                / "sess.jsonl"
            )
            cursor_file.parent.mkdir(parents=True)
            cursor_file.write_text(
                json.dumps({"role": "user", "message": "cursor kept"}) + "\n",
                encoding="utf-8",
            )
            buckets = defaultdict(list)
            ch.collect_claude(buckets, False, root / "proj")
            ch.collect_codex(buckets, False, codex_root)
            ch.collect_grok(buckets, False, root / "grok")
            ch.collect_cursor_transcripts(buckets, False, root / "cursor")
        texts = [entry["text"] for rows in buckets.values() for entry in rows]
        self.assertIn("hello from a string", texts)
        self.assertIn("codex kept", texts)
        self.assertIn("grok kept", texts)
        self.assertIn("cursor kept", texts)

    def test_composer_hash_path_and_odd_json(self):
        import sqlite3

        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "work#space" / "state.vscdb"
            db.parent.mkdir()
            con = sqlite3.connect(db)
            con.execute("CREATE TABLE ItemTable (key TEXT, value TEXT)")
            con.execute("CREATE TABLE cursorDiskKV (key TEXT, value TEXT)")
            headers = {
                "allComposers": [
                    "not-a-composer",
                    {"composerId": "c1"},
                ]
            }
            con.execute(
                "INSERT INTO ItemTable VALUES ('composer.composerHeaders', ?)",
                (json.dumps(headers),),
            )
            composer = {
                "fullConversationHeadersOnly": [
                    "nope",
                    {"bubbleId": "bad"},
                    {"bubbleId": "good"},
                ]
            }
            con.execute(
                "INSERT INTO cursorDiskKV VALUES ('composerData:c1', ?)",
                (json.dumps(composer),),
            )
            con.execute(
                "INSERT INTO cursorDiskKV VALUES ('bubbleId:c1:bad', ?)",
                ("[]",),
            )
            con.execute(
                "INSERT INTO cursorDiskKV VALUES ('bubbleId:c1:good', ?)",
                (
                    json.dumps(
                        {
                            "text": "kept line",
                            "createdAt": "2026-01-02T00:00:00Z",
                            "type": 1,
                        }
                    ),
                ),
            )
            con.commit()
            con.close()
            buckets = defaultdict(list)
            ch.collect_cursor_composer(buckets, db)
        texts = [entry["text"] for rows in buckets.values() for entry in rows]
        self.assertEqual(texts, ["kept line"])


if __name__ == "__main__":
    unittest.main()
