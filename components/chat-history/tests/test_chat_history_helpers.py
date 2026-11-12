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


_TS = "2026-10-15T12:00:00Z"


def _jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")


def _pairs(buckets) -> list[tuple[str, str]]:
    return [(entry["role"], entry["text"]) for rows in buckets.values() for entry in rows]


def _tool_paths(root: Path) -> "ch.paths.ToolPaths":
    return ch.paths.ToolPaths(
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


def _codex_result(buckets, raw_root: Path) -> dict:
    return {
        "tool": "Codex",
        "folder": "codex",
        "files": len(buckets),
        "entries": sum(len(rows) for rows in buckets.values()),
        "active_minutes_estimated": 0,
        "files_info": [
            {
                "path": raw_root / "chat-history" / "codex" / f"{day}.md",
                "date": day,
                "entries": len(rows),
                "size": 1,
                "has_secret": False,
                "secret_types": [],
            }
            for day, rows in buckets.items()
        ],
    }


def _evidence(buckets, root: Path, stats: dict, problems: list | None = None) -> dict:
    return ch.build_evidence(
        [_codex_result(buckets, root)],
        root,
        _tool_paths(root),
        parse_problems=problems,
        codex_stats=stats,
    )


def _response(role: str, text: str, part: str = "input_text") -> dict:
    return {
        "timestamp": _TS,
        "type": "response_item",
        "payload": {
            "type": "message",
            "role": role,
            "content": [{"type": part, "text": text}],
        },
    }


def _current_rollout() -> list[dict]:
    """Synthetic current-shape rollout. No real transcript text."""
    return [
        {"timestamp": _TS, "type": "session_meta", "payload": {"id": "sess", "cwd": "/work"}},
        {"timestamp": _TS, "type": "turn_context", "payload": {"turn_id": "turn-1"}},
        _response("developer", "developer instructions"),
        _response("system", "system prompt"),
        {
            "timestamp": _TS,
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "user",
                "content": [
                    {
                        "type": "input_text",
                        "text": (
                            "# AGENTS.md instructions for /work\n\n"
                            "<INSTRUCTIONS>\nbe brief\n</INSTRUCTIONS>"
                        ),
                    },
                    {
                        "type": "input_text",
                        "text": "<ENVIRONMENT_CONTEXT>cwd=/work</ENVIRONMENT_CONTEXT>",
                    },
                    {"type": "input_text", "text": "count this user turn"},
                ],
            },
        },
        {
            "timestamp": _TS,
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "user",
                "content": [
                    {
                        "type": "input_text",
                        "text": (
                            "<environment_context>\ncwd=/work\n</environment_context>\n\n"
                            "## My request for Codex:\nship the fix"
                        ),
                    }
                ],
            },
        },
        _response("user", "please update AGENTS.md"),
        {
            "timestamp": _TS,
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "user",
                "content": [{"type": "input_image", "image_url": "file://synthetic.png"}],
            },
        },
        _response("assistant", "count this assistant turn", part="output_text"),
        {
            "timestamp": _TS,
            "type": "response_item",
            "payload": {"type": "function_call", "name": "shell", "arguments": "{}"},
        },
        {
            "timestamp": _TS,
            "type": "response_item",
            "payload": {
                "type": "agent_message",
                "author": "root",
                "recipient": "worker",
                "content": [{"type": "input_text", "text": "inter-agent aside"}],
            },
        },
        {"timestamp": _TS, "type": "event_msg", "payload": {"type": "token_count", "info": None}},
    ]


class TestCodexRolloutShapes(unittest.TestCase):
    def test_current_shape_counts_user_and_assistant_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sessions = root / ".codex" / "sessions" / "2026" / "10" / "15"
            _jsonl(sessions / "rollout-current.jsonl", _current_rollout())
            buckets = defaultdict(list)
            stats: dict = {}
            ch.collect_codex(buckets, False, root / ".codex" / "sessions", stats=stats)
            env = _evidence(buckets, root, stats)
        self.assertEqual(
            _pairs(buckets),
            [
                ("user", "count this user turn"),
                ("user", "ship the fix"),
                ("user", "please update AGENTS.md"),
                ("assistant", "count this assistant turn"),
            ],
        )
        self.assertGreater(env["summary"]["codex_files"], 0)
        self.assertGreater(env["summary"]["codex_messages"], 0)
        self.assertEqual(env["summary"]["codex_messages"], 4)
        self.assertEqual(env["summary"]["codex_session_files_seen"], 1)
        self.assertNotIn("developer instructions", json.dumps(env))
        self.assertNotIn("inter-agent aside", json.dumps(env))
        self.assertNotIn("be brief", json.dumps(env))

    def test_legacy_event_msg_still_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _jsonl(
                root / "sess.jsonl",
                [
                    {
                        "timestamp": _TS,
                        "type": "event_msg",
                        "payload": {"type": "user_message", "message": "legacy user"},
                    },
                    {
                        "timestamp": _TS,
                        "type": "event_msg",
                        "payload": {"type": "agent_message", "message": "legacy assistant"},
                    },
                    {
                        "timestamp": _TS,
                        "type": "event_msg",
                        "payload": {"type": "token_count"},
                    },
                ],
            )
            buckets = defaultdict(list)
            ch.collect_codex(buckets, False, root)
        self.assertEqual(
            _pairs(buckets),
            [("user", "legacy user"), ("assistant", "legacy assistant")],
        )

    def test_repeated_response_messages_are_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _jsonl(root / "sess.jsonl", [_response("user", "ok"), _response("user", "ok")])
            buckets = defaultdict(list)
            ch.collect_codex(buckets, False, root)
        self.assertEqual(_pairs(buckets), [("user", "ok"), ("user", "ok")])

    def test_mixed_shape_does_not_double_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _jsonl(
                root / "sess.jsonl",
                [
                    _response("user", "shared line"),
                    _response("assistant", "shared answer", part="output_text"),
                    {
                        "timestamp": _TS,
                        "type": "event_msg",
                        "payload": {
                            "type": "item_completed",
                            "item": {
                                "type": "UserMessage",
                                "id": "u1",
                                "content": [{"type": "text", "text": "shared line"}],
                            },
                        },
                    },
                    {
                        "timestamp": _TS,
                        "type": "event_msg",
                        "payload": {
                            "type": "item_completed",
                            "item": {
                                "type": "AgentMessage",
                                "id": "a1",
                                "content": [{"type": "Text", "text": "completed only"}],
                            },
                        },
                    },
                    {
                        "timestamp": _TS,
                        "type": "event_msg",
                        "payload": {"type": "user_message", "message": "shared line"},
                    },
                    {
                        "timestamp": _TS,
                        "type": "event_msg",
                        "payload": {"type": "user_message", "message": "legacy only"},
                    },
                    {
                        "timestamp": _TS,
                        "type": "event_msg",
                        "payload": {"type": "agent_message", "message": "shared answer"},
                    },
                ],
            )
            buckets = defaultdict(list)
            ch.collect_codex(buckets, False, root)
        self.assertEqual(
            _pairs(buckets),
            [
                ("user", "shared line"),
                ("assistant", "shared answer"),
                ("assistant", "completed only"),
                ("user", "legacy only"),
            ],
        )

    def test_paginated_item_completed_counts_when_response_items_are_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _jsonl(
                root / "sess.jsonl",
                [
                    {"timestamp": _TS, "type": "session_meta", "payload": {"id": "sess"}},
                    {
                        "timestamp": _TS,
                        "type": "event_msg",
                        "payload": {
                            "type": "item_completed",
                            "turn_id": "turn-1",
                            "completed_at_ms": 1760000000000,
                            "item": {
                                "type": "UserMessage",
                                "id": "u1",
                                "content": [{"type": "text", "text": "paginated user"}],
                            },
                        },
                    },
                    {
                        "timestamp": _TS,
                        "type": "event_msg",
                        "payload": {
                            "type": "item_completed",
                            "item": {
                                "type": "AgentMessage",
                                "id": "a1",
                                "content": [{"type": "Text", "text": "paginated assistant"}],
                            },
                        },
                    },
                    {
                        "timestamp": _TS,
                        "type": "event_msg",
                        "payload": {
                            "type": "item_completed",
                            "item": {"type": "CommandExecution", "id": "c1", "command": "echo hi"},
                        },
                    },
                    {
                        "timestamp": _TS,
                        "type": "event_msg",
                        "payload": {"type": "user_message", "message": "paginated user"},
                    },
                    {
                        "timestamp": _TS,
                        "type": "event_msg",
                        "payload": {"type": "user_message", "message": "legacy only"},
                    },
                ],
            )
            buckets = defaultdict(list)
            ch.collect_codex(buckets, False, root)
        self.assertEqual(
            _pairs(buckets),
            [
                ("user", "paginated user"),
                ("assistant", "paginated assistant"),
                ("user", "legacy only"),
            ],
        )

    def test_inter_agent_messages_need_tool_details(self):
        records = [
            _response("user", "real user"),
            {
                "timestamp": _TS,
                "type": "response_item",
                "payload": {
                    "type": "agent_message",
                    "author": "root",
                    "recipient": "worker",
                    "content": [{"type": "input_text", "text": "inter-agent aside"}],
                },
            },
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _jsonl(root / "sess.jsonl", records)
            quiet = defaultdict(list)
            detailed = defaultdict(list)
            ch.collect_codex(quiet, False, root)
            ch.collect_codex(detailed, True, root)
        self.assertEqual(_pairs(quiet), [("user", "real user")])
        self.assertEqual(
            _pairs(detailed),
            [("user", "real user"), ("assistant", "inter-agent aside")],
        )

    def test_archived_sessions_are_collected(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / ".codex"
            _jsonl(
                home / "archived_sessions" / "rollout-old.jsonl",
                [
                    {
                        "timestamp": _TS,
                        "type": "event_msg",
                        "payload": {"type": "user_message", "message": "archived user"},
                    }
                ],
            )
            buckets = defaultdict(list)
            ch.collect_codex(buckets, False, home / "sessions")
        self.assertEqual(_pairs(buckets), [("user", "archived user")])

    def test_detected_but_zero_messages_warns_of_format_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sessions = root / ".codex" / "sessions"
            _jsonl(
                sessions / "2026" / "10" / "15" / "rollout-empty.jsonl",
                [
                    {"timestamp": _TS, "type": "session_meta", "payload": {"id": "sess"}},
                    _response("developer", "developer instructions"),
                    {
                        "timestamp": _TS,
                        "type": "response_item",
                        "payload": {"type": "function_call", "name": "shell", "arguments": "{}"},
                    },
                    {"timestamp": _TS, "type": "event_msg", "payload": {"type": "token_count"}},
                ],
            )
            buckets = defaultdict(list)
            stats: dict = {}
            ch.collect_codex(buckets, False, sessions, stats=stats)
            env = _evidence(buckets, root, stats)
        ids = [finding["id"] for finding in env["findings"]]
        self.assertIn("chat_history.codex.format_drift", ids)
        note = next(f for f in env["findings"] if f["id"] == "chat_history.codex.format_drift")
        self.assertIn("format may have changed", note["sample_redacted"])
        self.assertIn("coverage_gap", note["tags"])
        self.assertEqual(stats["files_seen"], 1)
        self.assertEqual(stats["messages"], 0)
        self.assertNotIn("developer instructions", json.dumps(env))

    def test_thread_history_sqlite_without_rollouts_is_a_coverage_note(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / ".codex"
            home.mkdir()
            (home / "thread_history_1.sqlite").write_bytes(b"")
            (home / "state_5.sqlite").write_bytes(b"")
            (home / "rollout-migrations").mkdir()
            buckets = defaultdict(list)
            stats: dict = {}
            ch.collect_codex(buckets, False, home / "sessions", stats=stats)
            env = _evidence(buckets, Path(tmp), stats)
        self.assertFalse(buckets)
        note = next(
            f for f in env["findings"] if f["id"] == "chat_history.codex.sqlite_history_not_counted"
        )
        self.assertIn("rollout_files=0", note["sample_redacted"])
        self.assertIn("thread_history_sqlite=1", note["sample_redacted"])
        self.assertIn("rollout_migrations=present", note["sample_redacted"])
        self.assertNotIn(str(home), json.dumps(env))

    def test_newer_thread_history_sqlite_is_a_coverage_note(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / ".codex"
            rollout = home / "sessions" / "2026" / "10" / "15" / "rollout.jsonl"
            _jsonl(
                rollout,
                [
                    {
                        "timestamp": _TS,
                        "type": "event_msg",
                        "payload": {"type": "user_message", "message": "still counted"},
                    }
                ],
            )
            db = home / "thread_history_1.sqlite"
            db.write_bytes(b"")
            old = rollout.stat().st_mtime - (3 * 24 * 60 * 60)
            os.utime(rollout, (old, old))
            buckets = defaultdict(list)
            stats: dict = {}
            ch.collect_codex(buckets, False, home / "sessions", stats=stats)
            env = _evidence(buckets, root, stats)
        self.assertEqual(_pairs(buckets), [("user", "still counted")])
        note = next(
            f for f in env["findings"] if f["id"] == "chat_history.codex.sqlite_history_not_counted"
        )
        self.assertIn("newer_than_rollouts=yes", note["sample_redacted"])
        self.assertNotIn("still counted", note["sample_redacted"])

    def test_thread_history_sqlite_beside_current_rollouts_is_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / ".codex"
            rollout = home / "sessions" / "rollout.jsonl"
            _jsonl(
                rollout,
                [
                    {
                        "timestamp": _TS,
                        "type": "event_msg",
                        "payload": {"type": "user_message", "message": "current"},
                    }
                ],
            )
            (home / "thread_history_1.sqlite").write_bytes(b"")
            buckets = defaultdict(list)
            stats: dict = {}
            ch.collect_codex(buckets, False, home / "sessions", stats=stats)
            env = _evidence(buckets, root, stats)
        ids = [finding["id"] for finding in env["findings"]]
        self.assertNotIn("chat_history.codex.sqlite_history_not_counted", ids)
        self.assertNotIn("chat_history.codex.format_drift", ids)
        self.assertEqual(_pairs(buckets), [("user", "current")])


if __name__ == "__main__":
    unittest.main()
