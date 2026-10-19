"""
Contract for codex.py session parsing (Step 1 hardening target).

These assert that approved-prefix extraction accepts ONLY bounded structured
content (a JSON array after the marker) and never promotes surrounding prompt
prose, markdown, or developer instructions into rules. Against the current
line-by-line fallback several of these FAIL by design; the Step 1 hardening
makes them pass without weakening the structured path.

Run:
    scripts/test-component.ps1 -Name <component>
"""

from __future__ import annotations

import builtins
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

import codex  # noqa: E402
import compressed  # noqa: E402
import paths  # noqa: E402

AWS_KEY = "AKIA" + "B" * 16


class TestParseApprovedPrefixes(unittest.TestCase):
    def test_json_array_form(self):
        text = 'Approved command prefixes: ["git status", "npm test"]'
        self.assertEqual(
            sorted(codex.parse_approved_prefixes(text)),
            ["git status", "npm test"],
        )

    def test_array_filters_non_strings(self):
        text = 'Approved command prefixes = ["git status", 5, null, "ls"]'
        out = codex.parse_approved_prefixes(text)
        self.assertIn("git status", out)
        self.assertIn("ls", out)
        self.assertNotIn("5", out)
        self.assertNotIn("None", out)

    def test_prose_after_marker_is_not_a_rule(self):
        # No JSON array. The hardened parser must return nothing, not split lines.
        text = (
            "Approved command prefixes\n"
            "You are a helpful assistant. Follow the user's instructions and\n"
            "do not run destructive commands without asking.\n"
        )
        self.assertEqual(codex.parse_approved_prefixes(text), [])

    def test_markdown_bullets_after_marker_rejected(self):
        text = (
            "## Approved command prefixes\n"
            "- here are some notes\n"
            "- another sentence of prose\n"
        )
        self.assertEqual(codex.parse_approved_prefixes(text), [])

    def test_no_marker_returns_empty(self):
        self.assertEqual(codex.parse_approved_prefixes("just a normal message"), [])

    def test_empty(self):
        self.assertEqual(codex.parse_approved_prefixes(""), [])


class TestCollectAgainstFixtures(unittest.TestCase):
    """Run collect() against a fake CODEX_HOME and assert clean, structured output."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.sessions = root / "sessions"
        self.sessions.mkdir(parents=True)
        self.tp = paths.resolve_tool_paths(cli_overrides={"codex_home": str(root)})

    def tearDown(self):
        self.tmp.cleanup()

    def _write_session(self, name, rows):
        path = self.sessions / name
        with path.open("w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row) + "\n")

    def test_structured_prefixes_only_no_leakage(self):
        prose_with_path_and_secret = {
            "timestamp": "2026-05-20T10:00:00Z",
            "payload": {
                "type": "message",
                "content": (
                    "Approved command prefixes\n"
                    "Work in C:\\Users\\Test User\\cursor-projects and "
                    f"never leak {AWS_KEY}.\n"
                ),
            },
        }
        real_block = {
            "timestamp": "2026-05-20T10:01:00Z",
            "payload": {
                "type": "message",
                "content": 'Approved command prefixes: ["git status", "npm run build"]',
            },
        }
        self._write_session("rollout-a.jsonl", [prose_with_path_and_secret, real_block])

        env = codex.collect(self.tp)
        rules = env.get("rules", [])
        blob = json.dumps(env)

        # No identifying path or secret anywhere in the envelope.
        self.assertNotIn("Test User", blob)
        self.assertNotIn("cursor-projects\\", blob)
        self.assertNotIn(AWS_KEY, blob)

        # Only the structured prefixes became rules; prose did not.
        rule_texts = {r["rule"] for r in rules}
        self.assertIn("git status", rule_texts)
        self.assertIn("npm run build", rule_texts)
        self.assertFalse(
            any("helpful assistant" in t or "never leak" in t for t in rule_texts),
            f"prose leaked into rules: {rule_texts}",
        )

    def test_duplicate_blocks_deduped(self):
        block = {
            "timestamp": "2026-05-20T10:00:00Z",
            "payload": {
                "type": "message",
                "content": 'Approved command prefixes: ["git status"]',
            },
        }
        self._write_session("rollout-a.jsonl", [block])
        self._write_session("rollout-b.jsonl", [dict(block)])
        env = codex.collect(self.tp)
        git_rules = [r for r in env.get("rules", []) if r["rule"] == "git status"]
        self.assertEqual(len(git_rules), 1, "duplicate prefix not deduped")

    def test_compressed_session_logs_are_counted_not_read(self):
        self._write_session(
            "rollout-a.jsonl",
            [{
                "timestamp": "2026-05-20T10:00:00Z",
                "payload": {
                    "type": "message",
                    "content": 'Approved command prefixes: ["git status"]',
                },
            }],
        )
        # Not valid zstd. The collector must count these and not try to open them.
        (self.sessions / "rollout-b.jsonl.zst").write_bytes(b"not-a-real-archive")
        nested = self.sessions / "2026" / "05"
        nested.mkdir(parents=True)
        (nested / "rollout-c.jsonl.zst").write_bytes(b"\x28\xb5\x2f\xfd")
        # A plain .zst that is not a session log is not part of the count.
        (self.sessions / "notes.zst").write_bytes(b"nope")

        opened: list[str] = []
        real_path_open = Path.open
        real_open = builtins.open

        def spy_path_open(self, *args, **kwargs):
            opened.append(str(self))
            return real_path_open(self, *args, **kwargs)

        def spy_open(file, *args, **kwargs):
            if isinstance(file, (str, Path)):
                opened.append(str(file))
            return real_open(file, *args, **kwargs)

        # Force the pre-3.14 path even when this interpreter has compression.zstd.
        with (
            mock.patch.object(compressed, "zstd_backend", return_value=None),
            mock.patch.object(Path, "open", spy_path_open),
            mock.patch("builtins.open", spy_open),
        ):
            env = codex.collect(self.tp)
        self.assertTrue(any(name.endswith(".jsonl") and not name.endswith(".jsonl.zst") for name in opened))
        self.assertFalse(any(name.endswith(".jsonl.zst") for name in opened))
        self.assertEqual(env["summary"]["session_files"], 1)
        self.assertEqual(env["summary"]["compressed_session_files"], 2)
        hits = [f for f in env["findings"] if f["id"] == "codex.sessions.compressed_not_scanned"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "low")
        self.assertEqual(hits[0]["evidence_count"], 2)
        self.assertEqual(hits[0]["title"], "2 compressed Codex session logs not scanned")
        self.assertEqual(hits[0]["tags"], ["coverage_gap"])
        self.assertTrue(any(r["rule"] == "git status" for r in env["rules"]))
        blob = json.dumps(env)
        self.assertNotIn("rollout-b", blob)
        self.assertNotIn("rollout-c", blob)

    def test_one_compressed_log_uses_singular_title(self):
        (self.sessions / "only.jsonl.zst").write_bytes(b"x")
        with mock.patch.object(compressed, "zstd_backend", return_value=None):
            env = codex.collect(self.tp)
        hits = [f for f in env["findings"] if f["id"] == "codex.sessions.compressed_not_scanned"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["title"], "1 compressed Codex session log not scanned")
        self.assertEqual(env["summary"]["compressed_session_files"], 1)
        self.assertEqual(env["summary"]["session_files"], 0)

    def test_no_finding_when_no_compressed_logs(self):
        self._write_session("rollout-a.jsonl", [])
        env = codex.collect(self.tp)
        self.assertEqual(env["summary"]["compressed_session_files"], 0)
        self.assertNotIn(
            "codex.sessions.compressed_not_scanned",
            [f["id"] for f in env["findings"]],
        )


if __name__ == "__main__":
    unittest.main()
