"""Compressed Codex rollouts are scanned when stdlib zstd is available.

The no-backend contract (count, do not open, low finding) lives in
test_codex_sessions.py and forces zstd_backend() to return None. Tests below
that need a real frame skip when compression.zstd cannot be imported.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"
import bootstrap  # noqa: E402,F401

import codex  # noqa: E402
import compressed  # noqa: E402
import paths  # noqa: E402

HAS_ZSTD = compressed.zstd_backend() is not None
OLD = 1_759_000_000
NEWER = 1_760_000_000
NEWEST = 1_760_500_000


def _day(stamp: int) -> str:
    return datetime.fromtimestamp(stamp).strftime("%Y-%m-%d")


def _rollout() -> bytes:
    row = {
        "timestamp": "2026-05-20T10:00:00Z",
        "payload": {
            "type": "message",
            "content": 'Approved command prefixes: ["git status"]',
        },
    }
    return (json.dumps(row) + "\n").encode("utf-8")


class CompressedCodex(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.sessions = self.root / "sessions"
        self.sessions.mkdir()
        self.tp = paths.resolve_tool_paths(cli_overrides={"codex_home": str(self.root)})

    def tearDown(self):
        self.tmp.cleanup()

    def test_discovery_counts_compressed_rollouts_once(self):
        (self.sessions / "a.jsonl").write_text("{}\n", encoding="utf-8")
        (self.sessions / "a.jsonl.zst").write_bytes(b"twin")
        (self.sessions / "b.jsonl.zst").write_bytes(b"x")
        (self.sessions / "notes.zst").write_bytes(b"nope")
        disc = paths.detected(self.tp)["codex_sessions"]
        self.assertEqual(disc["file_count"], 2)

    def test_plain_twin_is_not_reported_unread(self):
        (self.sessions / "a.jsonl").write_text(
            json.dumps({
                "timestamp": "2026-05-20T10:00:00Z",
                "payload": {"type": "message", "content": 'Approved command prefixes: ["git status"]'},
            }) + "\n",
            encoding="utf-8",
        )
        (self.sessions / "a.jsonl.zst").write_bytes(b"twin-not-opened")
        with mock.patch.object(compressed, "zstd_backend", return_value=None):
            env = codex.collect(self.tp)
        self.assertEqual(env["summary"]["session_files"], 1)
        self.assertEqual(env["summary"]["compressed_session_files"], 0)
        self.assertNotIn(
            "codex.sessions.compressed_not_scanned",
            [finding["id"] for finding in env["findings"]],
        )
        self.assertTrue(any(rule["rule"] == "git status" for rule in env["rules"]))

    def test_last_used_and_desktop_are_stat_only(self):
        packed = self.sessions / "only.jsonl.zst"
        packed.write_bytes(b"not-opened")
        os.utime(packed, (OLD, OLD))
        index = self.root / "session_index.jsonl"
        state = self.root / "state_5.sqlite"
        index.write_bytes(b"synthetic, must not be opened")
        state.write_bytes(b"synthetic, must not be opened")
        os.utime(index, (NEWER, NEWER))
        os.utime(state, (NEWEST, NEWEST))
        local = self.root / "localappdata"
        log = (
            local / "Packages" / "OpenAI.Codex_synthetic0"
            / "LocalCache" / "Local" / "Codex" / "Logs" / "2026" / "codex-desktop-synthetic.log"
        )
        log.parent.mkdir(parents=True)
        log.write_bytes(b"synthetic, must not be opened")
        os.utime(log, (NEWEST, NEWEST))

        opened: list[str] = []
        real_open = Path.open

        def spy(self, *args, **kwargs):
            opened.append(self.name)
            return real_open(self, *args, **kwargs)

        with (
            mock.patch.object(compressed, "zstd_backend", return_value=None),
            mock.patch.object(Path, "open", spy),
        ):
            env = codex.collect(self.tp, localappdata=local)
        summary = env["summary"]
        self.assertEqual(summary["last_used"], _day(NEWEST))
        self.assertEqual(summary["last_used_source"], "state_db")
        self.assertTrue(summary["desktop_installed"])
        self.assertEqual(summary["desktop_last_opened"], _day(NEWEST))
        self.assertNotIn("session_index.jsonl", opened)
        self.assertNotIn("state_5.sqlite", opened)
        self.assertNotIn("codex-desktop-synthetic.log", opened)
        self.assertFalse(any(name.endswith(".jsonl.zst") for name in opened))
        blob = json.dumps(env)
        self.assertNotIn("synthetic", blob)
        self.assertNotIn("OpenAI.Codex", blob)

    def test_desktop_absent(self):
        env = codex.collect(self.tp, localappdata=self.root / "empty-local")
        self.assertFalse(env["summary"]["desktop_installed"])
        self.assertEqual(env["summary"]["desktop_last_opened"], "")

    @unittest.skipUnless(HAS_ZSTD, "compression.zstd is not available")
    def test_compressed_rollout_is_scanned(self):
        packed = self.sessions / "rollout-z.jsonl.zst"
        packed.write_bytes(compressed.compress(_rollout()))
        opened: list[str] = []
        real_open = Path.open

        def spy(self, *args, **kwargs):
            opened.append(str(self))
            return real_open(self, *args, **kwargs)

        with mock.patch.object(Path, "open", spy):
            env = codex.collect(self.tp)
        self.assertTrue(any(name.endswith(".jsonl.zst") for name in opened))
        self.assertEqual(env["summary"]["session_files"], 1)
        self.assertEqual(env["summary"]["compressed_session_files"], 1)
        self.assertEqual(env["summary"]["compressed_session_unreadable"], 0)
        self.assertEqual(env["summary"]["zstd_backend"], "compression.zstd")
        self.assertTrue(any(rule["rule"] == "git status" for rule in env["rules"]))
        ids = [finding["id"] for finding in env["findings"]]
        self.assertNotIn("codex.sessions.compressed_not_scanned", ids)
        self.assertNotIn("codex.sessions.compressed_unreadable", ids)

    @unittest.skipUnless(HAS_ZSTD, "compression.zstd is not available")
    def test_corrupt_file_is_a_coverage_note(self):
        (self.sessions / "rollout-z.jsonl.zst").write_bytes(b"not-zstd")
        env = codex.collect(self.tp)
        hits = [f for f in env["findings"] if f["id"] == "codex.sessions.compressed_unreadable"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "low")
        self.assertEqual(hits[0]["evidence_count"], 1)
        self.assertEqual(hits[0]["title"], "1 compressed Codex session log could not be fully read")
        self.assertEqual(hits[0]["tags"], ["coverage_gap"])
        self.assertNotIn("codex.sessions.compressed_not_scanned", [f["id"] for f in env["findings"]])
        self.assertNotIn("not-zstd", json.dumps(env))

    @unittest.skipUnless(HAS_ZSTD, "compression.zstd is not available")
    def test_oversize_and_timeout_are_coverage_notes(self):
        packed = self.sessions / "rollout-z.jsonl.zst"
        packed.write_bytes(compressed.compress(_rollout()))
        with mock.patch.object(compressed, "MAX_DECOMPRESSED_BYTES", 4):
            env = codex.collect(self.tp)
        self.assertEqual(env["summary"]["compressed_session_unreadable"], 1)
        with mock.patch.object(compressed, "MAX_DECOMPRESS_SECONDS", -1):
            env = codex.collect(self.tp)
        hits = [f for f in env["findings"] if f["id"] == "codex.sessions.compressed_unreadable"]
        self.assertEqual(hits[0]["title"], "1 compressed Codex session log could not be fully read")


if __name__ == "__main__":
    unittest.main()
