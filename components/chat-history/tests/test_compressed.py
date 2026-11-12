"""Chat export reads Codex .jsonl.zst when stdlib zstd is available."""
from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path
from unittest import mock

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"
import bootstrap  # noqa: E402,F401
import compressed  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "chat_history_zst", Path(__file__).resolve().parent.parent / "chat-history.py"
)
mod = importlib.util.module_from_spec(_spec)
assert _spec is not None and _spec.loader is not None
_spec.loader.exec_module(mod)

HAS_ZSTD = compressed.zstd_backend() is not None
LINE = (
    b'{"type":"event_msg","timestamp":"2026-10-15T12:00:00Z",'
    b'"payload":{"type":"user_message","message":"synthetic hello"}}\n'
)


class ExportTests(unittest.TestCase):
    def test_no_backend_skips_without_opening(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            packed = root / "rollout.jsonl.zst"
            packed.write_bytes(b"not-opened")
            opened: list[str] = []
            real_open = Path.open

            def spy(self, *args, **kwargs):
                opened.append(str(self))
                return real_open(self, *args, **kwargs)

            buckets = defaultdict(list)
            problems: list[str] = []
            stats: dict = {}
            with (
                mock.patch.object(compressed, "zstd_backend", return_value=None),
                mock.patch.object(Path, "open", spy),
            ):
                mod.collect_codex(buckets, False, root, problems=problems, stats=stats)
            self.assertFalse(buckets)
            self.assertFalse(any(name.endswith(".jsonl.zst") for name in opened))
            self.assertEqual(stats["compressed_not_scanned"], 1)
            self.assertIn("compressed_not_scanned", problems)
            notes = mod.codex_coverage_findings(stats)
            self.assertEqual(
                [note["id"] for note in notes],
                ["chat_history.codex.compressed_not_scanned"],
            )

    @unittest.skipUnless(HAS_ZSTD, "compression.zstd is not available")
    def test_compressed_message_is_exported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            packed = root / "rollout.jsonl.zst"
            packed.write_bytes(compressed.compress(LINE))
            buckets = defaultdict(list)
            mod.collect_codex(buckets, False, root)
            entries = [entry for day in buckets.values() for entry in day]
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["source"], str(packed))
            self.assertEqual(entries[0]["tool"], "Codex")
            self.assertIn("synthetic hello", entries[0]["text"])

    @unittest.skipUnless(HAS_ZSTD, "compression.zstd is not available")
    def test_corrupt_does_not_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "rollout.jsonl.zst").write_bytes(b"corrupt")
            buckets = defaultdict(list)
            problems: list[str] = []
            stats: dict = {}
            mod.collect_codex(buckets, False, root, problems=problems, stats=stats)
            self.assertFalse(buckets)
            self.assertEqual(stats["compressed_unreadable"], 1)
            self.assertIn("unreadable", problems)
            notes = mod.codex_coverage_findings(stats)
            self.assertEqual(notes[0]["id"], "chat_history.codex.compressed_unreadable")
            self.assertIn("coverage_gap", notes[0]["tags"])

    @unittest.skipUnless(HAS_ZSTD, "compression.zstd is not available")
    def test_current_shape_zst_counts_user_and_assistant(self):
        records = [
            {"timestamp": "2026-10-15T12:00:00Z", "type": "session_meta", "payload": {"id": "s"}},
            {
                "timestamp": "2026-10-15T12:00:00Z",
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "developer",
                    "content": [{"type": "input_text", "text": "developer instructions"}],
                },
            },
            {
                "timestamp": "2026-10-15T12:00:00Z",
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": "zst user"}],
                },
            },
            {
                "timestamp": "2026-10-15T12:00:00Z",
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "zst assistant"}],
                },
            },
            {
                "timestamp": "2026-10-15T12:00:00Z",
                "type": "event_msg",
                "payload": {"type": "user_message", "message": "zst user"},
            },
            {"timestamp": "2026-10-15T12:00:00Z", "type": "event_msg", "payload": {"type": "token_count"}},
        ]
        import json

        payload = "".join(json.dumps(row) + "\n" for row in records).encode("utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            packed = root / "rollout.jsonl.zst"
            packed.write_bytes(compressed.compress(payload))
            buckets = defaultdict(list)
            stats: dict = {}
            mod.collect_codex(buckets, False, root, stats=stats)
            pairs = [(entry["role"], entry["text"]) for day in buckets.values() for entry in day]
        self.assertEqual(pairs, [("user", "zst user"), ("assistant", "zst assistant")])
        self.assertEqual(stats["messages"], 2)
        self.assertEqual(stats["files_read"], 1)

    @unittest.skipUnless(HAS_ZSTD, "compression.zstd is not available")
    def test_over_cap_zst_is_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            packed = root / "rollout.jsonl.zst"
            packed.write_bytes(compressed.compress(LINE))
            buckets = defaultdict(list)
            problems: list[str] = []
            stats: dict = {}
            with mock.patch.object(compressed, "MAX_DECOMPRESSED_BYTES", 1):
                mod.collect_codex(buckets, False, root, problems=problems, stats=stats)
        self.assertFalse(buckets)
        self.assertEqual(stats["compressed_unreadable"], 1)
        self.assertIn("unreadable", problems)

    def test_compressed_read_errors_are_recorded(self):
        cases = (
            compressed.ZstdUnavailable("no backend"),
            compressed.TooLarge("big"),
            compressed.DecompressTimeout("slow"),
            UnicodeError("bad byte"),
            OSError("corrupt"),
        )
        for exc in cases:
            with self.subTest(exc=type(exc).__name__):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    (root / "rollout.jsonl.zst").write_bytes(b"synthetic")
                    buckets = defaultdict(list)
                    problems: list[str] = []
                    stats: dict = {}
                    with (
                        mock.patch.object(compressed, "zstd_backend", return_value="compression.zstd"),
                        mock.patch.object(compressed, "read_text", side_effect=exc),
                    ):
                        mod.collect_codex(buckets, False, root, problems=problems, stats=stats)
                self.assertFalse(buckets)
                self.assertEqual(stats["compressed_unreadable"], 1)
                self.assertIn("unreadable", problems)
                self.assertEqual(stats["compressed_not_scanned"], 0)


if __name__ == "__main__":
    unittest.main()
