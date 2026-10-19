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
            with (
                mock.patch.object(compressed, "zstd_backend", return_value=None),
                mock.patch.object(Path, "open", spy),
            ):
                mod.collect_codex(buckets, False, root)
            self.assertFalse(buckets)
            self.assertFalse(any(name.endswith(".jsonl.zst") for name in opened))

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
            mod.collect_codex(buckets, False, root)
            self.assertFalse(buckets)


if __name__ == "__main__":
    unittest.main()
