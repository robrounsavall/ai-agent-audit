from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"
import bootstrap  # noqa: E402,F401
import compressed

spec = importlib.util.spec_from_file_location("chat_history_zst", Path(__file__).resolve().parent.parent / "chat-history.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class ExportTests(unittest.TestCase):
    @unittest.skipUnless(compressed.zstd_backend(), "zstd backend unavailable")
    def test_export_and_skip(self):
        from collections import defaultdict
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            p = root / "rollout.jsonl.zst"
            data = b'{"type":"event_msg","timestamp":"2026-10-15T12:00:00Z","payload":{"type":"user_message","message":"synthetic hello"}}\n'
            p.write_bytes(compressed.compress(data))
            buckets = defaultdict(list)
            mod.collect_codex(buckets, False, root)
            entries = [e for day in buckets.values() for e in day]
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["source"], str(p))
            self.assertEqual(entries[0]["tool"], "Codex")
            with patch.object(compressed, "zstd_backend", return_value=None):
                empty = defaultdict(list)
                mod.collect_codex(empty, False, root)
                self.assertFalse(empty)


if __name__ == "__main__":
    unittest.main()
