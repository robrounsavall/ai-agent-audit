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

spec = importlib.util.spec_from_file_location("pii_scan_zst", Path(__file__).resolve().parent.parent / "pii-scan.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class PiiCompressedTests(unittest.TestCase):
    def test_no_backend_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            (source / "a.jsonl.zst").touch()
            (source / "ignore.bin.zst").touch()
            with patch.object(compressed, "zstd_backend", return_value=None):
                env, hits = mod.collect([source], ["EMAIL_ADDRESS"], root / "out")
            self.assertEqual(env["summary"]["compressed_files_unreadable"], 1)
            self.assertIn("pii-scan.compressed_files_unreadable", [f["id"] for f in env["findings"]])

    @unittest.skipUnless(compressed.zstd_backend(), "zstd backend unavailable")
    def test_hits_and_decompressed_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "a.jsonl.zst"
            p.write_bytes(compressed.compress(b'synthetic@example.test'))
            hits, _ = mod.scan_file(p, ["EMAIL_ADDRESS"])
            self.assertEqual(hits[0]["file"], str(p))
            with patch.object(mod, "MAX_FILE_BYTES", 2):
                self.assertIsNone(mod.read_text(p))


class PiiTwinDedupe(unittest.TestCase):
    def test_plain_twin_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.jsonl").write_text("synthetic@example.test\n", encoding="utf-8")
            (root / "a.jsonl.zst").write_bytes(b"twin")
            (root / "b.jsonl.zst").write_bytes(b"only compressed")
            names = sorted(p.name for p in mod.iter_text_files(root))
            self.assertEqual(names, ["a.jsonl", "b.jsonl.zst"])


if __name__ == "__main__":
    unittest.main()
