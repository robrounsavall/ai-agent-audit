"""PII scan reads .jsonl.zst transcripts when stdlib zstd is available."""
from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"
import bootstrap  # noqa: E402,F401
import compressed  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "pii_scan_zst", Path(__file__).resolve().parent.parent / "pii-scan.py"
)
pii = importlib.util.module_from_spec(_spec)
assert _spec is not None and _spec.loader is not None
_spec.loader.exec_module(pii)

HAS_ZSTD = compressed.zstd_backend() is not None


class PiiCompressedTests(unittest.TestCase):
    def test_no_backend_counts_and_does_not_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            (source / "a.jsonl.zst").write_bytes(b"not-opened")
            (source / "ignore.bin.zst").write_bytes(b"nope")
            opened: list[str] = []
            real_open = Path.open

            def spy(self, *args, **kwargs):
                opened.append(str(self))
                return real_open(self, *args, **kwargs)

            with (
                mock.patch.object(compressed, "zstd_backend", return_value=None),
                mock.patch.object(Path, "open", spy),
            ):
                env, hits = pii.collect([source], ["EMAIL_ADDRESS"], root / "out", write_raw=False)
            self.assertEqual(hits, [])
            self.assertEqual(env["summary"]["compressed_files_unreadable"], 1)
            finding = next(f for f in env["findings"] if f["id"] == "pii-scan.compressed_files_unreadable")
            self.assertEqual(finding["severity"], "low")
            self.assertIn("were not scanned for PII", finding["title"])
            self.assertFalse(any(name.endswith(".jsonl.zst") for name in opened))

    def test_plain_twin_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.jsonl").write_text("synthetic@example.test\n", encoding="utf-8")
            (root / "a.jsonl.zst").write_bytes(b"twin")
            (root / "b.jsonl.zst").write_bytes(b"only compressed")
            names = sorted(path.name for path in pii.iter_text_files(root))
            self.assertEqual(names, ["a.jsonl", "b.jsonl.zst"])

    @unittest.skipUnless(HAS_ZSTD, "compression.zstd is not available")
    def test_compressed_email_is_a_hit(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.jsonl.zst"
            path.write_bytes(compressed.compress(b"synthetic@example.test\n"))
            hits, _private = pii.scan_file(path, ["EMAIL_ADDRESS"])
            self.assertEqual(hits[0]["file"], str(path))
            self.assertEqual(hits[0]["entity"], "EMAIL_ADDRESS")

    @unittest.skipUnless(HAS_ZSTD, "compression.zstd is not available")
    def test_corrupt_and_oversize_are_notes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            (source / "bad.jsonl.zst").write_bytes(b"corrupt")
            env, hits = pii.collect([source], ["EMAIL_ADDRESS"], root / "out", write_raw=False)
            self.assertEqual(hits, [])
            self.assertEqual(env["summary"]["compressed_files_unreadable"], 1)
            finding = next(f for f in env["findings"] if f["id"] == "pii-scan.compressed_files_unreadable")
            self.assertEqual(finding["severity"], "low")
            self.assertIn("could not be read", finding["title"])

            packed = source / "big.jsonl.zst"
            packed.write_bytes(compressed.compress(b"synthetic@example.test\n"))
            (source / "bad.jsonl.zst").unlink()
            with mock.patch.object(pii, "MAX_FILE_BYTES", 2):
                env, hits = pii.collect([source], ["EMAIL_ADDRESS"], root / "out", write_raw=False)
            self.assertEqual(hits, [])
            self.assertEqual(env["summary"]["compressed_files_unreadable"], 1)


if __name__ == "__main__":
    unittest.main()
