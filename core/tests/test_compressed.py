"""
Contract for core/compressed.py: .jsonl and .jsonl.zst read identically,
twins are deduplicated (plain wins), no-backend raises ZstdUnavailable, and
secrets-scan staging maps paths back and never leaves copies behind.

Real-decompression tests need stdlib compression.zstd (Python 3.14+) or an
already-installed zstandard; they skip otherwise.

Run:
    scripts/test-component.ps1 -Name core
"""
from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import bootstrap  # noqa: F401
import compressed

HAS_ZSTD = compressed.zstd_backend() is not None
DATA = b'{"a":1}\n\ninvalid\n{"b":2}\n'


class BackendDiscovery(unittest.TestCase):
    def test_stdlib_backend_present_on_314(self):
        if sys.version_info >= (3, 14):
            self.assertEqual(compressed.zstd_backend(), "compression.zstd")

    def test_is_compressed(self):
        self.assertTrue(compressed.is_compressed(Path("a.jsonl.zst")))
        self.assertTrue(compressed.is_compressed("A.JSONL.ZST"))
        self.assertFalse(compressed.is_compressed(Path("a.jsonl")))


class FileDiscovery(unittest.TestCase):
    def test_dedupe_mixed_and_ordering(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "2025/09/01").mkdir(parents=True)
            plain = root / "2025/09/01/a.jsonl"
            plain.write_bytes(DATA)
            (root / "2025/09/01/a.jsonl.zst").write_bytes(b"twin")
            other = root / "2025/09/01/b.jsonl.zst"
            other.write_bytes(b"x")
            (root / "c.jsonl.bak").write_bytes(b"x")
            (root / "dir.jsonl").mkdir()
            self.assertEqual(compressed.jsonl_files(root), [plain, other])

    def test_missing_root(self):
        self.assertEqual(compressed.jsonl_files(Path(tempfile.gettempdir()) / "aiscan-no-such-dir"), [])

    def test_plain_iter_matches_common(self):
        with tempfile.TemporaryDirectory() as tmp:
            plain = Path(tmp) / "a.jsonl"
            plain.write_bytes(DATA)
            self.assertEqual(list(compressed.iter_jsonl(plain)), [(1, {"a": 1}), (4, {"b": 2})])

    def test_no_backend_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            packed = Path(tmp) / "b.jsonl.zst"
            packed.write_bytes(b"x")
            with patch.object(compressed, "zstd_backend", return_value=None):
                with self.assertRaises(compressed.ZstdUnavailable):
                    list(compressed.iter_jsonl(packed))
                with self.assertRaises(compressed.ZstdUnavailable):
                    compressed.read_text(packed)
                staged, mapping, unreadable = compressed.stage_compressed([Path(tmp)], Path(tmp) / "stage")
            self.assertEqual((staged, mapping, unreadable), ([], {}, 1))

    def test_map_back_passthrough(self):
        self.assertEqual(compressed.map_back("", {"x": "y"}), "")
        self.assertEqual(compressed.map_back("some/file.md", {}), "some/file.md")


@unittest.skipUnless(HAS_ZSTD, "zstd backend unavailable (Python < 3.14)")
class Decompression(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.source = self.root / "source"
        self.source.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def test_plain_and_compressed_identical(self):
        plain = self.source / "a.jsonl"
        plain.write_bytes(DATA)
        packed = self.source / "b.jsonl.zst"
        packed.write_bytes(compressed.compress(DATA))
        self.assertEqual(list(compressed.iter_jsonl(plain)), list(compressed.iter_jsonl(packed)))
        self.assertEqual(compressed.read_text(packed), DATA.decode())
        with compressed.open_text(packed) as stream:
            self.assertEqual(stream.read(), DATA.decode())

    def test_multi_frame(self):
        packed = self.source / "b.jsonl.zst"
        packed.write_bytes(compressed.compress(DATA[:8]) + compressed.compress(DATA[8:]))
        self.assertEqual(compressed.read_text(packed), DATA.decode())

    def test_limits(self):
        packed = self.source / "b.jsonl.zst"
        packed.write_bytes(compressed.compress(DATA))
        with self.assertRaises(compressed.TooLarge):
            compressed.read_text(packed, max_bytes=2)
        self.assertEqual(compressed.read_text(packed, max_bytes=len(DATA)), DATA.decode())
        with patch.object(compressed, "MAX_DECOMPRESSED_BYTES", 4):
            self.assertEqual(list(compressed.iter_jsonl(packed)), [])
            with self.assertRaises(compressed.TooLarge):
                compressed.read_text(packed)

    def test_corrupt_does_not_raise(self):
        packed = self.source / "b.jsonl.zst"
        packed.write_bytes(b"definitely not zstd")
        self.assertEqual(list(compressed.iter_jsonl(packed)), [])
        with self.assertRaises(OSError):
            compressed.read_text(packed)
        packed.write_bytes(compressed.compress(DATA * 50)[:-4])
        list(compressed.iter_jsonl(packed))  # truncated: partial or nothing, never raises

    def test_staging_round_trip_and_exclusions(self):
        (self.source / "deep/er").mkdir(parents=True)
        packed = self.source / "deep/er/rollout-synthetic.jsonl.zst"
        packed.write_bytes(compressed.compress(DATA))
        twin_plain = self.source / "t.jsonl"
        twin_plain.write_bytes(DATA)
        (self.source / "t.jsonl.zst").write_bytes(compressed.compress(b"other"))
        bad = self.source / "bad.jsonl.zst"
        bad.write_bytes(b"corrupt")
        stage = self.source / "stage-inside-target"
        staged, mapping, unreadable = compressed.stage_compressed([self.source], stage)
        self.assertEqual(unreadable, 1)  # the corrupt file
        self.assertEqual(len(mapping), 1)  # twin skipped, corrupt counted
        self.assertEqual(len(staged), 1)
        dest = next(staged[0].rglob("*.jsonl"))
        self.assertEqual(dest.read_bytes(), DATA)
        self.assertEqual(compressed.map_back(str(dest), mapping), str(packed))
        self.assertEqual(
            compressed.map_back(dest.name, mapping, target=dest.parent), str(packed)
        )
        # Re-staging ignores the staging tree itself and starts fresh.
        staged2, mapping2, _ = compressed.stage_compressed([self.source], stage)
        self.assertEqual(len(mapping2), 1)
        self.assertFalse(bad.with_suffix("").exists(), "never writes next to originals")
        shutil.rmtree(stage)


if __name__ == "__main__":
    unittest.main()
