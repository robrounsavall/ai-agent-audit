"""Stdlib zstd reader: feature detection, limits, and .jsonl.zst listing.

Real decompression needs compression.zstd (Python 3.14+). Those tests skip
when the module cannot be imported.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import bootstrap  # noqa: F401
import compressed

DATA = b'{"a":1}\n\ninvalid\n{"b":2}\n'
HAS_ZSTD = compressed.zstd_backend() is not None


class BackendDiscovery(unittest.TestCase):
    def test_detection_uses_version_info_not_a_version_string(self):
        with (
            mock.patch.object(compressed.sys, "version", "not-a-version-string"),
            mock.patch.object(compressed.sys, "version_info", (3, 13, 0)),
            mock.patch.object(compressed.importlib, "import_module") as importer,
        ):
            self.assertIsNone(compressed.zstd_backend())
            importer.assert_not_called()

    def test_version_tuple_without_the_module_is_not_enough(self):
        with (
            mock.patch.object(compressed.sys, "version_info", (3, 14, 0)),
            mock.patch.object(compressed.importlib, "import_module", side_effect=ImportError),
        ):
            self.assertIsNone(compressed.zstd_backend())

    @unittest.skipUnless(HAS_ZSTD, "compression.zstd is not available")
    def test_stdlib_backend_name(self):
        self.assertEqual(compressed.zstd_backend(), "compression.zstd")
        self.assertGreaterEqual(sys.version_info, (3, 14))

    def test_is_compressed(self):
        self.assertTrue(compressed.is_compressed(Path("a.jsonl.zst")))
        self.assertTrue(compressed.is_compressed("A.JSONL.ZST"))
        self.assertFalse(compressed.is_compressed(Path("a.jsonl")))


class FileDiscovery(unittest.TestCase):
    def test_plain_twin_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "2025/09/01").mkdir(parents=True)
            plain = root / "2025/09/01/a.jsonl"
            plain.write_bytes(DATA)
            (root / "2025/09/01/a.jsonl.zst").write_bytes(b"twin")
            other = root / "2025/09/01/b.jsonl.zst"
            other.write_bytes(b"x")
            (root / "c.jsonl.bak").write_bytes(b"x")
            (root / "notes.zst").write_bytes(b"x")
            (root / "dir.jsonl").mkdir()
            self.assertEqual(compressed.jsonl_files(root), [plain, other])

    def test_missing_root(self):
        missing = Path(tempfile.gettempdir()) / "aiscan-no-such-dir"
        self.assertEqual(compressed.jsonl_files(missing), [])

    def test_plain_iter_matches_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            plain = Path(tmp) / "a.jsonl"
            plain.write_bytes(DATA)
            self.assertEqual(list(compressed.iter_jsonl(plain)), [(1, {"a": 1}), (4, {"b": 2})])

    def test_no_backend_raises_before_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            packed = Path(tmp) / "b.jsonl.zst"
            packed.write_bytes(b"x")
            opened: list[str] = []
            real_open = Path.open

            def spy(self, *args, **kwargs):
                opened.append(str(self))
                return real_open(self, *args, **kwargs)

            with (
                mock.patch.object(compressed, "zstd_backend", return_value=None),
                mock.patch.object(Path, "open", spy),
            ):
                with self.assertRaises(compressed.ZstdUnavailable):
                    list(compressed.iter_jsonl(packed))
                with self.assertRaises(compressed.ZstdUnavailable):
                    compressed.read_text(packed)
                staged, mapping, unreadable = compressed.stage_compressed([Path(tmp)], Path(tmp) / "stage")
            self.assertEqual((staged, mapping, unreadable), ([], {}, 1))
            self.assertFalse(any(name.endswith(".jsonl.zst") for name in opened))

    def test_map_back_passthrough(self):
        self.assertEqual(compressed.map_back("", {"x": "y"}), "")
        self.assertEqual(compressed.map_back("some/file.md", {}), "some/file.md")


@unittest.skipUnless(HAS_ZSTD, "compression.zstd is not available")
class Decompression(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_plain_and_compressed_match(self):
        plain = self.root / "a.jsonl"
        plain.write_bytes(DATA)
        packed = self.root / "b.jsonl.zst"
        packed.write_bytes(compressed.compress(DATA))
        self.assertEqual(list(compressed.iter_jsonl(plain)), list(compressed.iter_jsonl(packed)))
        self.assertEqual(compressed.read_text(packed), DATA.decode())

    def test_multi_frame(self):
        packed = self.root / "b.jsonl.zst"
        packed.write_bytes(compressed.compress(DATA[:8]) + compressed.compress(DATA[8:]))
        self.assertEqual(compressed.read_text(packed), DATA.decode())

    def test_size_cap(self):
        packed = self.root / "b.jsonl.zst"
        packed.write_bytes(compressed.compress(b"abcdefghij"))
        with self.assertRaises(compressed.TooLarge):
            compressed.read_text(packed, max_bytes=4)
        with mock.patch.object(compressed, "MAX_DECOMPRESSED_BYTES", 4):
            with self.assertRaises(compressed.TooLarge):
                list(compressed.iter_jsonl(packed))

    def test_time_budget(self):
        packed = self.root / "b.jsonl.zst"
        packed.write_bytes(compressed.compress(DATA))
        with mock.patch.object(compressed, "MAX_DECOMPRESS_SECONDS", -1):
            with self.assertRaises(compressed.DecompressTimeout):
                compressed.read_text(packed)

    def test_corrupt_raises(self):
        packed = self.root / "b.jsonl.zst"
        packed.write_bytes(b"definitely not zstd")
        with self.assertRaises(OSError):
            compressed.read_text(packed)
        with self.assertRaises(OSError):
            list(compressed.iter_jsonl(packed))

    def test_staging_maps_and_counts_corrupt(self):
        (self.root / "deep").mkdir()
        packed = self.root / "deep" / "rollout-synthetic.jsonl.zst"
        packed.write_bytes(compressed.compress(DATA))
        (self.root / "t.jsonl").write_bytes(DATA)
        (self.root / "t.jsonl.zst").write_bytes(compressed.compress(b"other"))
        bad = self.root / "bad.jsonl.zst"
        bad.write_bytes(b"corrupt")
        stage = self.root / "stage"
        staged, mapping, unreadable = compressed.stage_compressed([self.root], stage)
        self.assertEqual(unreadable, 1)
        self.assertEqual(len(mapping), 1)
        self.assertEqual(len(staged), 1)
        dest = next(staged[0].rglob("*.jsonl"))
        self.assertEqual(dest.read_bytes(), DATA)
        self.assertEqual(compressed.map_back(str(dest), mapping), str(packed))
        self.assertFalse(bad.with_suffix("").exists())


if __name__ == "__main__":
    unittest.main()
