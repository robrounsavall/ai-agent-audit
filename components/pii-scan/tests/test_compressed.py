"""PII scan reads .jsonl.zst transcripts when stdlib zstd is available."""
from __future__ import annotations

import importlib.util
import json
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
            finding = next(f for f in env["findings"] if f["id"] == "pii_scan.compressed_files_unreadable")
            self.assertEqual(finding["severity"], "low")
            self.assertIn("were not scanned for PII", finding["title"])
            self.assertFalse(any(f["id"].startswith("pii-scan.") for f in env["findings"]))
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
            finding = next(f for f in env["findings"] if f["id"] == "pii_scan.compressed_files_unreadable")
            self.assertEqual(finding["severity"], "low")
            self.assertIn("could not be read", finding["title"])
            self.assertNotIn("not scanned (too large)", finding["title"])

            packed = source / "big.jsonl.zst"
            packed.write_bytes(compressed.compress(b"synthetic@example.test\n"))
            (source / "bad.jsonl.zst").unlink()
            with mock.patch.object(pii, "MAX_FILE_BYTES", 2):
                env, hits = pii.collect([source], ["EMAIL_ADDRESS"], root / "out", write_raw=False)
            self.assertEqual(hits, [])
            self.assertEqual(env["summary"]["compressed_files_unreadable"], 0)
            self.assertEqual(env["summary"]["files_too_large"], 1)
            too_large = next(f for f in env["findings"] if f["id"] == "pii_scan.files_too_large")
            self.assertEqual(too_large["evidence_count"], 1)
            self.assertIn("not scanned (too large)", too_large["title"])
            self.assertIn("coverage_gap", too_large["tags"])
            self.assertNotIn("could not be read", too_large["title"])


class PiiSizeCapTests(unittest.TestCase):
    def test_plain_and_compressed_oversize_share_one_count_without_zstd(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            (source / "big.txt").write_text("plain@example.test\n" + ("x" * 40), encoding="utf-8")
            (source / "big.jsonl.zst").write_bytes(b"not-opened")
            (source / "ok.txt").write_text("kept@example.test\n", encoding="utf-8")
            real = pii.scan_file

            def scan(path, entities):
                if str(path).endswith(".zst"):
                    raise compressed.TooLarge("over the shared cap")
                return real(path, entities)

            with (
                mock.patch.object(pii.compressed, "zstd_backend", return_value="compression.zstd"),
                mock.patch.object(pii, "scan_file", side_effect=scan),
                mock.patch.object(pii, "MAX_FILE_BYTES", 30),
            ):
                env, hits = pii.collect([source], ["EMAIL_ADDRESS"], root / "out", write_raw=False)
        self.assertEqual(len(hits), 1)
        self.assertIn("kept@example.test", hits[0]["sample"])
        self.assertEqual(env["summary"]["files_too_large"], 2)
        self.assertEqual(env["summary"]["files_scanned"], 1)
        self.assertEqual(env["summary"]["compressed_files_unreadable"], 0)
        finding = next(f for f in env["findings"] if f["id"] == "pii_scan.files_too_large")
        self.assertEqual(finding["evidence_count"], 2)
        self.assertEqual(finding["title"], "2 file(s) not scanned (too large)")
        blob = json.dumps(env)
        self.assertNotIn("plain@example.test", blob)

    def test_compressed_timeout_stays_unreadable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            (source / "slow.jsonl.zst").write_bytes(b"not-opened")

            def scan(path, entities):
                raise compressed.DecompressTimeout("time budget")

            with (
                mock.patch.object(pii.compressed, "zstd_backend", return_value="compression.zstd"),
                mock.patch.object(pii, "scan_file", side_effect=scan),
            ):
                env, hits = pii.collect([source], ["EMAIL_ADDRESS"], root / "out", write_raw=False)
        self.assertEqual(hits, [])
        self.assertEqual(env["summary"]["files_too_large"], 0)
        self.assertEqual(env["summary"]["compressed_files_unreadable"], 1)
        finding = next(f for f in env["findings"] if f["id"] == "pii_scan.compressed_files_unreadable")
        self.assertIn("could not be read", finding["title"])

    def test_cap_matches_the_shared_limit(self):
        self.assertEqual(pii.MAX_FILE_BYTES, compressed.MAX_DECOMPRESSED_BYTES)
        self.assertEqual(pii.MAX_FILE_BYTES, 64 * 1024 * 1024)
        self.assertEqual(compressed.MAX_DECOMPRESS_SECONDS, 30)

    def test_plain_oversize_is_noted_and_under_the_cap_is_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            small = source / "small.txt"
            small.write_text("synthetic@example.test\n", encoding="utf-8")
            big = source / "big.txt"
            big.write_text("hidden@example.test\n" + ("x" * 80), encoding="utf-8")
            with mock.patch.object(pii, "MAX_FILE_BYTES", 40):
                env, hits = pii.collect([source], ["EMAIL_ADDRESS"], root / "out", write_raw=False)
        self.assertEqual([hit["file"] for hit in hits], [str(small)])
        self.assertEqual(env["summary"]["files_scanned"], 1)
        self.assertEqual(env["summary"]["files_too_large"], 1)
        finding = next(f for f in env["findings"] if f["id"] == "pii_scan.files_too_large")
        self.assertEqual(finding["severity"], "low")
        self.assertEqual(finding["evidence_count"], 1)
        self.assertEqual(finding["title"], "1 file(s) not scanned (too large)")
        self.assertNotIn("hidden@example.test", json.dumps(env))
        self.assertFalse(any(f["id"].startswith("pii-scan.") for f in env["findings"]))

    @unittest.skipUnless(HAS_ZSTD, "compression.zstd is not available")
    def test_plain_and_compressed_oversize_share_one_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            (source / "big.txt").write_text("plain@example.test\n" + ("x" * 40), encoding="utf-8")
            packed = source / "big.jsonl.zst"
            packed.write_bytes(compressed.compress(b"packed@example.test\n" + b"x" * 40))
            (source / "ok.txt").write_text("kept@example.test\n", encoding="utf-8")
            with mock.patch.object(pii, "MAX_FILE_BYTES", 30):
                env, hits = pii.collect([source], ["EMAIL_ADDRESS"], root / "out", write_raw=False)
        self.assertEqual([hit["entity"] for hit in hits], ["EMAIL_ADDRESS"])
        self.assertIn("kept@example.test", hits[0]["sample"])
        self.assertEqual(env["summary"]["files_too_large"], 2)
        self.assertEqual(env["summary"]["files_scanned"], 1)
        self.assertEqual(env["summary"]["compressed_files_unreadable"], 0)
        finding = next(f for f in env["findings"] if f["id"] == "pii_scan.files_too_large")
        self.assertEqual(finding["evidence_count"], 2)
        self.assertEqual(finding["title"], "2 file(s) not scanned (too large)")
        blob = json.dumps(env)
        self.assertNotIn("plain@example.test", blob)
        self.assertNotIn("packed@example.test", blob)


if __name__ == "__main__":
    unittest.main()
