"""Secrets scan stages .jsonl.zst transcripts when stdlib zstd is available."""
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
    "secrets_scan_zst", Path(__file__).resolve().parent.parent / "secrets-scan.py"
)
ss = importlib.util.module_from_spec(_spec)
assert _spec is not None and _spec.loader is not None
_spec.loader.exec_module(ss)

HAS_ZSTD = compressed.zstd_backend() is not None


def _gitleaks(target, _binary):
    hits = [
        {"RuleID": "synthetic", "File": str(path), "Secret": "placeholder"}
        for path in Path(target).rglob("*.jsonl")
    ]
    return hits, None


class StagingTests(unittest.TestCase):
    def test_no_backend_counts_and_does_not_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sessions"
            source.mkdir()
            (source / "a.jsonl.zst").write_bytes(b"not-opened")
            opened: list[str] = []
            real_open = Path.open

            def spy(self, *args, **kwargs):
                opened.append(str(self))
                return real_open(self, *args, **kwargs)

            with (
                mock.patch.object(compressed, "zstd_backend", return_value=None),
                mock.patch.object(ss, "find_scanner", return_value=("gitleaks", "fake")),
                mock.patch.object(ss, "run_gitleaks", return_value=([], None)),
                mock.patch.object(Path, "open", spy),
            ):
                env, ok, hits = ss.collect(root / "raw", [], None, native_roots=[source])
            self.assertTrue(ok)
            self.assertEqual(hits, [])
            self.assertEqual(env["summary"]["compressed_files_unreadable"], 1)
            self.assertEqual(env["summary"]["compressed_files_staged"], 0)
            finding = next(f for f in env["findings"] if f["id"] == "secrets-scan.compressed_files_unreadable")
            self.assertEqual(finding["severity"], "low")
            self.assertEqual(finding["evidence_count"], 1)
            self.assertIn("were not scanned for secrets", finding["title"])
            self.assertFalse(any(name.endswith(".jsonl.zst") for name in opened))

    def test_repo_roots_are_not_walked_for_zst(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            (repo / "data.jsonl.zst").write_bytes(b"x")
            with (
                mock.patch.object(compressed, "zstd_backend", return_value=None),
                mock.patch.object(ss, "find_scanner", return_value=("gitleaks", "fake")),
                mock.patch.object(ss, "run_gitleaks", return_value=([], None)),
            ):
                env, _ok, _hits = ss.collect(root / "raw", [repo], None)
            self.assertEqual(env["summary"]["compressed_files_unreadable"], 0)

    def test_resolved_alias_of_a_repo_root_is_not_walked_for_zst(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real-repo"
            real.mkdir()
            (real / "data.jsonl.zst").write_bytes(b"x")
            link = root / "link-repo"
            try:
                link.symlink_to(real, target_is_directory=True)
            except OSError:
                self.skipTest("symlinks are not available")
            with (
                mock.patch.object(compressed, "zstd_backend", return_value=None),
                mock.patch.object(ss, "find_scanner", return_value=("gitleaks", "fake")),
                mock.patch.object(ss, "run_gitleaks", return_value=([], None)),
            ):
                env, _ok, _hits = ss.collect(root / "raw", [link], None)
            self.assertEqual(env["summary"]["compressed_files_unreadable"], 0)

    @unittest.skipUnless(HAS_ZSTD, "compression.zstd is not available")
    def test_staged_hit_maps_back_and_temp_is_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sessions"
            source.mkdir()
            original = source / "a.jsonl.zst"
            original.write_bytes(compressed.compress(b"synthetic\n"))
            stage = root / "stage"
            with (
                mock.patch.object(ss.tempfile, "mkdtemp", return_value=str(stage)),
                mock.patch.object(ss, "find_scanner", return_value=("gitleaks", "fake")),
                mock.patch.object(ss, "run_gitleaks", side_effect=_gitleaks),
            ):
                env, ok, hits = ss.collect(root / "raw", [], None, native_roots=[source])
            self.assertTrue(ok)
            self.assertEqual(
                [Path(hit["file"]).resolve() for hit in hits],
                [original.resolve()],
            )
            self.assertEqual(env["summary"]["compressed_files_staged"], 1)
            self.assertFalse(stage.exists())

    @unittest.skipUnless(HAS_ZSTD, "compression.zstd is not available")
    def test_corrupt_is_a_coverage_note(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sessions"
            source.mkdir()
            (source / "a.jsonl.zst").write_bytes(b"corrupt")
            with (
                mock.patch.object(ss, "find_scanner", return_value=("gitleaks", "fake")),
                mock.patch.object(ss, "run_gitleaks", return_value=([], None)),
            ):
                env, _ok, hits = ss.collect(root / "raw", [], None, native_roots=[source])
            self.assertEqual(hits, [])
            finding = next(f for f in env["findings"] if f["id"] == "secrets-scan.compressed_files_unreadable")
            self.assertEqual(finding["severity"], "low")
            self.assertIn("could not be read", finding["title"])

    @unittest.skipUnless(HAS_ZSTD, "compression.zstd is not available")
    def test_copy_inside_a_scanned_tree_is_not_counted_twice(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sessions"
            source.mkdir()
            original = source / "a.jsonl.zst"
            original.write_bytes(compressed.compress(b"synthetic\n"))
            stage = root / "nested-stage"
            with (
                mock.patch.object(ss.tempfile, "mkdtemp", return_value=str(stage)),
                mock.patch.object(ss, "find_scanner", return_value=("gitleaks", "fake")),
                mock.patch.object(ss, "run_gitleaks", side_effect=_gitleaks),
            ):
                _env, ok, hits = ss.collect(root / "raw", [root], None, native_roots=[source])
            self.assertTrue(ok)
            self.assertEqual(
                [Path(hit["file"]).resolve() for hit in hits],
                [original.resolve()],
            )
            self.assertFalse(stage.exists())


if __name__ == "__main__":
    unittest.main()
