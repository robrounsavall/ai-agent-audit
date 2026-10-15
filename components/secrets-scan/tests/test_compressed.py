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

spec = importlib.util.spec_from_file_location("secrets_scan_zst", Path(__file__).resolve().parent.parent / "secrets-scan.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class StagingTests(unittest.TestCase):
    @unittest.skipUnless(compressed.zstd_backend(), "zstd backend unavailable")
    def test_scanner_mapping_and_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            p = source / "a.jsonl.zst"
            p.write_bytes(compressed.compress(b'synthetic'))
            def scanner(target, binary):
                return [{"RuleID": "synthetic", "File": str(f), "Secret": "placeholder"} for f in target.rglob("*.jsonl")]
            with patch.object(mod, "find_scanner", return_value=("gitleaks", "fake")), patch.object(mod, "run_gitleaks", side_effect=scanner):
                env, ok, hits = mod.collect(root / "raw", [], native_roots=[source])
            self.assertTrue(ok)
            self.assertEqual(hits[0]["file"], str(p))
            stage = root / "raw/tmp/secrets-scan-zst"
            self.assertFalse(stage.exists())
            with patch.object(mod, "find_scanner", return_value=("gitleaks", "fake")), patch.object(mod, "run_gitleaks", side_effect=RuntimeError("synthetic failure")):
                with self.assertRaises(RuntimeError):
                    mod.collect(root / "raw", [], native_roots=[source])
            self.assertFalse(stage.exists())

    def test_no_backend(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.jsonl.zst").touch()
            with patch.object(compressed, "zstd_backend", return_value=None), patch.object(mod, "find_scanner", return_value=("gitleaks", "fake")), patch.object(mod, "run_gitleaks", return_value=[]):
                env, _, _ = mod.collect(root / "raw", [], native_roots=[root])
            self.assertEqual(env["summary"]["compressed_files_unreadable"], 1)
            finding = next(f for f in env["findings"] if f["id"] == "secrets-scan.compressed_files_unreadable")
            self.assertEqual((finding["severity"], finding["evidence_count"]), ("medium", 1))
            self.assertFalse((root / "raw/tmp/secrets-scan-zst").exists())

    def test_repo_roots_are_not_walked_for_zst(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            (repo / "data.jsonl.zst").write_bytes(b"x")
            with patch.object(compressed, "zstd_backend", return_value=None), patch.object(mod, "find_scanner", return_value=("gitleaks", "fake")), patch.object(mod, "run_gitleaks", return_value=[]):
                env, _, _ = mod.collect(root / "raw", [repo])
            self.assertEqual(env["summary"]["compressed_files_unreadable"], 0)


@unittest.skipUnless(compressed.zstd_backend(), "zstd backend unavailable")
class StagingInsideTarget(unittest.TestCase):
    def test_enclosing_target_relative_paths_do_not_double_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sessions"
            source.mkdir()
            original = source / "a.jsonl.zst"
            original.write_bytes(compressed.compress(b"synthetic"))
            def scanner(target, binary, major):
                return [{"rule_id": "synthetic", "location": {"path": str(f.relative_to(target))}, "match": {"value": "placeholder"}} for f in target.rglob("*.jsonl")], None
            with patch.object(mod, "find_scanner", return_value=("betterleaks-v2", "fake")), patch.object(mod, "run_betterleaks", side_effect=scanner):
                env, ok, hits = mod.collect(root / "raw", [root], native_roots=[source])
            self.assertTrue(ok)
            self.assertEqual([h["file"] for h in hits], [str(original)])

    def test_scanner_error_denominator_includes_staged_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sessions"
            source.mkdir()
            (source / "a.jsonl.zst").write_bytes(compressed.compress(b"synthetic"))
            with patch.object(mod, "find_scanner", return_value=("betterleaks-v2", "fake")), patch.object(mod, "run_betterleaks", return_value=([], "synthetic failure")) as scanner:
                env, _, hits = mod.collect(root / "raw", [], native_roots=[source])
            self.assertEqual(scanner.call_count, 2)
            self.assertEqual(hits, [])
            finding = next(f for f in env["findings"] if f["id"] == "secrets-scan.scanner_error")
            self.assertIn("2 of 2 scan targets", finding["title"])

    def test_enclosing_target_does_not_double_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sessions"
            source.mkdir()
            (source / "a.jsonl.zst").write_bytes(compressed.compress(b"synthetic"))
            def scanner(target, binary):
                return [{"RuleID": "synthetic", "File": str(f), "Secret": "placeholder"} for f in target.rglob("*.jsonl")]
            # The repo root encloses raw/, so the staged copy is visible through it too.
            with patch.object(mod, "find_scanner", return_value=("gitleaks", "fake")), patch.object(mod, "run_gitleaks", side_effect=scanner):
                env, ok, hits = mod.collect(root / "raw", [root], native_roots=[source])
            self.assertEqual([h["file"] for h in hits], [str(source / "a.jsonl.zst")])


if __name__ == "__main__":
    unittest.main()
