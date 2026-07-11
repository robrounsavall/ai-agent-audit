"""Unit tests for secrets-scan hit normalization (no scanner binary required)."""

from __future__ import annotations

import importlib.util
import os
import unittest
from pathlib import Path

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"

import bootstrap  # noqa: E402,F401

_mod_path = Path(__file__).resolve().parent.parent / "secrets-scan.py"
_spec = importlib.util.spec_from_file_location("secrets_scan_mod", _mod_path)
ss = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(ss)


class TestNormalizeHit(unittest.TestCase):
    def test_gitleaks_shape(self):
        hit = {
            "RuleID": "aws-access-token",
            "File": r"C:\Users\Test User\chat\note.md",
            "StartLine": 12,
            "Secret": "AKIA" + "C" * 16,
            "Tags": ["key"],
        }
        out = ss.normalize_hit("gitleaks", hit)
        self.assertEqual(out["rule"], "aws-access-token")
        self.assertEqual(out["line"], 12)
        self.assertIn("secret", out)
        self.assertTrue(out["secret"].startswith("AKIA"))

    def test_trufflehog_shape(self):
        hit = {
            "DetectorName": "GitHub",
            "Raw": "ghp_" + "a" * 36,
            "SourceMetadata": {
                "Data": {"Filesystem": {"file": "/tmp/x.md"}}
            },
        }
        out = ss.normalize_hit("trufflehog", hit)
        self.assertEqual(out["rule"], "GitHub")
        self.assertIn("ghp_", out["secret"])


class TestCoverageFindings(unittest.TestCase):
    """collect() flags what it could NOT scan, even when no scanner is installed."""

    def _collect_no_scanner(self, raw_root, repo_roots):
        original = ss.find_scanner
        ss.find_scanner = lambda: None
        try:
            envelope, tool_ok, hits = ss.collect(raw_root, repo_roots)
        finally:
            ss.find_scanner = original
        return envelope

    def test_missing_chat_corpus_and_repo_roots_flagged(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            envelope = self._collect_no_scanner(Path(td), [])
            ids = [f["id"] for f in envelope["findings"]]
            self.assertIn("secrets-scan.chat_corpus_not_scanned", ids)
            self.assertIn("secrets-scan.no_repo_roots", ids)
            self.assertIn("secrets-scan.tool_unavailable", ids)

    def test_present_chat_corpus_not_flagged(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            raw_root = Path(td)
            (raw_root / "chat-history").mkdir()
            envelope = self._collect_no_scanner(raw_root, [])
            ids = [f["id"] for f in envelope["findings"]]
            self.assertNotIn("secrets-scan.chat_corpus_not_scanned", ids)


if __name__ == "__main__":
    unittest.main()
