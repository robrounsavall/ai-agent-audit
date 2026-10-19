"""Unit tests for secrets-scan hit normalization (no scanner binary required)."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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


class TestScannerFailures(unittest.TestCase):
    def test_gitleaks_leak_exit_with_json_is_not_a_failure(self):
        report = json.dumps([
            {"RuleID": "generic-api-key", "File": "note.txt", "StartLine": 1, "Secret": "x" * 12}
        ])
        with mock.patch.object(
            ss.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], ss._GITLEAKS_LEAK_EXIT, report, ""),
        ) as run:
            hits, error = ss.run_gitleaks(Path("target"), "gitleaks")
        self.assertIsNone(error)
        self.assertEqual(len(hits), 1)
        self.assertIn("--exit-code", run.call_args.args[0])
        self.assertIn("2", run.call_args.args[0])

    def test_gitleaks_error_exit_is_not_zero_hits(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "chat-history").mkdir()
            with mock.patch.object(ss, "find_scanner", return_value=("gitleaks", "gitleaks")), mock.patch.object(
                ss.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "failed")
            ):
                envelope, ok, hits = ss.collect(root, [])
        self.assertTrue(ok)
        self.assertEqual(hits, [])
        self.assertEqual(envelope["summary"]["hits"], 0)
        errors = [f for f in envelope["findings"] if f["id"] == "secrets-scan.scanner_error"]
        self.assertEqual(len(errors), 1)
        self.assertIn("gitleaks", errors[0]["title"])
        self.assertNotIn("failed", errors[0]["title"])

    def test_gitleaks_timeout_is_an_error(self):
        with mock.patch.object(
            ss.subprocess, "run", side_effect=subprocess.TimeoutExpired("gitleaks", 600)
        ):
            hits, error = ss.run_gitleaks(Path("target"), "gitleaks")
        self.assertEqual(hits, [])
        self.assertEqual(error, "TimeoutExpired")

    def test_dry_run_writes_no_raw_or_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evidence = root / "out"
            evidence.mkdir()
            corpus = root / "code"
            corpus.mkdir()
            argv = [
                "secrets-scan.py",
                "--evidence-root", str(evidence),
                "--repo-roots", str(corpus),
                "--dry-run",
            ]
            with mock.patch.object(ss, "find_scanner", return_value=("gitleaks", "gitleaks")), mock.patch.object(
                ss, "run_gitleaks", return_value=([], None)
            ), mock.patch.object(sys, "argv", argv), mock.patch("sys.stdout", io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    ss.main()
        self.assertEqual(raised.exception.code, 0)
        self.assertFalse((evidence / "raw" / "secrets-scan" / "findings.csv").exists())
        self.assertFalse((evidence / "evidence" / "secrets-scan.json").exists())


class TestTrufflehogCommand(unittest.TestCase):
    def test_disables_live_verification(self):
        payload = json.dumps({"DetectorName": "GitHub", "Raw": "example"})
        with mock.patch.object(
            ss.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, payload + "\n", ""),
        ) as run:
            hits, error = ss.run_trufflehog(Path("target"), "trufflehog")
        self.assertIsNone(error)
        self.assertEqual(len(hits), 1)
        cmd = run.call_args.args[0]
        self.assertEqual(cmd[0], "trufflehog")
        self.assertEqual(cmd[1], "filesystem")
        self.assertEqual(cmd[-3:], ["--json", "--no-verification", "--no-update"])

    def test_timeout_is_an_error_not_zero_hits(self):
        with mock.patch.object(
            ss.subprocess, "run", side_effect=subprocess.TimeoutExpired("trufflehog", 600)
        ):
            hits, error = ss.run_trufflehog(Path("target"), "trufflehog")
        self.assertEqual(hits, [])
        self.assertEqual(error, "TimeoutExpired")

    def test_nonzero_exit_is_an_error(self):
        with mock.patch.object(
            ss.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "boom")
        ):
            hits, error = ss.run_trufflehog(Path("target"), "trufflehog")
        self.assertEqual(hits, [])
        self.assertIn("exit code 1", error)
        self.assertNotIn("boom", error)


if __name__ == "__main__":
    unittest.main()
