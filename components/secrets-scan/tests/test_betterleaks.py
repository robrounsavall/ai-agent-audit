"""Betterleaks support in secrets-scan: scanner choice, parsing, and the
no-validation guarantee. No scanner binary is needed except for the last
test, which runs only when BETTERLEAKS_PATH points at a real binary."""

from __future__ import annotations

import csv
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"

import bootstrap  # noqa: E402,F401

_mod_path = Path(__file__).resolve().parent.parent / "secrets-scan.py"
_spec = importlib.util.spec_from_file_location("secrets_scan_bl", _mod_path)
ss = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(ss)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
V2_REPORT = (FIXTURES / "betterleaks-v2-filesystem.json").read_text(encoding="utf-8")
V1_REPORT = (FIXTURES / "betterleaks-v1-dir.json").read_text(encoding="utf-8")

# Variables that must never reach the Betterleaks child process.
DANGEROUS_ENV = {
    "BETTERLEAKS_VALIDATE": "true",
    "BETTERLEAKS_ANALYZE": "true",
    "BETTERLEAKS_CONFIG": "evil.toml",
    "BETTERLEAKS_CONFIG_TOML": "[extend]",
    "GITLEAKS_CONFIG": "evil.toml",
    "GITLEAKS_CONFIG_TOML": "[extend]",
    "betterleaks_validate": "true",  # Windows env names are case-insensitive
}


def _proc(stdout: str = "", returncode: int = 0, stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _assert_no_provider_flags(test: unittest.TestCase, cmd: list[str]) -> None:
    for arg in cmd:
        name = arg.split("=", 1)[0]
        if name in ss.BETTERLEAKS_FORBIDDEN_FLAGS:
            # Only the explicit forced-off form is allowed.
            test.assertTrue(arg.endswith("=false"), f"provider flag enabled: {arg}")
        test.assertNotIn(name, ("--status", "--provider-env-vars", "--validation-env-vars"))
        test.assertFalse(name.startswith(("--provider-", "--validation-")), arg)
    # Short flags must not be bundled (e.g. -va).
    for arg in cmd:
        if arg.startswith("-") and not arg.startswith("--") and len(arg) > 2:
            test.fail(f"bundled short flag: {arg}")


class TestNoValidationGuarantee(unittest.TestCase):
    def test_v2_command_forces_validation_and_analysis_off(self):
        cmd = ss.betterleaks_command("betterleaks", Path("target"), 2)
        self.assertEqual(cmd[1], "filesystem")
        self.assertIn("--validate=false", cmd)
        self.assertIn("--analyze=false", cmd)
        self.assertNotIn("-v", cmd)
        self.assertNotIn("-a", cmd)
        self.assertNotIn("--validate", cmd)
        self.assertNotIn("--analyze", cmd)
        _assert_no_provider_flags(self, cmd)

    def test_v1_command_forces_validation_off(self):
        cmd = ss.betterleaks_command("betterleaks", Path("target"), 1)
        self.assertEqual(cmd[1], "dir")
        self.assertIn("--validation=false", cmd)
        self.assertNotIn("--validation", cmd)
        _assert_no_provider_flags(self, cmd)

    def test_child_env_drops_validation_and_config_vars(self):
        base = {"PATH": "/bin", "HOME": "/home/x", **DANGEROUS_ENV}
        env = ss.betterleaks_env(base)
        self.assertEqual(env.get("PATH"), "/bin")
        for key in DANGEROUS_ENV:
            self.assertNotIn(key, env)

    def test_run_betterleaks_passes_clean_env_and_safe_command(self):
        for major, report in ((2, V2_REPORT), (1, V1_REPORT)):
            with self.subTest(major=major), mock.patch.dict(os.environ, DANGEROUS_ENV), mock.patch.object(
                ss.subprocess, "run", return_value=_proc(report)
            ) as run:
                hits, error = ss.run_betterleaks(Path("target"), "betterleaks", major)
                self.assertIsNone(error)
                self.assertEqual(len(hits), 1)
                cmd = run.call_args.args[0]
                env = run.call_args.kwargs["env"]
                _assert_no_provider_flags(self, cmd)
                for key in DANGEROUS_ENV:
                    self.assertNotIn(key, env)
                    self.assertNotIn(key.upper(), env)

    def test_version_probe_also_uses_clean_env(self):
        with mock.patch.dict(os.environ, DANGEROUS_ENV), mock.patch.object(
            ss.subprocess, "run", return_value=_proc("2.0.0-rc.2\n")
        ) as run:
            self.assertEqual(ss.betterleaks_major("betterleaks"), 2)
            self.assertEqual(run.call_args.args[0], ["betterleaks", "version"])
            for key in DANGEROUS_ENV:
                self.assertNotIn(key, run.call_args.kwargs["env"])


class TestVersionAndPreference(unittest.TestCase):
    def test_major_version_parsing(self):
        cases = {"2.0.0-rc.2\n": 2, "1.9.0\n": 1, "betterleaks version v2.1.3": 2}
        for out, expected in cases.items():
            with self.subTest(out=out), mock.patch.object(ss.subprocess, "run", return_value=_proc(out)):
                self.assertEqual(ss.betterleaks_major("betterleaks"), expected)

    def test_unknown_version_is_none(self):
        with mock.patch.object(ss.subprocess, "run", return_value=_proc("weird", returncode=1)):
            self.assertIsNone(ss.betterleaks_major("betterleaks"))

    def _which(self, available):
        return lambda name: f"/bin/{name}" if name in available else None

    def test_betterleaks_preferred_over_gitleaks(self):
        env = {k: v for k, v in os.environ.items() if not k.endswith("_PATH") or k == "PATH"}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(
            ss.shutil, "which", self._which({"betterleaks", "gitleaks", "trufflehog"})
        ), mock.patch.object(ss, "betterleaks_major", return_value=2):
            self.assertEqual(ss.find_scanner(), ("betterleaks-v2", "/bin/betterleaks"))
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(
            ss.shutil, "which", self._which({"betterleaks", "gitleaks"})
        ), mock.patch.object(ss, "betterleaks_major", return_value=1):
            self.assertEqual(ss.find_scanner(), ("betterleaks-v1", "/bin/betterleaks"))

    def test_betterleaks_path_env_wins(self):
        with mock.patch.dict(os.environ, {"BETTERLEAKS_PATH": "/opt/bl/betterleaks"}), mock.patch.object(
            ss.shutil, "which", self._which({"gitleaks"})
        ), mock.patch.object(ss, "betterleaks_major", return_value=2):
            self.assertEqual(ss.find_scanner(), ("betterleaks-v2", "/opt/bl/betterleaks"))

    def test_unreadable_betterleaks_falls_back_to_gitleaks(self):
        env = {k: v for k, v in os.environ.items() if not k.endswith("_PATH") or k == "PATH"}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(
            ss.shutil, "which", self._which({"betterleaks", "gitleaks"})
        ), mock.patch.object(ss, "betterleaks_major", return_value=None):
            self.assertEqual(ss.find_scanner(), ("gitleaks", "/bin/gitleaks"))


class TestParsing(unittest.TestCase):
    def test_v2_finding_normalizes_to_common_shape(self):
        hit = json.loads(V2_REPORT)["findings"][0]
        out = ss.normalize_hit("betterleaks-v2", hit)
        self.assertEqual(out["rule"], "github-pat")
        self.assertEqual(out["file"], "fixture/config.env")
        self.assertEqual(out["line"], 2)
        self.assertTrue(out["secret"].startswith("ghp_"))
        self.assertEqual(out["tags"], [])
        self.assertEqual(set(out), {"rule", "file", "line", "secret", "tags"})

    def test_v1_finding_uses_gitleaks_shape(self):
        hit = json.loads(V1_REPORT)[0]
        self.assertEqual(ss.normalize_hit("betterleaks-v1", hit), ss.normalize_hit("gitleaks", hit))
        self.assertEqual(ss.normalize_hit("betterleaks-v1", hit)["line"], 2)

    def test_v2_sparse_finding_does_not_crash(self):
        out = ss.normalize_hit("betterleaks-v2", {"rule_id": "x", "match": None, "location": "bad"})
        self.assertEqual(out, {"rule": "x", "file": "", "line": 0, "secret": "", "tags": []})

    def test_empty_v2_report(self):
        empty = json.dumps({"schema_version": "1", "findings": [], "scan": {"state": "complete"}})
        with mock.patch.object(ss.subprocess, "run", return_value=_proc(empty)):
            self.assertEqual(ss.run_betterleaks(Path("t"), "betterleaks", 2), ([], None))

    def test_log_line_before_report_is_tolerated(self):
        with mock.patch.object(ss.subprocess, "run", return_value=_proc("WRN something\n" + V2_REPORT)):
            hits, error = ss.run_betterleaks(Path("t"), "betterleaks", 2)
        self.assertIsNone(error)
        self.assertEqual(len(hits), 1)

    def test_failed_run_reports_exit_code_only(self):
        with mock.patch.object(
            ss.subprocess, "run", return_value=_proc("", returncode=126, stderr=r"error reading C:\Users\Test User\x")
        ):
            hits, error = ss.run_betterleaks(Path("t"), "betterleaks", 2)
        self.assertEqual(hits, [])
        self.assertIn("126", error)
        self.assertNotIn("Users", error)


class TestCollectWithBetterleaks(unittest.TestCase):
    def test_summary_findings_and_csv(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "chat-history").mkdir()
            out_dir = root / "out"
            with mock.patch.object(ss, "find_scanner", return_value=("betterleaks-v2", "betterleaks")), mock.patch.object(
                ss.subprocess, "run", return_value=_proc(V2_REPORT)
            ):
                envelope, ok, hits = ss.collect(root, [], out_dir)
            self.assertTrue(ok)
            self.assertEqual(envelope["summary"]["scanner"], "betterleaks")
            self.assertEqual(envelope["summary"]["scanner_mode"], "betterleaks-v2")
            self.assertEqual(envelope["summary"]["hits"], 1)
            self.assertEqual(envelope["summary"]["rule_github-pat"], 1)
            secret_findings = [f for f in envelope["findings"] if f["id"].startswith("secrets_scan.")]
            self.assertEqual(len(secret_findings), 1)
            finding = secret_findings[0]
            self.assertEqual(
                finding["title"],
                "Secret detected by betterleaks: github-pat (1 hit(s) across 1 file(s))",
            )
            self.assertEqual(finding["evidence_count"], 1)
            self.assertEqual(finding["severity"], "critical")
            self.assertNotIn("FAKEFAKE", json.dumps(envelope))
            with (out_dir / "findings.csv").open(encoding="utf-8", newline="") as handle:
                rows = list(csv.reader(handle))
            self.assertEqual(rows[0], ["file", "line", "rule", "sample_redacted"])
            self.assertEqual(rows[1][:3], ["fixture/config.env", "2", "github-pat"])
            self.assertNotIn("FAKEFAKE", rows[1][3])

    def test_scanner_error_becomes_finding(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "chat-history").mkdir()
            with mock.patch.object(ss, "find_scanner", return_value=("betterleaks-v2", "betterleaks")), mock.patch.object(
                ss.subprocess, "run", return_value=_proc("", returncode=2)
            ):
                envelope, ok, hits = ss.collect(root, [])
            ids = [f["id"] for f in envelope["findings"]]
            self.assertIn("secrets-scan.scanner_error", ids)


@unittest.skipUnless(os.environ.get("BETTERLEAKS_PATH"), "set BETTERLEAKS_PATH to run against a real binary")
class TestRealBetterleaks(unittest.TestCase):
    """End-to-end against the real binary on a synthetic file. Validation is
    forced off, so this makes no network calls even with the env var set."""

    def test_detects_synthetic_token(self):
        fake = "ghp_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJ3lN6"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "chat-history").mkdir()
            (root / "chat-history" / "note.txt").write_text(f"token={fake}\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {"BETTERLEAKS_VALIDATE": "true", "BETTERLEAKS_ANALYZE": "true"}):
                envelope, ok, hits = ss.collect(root, [], root / "out")
            self.assertTrue(ok)
            self.assertEqual(envelope["summary"]["scanner"], "betterleaks")
            self.assertGreaterEqual(envelope["summary"]["hits"], 1)
            self.assertEqual(hits[0]["rule"], "github-pat")
            self.assertNotIn("secrets-scan.scanner_error", [f["id"] for f in envelope["findings"]])


if __name__ == "__main__":
    unittest.main()
