"""Exit-code rules shared with aiscan.ps1.

aiscan.ps1 records one row per collector as exit,has,parsed and passes
``--briefing 0|1``. These tests cover that contract.
"""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

import bootstrap  # noqa: E402,F401
import run_status  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
HELPER = REPO / "core" / "run_status.py"


def _cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(HELPER), *args],
        check=False,
        capture_output=True,
        text=True,
    )


class TestCollectorFailed(unittest.TestCase):
    def test_not_detected_is_success(self):
        # Exit 2 plus a parsed envelope is "platform not detected".
        self.assertFalse(run_status.collector_failed(2, True, True))

    def test_exit_2_without_evidence_is_a_failure(self):
        self.assertTrue(run_status.collector_failed(2, False, False))

    def test_parse_error_is_a_failure_even_on_exit_0(self):
        self.assertTrue(run_status.collector_failed(0, True, False))

    def test_other_nonzero_with_a_parsed_envelope_is_a_failure(self):
        self.assertTrue(run_status.collector_failed(1, True, True))

    def test_clean_collector_is_success(self):
        self.assertFalse(run_status.collector_failed(0, True, True))

    def test_exit_0_with_no_file_is_a_collector_error(self):
        self.assertTrue(run_status.collector_failed(0, False, False))


class TestScanExitCode(unittest.TestCase):
    def test_collectors_ok_and_briefing_ok(self):
        self.assertEqual(
            run_status.scan_exit_code(collector_failed=False, briefing_failed=False),
            0,
        )

    def test_any_collector_failure_is_2(self):
        self.assertEqual(
            run_status.scan_exit_code(collector_failed=True, briefing_failed=False),
            2,
        )

    def test_briefing_only_is_3(self):
        self.assertEqual(
            run_status.scan_exit_code(collector_failed=False, briefing_failed=True),
            3,
        )

    def test_collector_failure_wins_over_the_briefing(self):
        self.assertEqual(
            run_status.scan_exit_code(collector_failed=True, briefing_failed=True),
            2,
        )

    def test_one_bad_row_among_clean_rows_is_2(self):
        rows = [
            (0, True, True),
            (2, True, True),  # not detected
            (0, True, False),  # parse error
        ]
        self.assertTrue(run_status.rows_failed(rows))
        self.assertEqual(
            run_status.scan_exit_code(collector_failed=True, briefing_failed=False),
            2,
        )

    def test_not_detected_rows_alone_are_0(self):
        rows = [(2, True, True), (0, True, True)]
        self.assertFalse(run_status.rows_failed(rows))

    def test_a_missing_file_among_clean_rows_is_a_failure(self):
        rows = [(2, True, True), (0, False, False)]
        self.assertTrue(run_status.rows_failed(rows))


class TestRunStatusCli(unittest.TestCase):
    def test_cli_not_detected_and_clean_is_0(self):
        proc = _cli("0,1,1", "2,1,1", "--briefing", "0")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.strip(), "0")

    def test_cli_parse_error_is_2_even_if_briefing_failed(self):
        proc = _cli("0,1,0", "--briefing", "1")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.strip(), "2")

    def test_cli_briefing_only_is_3(self):
        proc = _cli("2,1,1", "--briefing", "1")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.strip(), "3")

    def test_cli_missing_evidence_nonzero_is_2(self):
        proc = _cli("1,0,0", "--briefing", "0")
        self.assertEqual(proc.stdout.strip(), "2")

    def test_cli_exit_0_with_no_file_is_2(self):
        proc = _cli("0,0,0", "--briefing", "0")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.strip(), "2")

    def test_cli_missing_evidence_wins_over_a_briefing_failure(self):
        proc = _cli("0,0,0", "--briefing", "1")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.strip(), "2")

    def test_cli_rejects_a_bad_row(self):
        proc = _cli("nope", "--briefing", "0")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("bad collector row", proc.stderr)

    def test_launcher_calls_the_helper_and_prints_the_browser_line(self):
        text = (REPO / "aiscan.ps1").read_text(encoding="utf-8")
        self.assertIn("[switch]$AgentMode", text)
        self.assertIn("run_status.py", text)
        self.assertIn("Opened briefing in default browser", text)
        self.assertIn("Start-Process -FilePath $briefingOut -ErrorAction Stop", text)
        self.assertIn("Evidence kept at:", text)
        self.assertIn("-not $AgentMode", text)
        self.assertIn("New-CollectorStatusRow", text)
        self.assertIn("Read-EvidenceEnvelope", text)
        self.assertIn("Clear-CollectorEvidence", text)
        self.assertIn('[guid]::NewGuid().ToString("N")', text)


if __name__ == "__main__":
    unittest.main()
