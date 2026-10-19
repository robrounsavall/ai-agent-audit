"""Run origin: precedence, sanitizing, the file, summary, and a quiet diff."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import bootstrap  # noqa: E402, F401
import agent_summary  # noqa: E402
import run_origin  # noqa: E402
import scan_diff  # noqa: E402

STAMP = "2026-10-19T23:00:00+00:00"


def _secret() -> str:
    return "AKIA" + "0" * 16


def _path() -> str:
    return "C:\\Users\\Test User\\work\\notes.txt"


def _envelope() -> dict:
    return {
        "collector": "claude",
        "version": "1.0.0",
        "ran_at": "2026-10-07T12:00:00+00:00",
        "host": "DEMO-ENDPOINT",
        "platform_detected": True,
        "scope_hash": "abcd",
        "summary": {"total_messages": 3},
        "findings": [],
        "rules": [],
        "raw_pointers": [],
    }


def _write_scan(folder: Path, *, origin: str | None = None) -> None:
    evidence = folder / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / "claude.json").write_text(json.dumps(_envelope()), encoding="utf-8")
    if origin is not None:
        (folder / "run-origin.txt").write_text(origin, encoding="utf-8")


class TestSanitize(unittest.TestCase):
    def test_strips_newlines_and_controls_and_caps_length(self):
        raw = "Claude\r\nCode\x00\x01\x1b\x7f\u0085\u2028tail"
        self.assertEqual(run_origin.sanitize_origin_field(raw), "ClaudeCodetail")
        self.assertEqual(run_origin.sanitize_origin_field("a" * 120), "a" * 120)
        self.assertEqual(run_origin.sanitize_origin_field("b" * 121), "b" * 120)
        self.assertEqual(len(run_origin.sanitize_origin_field("c" * 500)), 120)
        self.assertEqual(run_origin.sanitize_origin_field("  \r\n\t"), "unknown")
        self.assertNotIn("\n", run_origin.sanitize_origin_field("a\nb"))

    def test_secret_and_path_are_masked_even_when_redact_is_off(self):
        secret = _secret()
        previous = os.environ.pop("AISCAN_REDACT", None)
        try:
            broken = "AKIA" + "\n" + ("0" * 16)
            masked_secret = run_origin.sanitize_origin_field(broken)
            masked_path = run_origin.sanitize_origin_field("see " + _path())
            self.assertNotIn("AISCAN_REDACT", os.environ)
        finally:
            if previous is not None:
                os.environ["AISCAN_REDACT"] = previous
        self.assertNotIn(secret, masked_secret)
        self.assertNotIn("AKIA", masked_secret)
        self.assertIn("REDACTED:aws_key", masked_secret)
        self.assertNotIn("Test User", masked_path)
        self.assertNotIn("notes.txt", masked_path)
        self.assertNotIn(_path(), masked_path)
        self.assertTrue("<userprofile>" in masked_path or "<path#" in masked_path)
        self.assertLessEqual(len(masked_secret), 120)
        self.assertLessEqual(len(masked_path), 120)

    def test_long_prefix_does_not_keep_a_trailing_secret(self):
        secret = _secret()
        text = ("Q" * 100) + secret
        out = run_origin.sanitize_origin_field(text)
        self.assertLessEqual(len(out), 120)
        self.assertNotIn("AKIA", out)
        self.assertNotIn(secret, out)


class TestPrecedence(unittest.TestCase):
    def test_parameter_beats_env_beats_unknown(self):
        env = {
            "AISCAN_LAUNCHED_BY": "from-env",
            "AISCAN_REASON": "env-reason",
            "USERNAME": "Robert",
            "USER": "robert",
            "COMPUTERNAME": "WORKSTATION",
            "HOSTNAME": "workstation",
        }
        chosen = run_origin.build_run_origin("from-param", "param-reason", STAMP, environ=env)
        self.assertEqual(chosen["launched_by"], "from-param")
        self.assertEqual(chosen["reason"], "param-reason")
        self.assertEqual(chosen["started"], STAMP)

        from_env = run_origin.build_run_origin(None, None, STAMP, environ=env)
        self.assertEqual(from_env["launched_by"], "from-env")
        self.assertEqual(from_env["reason"], "env-reason")

        mixed = run_origin.build_run_origin("from-param", None, STAMP, environ=env)
        self.assertEqual(mixed["launched_by"], "from-param")
        self.assertEqual(mixed["reason"], "env-reason")

        blank = run_origin.build_run_origin("", "   ", STAMP, environ=env)
        self.assertEqual(blank["launched_by"], "unknown")
        self.assertEqual(blank["reason"], "unknown")

        neither = run_origin.build_run_origin(None, None, STAMP, environ={})
        self.assertEqual(neither, {
            "launched_by": "unknown",
            "started": STAMP,
            "reason": "unknown",
        })
        line = run_origin.format_origin_line(neither)
        self.assertNotIn("Robert", line)
        self.assertNotIn("WORKSTATION", line)
        self.assertNotIn("robert", line)

    def test_controls_do_not_survive_into_the_line(self):
        origin = run_origin.build_run_origin("A\r\nB", "c\x00d", STAMP, environ={})
        line = run_origin.format_origin_line(origin)
        self.assertEqual(origin["launched_by"], "AB")
        self.assertEqual(origin["reason"], "cd")
        self.assertNotIn("\n", line)
        self.assertNotIn("\r", line)
        self.assertEqual(line.splitlines(), [line])


class TestFileAndSummary(unittest.TestCase):
    def test_file_is_one_utf8_line_and_summary_copies_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            origin = run_origin.build_run_origin(
                "Claude Code",
                "comparison baseline",
                STAMP,
                environ={},
            )
            path = run_origin.write_run_origin(root, origin)
            raw = path.read_bytes()
            self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
            self.assertEqual(
                raw.decode("utf-8").splitlines(),
                [
                    "launched_by=Claude Code | started="
                    + STAMP
                    + " | reason=comparison baseline"
                ],
            )
            self.assertEqual(run_origin.load_run_origin(root), origin)

            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "claude.json").write_text(json.dumps(_envelope()), encoding="utf-8")
            summary = agent_summary.build_agent_summary(root)
            self.assertEqual(summary["run_origin"], origin)

            out = io.StringIO()
            with redirect_stdout(out):
                code = agent_summary.main(["--evidence-root", str(root), "--write"])
            self.assertEqual(code, 0)
            printed = json.loads(out.getvalue())
            self.assertEqual(printed["run_origin"], origin)

    def test_secret_and_path_are_masked_in_the_file(self):
        secret = _secret()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous = os.environ.pop("AISCAN_REDACT", None)
            try:
                code = run_origin.main([
                    "--root",
                    str(root),
                    "--started",
                    STAMP,
                    "--launched-by",
                    secret,
                    "--reason",
                    _path(),
                ])
            finally:
                if previous is not None:
                    os.environ["AISCAN_REDACT"] = previous
            self.assertEqual(code, 0)
            text = (root / "run-origin.txt").read_text(encoding="utf-8")
            self.assertNotIn(secret, text)
            self.assertNotIn("AKIA", text)
            self.assertNotIn("Test User", text)
            self.assertNotIn("notes.txt", text)
            self.assertNotIn(_path(), text)
            self.assertIn("REDACTED:aws_key", text)
            self.assertTrue("<userprofile>" in text or "<path#" in text)
            loaded = run_origin.load_run_origin(root)
            self.assertNotIn(secret, loaded["launched_by"])
            self.assertNotIn("Test User", loaded["reason"])

    def test_cli_env_fallback_and_explicit_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.dict(
                os.environ,
                {"AISCAN_LAUNCHED_BY": "from-env", "AISCAN_REASON": "env-reason"},
            ):
                code = run_origin.main(["--root", str(root), "--started", STAMP])
                self.assertEqual(code, 0)
                loaded = run_origin.load_run_origin(root)
                self.assertEqual(loaded["launched_by"], "from-env")
                self.assertEqual(loaded["reason"], "env-reason")

                code = run_origin.main([
                    "--root",
                    str(root),
                    "--started",
                    STAMP,
                    "--launched-by",
                    "",
                    "--reason",
                    "",
                ])
            self.assertEqual(code, 0)
            loaded = run_origin.load_run_origin(root)
            self.assertEqual(loaded["launched_by"], "unknown")
            self.assertEqual(loaded["reason"], "unknown")

    def test_old_folder_summary_is_unknown_and_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_scan(root)
            self.assertFalse((root / "run-origin.txt").exists())
            summary = agent_summary.build_agent_summary(root)
            self.assertEqual(summary["run_origin"], run_origin.unknown_origin())
            (root / "run-origin.txt").write_bytes(b"\xff\xfe not a line\n")
            summary = agent_summary.build_agent_summary(root)
            self.assertEqual(summary["run_origin"]["launched_by"], "unknown")
            (root / "run-origin.txt").write_text("nope\nsecond\n", encoding="utf-8")
            summary = agent_summary.build_agent_summary(root)
            self.assertEqual(summary["run_origin"], run_origin.unknown_origin())


class TestDiffIgnoresOrigin(unittest.TestCase):
    def test_missing_or_different_origin_is_not_a_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous = root / "old"
            current = root / "new"
            _write_scan(previous)
            _write_scan(
                current,
                origin=(
                    "launched_by=bob | started="
                    + STAMP
                    + " | reason=comparison baseline\n"
                ),
            )
            (current / "evidence" / "agent-summary.json").write_text(
                json.dumps({
                    "run_origin": {
                        "launched_by": "bob",
                        "started": STAMP,
                        "reason": "comparison baseline",
                    },
                    "findings": [{
                        "title": "SENTINEL_ORIGIN",
                        "severity": "critical",
                        "category": "General Tooling",
                        "evidence_count": 9,
                    }],
                }),
                encoding="utf-8",
            )
            env = scan_diff.build_changes_envelope(current, previous)
            blob = json.dumps(env)
            self.assertEqual(env["summary"]["comparison"], "diff")
            self.assertEqual(env["summary"]["collectors_changed"], 0)
            self.assertEqual(env["findings"], [])
            self.assertNotIn("bob", blob)
            self.assertNotIn("launched_by", blob)
            self.assertNotIn("SENTINEL_ORIGIN", blob)
            self.assertNotIn("run_origin", blob)

            _write_scan(
                previous,
                origin="launched_by=alice | started=2026-10-01T00:00:00+00:00 | reason=earlier\n",
            )
            env = scan_diff.build_changes_envelope(current, previous)
            blob = json.dumps(env)
            self.assertEqual(env["summary"]["collectors_changed"], 0)
            self.assertEqual(env["findings"], [])
            self.assertNotIn("alice", blob)
            self.assertNotIn("bob", blob)

            out = io.StringIO()
            with redirect_stdout(out):
                code = scan_diff.main([
                    "--current",
                    str(current),
                    "--previous",
                    str(previous),
                    "--dry-run",
                ])
            self.assertEqual(code, 0)
            self.assertNotIn("launched_by", out.getvalue())
            self.assertNotIn("SENTINEL_ORIGIN", out.getvalue())


if __name__ == "__main__":
    unittest.main()
