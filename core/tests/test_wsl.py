"""Unit tests for WSL discovery (core/wsl.py)."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ["USERPROFILE"] = r"C:\Users\Test User"

import bootstrap  # noqa: E402,F401
import wsl  # noqa: E402


class TestParseDistroList(unittest.TestCase):
    def test_utf16_output_with_bom(self):
        raw = "\ufeffUbuntu\r\nDebian\r\n".encode("utf-16-le")
        self.assertEqual(wsl.parse_distro_list(raw), ["Ubuntu", "Debian"])

    def test_utf8_output(self):
        self.assertEqual(wsl.parse_distro_list(b"Ubuntu-22.04\n\n"), ["Ubuntu-22.04"])

    def test_rejects_odd_names(self):
        raw = "Ubuntu\r\n..\\evil\r\nhas space\r\n".encode("utf-16-le")
        self.assertEqual(wsl.parse_distro_list(raw), ["Ubuntu"])


class TestRunningDistros(unittest.TestCase):
    def test_disabled_by_env(self):
        with mock.patch.dict(os.environ, {"AISCAN_WSL": "0"}), mock.patch.object(
            wsl.subprocess, "run"
        ) as run:
            self.assertEqual(wsl.running_distros(), [])
            run.assert_not_called()

    def test_wsl_missing(self):
        with mock.patch.object(wsl.sys, "platform", "win32"), mock.patch.dict(
            os.environ, {"AISCAN_WSL": ""}
        ), mock.patch.object(wsl.subprocess, "run", side_effect=FileNotFoundError):
            self.assertEqual(wsl.running_distros(), [])

    def test_asks_only_for_running_distros(self):
        result = mock.Mock(returncode=0, stdout="Ubuntu\r\n".encode("utf-16-le"))
        with mock.patch.object(wsl.sys, "platform", "win32"), mock.patch.dict(
            os.environ, {"AISCAN_WSL": ""}
        ), mock.patch.object(wsl.subprocess, "run", return_value=result) as run:
            self.assertEqual(wsl.running_distros(), ["Ubuntu"])
        self.assertIn("--running", run.call_args.args[0])


class TestClaudeHomes(unittest.TestCase):
    def test_finds_user_homes_with_claude(self):
        with tempfile.TemporaryDirectory() as tmp:
            unc = Path(tmp)
            (unc / "Ubuntu" / "home" / "alice" / ".claude").mkdir(parents=True)
            (unc / "Ubuntu" / "home" / "bob").mkdir(parents=True)
            (unc / "Stopped").mkdir()
            homes = wsl.claude_homes(["Ubuntu", "Stopped", "Missing"], unc_roots=(unc,))
        self.assertEqual([(h.distro, h.home.name) for h in homes], [("Ubuntu", "alice")])
        self.assertEqual(homes[0].label, "wsl:Ubuntu")
        self.assertNotIn("alice", homes[0].label)

    def test_falls_back_to_second_unc_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            first, second = Path(tmp) / "a", Path(tmp) / "b"
            first.mkdir()
            (second / "Ubuntu" / "home" / "u" / ".claude").mkdir(parents=True)
            homes = wsl.claude_homes(["Ubuntu"], unc_roots=(first, second))
        self.assertEqual(len(homes), 1)


if __name__ == "__main__":
    unittest.main()
