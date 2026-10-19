"""Smoke tests for aiscan.ps1 through pwsh.

Collectors are replaced by a python shim so the test does not scan the
machine. Skipped when neither pwsh nor powershell is on PATH.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LAUNCHER = REPO / "aiscan.ps1"

SHIM_PY = r"""
import json
import os
import subprocess
import sys
from pathlib import Path

log_path = os.environ.get("AISCAN_SHIM_LOG")
argv = sys.argv[1:]
if log_path:
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(argv) + "\n")

if not argv:
    sys.exit(0)

script = Path(argv[0])
name = script.name
rest = argv[1:]
mode = os.environ.get("AISCAN_TEST_MODE", "")
real = os.environ["AISCAN_REAL_PYTHON"]

# aiscan.ps1 probes `python -c` for 3.11+ before any collector runs.
if argv[0] == "-c":
    sys.exit(subprocess.call([real, *argv]))
forward = {"tool_version.py", "run_status.py", "scan_diff.py", "build-briefing.py"}


def evidence_file():
    root = None
    for index, arg in enumerate(rest):
        if arg == "--evidence-root" and index + 1 < len(rest):
            root = Path(rest[index + 1])
    if root is None:
        sys.stderr.write("shim: no --evidence-root\n")
        sys.exit(1)
    path = root / "evidence" / f"{script.stem}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


if name == "discover.py":
    print("discover-ok" if mode == "discover-log" else "{}")
    sys.exit(0)

if name in forward:
    sys.exit(subprocess.call([real, os.fspath(script), *rest]))

if mode == "ok-exit0":
    evidence_file().write_text(
        json.dumps(
            {
                "collector": script.stem,
                "version": "1.0.0",
                "platform_detected": True,
                "findings": [],
            }
        ),
        encoding="utf-8",
    )
    sys.exit(0)

if mode == "ok-exit2":
    evidence_file().write_text(
        json.dumps(
            {
                "collector": script.stem,
                "version": "1.0.0",
                "platform_detected": False,
                "findings": [],
            }
        ),
        encoding="utf-8",
    )
    sys.exit(2)

if mode == "no-file":
    sys.exit(0)

if mode == "bad-json":
    evidence_file().write_text("{", encoding="utf-8")
    sys.exit(0)

if mode == "null-json":
    evidence_file().write_text("null", encoding="utf-8")
    sys.exit(0)

if mode == "not-envelope":
    evidence_file().write_text('{"foo": 1}', encoding="utf-8")
    sys.exit(0)

if mode == "stale-fail":
    sys.exit(2)

sys.stderr.write(f"shim: unknown mode {mode}\n")
sys.exit(1)
"""


def _pwsh() -> str | None:
    for name in ("pwsh", "powershell"):
        found = shutil.which(name)
        if found:
            return found
    return None


PWSH = _pwsh()


def _write_shim(directory: Path) -> None:
    (directory / "shim.py").write_text(SHIM_PY, encoding="utf-8")
    launcher = directory / "python"
    launcher.write_text(
        "#!/bin/sh\n"
        'exec "$AISCAN_REAL_PYTHON" "$(dirname "$0")/shim.py" "$@"\n',
        encoding="utf-8",
    )
    launcher.chmod(launcher.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    (directory / "python.cmd").write_text(
        "@echo off\r\n"
        '"%AISCAN_REAL_PYTHON%" "%~dp0shim.py" %*\r\n',
        encoding="utf-8",
    )


class TestAiscanLauncher(unittest.TestCase):
    def setUp(self):
        if PWSH is None:
            self.skipTest("pwsh or powershell is not on PATH")
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.shim_dir = self.tmp / "shim"
        self.shim_dir.mkdir()
        _write_shim(self.shim_dir)
        self.work = self.tmp / "work"
        self.work.mkdir()
        self.log_path = self.tmp / "shim.log"

    def tearDown(self):
        if hasattr(self, "_tmp"):
            self._tmp.cleanup()

    def _env(self, mode: str) -> dict[str, str]:
        env = os.environ.copy()
        env["PATH"] = str(self.shim_dir) + os.pathsep + env.get("PATH", "")
        env["AISCAN_REAL_PYTHON"] = sys.executable
        env["AISCAN_TEST_MODE"] = mode
        env["AISCAN_SHIM_LOG"] = str(self.log_path)
        env["TEMP"] = str(self.work)
        env["TMP"] = str(self.work)
        env.pop("AISCAN_VERSION", None)
        env.pop("AISCAN_AGENT_MODE", None)
        env.pop("AISCAN_REDACT", None)
        return env

    def _run(self, mode: str, *args: str, script: Path = LAUNCHER) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [PWSH, "-NoProfile", "-File", str(script), *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=90,
            env=self._env(mode),
            cwd=str(script.parent),
        )

    def _kept_dirs(self, stdout: str) -> list[Path]:
        found = []
        for line in stdout.splitlines():
            match = re.search(r"Evidence kept at:\s*(.+)", line)
            if match:
                found.append(Path(match.group(1).strip()))
        return found

    def test_error_action_stop_is_what_the_catch_sees(self):
        script = self.tmp / "ea.ps1"
        script.write_text(
            '$ErrorActionPreference = "Continue"\n'
            "$without = $false\n"
            'try { Write-Error "boom" -ErrorAction Continue } catch { $without = $true }\n'
            "$with = $false\n"
            'try { Write-Error "boom" -ErrorAction Stop } catch { $with = $true }\n'
            'Write-Output ("without={0} with={1}" -f $without, $with)\n',
            encoding="utf-8",
        )
        proc = subprocess.run(
            [PWSH, "-NoProfile", "-File", str(script)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env=self._env("ok-exit0"),
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("without=False with=True", proc.stdout)
        text = LAUNCHER.read_text(encoding="utf-8")
        self.assertIn("Start-Process -FilePath $briefingOut -ErrorAction Stop", text)

    def test_exit_0_with_an_envelope_is_success(self):
        out = self.tmp / "scan-ok"
        proc = self._run("ok-exit0", "copilot", "-OutDir", str(out))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue((out / "evidence" / "copilot.json").is_file())

    def test_not_detected_with_an_envelope_is_success(self):
        out = self.tmp / "scan-missing-tool"
        proc = self._run("ok-exit2", "copilot", "-OutDir", str(out))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("platform not detected", proc.stdout)

    def test_exit_0_with_no_file_is_a_failure(self):
        out = self.tmp / "scan-empty"
        proc = self._run("no-file", "copilot", "-OutDir", str(out))
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("produced no evidence file", proc.stdout)

    def test_null_and_non_envelope_json_are_failures(self):
        for mode in ("bad-json", "null-json", "not-envelope"):
            with self.subTest(mode=mode):
                out = self.tmp / mode
                proc = self._run(mode, "copilot", "-OutDir", str(out))
                self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
                self.assertIn("could not be parsed", proc.stdout)

    def test_stale_envelope_plus_a_new_failure_is_not_success(self):
        out = self.tmp / "scan-stale"
        evidence = out / "evidence"
        evidence.mkdir(parents=True)
        (evidence / "copilot.json").write_text(
            json.dumps(
                {
                    "collector": "copilot",
                    "version": "1.0.0",
                    "platform_detected": False,
                    "findings": [],
                    "sample_redacted": "STALE_MARKER",
                }
            ),
            encoding="utf-8",
        )
        proc = self._run("stale-fail", "copilot", "-OutDir", str(out))
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertNotIn("STALE_MARKER", proc.stdout)
        self.assertNotIn("platform not detected", proc.stdout)
        self.assertFalse((evidence / "copilot.json").exists())

    def test_agent_mode_omits_the_scan_folder_path(self):
        out = self.tmp / "scan-agent"
        proc = self._run("ok-exit0", "copilot", "-OutDir", str(out), "-AgentMode")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn("Evidence kept at", proc.stdout)
        self.assertNotIn(str(out), proc.stdout)
        self.assertNotIn(str(out).replace("/", "\\"), proc.stdout)

    def test_agent_mode_missing_script_is_relative(self):
        copy = self.tmp / "tree"
        (copy / "core").mkdir(parents=True)
        shutil.copy(LAUNCHER, copy / "aiscan.ps1")
        shutil.copy(REPO / "VERSION", copy / "VERSION")
        for name in ("tool_version.py", "run_status.py", "discover.py"):
            shutil.copy(REPO / "core" / name, copy / "core" / name)
        out = self.tmp / "scan-missing-script"
        proc = self._run(
            "ok-exit0",
            "copilot",
            "-OutDir",
            str(out),
            "-AgentMode",
            script=copy / "aiscan.ps1",
        )
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("Collector script missing:", proc.stdout)
        self.assertIn("copilot.py", proc.stdout)
        self.assertNotIn(str(copy), proc.stdout)
        self.assertNotIn(str(out), proc.stdout)

    def test_throwaway_folders_differ_inside_the_same_second(self):
        first = self._run("ok-exit0", "copilot", "-Keep")
        second = self._run("ok-exit0", "copilot", "-Keep")
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        kept = self._kept_dirs(first.stdout) + self._kept_dirs(second.stdout)
        try:
            self.assertEqual(len(kept), 2, first.stdout + second.stdout)
            self.assertNotEqual(kept[0], kept[1])
            for path in kept:
                self.assertRegex(path.name, r"^aiscan-\d{8}-\d{6}-[0-9a-f]{8}$")
        finally:
            for path in kept:
                shutil.rmtree(path, ignore_errors=True)

    def test_discover_does_not_resolve_the_version(self):
        proc = self._run("discover-log", "discover")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("discover-ok", proc.stdout)
        logged = self.log_path.read_text(encoding="utf-8")
        self.assertIn("discover.py", logged)
        self.assertNotIn("tool_version.py", logged)


if __name__ == "__main__":
    unittest.main()
