"""Claude Code homes inside WSL distros are read alongside the Windows home."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"

import bootstrap  # noqa: E402,F401
import claude  # noqa: E402
import wsl  # noqa: E402
from test_claude_project_settings import tool_paths  # noqa: E402


def ids(findings):
    return {f["id"] for f in findings}


def make_wsl_home(root: Path, user: str = "linuxuser") -> wsl.WslHome:
    home = root / "unc" / "Ubuntu" / "home" / user
    claude_dir = home / ".claude"
    (claude_dir / "projects" / "-mnt-c-repo").mkdir(parents=True)
    (claude_dir / "settings.json").write_text(
        json.dumps({"permissions": {"allow": ["Bash(curl:*)"]}}), encoding="utf-8"
    )
    (claude_dir / "history.jsonl").write_text("x" * 2048, encoding="utf-8")
    for i in range(3):
        (claude_dir / "projects" / "-mnt-c-repo" / f"s{i}.jsonl").write_text(
            json.dumps({"version": "2.1.322", "entrypoint": "cli"}) + "\n", encoding="utf-8"
        )
    return wsl.WslHome("Ubuntu", home)


class TestClaudeWsl(unittest.TestCase):
    def run_collect(self, root: Path, homes, windows_settings: dict | None = None):
        win_home = root / "win" / ".claude"
        (win_home / "projects").mkdir(parents=True)
        if windows_settings is not None:
            (win_home / "settings.json").write_text(json.dumps(windows_settings), encoding="utf-8")
        tp = tool_paths(root, win_home)
        with mock.patch.object(claude, "desktop_config_path", return_value=root / "missing.json"):
            return claude.collect("all", tp, repo_roots=[], wsl_homes=homes)

    def test_wsl_home_rules_findings_and_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = make_wsl_home(root)
            env = self.run_collect(root, [home], windows_settings={"permissions": {"defaultMode": "default"}})
        s = env["summary"]
        self.assertEqual(s["wsl_sessions"], 3)
        self.assertEqual(len(s["wsl_homes"]), 1)
        wsl_sum = s["wsl_homes"][0]
        self.assertEqual(wsl_sum["distro"], "Ubuntu")
        self.assertEqual(wsl_sum["claude_code_version"], "2.1.322")
        self.assertEqual(wsl_sum["permission_mode"], "auto (implicit default)")
        self.assertEqual(wsl_sum["rules"], 1)
        # Windows mode is untouched by the WSL home.
        self.assertEqual(s["permission_mode"], "default")
        self.assertIn("claude.permission.bash_curl_wide", ids(env["findings"]))
        auto = [f for f in env["findings"] if f["id"] == "claude.permission.auto_mode_default"]
        self.assertEqual(len(auto), 1)
        self.assertIn("wsl:Ubuntu", auto[0]["sample_redacted"])
        self.assertNotIn("linuxuser", json.dumps(env))

    def test_wsl_finding_folds_into_windows_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = make_wsl_home(root)
            env = self.run_collect(root, [home], windows_settings={})
        auto = [f for f in env["findings"] if f["id"] == "claude.permission.auto_mode_default"]
        self.assertEqual(len(auto), 1)
        self.assertEqual(auto[0]["evidence_count"], 2)
        self.assertTrue(auto[0]["sample_redacted"].startswith("permissions.defaultMode=unset"))
        self.assertIn("; wsl:Ubuntu:", auto[0]["sample_redacted"])

    def test_no_wsl_homes_leaves_summary_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.run_collect(Path(tmp), None, windows_settings={})
        self.assertNotIn("wsl_homes", env["summary"])

    def test_wsl_home_that_is_the_windows_home_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = make_wsl_home(root)
            tp = tool_paths(root, home.claude_home)
            with mock.patch.object(claude, "desktop_config_path", return_value=root / "missing.json"):
                env = claude.collect("all", tp, repo_roots=[], wsl_homes=[home])
        self.assertNotIn("wsl_homes", env["summary"])

    def test_wsl_only_machine_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = make_wsl_home(root)
            tp = tool_paths(root, root / "absent" / ".claude")
            with mock.patch.object(claude, "desktop_config_path", return_value=root / "missing.json"):
                env = claude.collect("all", tp, repo_roots=[], wsl_homes=[home])
        self.assertTrue(env["platform_detected"])
        self.assertEqual(env["summary"]["wsl_sessions"], 3)


if __name__ == "__main__":
    unittest.main()
