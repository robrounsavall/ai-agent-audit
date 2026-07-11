"""Unit tests for git-posture helpers."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"

import bootstrap  # noqa: E402,F401

_mod_path = Path(__file__).resolve().parent.parent / "git-posture.py"
_spec = importlib.util.spec_from_file_location("git_posture_mod", _mod_path)
gp = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(gp)


class TestParseGhRepo(unittest.TestCase):
    def test_https(self):
        self.assertEqual(
            gp.parse_gh_repo("https://github.com/acme/widget.git"),
            ("acme", "widget"),
        )

    def test_ssh(self):
        self.assertEqual(
            gp.parse_gh_repo("git@github.com:acme/widget.git"),
            ("acme", "widget"),
        )

    def test_non_github(self):
        self.assertIsNone(gp.parse_gh_repo("https://gitlab.com/acme/widget.git"))


class TestCheckGitignore(unittest.TestCase):
    def test_missing_env_ignore(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
            (repo / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
            has_env, missing = gp.check_gitignore(repo)
            self.assertFalse(has_env)
            self.assertTrue(any(".env" in m for m in missing))


class TestNotDetectedFindings(unittest.TestCase):
    def test_no_repo_roots(self):
        envelope = gp.collect([], allow_gh=False)
        self.assertFalse(envelope["platform_detected"])
        ids = [f["id"] for f in envelope["findings"]]
        self.assertIn("git.scan.no_repo_roots", ids)

    def test_roots_without_repos(self):
        with tempfile.TemporaryDirectory() as d:
            envelope = gp.collect([Path(d)], allow_gh=False)
            self.assertFalse(envelope["platform_detected"])
            ids = [f["id"] for f in envelope["findings"]]
            self.assertIn("git.scan.no_repos_in_roots", ids)


if __name__ == "__main__":
    unittest.main()
