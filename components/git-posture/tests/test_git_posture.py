"""Unit tests for git-posture helpers."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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


class TestNoLazyFetch(unittest.TestCase):
    def test_every_git_command_disables_lazy_fetch(self):
        with mock.patch.object(
            gp.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 1, "", ""),
        ) as run:
            gp.run_git(Path("repo"), "status")
        env = run.call_args.kwargs["env"]
        self.assertEqual(env["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(env["GIT_ASKPASS"], "")
        self.assertEqual(run.call_args.args[0][:3], ["git", "-C", "repo"])

    def test_partial_clone_is_a_coverage_gap(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "repo"
            repo.mkdir()
            subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
            subprocess.run(
                ["git", "config", "extensions.partialclone", "origin"],
                cwd=repo,
                check=True,
                capture_output=True,
            )
            seen: list[str | None] = []
            real_run = subprocess.run

            def spy(cmd, **kwargs):
                if isinstance(cmd, list) and cmd and cmd[0] == "git":
                    seen.append((kwargs.get("env") or {}).get("GIT_NO_LAZY_FETCH"))
                return real_run(cmd, **kwargs)

            with mock.patch.object(gp.subprocess, "run", side_effect=spy):
                envelope = gp.collect([repo], allow_gh=False)
        hits = [f for f in envelope["findings"] if f["id"] == "git.partial_clone"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "low")
        self.assertEqual(hits[0]["evidence_count"], 1)
        self.assertEqual(hits[0]["title"], "1 partial clone scanned without fetching missing git objects")
        self.assertEqual(envelope["summary"]["partial_clones"], 1)
        self.assertTrue(seen)
        self.assertTrue(all(value == "1" for value in seen))
        self.assertNotIn("origin", hits[0]["title"])

    def test_full_clone_has_no_partial_finding(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "repo"
            repo.mkdir()
            subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
            envelope = gp.collect([repo], allow_gh=False)
        self.assertNotIn("git.partial_clone", [f["id"] for f in envelope["findings"]])
        self.assertEqual(envelope["summary"]["partial_clones"], 0)


if __name__ == "__main__":
    unittest.main()
