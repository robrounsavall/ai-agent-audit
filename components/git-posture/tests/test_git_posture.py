"""Unit tests for git-posture helpers."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import unittest
import unittest.mock
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


def _git(repo: Path, *args: str) -> None:
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = "Test"
    env["GIT_AUTHOR_EMAIL"] = "test@example.com"
    env["GIT_COMMITTER_NAME"] = "Test"
    env["GIT_COMMITTER_EMAIL"] = "test@example.com"
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        env=env,
    )


def _commit_repo(path: Path, filename: str) -> None:
    path.mkdir(parents=True)
    _git(path, "init")
    _git(path, "config", "user.email", "test@example.com")
    _git(path, "config", "user.name", "Test")
    (path / filename).write_text("A=1\n", encoding="utf-8")
    _git(path, "add", "-f", "--", filename)
    _git(path, "commit", "-m", "add file")


class TestDuplicateTitles(unittest.TestCase):
    def test_count_label_plural(self):
        self.assertEqual(gp._count_label(1, "repo"), "1 repo")
        self.assertEqual(gp._count_label(2, "repo"), "2 repos")

    def test_same_check_is_one_finding_per_title(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _commit_repo(root / "with-env", ".env")
            _commit_repo(root / "with-env-local", ".env.local")
            _commit_repo(root / "clean", "readme.txt")
            hook = root / "clean" / ".git" / "hooks" / "pre-commit"
            hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            with unittest.mock.patch.object(
                gp, "check_large_blobs", return_value=[("weights.bin", 11 * 1024 * 1024)]
            ), unittest.mock.patch.object(gp, "check_branch_protection", return_value=False):
                envelope = gp.collect([root], allow_gh=True)

        findings = envelope["findings"]
        titles = [item["title"] for item in findings]
        self.assertEqual(len(titles), len(set(titles)))

        env_hit = next(item for item in findings if item["id"] == "git.env.in_history")
        self.assertEqual(env_hit["evidence_count"], 2)
        self.assertEqual(env_hit["severity"], "critical")
        self.assertIn("2 repos", env_hit["title"])
        self.assertIn("with-env", env_hit["sample_redacted"])
        self.assertIn("with-env-local", env_hit["sample_redacted"])
        self.assertNotIn("clean", env_hit["sample_redacted"])

        hooks = next(item for item in findings if item["id"] == "git.hooks.missing")
        self.assertEqual(hooks["evidence_count"], 2)
        self.assertIn("2 repos", hooks["title"])

        protection = next(item for item in findings if item["id"] == "git.branch.no_protection")
        self.assertEqual(protection["evidence_count"], 3)
        self.assertIn("3 repos", protection["title"])

        blobs = next(item for item in findings if item["id"] == "git.blob.large")
        self.assertEqual(len([item for item in findings if item["id"] == "git.blob.large"]), 1)
        self.assertEqual(blobs["evidence_count"], 3)
        self.assertIn("3 blobs", blobs["title"])
        self.assertEqual(envelope["summary"]["env_in_history"], 2)
        self.assertEqual(envelope["summary"]["no_pre_commit"], 2)
        self.assertEqual(envelope["summary"]["large_blobs"], 3)


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
