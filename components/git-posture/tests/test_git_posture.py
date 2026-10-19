"""Unit tests for git-posture helpers."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import unittest
import unittest.mock
from pathlib import Path
from unittest import mock
from unittest.mock import patch

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

    def test_comments_and_negations_are_not_coverage(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            repo.mkdir(exist_ok=True)
            cases = {
                "# .env\n": True,
                "!.env\n": True,
                ".env\n!.env\n": True,
                ".env.example\n": True,
                ".env\n": False,
                ".env*\n": False,
            }
            for content, env_missing in cases.items():
                (repo / ".gitignore").write_text(content, encoding="utf-8")
                _ok, missing = gp.check_gitignore(repo)
                with self.subTest(content=content):
                    self.assertEqual(".env" in missing, env_missing)
                    self.assertFalse(_ok)

    def test_real_patterns_count_as_covered(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            (repo / ".gitignore").write_text(
                "\n".join(gp.SECRET_GITIGNORE_PATTERNS) + "\n",
                encoding="utf-8",
            )
            ok, missing = gp.check_gitignore(repo)
            self.assertTrue(ok)
            self.assertEqual(missing, [])


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

    def test_sample_list_ignores_blank_labels(self):
        text = gp._sample_list(["a", "", "b", "c", "d", "e", "f", ""], limit=5)
        self.assertEqual(text, "a, b, c, d, e (+1 more)")

    def test_example_env_files_are_not_a_committed_secret(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d) / "docs"
            _commit_repo(repo, ".env.example")
            for name in (".env.sample", ".env.template", ".env.dist"):
                (repo / name).write_text("A=1\n", encoding="utf-8")
                _git(repo, "add", "-f", "--", name)
                _git(repo, "commit", "-m", f"add {name}")
            self.assertFalse(gp.check_env_in_history(repo))
            (repo / ".env").write_text("A=1\n", encoding="utf-8")
            _git(repo, "add", "-f", "--", ".env")
            _git(repo, "commit", "-m", "add env")
            self.assertTrue(gp.check_env_in_history(repo))
            (repo / ".env.local").write_text("A=1\n", encoding="utf-8")
            _git(repo, "add", "-f", "--", ".env.local")
            _git(repo, "commit", "-m", "add env local")
            self.assertTrue(gp.check_env_in_history(repo))

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
        self.assertIn("largest 11MB", blobs["title"])
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


class TestLargeBlobSample(unittest.TestCase):
    def test_blob_name_is_masked_before_truncate(self):
        secret = "AKIA" + "B" * 16
        name = ("n" * 32) + secret
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
            with patch.object(gp, "check_large_blobs", return_value=[(name, 11 * 1024 * 1024)]):
                with patch.dict(os.environ, {"AISCAN_REDACT": "1"}):
                    envelope = gp.collect([Path(tmp)], allow_gh=False)
        sample = next(
            f["sample_redacted"] for f in envelope["findings"] if f["id"] == "git.blob.large"
        )
        self.assertNotIn(secret, sample)
        self.assertNotIn("AKIA", sample)


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
