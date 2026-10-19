"""Tool version resolution: git describe, VERSION file, then dev."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import bootstrap  # noqa: E402,F401
import tool_version  # noqa: E402
from common import display_path  # noqa: E402

REPO = Path(__file__).resolve().parents[2]


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def _init_repo(repo: Path) -> None:
    _git(repo, "init")
    _git(repo, "config", "user.email", "aiscan-test@example.com")
    _git(repo, "config", "user.name", "aiscan test")
    (repo / "README").write_text("synthetic\n", encoding="utf-8")
    _git(repo, "add", "README")
    _git(repo, "-c", "commit.gpgsign=false", "commit", "-m", "init")


class TestToolVersion(unittest.TestCase):
    def test_env_wins_over_the_tree(self):
        previous = os.environ.get("AISCAN_VERSION")
        os.environ["AISCAN_VERSION"] = "9.9.9-from-env"
        try:
            self.assertEqual(tool_version.tool_version(REPO), "9.9.9-from-env")
        finally:
            if previous is None:
                os.environ.pop("AISCAN_VERSION", None)
            else:
                os.environ["AISCAN_VERSION"] = previous

    def test_version_file_when_git_is_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "VERSION").write_text("4.5.6\n", encoding="utf-8")
            self.assertEqual(tool_version.tool_version(root, use_env=False), "4.5.6")

    def test_version_file_bom_is_stripped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "VERSION").write_bytes(b"\xef\xbb\xbf4.5.6\n")
            self.assertEqual(tool_version.tool_version(root, use_env=False), "4.5.6")

    def test_dev_when_nothing_is_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(tool_version.tool_version(Path(tmp), use_env=False), "dev")

    def test_broken_git_dir_falls_back_to_version_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git").write_text("gitdir: /nowhere\n", encoding="utf-8")
            (root / "VERSION").write_text("4.5.6\n", encoding="utf-8")
            self.assertEqual(tool_version.tool_version(root, use_env=False), "4.5.6")

    def test_git_describe_on_a_tag_strips_one_leading_v(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _init_repo(root)
            _git(root, "tag", "v1.2.3")
            (root / "VERSION").write_text("9.9.9\n", encoding="utf-8")
            self.assertEqual(tool_version.tool_version(root, use_env=False), "1.2.3")

    def test_git_describe_after_the_tag_is_not_a_bare_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _init_repo(root)
            _git(root, "tag", "v1.2.3")
            (root / "README").write_text("changed\n", encoding="utf-8")
            _git(root, "add", "README")
            _git(root, "-c", "commit.gpgsign=false", "commit", "-m", "second")
            described = tool_version.tool_version(root, use_env=False)
            self.assertRegex(described, r"^1\.2\.3-1-g[0-9a-f]+$")

    def test_dirty_tree_is_marked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _init_repo(root)
            _git(root, "tag", "v1.2.3")
            (root / "README").write_text("dirty\n", encoding="utf-8")
            self.assertEqual(tool_version.tool_version(root, use_env=False), "1.2.3-dirty")

    def test_untagged_commit_is_a_hash_not_the_version_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _init_repo(root)
            (root / "VERSION").write_text("9.9.9\n", encoding="utf-8")
            described = tool_version.tool_version(root, use_env=False)
            self.assertNotEqual(described, "9.9.9")
            self.assertRegex(described, r"^[0-9a-f]+$")

    def test_release_script_writes_version_once(self):
        text = (REPO / "scripts" / "build-release-zip.sh").read_text(encoding="utf-8")
        files_line = next(line for line in text.splitlines() if line.startswith("files=("))
        self.assertNotIn("VERSION", files_line)
        self.assertIn("printf '%s\\n' \"$version\" > \"$stage/VERSION\"", text)

    def test_cli_ignores_aiscan_version_env(self):
        env = os.environ.copy()
        env["AISCAN_VERSION"] = "should-ignore"
        proc = subprocess.run(
            [sys.executable, str(REPO / "core" / "tool_version.py")],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(proc.returncode, 0)
        printed = proc.stdout.strip()
        self.assertNotEqual(printed, "should-ignore")
        self.assertEqual(printed, tool_version.tool_version(use_env=False))


class TestDisplayPath(unittest.TestCase):
    def test_absolute_unless_agent_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "evidence" / "changes.json"
            previous = os.environ.get("AISCAN_AGENT_MODE")
            os.environ.pop("AISCAN_AGENT_MODE", None)
            try:
                self.assertEqual(display_path(target, root), str(target))
                os.environ["AISCAN_AGENT_MODE"] = "1"
                self.assertEqual(display_path(target, root), str(Path("evidence") / "changes.json"))
                outside = root.parent / "other.json"
                self.assertEqual(display_path(outside, root), str(outside))
            finally:
                if previous is None:
                    os.environ.pop("AISCAN_AGENT_MODE", None)
                else:
                    os.environ["AISCAN_AGENT_MODE"] = previous


if __name__ == "__main__":
    unittest.main()
