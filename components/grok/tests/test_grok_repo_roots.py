"""Regression tests for shared default repository roots."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import bootstrap  # noqa: F401

import grok


class TestGrokRepoRoots(unittest.TestCase):
    def test_default_roots_discover_project_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            repo_root = home / "cursor-projects"
            project = repo_root / "demo-proj"
            (project / ".git").mkdir(parents=True)
            config = project / ".grok" / "config.toml"
            config.parent.mkdir()
            config.write_text('model = "grok-code-fast-1"\n', encoding="utf-8")

            with mock.patch.dict(os.environ, {"USERPROFILE": str(home)}):
                self.assertIn(repo_root, grok.default_repo_roots())
                self.assertIn(
                    config,
                    grok.discover_project_configs(grok.default_repo_roots()),
                )


if __name__ == "__main__":
    unittest.main()
