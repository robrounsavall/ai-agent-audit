"""Access map reads the Codex/Cursor permission-file findings and summaries.

Run from the repo root:
    python -m unittest discover -s tests/integration -p "test_access_map_permission_files.py" -v
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "report"))

from access_map import build_access_map  # noqa: E402


def _env(collector: str, summary: dict, findings: list[str], rules: list[dict] | None = None) -> dict:
    return {
        "collector": collector,
        "platform_detected": True,
        "summary": summary,
        "findings": [{"id": fid, "severity": "high", "category": "Shell Execution"} for fid in findings],
        "rules": rules or [],
    }


class TestCodexPermissionFiles(unittest.TestCase):
    def test_desktop_full_access_is_unrestricted(self) -> None:
        grid = build_access_map({"codex": _env("codex", {"sandbox_mode": "unset"}, ["codex.desktop.full_access_mode"])})
        cells = grid["cells"]["codex"]
        self.assertEqual(cells["shell"]["value"], "yes")
        self.assertEqual(cells["shell"]["evidence"], "high")
        self.assertEqual(cells["approval"]["value"], "yes")
        self.assertIn("Full access", cells["approval"]["reason"])

    def test_default_permissions_full_access(self) -> None:
        grid = build_access_map({"codex": _env("codex", {}, ["codex.permissions.full_access"])})
        self.assertEqual(grid["cells"]["codex"]["approval"]["value"], "yes")
        self.assertIn(":danger-full-access", grid["cells"]["codex"]["approval"]["reason"])

    def test_auto_review_is_partial(self) -> None:
        grid = build_access_map({"codex": _env("codex", {"approval_policy": "on-request"}, ["codex.approval.auto_review"])})
        self.assertEqual(grid["cells"]["codex"]["approval"]["value"], "partial")

    def test_latent_profile_does_not_flip_cells(self) -> None:
        latent = [
            "codex.profile.full_access",
            "codex.profile.approval_never",
            "codex.profile.approval_auto_review",
            "codex.profile.sandbox_full_access",
            "codex.desktop.thread_auto_review",
        ]
        grid = build_access_map({"codex": _env("codex", {"approval_policy": "on-request"}, latent)})
        cells = grid["cells"]["codex"]
        self.assertNotEqual(cells["approval"]["value"], "yes")
        self.assertNotIn("auto_review agent", cells["approval"]["reason"])
        self.assertNotEqual(cells["shell"]["reason"], "Sandbox is disabled, so shell commands are not contained.")


class TestCursorPermissionFiles(unittest.TestCase):
    def test_full_auto_mode_is_auto_approve(self) -> None:
        grid = build_access_map(
            {"cursor": _env("cursor", {"ide_full_auto_modes": ["Agent"]}, ["cursor.run_mode.full_auto_mode"])}
        )
        cell = grid["cells"]["cursor"]["approval"]
        self.assertEqual(cell["value"], "yes")
        self.assertIn("Agent", cell["reason"])

    def test_unrestricted_run_mode(self) -> None:
        grid = build_access_map({"cursor": _env("cursor", {}, ["cursor.run_mode.unrestricted"])})
        self.assertEqual(grid["cells"]["cursor"]["approval"]["value"], "yes")
        self.assertEqual(grid["cells"]["cursor"]["shell"]["value"], "yes")

    def test_ide_allowlist_rules_make_shell_partial(self) -> None:
        rules = [
            {"rule_type": "bash", "rule": "Shell(git)", "command_or_tool_redacted": "git", "decision": "allow"},
            {"rule_type": "bash", "rule": "Shell(npm)", "command_or_tool_redacted": "npm", "decision": "allow"},
        ]
        grid = build_access_map(
            {
                "cursor": _env(
                    "cursor",
                    {"ide_run_mode": "auto-run (allowlist)", "ide_auto_run_modes": ["Agent"], "ide_allowlist_count": 2},
                    [],
                    rules,
                )
            }
        )
        cells = grid["cells"]["cursor"]
        self.assertEqual(cells["shell"]["value"], "partial")
        self.assertEqual(cells["approval"]["value"], "partial")
        self.assertIn("2 allowlisted", cells["approval"]["reason"])

    def test_shell_star_is_unrestricted(self) -> None:
        rules = [{"rule_type": "bash", "rule": "Shell(*)", "command_or_tool_redacted": "*", "decision": "allow"}]
        grid = build_access_map({"cursor": _env("cursor", {}, [], rules)})
        self.assertEqual(grid["cells"]["cursor"]["shell"]["value"], "yes")


if __name__ == "__main__":
    unittest.main()
