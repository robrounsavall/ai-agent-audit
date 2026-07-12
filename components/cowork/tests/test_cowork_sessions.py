"""Unit tests for the Cowork session collector."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"

import bootstrap  # noqa: E402,F401
import cowork  # noqa: E402


def ids(findings):
    return {f["id"] for f in findings}


def make_fixture(root: Path) -> None:
    sess = root / "local-agent-mode-sessions" / "acct-1" / "org-1" / "local_aaaa"
    (sess / ".claude" / "projects" / "proj").mkdir(parents=True)
    (sess / ".claude" / "projects" / "proj" / "s1.jsonl").write_text("{}\n", encoding="utf-8")
    (sess / ".claude" / "projects" / "proj" / "s2.jsonl").write_text("{}\n", encoding="utf-8")
    (sess / "audit.jsonl").write_text("{}\n", encoding="utf-8")
    (sess / "outputs").mkdir()
    (sess / "outputs" / "report.docx").write_bytes(b"x")
    (sess / "uploads").mkdir()

    meta = root / "claude-code-sessions" / "acct-1" / "org-1"
    meta.mkdir(parents=True)
    (meta / "local_aaaa.json").write_text("{}", encoding="utf-8")

    cache = root / "cowork-file-preview" / "office-cache"
    cache.mkdir(parents=True)
    (cache / "abc123.pdf").write_bytes(b"%PDF")

    (root / "bridge-state.json").write_text(
        json.dumps({"acct:org": {"enabled": True, "environmentId": "env_x"}}),
        encoding="utf-8",
    )


class TestCoworkCollect(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        make_fixture(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_platform_detected_and_counts(self):
        env = cowork.collect(self.root)
        self.assertTrue(env["platform_detected"])
        s = env["summary"]
        self.assertEqual(s["sessions"], 1)
        self.assertEqual(s["transcript_files"], 2)
        self.assertEqual(s["audit_logs"], 1)
        self.assertEqual(s["output_files"], 1)
        self.assertEqual(s["upload_files"], 0)
        self.assertEqual(s["preview_pdfs"], 1)
        self.assertEqual(s["bridge_synced_sessions"], 1)
        self.assertEqual(s["metadata_files"], 1)

    def test_findings_emitted(self):
        env = cowork.collect(self.root)
        found = ids(env["findings"])
        self.assertIn("cowork.sessions.transcripts_on_disk", found)
        self.assertIn("cowork.workspace.artifacts_on_disk", found)
        self.assertIn("cowork.office_cache.previews", found)
        self.assertIn("cowork.bridge.remote_sync", found)
        # Fresh fixture dirs: no retention finding.
        self.assertNotIn("cowork.retention.exceeds_90d", found)

    def test_not_detected(self):
        with tempfile.TemporaryDirectory() as empty:
            env = cowork.collect(Path(empty))
            self.assertFalse(env["platform_detected"])
            self.assertEqual(env["summary"]["sessions"], 0)

    def test_bridge_disabled_not_counted(self):
        (self.root / "bridge-state.json").write_text(
            json.dumps({"acct:org": {"enabled": False}}), encoding="utf-8"
        )
        env = cowork.collect(self.root)
        self.assertEqual(env["summary"]["bridge_synced_sessions"], 0)
        self.assertNotIn("cowork.bridge.remote_sync", ids(env["findings"]))


if __name__ == "__main__":
    unittest.main()
