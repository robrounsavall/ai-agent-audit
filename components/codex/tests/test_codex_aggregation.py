"""
Contract: repeated Codex session approval events aggregate into one finding.

A noisy session can contain dozens of require_escalated approval requests. The
briefing must not render dozens of identical rows. collect() must emit ONE
finding per event id, carrying evidence_count and a first/last span.

Run:
    scripts/test-component.ps1 -Name <component>
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"
import bootstrap  # noqa: E402,F401

import codex  # noqa: E402
import paths  # noqa: E402


class TestEventAggregation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.sessions = root / "sessions"
        self.sessions.mkdir(parents=True)
        self.tp = paths.resolve_tool_paths(cli_overrides={"codex_home": str(root)})

    def tearDown(self):
        self.tmp.cleanup()

    def test_require_escalated_aggregated(self):
        rows = []
        for i in range(8):
            rows.append({
                "timestamp": f"2026-05-2{i % 3}T10:0{i}:00Z",
                "payload": {
                    "type": "function_call",
                    "name": "shell",
                    "arguments": json.dumps({
                        "sandbox_permissions": "require_escalated",
                        "command": f"powershell -c step{i}",
                    }),
                },
            })
        path = self.sessions / "rollout.jsonl"
        with path.open("w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")

        env = codex.collect(self.tp)
        esc = [f for f in env["findings"] if f["id"] == "codex.sandbox.require_escalated"]
        self.assertEqual(len(esc), 1, "require_escalated findings not aggregated")
        self.assertEqual(esc[0]["evidence_count"], 8)
        # span populated from the observed timestamps
        self.assertTrue(esc[0]["first_seen"])
        self.assertTrue(esc[0]["last_seen"])
        self.assertLessEqual(esc[0]["first_seen"], esc[0]["last_seen"])


if __name__ == "__main__":
    unittest.main()
