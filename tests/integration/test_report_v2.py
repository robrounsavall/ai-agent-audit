"""Report v2 briefing: skip the changes envelope, tabs, missing-evidence notes."""

from __future__ import annotations

import importlib.util
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BRIEFING_PATH = ROOT / "report" / "build-briefing.py"


def _load_briefing():
    spec = importlib.util.spec_from_file_location("report_v2_briefing", BRIEFING_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _envelope(collector: str, **extra) -> dict:
    data = {
        "collector": collector,
        "version": "1.0.0",
        "ran_at": "2026-10-07T12:00:00+00:00",
        "host": "DEMO-ENDPOINT",
        "platform_detected": True,
        "scope_hash": "abcd",
        "summary": {},
        "findings": [],
        "rules": [],
        "raw_pointers": [],
    }
    data.update(extra)
    return data


class TestReportV2(unittest.TestCase):
    def test_changes_envelope_is_not_a_normal_collector(self):
        briefing = _load_briefing()
        with self._root() as raw:
            root = Path(raw)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "codex.json").write_text(
                json.dumps(_envelope("codex", findings=[{
                    "id": "codex.sample",
                    "severity": "low",
                    "category": "General Tooling",
                    "title": "Codex sample finding",
                    "evidence_count": 1,
                }])),
                encoding="utf-8",
            )
            (evidence / "changes.json").write_text(
                json.dumps({
                    "collector": "changes",
                    "version": "9.0.0",
                    "ran_at": "2026-10-07T12:00:00+00:00",
                    "host": "DEMO-ENDPOINT",
                    "platform_detected": True,
                    "scope_hash": "abcd",
                    "summary": {
                        "comparison": "first_scan",
                        "current_label": "today",
                        "findings_added": 0,
                    },
                    "findings": [{
                        "id": "changes.sentinel",
                        "severity": "high",
                        "category": "General Tooling",
                        "title": "SENTINEL_CHANGES_ONLY",
                        "evidence_count": 1,
                    }],
                    "rules": [],
                    "raw_pointers": [],
                    "changes": {"collectors": {}},
                }),
                encoding="utf-8",
            )
            loaded = briefing.load_evidence(root)
            self.assertIn("codex", loaded)
            self.assertNotIn("changes", loaded)
            titles = [item.get("title") for item in briefing.aggregate_findings(loaded)]
            self.assertIn("Codex sample finding", titles)
            self.assertNotIn("SENTINEL_CHANGES_ONLY", titles)

            html = briefing.build_html(root, customer="Example", operator="Test")
            findings_html = _panel(html, "findings")
            self.assertNotIn("SENTINEL_CHANGES_ONLY", findings_html)
            self.assertIn("Codex sample finding", findings_html)
            changes_html = _panel(html, "changes")
            self.assertIn("Nothing to compare yet", changes_html)
            self.assertNotIn("fonts.googleapis", html)
            self.assertNotIn("%%", html)
            for label in (
                "Findings",
                "Access map",
                "Changes",
                "Agents / collectors",
                "Approvals",
                "Usage",
                "Coverage gaps",
            ):
                self.assertIn(label, html)
            self.assertIn('role="tablist"', html)
            self.assertIn("UNCAPTURED", _panel(html, "coverage"))
            self.assertIn(
                "Not collected — run aiscan telemetry -OtelFile",
                _panel(html, "approvals"),
            )
            self.assertIn(
                "Not collected — run aiscan cloud-agents to enable.",
                _panel(html, "agents"),
            )
            self.assertNotIn('id="cloud-agents"', html)

    def test_missing_changes_file_is_a_note(self):
        briefing = _load_briefing()
        with self._root() as raw:
            root = Path(raw)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "codex.json").write_text(
                json.dumps(_envelope("codex")),
                encoding="utf-8",
            )
            html = briefing.build_html(root, customer="Example", operator="Test")
            self.assertIn(
                "Not collected — run python core/scan_diff.py --current",
                _panel(html, "changes"),
            )

    def test_opt_in_commands_stay_out_of_all(self):
        text = (ROOT / "aiscan.ps1").read_text(encoding="utf-8")
        match = re.search(r"\$StdlibOrder = @\((.*?)\)", text, re.S)
        self.assertIsNotNone(match)
        body = match.group(1)
        self.assertIn("grok-bot", body)
        self.assertNotIn("cloud-agents", body)
        self.assertNotIn("telemetry", body)
        self.assertIn('"telemetry"', text)
        self.assertIn("scan_diff.py", text)

    def _root(self):
        import tempfile
        return tempfile.TemporaryDirectory()


def _panel(html: str, tab_id: str) -> str:
    marker = f'id="panel-{tab_id}"'
    start = html.find(marker)
    if start < 0:
        return ""
    next_panel = html.find('class="page-panel', start + len(marker))
    if next_panel < 0:
        next_panel = html.find("<footer", start)
    return html[start:next_panel]


if __name__ == "__main__":
    unittest.main()
