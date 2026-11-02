"""Briefing interaction markup: chips, findings rows, tabs, and contrast."""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BRIEFING_PATH = ROOT / "report" / "build-briefing.py"
CSS_PATH = ROOT / "report" / "templates" / "briefing.css"
CHANGES_PATH = ROOT / "report" / "sections" / "changes.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _contrast(fg: str, bg: str) -> float:
    def channel(value: int) -> float:
        scaled = value / 255
        if scaled <= 0.04045:
            return scaled / 12.92
        return ((scaled + 0.055) / 1.055) ** 2.4

    def luminance(color: str) -> float:
        text = color.lstrip("#")
        red, green, blue = int(text[0:2], 16), int(text[2:4], 16), int(text[4:6], 16)
        return 0.2126 * channel(red) + 0.7152 * channel(green) + 0.0722 * channel(blue)

    lighter = max(luminance(fg), luminance(bg))
    darker = min(luminance(fg), luminance(bg))
    return (lighter + 0.05) / (darker + 0.05)


class TestBriefingInteractions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.briefing = _load(BRIEFING_PATH, "briefing_interactions")
        cls.changes = _load(CHANGES_PATH, "briefing_changes_interactions")

    def _html(self) -> str:
        import tempfile

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "claude.json").write_text(
                json.dumps({
                    "collector": "claude",
                    "version": "1.0.0",
                    "ran_at": "2026-10-07T12:00:00+00:00",
                    "host": "DEMO-ENDPOINT",
                    "platform_detected": True,
                    "scope_hash": "abcd",
                    "summary": {},
                    "findings": [{
                        "id": "claude.sample",
                        "severity": "medium",
                        "category": "Shell Execution",
                        "title": "Sample shell finding",
                        "evidence_count": 1,
                        "sample_redacted": "bash",
                    }],
                    "rules": [{
                        "rule_type": "bash",
                        "rule": "Bash(*)",
                        "decision": "allow",
                        "command_or_tool_redacted": "*",
                    }],
                    "raw_pointers": [],
                }),
                encoding="utf-8",
            )
            return self.briefing.build_html(root, customer=None, operator=None)

    def test_access_chips_are_labeled_buttons(self):
        html = self._html()
        self.assertIn("class='access-chip pill", html)
        self.assertIn("aria-expanded='false'", html)
        self.assertIn("show evidence", html)
        self.assertIn("Claude Code, Runs shell commands,", html)
        self.assertNotIn("<a class='pill", html)
        self.assertNotIn("<summary>Evidence</summary>", html)
        self.assertIn("class='help-tip'", html)
        self.assertIn("scope='col'", html)
        self.assertIn("scope='row'", html)

    def test_findings_table_has_no_height_cap(self):
        html = self._html()
        self.assertIn('class="table-wrap findings-table"', html)
        css = CSS_PATH.read_text(encoding="utf-8")
        self.assertIn(".table-wrap.findings-table", css)
        rule = css.split(".table-wrap.findings-table", 1)[1].split("}", 1)[0]
        self.assertIn("max-height: none", rule)
        panel = html.split('id="panel-findings"', 1)[1].split('id="panel-access-map"', 1)[0]
        self.assertNotIn("580px", panel)
        self.assertIn('role="tab"', html)
        self.assertIn('aria-selected="true"', html)
        self.assertIn('id="findings-tabs" role="tablist"', html)
        self.assertIn('class="page-tablist" role="tablist"', html)
        script = html.split("<script>", 1)[1]
        for key in ("ArrowRight", "ArrowLeft", "Home", "End"):
            self.assertIn(key, script)

    def test_placeholders_are_hidden_and_empty_tabs_are_marked(self):
        html = self._html()
        self.assertNotIn("Unknown customer", html)
        self.assertNotIn("Unknown operator", html)
        self.assertNotIn("Manifest: not generated", html)
        self.assertIn("not collected", html)
        self.assertIn('class="page-tab page-tab--empty"', html)
        self.assertIn('class="goto-tab"', html)
        self.assertIn("Open the Changes tab", html)

    def test_severity_chip_colors_clear_aa(self):
        css = CSS_PATH.read_text(encoding="utf-8")
        self.assertIn("font-size: 12px", css.split(".pill{", 1)[1].split("}", 1)[0])
        pairs = (
            ("#7f1d1d", "#fee2e2"),
            ("#1e3a8a", "#dbeafe"),
            ("#92400e", "#fef3c7"),
            ("#065f46", "#d1fae5"),
            ("#991b1b", "#f4f6f8"),
        )
        for fg, bg in pairs:
            self.assertIn(fg, css)
            self.assertGreaterEqual(_contrast(fg, bg), 4.5)
        self.assertIn(".sev-strip .v.zero", css)

    def test_changes_sort_fold_and_zero_counts(self):
        env = {
            "collector": "changes",
            "version": "1.0.0",
            "summary": {
                "comparison": "diff",
                "new_high_or_critical": 1,
                "drift_warnings": 0,
                "mcp_servers_added": 0,
                "findings_added": 2,
                "findings_resolved": 0,
                "findings_severity_changed": 0,
                "current_label": "today",
                "previous_label": "yesterday",
            },
            "findings": [
                {
                    "severity": "low",
                    "title": "New allow rule on codex",
                    "sample_redacted": "Bash(ls)",
                    "tags": ["new_allow_rule"],
                },
                {
                    "severity": "low",
                    "title": "New allow rule on claude",
                    "sample_redacted": "Bash(pwd)",
                    "tags": ["new_allow_rule"],
                },
                {
                    "severity": "high",
                    "title": "New high finding in claude: sandbox off",
                    "sample_redacted": "id=1",
                    "tags": ["new_high_finding"],
                },
            ],
            "changes": {"collectors": {}},
        }
        html = self.changes.render_changes_section(env)
        self.assertLess(html.find("pill high"), html.find("new allow rules (low)"))
        self.assertIn("2 new allow rules (low)", html)
        self.assertIn('class="v zero"', html)
        self.assertNotIn('class="v amber">0', html)
        self.assertNotIn('class="v yellow">0', html)
