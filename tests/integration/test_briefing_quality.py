"""Briefing quality: grouping, placeholders, numbering, search, and copy."""

from __future__ import annotations

import importlib.util
import json
import re
import unittest
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BRIEFING_PATH = ROOT / "report" / "build-briefing.py"


def _load_briefing():
    spec = importlib.util.spec_from_file_location("briefing_quality", BRIEFING_PATH)
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


def _secret(rule: str, sample: str, severity: str = "high", **extra) -> dict:
    row = {
        "id": f"secrets_scan.{rule}",
        "severity": severity,
        "category": "Secrets Exposure",
        "title": f"Secret detected by gitleaks: {rule}",
        "evidence_count": 1,
        "sample_redacted": sample,
        "secret_redacted": True,
        "tags": ["env_read"],
        "raw_evidence_ref": "raw/secrets-scan/findings.csv",
    }
    row.update(extra)
    return row


class TestSecretPresentation(unittest.TestCase):
    def setUp(self):
        self.briefing = _load_briefing()

    def test_groups_by_rule_and_redacted_value_with_file_list(self):
        findings = [
            _secret("generic-api-key", "ab12...cd34 (generic-api-key)", file="demo/a.txt"),
            _secret("generic-api-key", "ab12...cd34 (generic-api-key)", file="demo/b.txt"),
            _secret("generic-api-key", "zzzz...9999 (generic-api-key)", file="demo/c.txt"),
            {
                "id": "git.env",
                "severity": "critical",
                "category": "Git Posture",
                "title": ".env file found in git commit history",
                "evidence_count": 1,
            },
        ]
        presented, stats = self.briefing.present_findings(findings)
        secrets = [row for row in presented if row.get("_rule") == "generic-api-key"]
        self.assertEqual(len(secrets), 2)
        grouped = next(row for row in secrets if "ab12...cd34" in row["sample_redacted"])
        self.assertEqual(grouped["evidence_count"], 2)
        self.assertEqual(grouped["_files"], ["demo/a.txt", "demo/b.txt"])
        self.assertEqual(stats["secret_hits"], 3)
        self.assertEqual(stats["secret_rows"], 2)
        self.assertEqual(presented[0]["severity"], "critical")

    def test_placeholders_leave_the_high_count_but_stay_visible(self):
        samples = [
            ("curl-auth-header", "YOUR...HERE (curl-auth-header)"),
            ("curl-auth-user", "admi...dmin (curl-auth-user)"),
            ("curl-auth-user", "admi...word (curl-auth-user)"),
            ("curl-auth-user", "admi...PASS (curl-auth-user)"),
            ("generic-api-key", "gitl...ehog (generic-api-key)"),
            ("generic-api-key", "truf...ehog (generic-api-key)"),
            ("generic-api-key", "gpl-...ater (generic-api-key)"),
            ("generic-api-key", "gfdl...ater (generic-api-key)"),
            ("generic-api-key", "ed25...eKey (generic-api-key)"),
            ("generic-api-key", "ab12...cd34 (generic-api-key)"),
            ("generic-api-key", "****REDACTED:generic-api-key****"),
            ("generic-api-key", "admi...word (generic-api-key)"),
        ]
        presented, stats = self.briefing.present_findings([_secret(rule, sample) for rule, sample in samples])
        highs = [row for row in presented if row["severity"] == "high"]
        lows = [row for row in presented if row["severity"] == "low"]
        self.assertTrue(all("likely test value" in row["title"] for row in lows))
        self.assertGreaterEqual(len(lows), 8)
        self.assertEqual(stats["placeholder_hits"], len(samples) - 3)
        high_titles = " ".join(row["title"] for row in highs)
        self.assertIn("Generic API key", high_titles)
        self.assertNotIn("likely test value", high_titles)
        self.assertTrue(any("ab12...cd34" in row["sample_redacted"] for row in highs))
        self.assertTrue(any("REDACTED" in row["sample_redacted"] for row in highs))

    def test_secret_severity_follows_type_not_scanner(self):
        findings = [
            _secret("github-oauth", "ab12...cd34 (github-oauth)", severity="critical"),
            {
                "id": "pii_scan.secret_github_pat",
                "severity": "medium",
                "category": "PII Exposure",
                "title": "SECRET_GITHUB_PAT detected (2 hit(s) across 2 file(s))",
                "evidence_count": 2,
                "sample_redacted": "ghp_...demo (SECRET_GITHUB_PAT)",
            },
            _secret("generic-api-key", "ab12...cd34 (generic-api-key)", severity="high"),
            {
                "id": "pii_scan.secret_generic_secret",
                "severity": "medium",
                "category": "PII Exposure",
                "title": "SECRET_GENERIC_SECRET detected (4 hit(s) across 1 file(s))",
                "evidence_count": 4,
                "sample_redacted": "abcd...wxyz (SECRET_GENERIC_SECRET)",
            },
            _secret("private-key", "----...KEY- (private-key)", severity="high"),
        ]
        presented, _stats = self.briefing.present_findings(findings)
        by_id = {row["id"]: row for row in presented}
        self.assertEqual(by_id["secrets_scan.github-oauth"]["severity"], "critical")
        self.assertEqual(by_id["pii_scan.secret_github_pat"]["severity"], "critical")
        self.assertEqual(by_id["secrets_scan.generic-api-key"]["severity"], "high")
        self.assertEqual(by_id["pii_scan.secret_generic_secret"]["severity"], "high")
        self.assertEqual(by_id["secrets_scan.private-key"]["severity"], "critical")
        self.assertEqual(by_id["pii_scan.secret_github_pat"]["title"], "GitHub tokens across 2 files")
        self.assertEqual(
            by_id["pii_scan.secret_generic_secret"]["title"],
            "Generic secrets across 1 file",
        )

    def test_redundant_count_leaves_the_title(self):
        presented, _stats = self.briefing.present_findings([
            {
                "id": "grok.sandbox.off",
                "severity": "high",
                "category": "Shell Execution",
                "title": "Grok sessions with sandbox_profile off/disabled: 10",
                "evidence_count": 10,
            }
        ])
        self.assertEqual(
            presented[0]["title"],
            "Grok sessions with sandbox_profile off/disabled",
        )


class TestBriefingHtmlQuality(unittest.TestCase):
    def test_numbering_manifest_search_and_copy(self):
        briefing = _load_briefing()
        import tempfile

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "codex.json").write_text(
                json.dumps(_envelope(
                    "codex",
                    summary={"design_used": False},
                    findings=[
                        _secret("curl-auth-user", "admi...dmin (curl-auth-user)"),
                        _secret("curl-auth-user", "admi...dmin (curl-auth-user)", file="demo/notes.txt"),
                        {
                            "id": "codex.sample",
                            "severity": "critical",
                            "category": "Shell Execution",
                            "title": "Codex sandbox bypass observed",
                            "evidence_count": 1,
                            "sample_redacted": "sandbox=disabled",
                        },
                    ],
                )),
                encoding="utf-8",
            )
            (evidence / "pii-scan.json").write_text(
                json.dumps(_envelope("pii-scan", summary={"hits": 2})),
                encoding="utf-8",
            )
            (evidence / "changes.json").write_text(
                json.dumps({
                    "collector": "changes",
                    "version": "1.0.0",
                    "summary": {"comparison": "first_scan", "current_label": "today"},
                    "changes": {},
                }),
                encoding="utf-8",
            )
            html = briefing.build_html(root, customer="Example", operator="Test")

        self.assertIn("Manifest: not generated", html)
        self.assertNotIn("manifest not pre", html)
        self.assertNotIn('<a href="#changes">Changes</a>', html)
        self.assertIn('class="filter-empty"', html)
        self.assertIn("No matches", html)
        self.assertIn("demo/notes.txt", html)
        self.assertIn("<details class='hit-files'>", html)
        self.assertIn("likely test value", html)
        self.assertIn("PII Scan", html)
        self.assertNotIn("Completion times are in Methodology", html)
        self.assertNotIn(">Duration<", html)
        self.assertIn(">C1<", html)
        self.assertNotIn('class="case-num">/01<', html)
        self.assertIn("Hits are matches, findings are rows.", html)
        self.assertIn("Not collected in this scan.", html)
        self.assertIn("Open a cell for the evidence", html)
        self.assertNotIn("Each cell links to the evidence row below", html)

        kickers = re.findall(
            r'<span class="num">([^<]*)</span>\s*<span class="kicker-label">([^<]*)</span>',
            html,
        )
        numbers = [num for num, _label in kickers]
        self.assertEqual(numbers, [f"/{index:02d}" for index in range(1, len(numbers) + 1)])
        labels = [label for _num, label in kickers]
        self.assertEqual(labels[0], "EXECUTIVE SUMMARY")
        self.assertIn("FINDINGS", labels)
        self.assertLess(labels.index("FINDINGS"), labels.index("APPENDIX"))
        self.assertLess(labels.index("APPENDIX"), labels.index("CROSS-AGENT ACCESS"))
        self.assertEqual(len(numbers), len(set(numbers)))

    def test_retention_caption_uses_the_oldest_tool_and_skips_empty_tools(self):
        briefing = _load_briefing()
        today = datetime.now()
        composer_day = "2026-05-01"
        claude_day = "2026-05-20"
        env = _envelope(
            "chat-history",
            summary={
                "total_files": 2,
                "cursor-composer_files": 1,
                "claude_files": 1,
                "grok_files": 0,
                "retention_days": 400,
            },
            raw_pointers=[
                {"path": f"raw/chat-history/cursor-composer/{composer_day}.md"},
                {"path": f"raw/chat-history/claude/{claude_day}.md"},
            ],
        )
        rows = briefing.per_tool_chat_stats(env)
        names = [row["tool_display"] for row in rows]
        self.assertIn("Cursor composer", names)
        self.assertIn("Claude Code", names)
        self.assertNotIn("Grok Build", names)
        html = briefing.render_chat_section(env)
        composer_days = (today - datetime.strptime(composer_day, "%Y-%m-%d")).days
        over = composer_days - 90
        self.assertIn(f"Cursor composer over by {over} days", html)
        self.assertNotIn("Claude Code over by", html)
        self.assertNotIn("1 files", html)


if __name__ == "__main__":
    unittest.main()
