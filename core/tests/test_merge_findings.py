"""Duplicate finding titles collapse to one row with a summed count."""

from __future__ import annotations

import os
import unittest

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"

import bootstrap  # noqa: E402,F401
from common import make_finding, merge_duplicate_findings  # noqa: E402


class TestMergeDuplicateFindings(unittest.TestCase):
    def test_same_title_and_severity_merge_counts_and_samples(self):
        rows = [
            make_finding(
                "git.env.in_history",
                "critical",
                "Git Posture",
                "Same title",
                evidence_count=1,
                sample_redacted="one",
            ),
            make_finding(
                "git.env.in_history",
                "critical",
                "Git Posture",
                "Same title",
                evidence_count=2,
                sample_redacted="two",
                tags=["extra"],
            ),
            make_finding(
                "git.env.in_history",
                "high",
                "Git Posture",
                "Same title",
                evidence_count=1,
            ),
            make_finding(
                "git.hooks.missing",
                "medium",
                "Git Posture",
                "Other title",
            ),
        ]
        merged = merge_duplicate_findings(rows)
        self.assertEqual(len(merged), 3)
        critical = next(item for item in merged if item["severity"] == "critical")
        self.assertEqual(critical["evidence_count"], 3)
        self.assertIn("one", critical["sample_redacted"])
        self.assertIn("two", critical["sample_redacted"])
        self.assertIn("extra", critical["tags"])
        high = next(item for item in merged if item["severity"] == "high")
        self.assertEqual(high["title"], "Same title")
        self.assertEqual(high["evidence_count"], 1)
        self.assertEqual(merged[-1]["title"], "Other title")

    def test_zero_count_is_kept(self):
        rows = [
            make_finding("a", "low", "Git Posture", "Same", evidence_count=0),
            make_finding("b", "low", "Git Posture", "Same", evidence_count=0),
        ]
        merged = merge_duplicate_findings(rows)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["evidence_count"], 0)

    def test_distinct_titles_stay_separate(self):
        rows = [
            make_finding("a", "high", "Shell Execution", "First"),
            make_finding("b", "high", "Shell Execution", "Second"),
        ]
        merged = merge_duplicate_findings(rows)
        self.assertEqual([item["title"] for item in merged], ["First", "Second"])
        self.assertEqual([item["evidence_count"] for item in merged], [1, 1])


if __name__ == "__main__":
    unittest.main()
