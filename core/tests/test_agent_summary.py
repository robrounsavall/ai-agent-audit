"""Unit tests for the safe agent summary and newest-folder selection."""

from __future__ import annotations

import io
import json
import os
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import bootstrap  # noqa: E402,F401
import agent_summary  # noqa: E402

# Hard-coded on purpose. Importing the allow-list from the module would let
# a new field ship in both places and the test would still pass.
ALLOWED_KEYS = {
    "aiscan_version",
    "collectors",
    "findings",
    "collector_errors",
    "coverage_caveats",
    "collector",
    "platform_detected",
    "detection_status",
    "severity",
    "title",
    "category",
    "evidence_count",
}
_STATUS_RE = re.compile(
    r"^(detected|not detected|parse error|not collected|error \(exit -?\d+\))$"
)
_LEAKS = (
    "Test User",
    "LEAK_SENTINEL",
    "Bash(curl:*)",
    "raw/chat-history",
    "sample_redacted",
    "raw_pointers",
    "scope_hash",
    "DEMO-ENDPOINT",
    r"C:\Users",
    "C:/Users",
)


def _envelope(collector: str, **overrides) -> dict:
    data = {
        "collector": collector,
        "version": "1.0.0",
        "ran_at": "2026-10-16T12:00:00+00:00",
        "host": "DEMO-ENDPOINT",
        "platform_detected": True,
        "scope_hash": "LEAK_SENTINEL_SCOPE",
        "summary": {"note": r"C:\Users\Test User\.claude"},
        "findings": [],
        "rules": [{
            "rule": "Bash(curl:*)",
            "command_or_tool_redacted": "LEAK_SENTINEL_RULE",
            "scope_label_redacted": "user#abc",
        }],
        "raw_pointers": [{
            "kind": "chat_transcript",
            "path": "raw/chat-history/claude/secret.md",
            "sha256": "abc",
        }],
        "username": "Test User",
        "sample_redacted": "LEAK_SENTINEL_TOP",
    }
    data.update(overrides)
    data["collector"] = collector
    return data


def _finding(severity, title, category, evidence_count, **extra):
    row = {
        "id": extra.pop("id", "test.finding"),
        "severity": severity,
        "category": category,
        "title": title,
        "evidence_count": evidence_count,
        "first_seen": "2026-10-01T00:00:00Z",
        "last_seen": "2026-10-16T00:00:00Z",
        "sample_redacted": r"C:\Users\Test User\secret LEAK_SENTINEL_SAMPLE",
        "secret_redacted": True,
        "tags": extra.pop("tags", ["env_read"]),
        "raw_evidence_ref": "raw/chat-history/claude/secret.md",
    }
    row.update(extra)
    return row


def _write_envelope(root: Path, collector: str, **overrides) -> None:
    evidence = root / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    payload = _envelope(collector, **overrides)
    (evidence / f"{collector}.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )


def _keys(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from _keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from _keys(child)


class TestAllowList(unittest.TestCase):
    def test_only_allowed_fields_and_nothing_else_leaks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_envelope(
                root,
                "claude",
                findings=[
                    _finding("high", "Claude has unrestricted curl approval", "Shell Execution", 3),
                    "not-a-finding",
                    {"severity": "LOW", "title": "Lower case severity", "category": "General Tooling", "evidence_count": "4"},
                    {"severity": r"C:\Users\Test User", "title": "Weird severity", "category": "General Tooling", "evidence_count": 1},
                ],
            )
            _write_envelope(
                root,
                "cursor",
                platform_detected=False,
                findings=[_finding("low", "Cursor was not configured", "General Tooling", 1)],
            )
            # Derived files and unsafe filenames must not become collectors.
            evidence = root / "evidence"
            (evidence / "changes.json").write_text(json.dumps({
                "collector": "changes",
                "ran_at": "2099-01-01T00:00:00+00:00",
                "findings": [_finding("critical", "LEAK_SENTINEL_CHANGES", "General Tooling", 9)],
            }), encoding="utf-8")
            (evidence / "agent-summary.json").write_text(json.dumps({
                "findings": [_finding("critical", "LEAK_SENTINEL_OLD_SUMMARY", "General Tooling", 9)],
                "host": "DEMO-ENDPOINT",
            }), encoding="utf-8")
            (evidence / "run-status.json").write_text(json.dumps({
                "collectors": [{
                    "collector": "codex",
                    "exit_code": 1,
                    "detection_status": r"error (exit 1) C:\Users\Test User\LEAK_SENTINEL_STATUS",
                }],
            }), encoding="utf-8")
            (evidence / "Test User.json").write_text(json.dumps(
                _envelope("Test User", findings=[_finding("critical", "Named like a person", "General Tooling", 1)])
            ), encoding="utf-8")

            summary = agent_summary.build_agent_summary(root)
            blob = json.dumps(summary)

            self.assertEqual(
                set(summary),
                {"aiscan_version", "collectors", "findings", "collector_errors", "coverage_caveats"},
            )
            self.assertEqual(summary["aiscan_version"], agent_summary.tool_version())
            self.assertNotIn("/", summary["aiscan_version"])
            self.assertNotIn("\\", summary["aiscan_version"])
            self.assertTrue(set(_keys(summary)) <= ALLOWED_KEYS)
            for needle in _LEAKS:
                self.assertNotIn(needle, blob)
            self.assertNotIn(str(root), blob)
            self.assertNotIn("raw_evidence_ref", blob)
            self.assertNotIn("secret_redacted", blob)
            self.assertNotIn("first_seen", blob)

            by_name = {row["collector"]: row for row in summary["collectors"]}
            self.assertEqual(set(by_name), {"claude", "cursor"})
            self.assertEqual(by_name["claude"]["platform_detected"], True)
            self.assertEqual(by_name["claude"]["detection_status"], "detected")
            self.assertEqual(by_name["cursor"]["platform_detected"], False)
            self.assertEqual(by_name["cursor"]["detection_status"], "not detected")
            self.assertIsInstance(by_name["claude"]["platform_detected"], bool)

            titles = [row["title"] for row in summary["findings"]]
            self.assertEqual(titles, [
                "Claude has unrestricted curl approval",
                "Lower case severity",
                "Cursor was not configured",
                "Weird severity",
            ])
            self.assertEqual(summary["findings"][3]["severity"], "unknown")
            high = summary["findings"][0]
            self.assertEqual(set(high), {"collector", "severity", "title", "category", "evidence_count"})
            self.assertEqual(high["severity"], "high")
            self.assertEqual(high["evidence_count"], 3)
            self.assertEqual(summary["findings"][1]["severity"], "low")
            self.assertEqual(summary["findings"][1]["evidence_count"], 4)
            self.assertNotIn("Named like a person", titles)
            self.assertNotIn("LEAK_SENTINEL_CHANGES", titles)

            error = summary["collector_errors"]
            self.assertEqual(len(error), 1)
            self.assertEqual(error[0]["collector"], "codex")
            self.assertEqual(error[0]["platform_detected"], False)
            self.assertEqual(error[0]["detection_status"], "error (exit 1)")
            self.assertTrue(_STATUS_RE.fullmatch(error[0]["detection_status"]))


class TestSortOrder(unittest.TestCase):
    def test_severity_then_evidence_count_desc_then_title(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_envelope(root, "claude", findings=[
                _finding("low", "Low many", "General Tooling", 100),
                _finding("critical", "Crit one", "Shell Execution", 1),
                _finding("high", "High five", "Secrets Exposure", 5),
                _finding("high", "High nine", "Secrets Exposure", 9),
                _finding("medium", "Med", "Git Posture", 2),
                _finding("critical", "Crit tie B", "Shell Execution", 3),
                _finding("critical", "Crit tie A", "Shell Execution", 3),
            ])
            _write_envelope(root, "secrets-scan", findings=[
                _finding("critical", "Crit more", "Secrets Exposure", 50),
            ])
            summary = agent_summary.build_agent_summary(root)
            ranked = [
                (row["severity"], row["evidence_count"], row["title"], row["collector"])
                for row in summary["findings"]
            ]
            self.assertEqual(ranked, [
                ("critical", 50, "Crit more", "secrets-scan"),
                ("critical", 3, "Crit tie A", "claude"),
                ("critical", 3, "Crit tie B", "claude"),
                ("critical", 1, "Crit one", "claude"),
                ("high", 9, "High nine", "claude"),
                ("high", 5, "High five", "claude"),
                ("medium", 2, "Med", "claude"),
                ("low", 100, "Low many", "claude"),
            ])

    def test_test_data_sorts_last_and_collector_breaks_ties(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_envelope(root, "claude", findings=[
                _finding("high", "Z real", "Shell Execution", 1, tags=["env_read"]),
                _finding("high", "A fixture", "Shell Execution", 99, tags=["test_data"]),
                _finding("high", "(10 items)", "Shell Execution", 2, tags=["env_read"]),
                _finding("high", "(2 items)", "Shell Execution", 2, tags=["env_read"]),
            ])
            _write_envelope(root, "secrets-scan", findings=[
                _finding("high", "A earlier title", "Shell Execution", 1, tags=["env_read"]),
            ])
            summary = agent_summary.build_agent_summary(root)
            ranked = [
                (row["collector"], row["evidence_count"], row["title"])
                for row in summary["findings"]
            ]
            self.assertEqual(ranked, [
                ("claude", 2, "(10 items)"),
                ("claude", 2, "(2 items)"),
                ("claude", 1, "Z real"),
                ("secrets-scan", 1, "A earlier title"),
                ("claude", 99, "A fixture"),
            ])
            self.assertNotIn("_test_data", json.dumps(summary))
            self.assertNotIn("test_data", json.dumps(summary))


class TestErrorsAndCaveats(unittest.TestCase):
    def test_parse_errors_missing_collectors_and_coverage_caveats(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"
            evidence.mkdir(parents=True)
            (evidence / "codex.json").write_text("{not json", encoding="utf-8")
            (evidence / "pii-scan.json").write_text("[1, 2, 3]", encoding="utf-8")
            _write_envelope(
                root,
                "secrets-scan",
                summary={"scanner": "none", "hits": 0, "targets": 2},
                findings=[
                    _finding(
                        "medium",
                        "No secrets scanner found (looked for betterleaks, gitleaks, and trufflehog)",
                        "Secrets Exposure",
                        1,
                        id="secrets-scan.tool_unavailable",
                        tags=["env_read"],
                    ),
                    _finding(
                        "high",
                        "Secret detected by gitleaks: example",
                        "Secrets Exposure",
                        4,
                        id="secrets_scan.example",
                        tags=["env_read"],
                    ),
                ],
            )
            _write_envelope(
                root,
                "cloud-agents",
                findings=[
                    _finding(
                        "low",
                        "Cloud agent inventory omits cost, conversations, and key scope",
                        "General Tooling",
                        1,
                        id="cloud_agents.coverage",
                        tags=["coverage_gap", "cloud_agent"],
                    ),
                ],
            )
            _write_envelope(
                root,
                "git-posture",
                platform_detected=False,
                findings=[
                    _finding(
                        "low",
                        "Repo roots exist but contain no git repositories",
                        "Git Posture",
                        1,
                        id="git.scan.no_repos_in_roots",
                        tags=["env_read"],
                    ),
                ],
            )
            _write_envelope(
                root,
                "claude",
                findings=[
                    _finding("high", "A real finding", "Shell Execution", 2, id="claude.real", tags=["env_read"]),
                ],
            )
            statuses = {
                "cursor": {"exit_code": 1, "raw_status": "error (exit 1)"},
                "copilot": {"exit_code": 0, "raw_status": "-"},
                "grok": {"exit_code": 2, "raw_status": "not detected"},
            }
            summary = agent_summary.build_agent_summary(root, statuses)

            errors = {row["collector"]: row["detection_status"] for row in summary["collector_errors"]}
            self.assertEqual(errors, {
                "codex": "parse error",
                "pii-scan": "parse error",
                "cursor": "error (exit 1)",
                "grok": "error (exit 2)",
                "copilot": "error (exit 0)",
            })
            detected = {row["collector"]: row["detection_status"] for row in summary["collectors"]}
            self.assertEqual(detected["claude"], "detected")
            self.assertEqual(detected["secrets-scan"], "detected")
            self.assertEqual(detected["git-posture"], "not detected")
            self.assertNotIn("copilot", detected)
            self.assertNotIn("grok", detected)
            self.assertNotIn("cursor", detected)
            self.assertNotIn("codex", detected)

            caveat_titles = [row["title"] for row in summary["coverage_caveats"]]
            self.assertEqual(caveat_titles, [
                "No secrets scanner found (looked for betterleaks, gitleaks, and trufflehog)",
                "Cloud agent inventory omits cost, conversations, and key scope",
                "Repo roots exist but contain no git repositories",
            ])
            self.assertNotIn("A real finding", caveat_titles)
            self.assertNotIn("Secret detected by gitleaks: example", caveat_titles)
            finding_titles = [row["title"] for row in summary["findings"]]
            for title in caveat_titles:
                self.assertNotIn(title, finding_titles)
            self.assertIn("A real finding", finding_titles)
            self.assertIn("Secret detected by gitleaks: example", finding_titles)

            for row in summary["collectors"] + summary["collector_errors"]:
                self.assertTrue(_STATUS_RE.fullmatch(row["detection_status"]))
                self.assertIsInstance(row["platform_detected"], bool)

    def test_scanner_none_without_a_coverage_finding_still_reports_a_caveat(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_envelope(
                root,
                "secrets-scan",
                summary={"scanner": "none", "hits": 0},
                findings=[],
            )
            summary = agent_summary.build_agent_summary(root)
            self.assertEqual(len(summary["coverage_caveats"]), 1)
            caveat = summary["coverage_caveats"][0]
            self.assertEqual(caveat["title"], "No secrets scanner found")
            self.assertEqual(caveat["severity"], "medium")
            self.assertEqual(caveat["collector"], "secrets-scan")
            self.assertEqual(summary["findings"], [])

    def test_envelope_detection_wins_over_exit_code_2(self):
        # secrets-scan exits 2 when no scanner is installed, even if it
        # wrote an envelope with platform_detected true. The summary follows
        # the envelope and reports the gap as a caveat.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_envelope(
                root,
                "secrets-scan",
                platform_detected=True,
                summary={"scanner": "none"},
                findings=[_finding(
                    "medium",
                    "No secrets scanner found",
                    "Secrets Exposure",
                    1,
                    id="secrets-scan.tool_unavailable",
                )],
            )
            summary = agent_summary.build_agent_summary(root, {
                "secrets-scan": {"exit_code": 2, "raw_status": "not detected"},
            })
            row = summary["collectors"][0]
            self.assertEqual(row["platform_detected"], True)
            self.assertEqual(row["detection_status"], "detected")
            self.assertEqual(summary["collector_errors"], [])
            self.assertEqual(summary["coverage_caveats"][0]["title"], "No secrets scanner found")
            self.assertNotIn(
                "No secrets scanner found",
                [row["title"] for row in summary["findings"]],
            )

    def test_run_status_file_is_used_when_no_tokens_are_passed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "run-status.json").write_text(json.dumps({
                "collectors": [
                    {"collector": "cursor", "exit_code": 3, "detection_status": "error (exit 3)"},
                    {"collector": "not a name", "exit_code": 1, "detection_status": "error (exit 1)"},
                ],
            }), encoding="utf-8")
            summary = agent_summary.build_agent_summary(root)
            self.assertEqual(summary["collector_errors"], [{
                "collector": "cursor",
                "platform_detected": False,
                "detection_status": "error (exit 3)",
            }])
            self.assertNotIn("not a name", json.dumps(summary))

    def test_bad_bytes_are_a_collector_error_and_do_not_abort(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "codex.json").write_bytes(b"\xff\xfe not utf-8 {")
            _write_envelope(root, "claude", findings=[
                _finding("low", "Still here", "General Tooling", 1),
            ])
            summary = agent_summary.build_agent_summary(root)
            errors = {row["collector"]: row["detection_status"] for row in summary["collector_errors"]}
            self.assertEqual(errors["codex"], "parse error")
            self.assertEqual(summary["findings"][0]["title"], "Still here")

    def test_non_finite_evidence_count_does_not_abort(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "claude.json").write_text(
                """{
                  "collector": "claude",
                  "platform_detected": true,
                  "findings": [
                    {
                      "severity": "high",
                      "title": "Huge count",
                      "category": "General Tooling",
                      "evidence_count": 1e309
                    },
                    {
                      "severity": "low",
                      "title": "After the huge count",
                      "category": "General Tooling",
                      "evidence_count": 2
                    }
                  ]
                }""",
                encoding="utf-8",
            )
            summary = agent_summary.build_agent_summary(root)
            by_title = {row["title"]: row["evidence_count"] for row in summary["findings"]}
            self.assertEqual(by_title["Huge count"], 0)
            self.assertEqual(by_title["After the huge count"], 2)

    def test_nonzero_exit_with_an_envelope_is_a_collector_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_envelope(
                root,
                "claude",
                platform_detected=True,
                findings=[
                    _finding("high", "Partial finding", "Shell Execution", 2, id="claude.real"),
                    _finding(
                        "low",
                        "Coverage only",
                        "General Tooling",
                        9,
                        id="claude.coverage",
                        tags=["coverage_gap"],
                    ),
                ],
            )
            summary = agent_summary.build_agent_summary(root, {
                "claude": {"exit_code": 1, "raw_status": "detected"},
            })
            self.assertEqual(summary["collectors"], [])
            self.assertEqual(summary["collector_errors"], [{
                "collector": "claude",
                "platform_detected": True,
                "detection_status": "error (exit 1)",
            }])
            self.assertEqual([row["title"] for row in summary["findings"]], ["Partial finding"])
            self.assertEqual([row["title"] for row in summary["coverage_caveats"]], ["Coverage only"])

    def test_titles_and_categories_are_masked_even_when_redact_is_off(self):
        old = os.environ.pop("AISCAN_REDACT", None)
        try:
            token = "ghp_" + ("a" * 20)
            path = r"C:\build\agent\config.toml"
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                _write_envelope(root, "claude", findings=[
                    _finding("high", f"Config at {path} uses {token}", path, 1),
                ])
                summary = agent_summary.build_agent_summary(root)
            title = summary["findings"][0]["title"]
            category = summary["findings"][0]["category"]
            self.assertNotIn(path, title)
            self.assertNotIn(token, title)
            self.assertIn("****REDACTED:github_pat****", title)
            self.assertIn("<path#", title)
            self.assertNotIn(path, category)
            self.assertTrue(category.startswith("<path#"))
        finally:
            if old is not None:
                os.environ["AISCAN_REDACT"] = old


class TestNewestFolder(unittest.TestCase):
    def _scan(self, parent: Path, name: str) -> Path:
        folder = parent / name
        (folder / "evidence").mkdir(parents=True)
        return folder

    def test_later_timestamp_wins_over_newer_mtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            older = self._scan(root, "20261016-120000")
            newer = self._scan(root, "20261018-090000")
            os.utime(older, (2_000_000_000, 2_000_000_000))
            os.utime(newer, (100, 100))
            (root / "notes.txt").write_text("not a scan", encoding="utf-8")
            self._scan(root, "20261018-090000-extra")  # not a pure timestamp; mtime ~ now
            # The extra folder's mtime is "now", which is before 20261018 only if
            # the clock is before that date. Pin it to an old mtime so the
            # timestamp folder is the one that should win.
            extra = root / "20261018-090000-extra"
            os.utime(extra, (100, 100))
            bare = root / "20261019-000000"
            bare.mkdir()
            self.assertEqual(agent_summary.newest_scan_dir(root).name, "20261018-090000")
            self.assertFalse((bare / "evidence").exists())

    def test_unstamped_folders_use_mtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            alpha = self._scan(root, "alpha")
            beta = self._scan(root, "beta")
            os.utime(alpha, (100, 100))
            os.utime(beta, (200, 200))
            self.assertEqual(agent_summary.newest_scan_dir(root).name, "beta")

    def test_custom_folder_newer_than_a_stamp_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._scan(root, "20200101-000000")
            custom = self._scan(root, "manual")
            os.utime(custom, (2_000_000_000, 2_000_000_000))
            self.assertEqual(agent_summary.newest_scan_dir(root).name, "manual")

    def test_future_stamp_beats_an_old_mtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._scan(root, "20900101-000000")
            custom = self._scan(root, "manual")
            os.utime(custom, (100, 100))
            self.assertEqual(agent_summary.newest_scan_dir(root).name, "20900101-000000")

    def test_newer_partial_does_not_hide_the_full_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            first = parent / "20261001-000000"
            partial = parent / "20261005-000000"
            second = parent / "20261007-000000"
            for name in ("claude", "cursor", "codex", "copilot"):
                _write_envelope(first, name)
            _write_envelope(
                first,
                "claude",
                findings=[_finding("low", "Full finding", "General Tooling", 1)],
            )
            _write_envelope(
                partial,
                "codex",
                findings=[_finding("high", "Partial finding", "Shell Execution", 2)],
            )
            self.assertEqual(agent_summary.newest_scan_dir(parent).name, "20261001-000000")
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                code = agent_summary.main(["--results-root", str(parent)])
            self.assertEqual(code, 0)
            summary = json.loads(out.getvalue())
            titles = [row["title"] for row in summary["findings"]]
            self.assertIn("Full finding", titles)
            self.assertNotIn("Partial finding", titles)
            collectors = {row["collector"] for row in summary["collectors"]}
            self.assertEqual(collectors, {"claude", "cursor", "codex", "copilot"})

            for name in ("claude", "cursor", "codex", "copilot"):
                _write_envelope(second, name)
            _write_envelope(
                second,
                "claude",
                findings=[_finding("medium", "Later full finding", "General Tooling", 1)],
            )
            self.assertEqual(agent_summary.newest_scan_dir(parent).name, "20261007-000000")
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                code = agent_summary.main(["--results-root", str(parent), "--print-id"])
            self.assertEqual(code, 0)
            self.assertEqual(out.getvalue().strip(), "20261007-000000")

    def test_older_extra_collector_does_not_win_forever(self):
        names = (
            "claude", "cowork", "cursor", "codex", "copilot", "chat-history",
            "git-posture", "secrets-scan", "grok", "grok-bot", "pii-scan",
            "accounts",
        )
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            older = parent / "20261001-000000"
            newer = parent / "20261007-000000"
            for name in names:
                _write_envelope(older, name)
            for name in names[:-1]:
                _write_envelope(newer, name)
            self.assertEqual(
                agent_summary.newest_scan_dir(parent).name, "20261007-000000"
            )

    def test_newer_scan_missing_one_collector_is_not_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            older = parent / "20261001-000000"
            newer = parent / "20261007-000000"
            for name in ("claude", "cursor", "codex", "copilot"):
                _write_envelope(older, name)
            for name in ("claude", "cursor", "codex"):
                _write_envelope(newer, name)
            self.assertEqual(
                agent_summary.newest_scan_dir(parent).name, "20261007-000000"
            )

    def test_ignores_directories_without_evidence_and_missing_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertIsNone(agent_summary.newest_scan_dir(root))
            self.assertIsNone(agent_summary.newest_scan_dir(root / "missing"))
            (root / "20261018-090000").mkdir()
            real = self._scan(root, "20261017-090000")
            self.assertEqual(agent_summary.newest_scan_dir(root), real)


class TestCli(unittest.TestCase):
    def test_stdout_is_json_and_matches_the_written_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "20261018-153045"
            _write_envelope(root, "claude", findings=[
                _finding("high", "Kept title", "Shell Execution", 2),
            ])
            out = io.StringIO()
            err = io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = agent_summary.main(["--evidence-root", str(root), "--write"])
            self.assertEqual(code, 0)
            summary = json.loads(out.getvalue())
            self.assertEqual(summary["findings"][0]["title"], "Kept title")
            self.assertNotIn("OUTDIR_ID", out.getvalue())
            self.assertNotIn("OUTDIR_ID", err.getvalue())
            self.assertNotIn(str(root.parent), err.getvalue())
            written = json.loads((root / "evidence" / "agent-summary.json").read_text(encoding="utf-8"))
            self.assertEqual(written, summary)
            status = json.loads((root / "evidence" / "run-status.json").read_text(encoding="utf-8"))
            self.assertEqual(status["collectors"][0]["collector"], "claude")
            self.assertNotIn("LEAK_SENTINEL", json.dumps(status))
            self.assertNotIn("Test User", json.dumps(written))

    def test_results_root_selects_the_newest_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            older = parent / "20261016-120000"
            newer = parent / "20261018-090000"
            _write_envelope(older, "claude", findings=[
                _finding("low", "Old finding", "General Tooling", 1),
            ])
            _write_envelope(newer, "cursor", findings=[
                _finding("high", "New finding", "Shell Execution", 2),
            ])
            os.utime(older, (2_000_000_000, 2_000_000_000))
            out = io.StringIO()
            err = io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = agent_summary.main(["--results-root", str(parent)])
            self.assertEqual(code, 0)
            summary = json.loads(out.getvalue())
            self.assertEqual([row["title"] for row in summary["findings"]], ["New finding"])
            self.assertEqual(summary["collectors"][0]["collector"], "cursor")
            self.assertNotIn("OUTDIR_ID", out.getvalue())
            self.assertNotIn("OUTDIR_ID", err.getvalue())
            self.assertNotIn(str(parent), out.getvalue())

    def test_usage_errors_do_not_print_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "scan"
            _write_envelope(root, "claude")
            out = io.StringIO()
            err = io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = agent_summary.main(["--evidence-root", str(root)])
            self.assertEqual(code, 0)
            self.assertNotIn("OUTDIR_ID", out.getvalue())
            self.assertNotIn("OUTDIR_ID", err.getvalue())
            self.assertFalse((root / "evidence" / "agent-summary.json").exists())

            err = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(err):
                code = agent_summary.main(["--evidence-root", str(root / "missing")])
            self.assertEqual(code, 1)
            self.assertEqual(err.getvalue().strip(), "Output folder not found.")
            self.assertNotIn(str(root), err.getvalue())

            err = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(err):
                code = agent_summary.main(["--results-root", str(root / "empty")])
            self.assertEqual(code, 1)
            self.assertEqual(err.getvalue().strip(), "No scan folders found.")

            err = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(err):
                code = agent_summary.main([])
            self.assertEqual(code, 1)
            self.assertIn("--evidence-root", err.getvalue())

            err = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(err):
                code = agent_summary.main([
                    "--evidence-root", str(root),
                    "--results-root", str(tmp),
                ])
            self.assertEqual(code, 1)
            self.assertIn("only one", err.getvalue())

    def test_print_id_is_the_folder_name_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            older = parent / "20261016-120000"
            newer = parent / "20261018-090000"
            _write_envelope(older, "claude", findings=[
                _finding("low", "Old finding", "General Tooling", 1),
            ])
            _write_envelope(newer, "cursor", findings=[
                _finding("high", "New finding", "Shell Execution", 2),
            ])
            os.utime(older, (2_000_000_000, 2_000_000_000))
            out = io.StringIO()
            err = io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = agent_summary.main(["--results-root", str(parent), "--print-id"])
            self.assertEqual(code, 0)
            self.assertEqual(out.getvalue().strip(), "20261018-090000")
            self.assertEqual(err.getvalue(), "")
            self.assertNotIn(str(parent), out.getvalue())
            self.assertFalse((newer / "evidence" / "agent-summary.json").exists())

    def test_bad_status_token_fails_without_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "evidence").mkdir()
            err = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(err):
                code = agent_summary.main([
                    "--evidence-root", str(root),
                    "--write",
                    "--collector-status", "not a token",
                ])
            self.assertEqual(code, 1)
            self.assertFalse((root / "evidence" / "agent-summary.json").exists())
            self.assertNotIn(str(root), err.getvalue())

    def test_write_failure_still_prints_the_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "scan"
            _write_envelope(root, "claude", findings=[
                _finding("high", "Printed first", "Shell Execution", 1),
            ])
            out = io.StringIO()
            err = io.StringIO()

            def boom(evidence_root, summary, statuses=None):
                self.assertIn("Printed first", out.getvalue())
                raise OSError("read only")

            with redirect_stdout(out), redirect_stderr(err), patch.object(
                agent_summary, "write_summary_files", boom
            ):
                code = agent_summary.main(["--evidence-root", str(root), "--write"])
            self.assertEqual(code, 0)
            self.assertIn("Printed first", out.getvalue())
            self.assertIn("Could not write the agent summary.", err.getvalue())
            self.assertFalse((root / "evidence" / "agent-summary.json").exists())

    def test_rerun_keeps_stored_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_envelope(root, "claude", findings=[
                _finding("low", "Still listed", "General Tooling", 1),
            ])
            evidence = root / "evidence"
            (evidence / "run-status.json").write_text(json.dumps({
                "collectors": [
                    {"collector": "claude", "exit_code": 4, "detection_status": "error (exit 4)"},
                    {"collector": "cursor", "exit_code": 5, "detection_status": "error (exit 5)"},
                ],
            }), encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                code = agent_summary.main([
                    "--evidence-root", str(root),
                    "--write",
                    "--collector-status", "cursor,0,0,0",
                ])
            self.assertEqual(code, 0)
            summary = json.loads(out.getvalue())
            errors = {row["collector"]: row["detection_status"] for row in summary["collector_errors"]}
            self.assertEqual(errors["claude"], "error (exit 4)")
            self.assertEqual(errors["cursor"], "error (exit 0)")
            stored = json.loads((evidence / "run-status.json").read_text(encoding="utf-8"))
            codes = {row["collector"]: row.get("exit_code") for row in stored["collectors"]}
            self.assertEqual(codes["claude"], 4)
            self.assertEqual(codes["cursor"], 0)
            self.assertIn("Still listed", [row["title"] for row in summary["findings"]])


class TestDerivedFilesStayOutOfScanDiff(unittest.TestCase):
    def test_agent_summary_ran_at_does_not_change_previous_scan(self):
        # Imported here so this file does not load core.common before the
        # sanitize tests set USERPROFILE. common snapshots that env at import.
        import scan_diff

        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            middle = parent / "2026-10-05"
            current = parent / "2026-10-07"
            _write_envelope(middle, "claude")
            _write_envelope(current, "claude", ran_at="2026-10-07T00:00:00+00:00")
            (middle / "evidence" / "claude.json").write_text(json.dumps({
                **_envelope("claude"),
                "ran_at": "2026-10-05T00:00:00+00:00",
            }), encoding="utf-8")
            (middle / "evidence" / "agent-summary.json").write_text(json.dumps({
                "collector": "agent-summary",
                "ran_at": "2026-10-09T00:00:00+00:00",
                "findings": [_finding("critical", "LEAK_SENTINEL_DIFF", "General Tooling", 1)],
            }), encoding="utf-8")
            (middle / "evidence" / "run-status.json").write_text("{not json", encoding="utf-8")
            loaded = scan_diff.load_scan(middle)
            self.assertEqual(set(loaded), {"claude"})
            picked = scan_diff.resolve_previous(current, parent)
            self.assertEqual(picked, middle.resolve())


if __name__ == "__main__":
    unittest.main()
