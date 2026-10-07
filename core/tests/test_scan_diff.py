"""Unit tests for scan-to-scan evidence diff and the changes HTML fragment."""

from __future__ import annotations

import io
import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import bootstrap  # noqa: E402,F401
import scan_diff  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "report" / "sections"))
import changes as changes_section  # noqa: E402


def _finding(finding_id, severity, title, category="General Tooling"):
    return {
        "id": finding_id,
        "severity": severity,
        "category": category,
        "title": title,
        "evidence_count": 1,
        "sample_redacted": "",
        "secret_redacted": False,
        "tags": [],
    }


def _rule(rule, rule_type="bash", decision="allow", risk="medium", platform="claude"):
    return {
        "platform": platform,
        "scope": "user",
        "scope_label_redacted": "user#abc123",
        "rule_type": rule_type,
        "rule": rule,
        "decision": decision,
        "command_or_tool_redacted": rule,
        "risk": risk,
        "exposure_category": "Shell Execution" if rule_type == "bash" else "MCP Tooling",
    }


def _write(root: Path, collector: str, **overrides) -> None:
    evidence = root / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    data = {
        "collector": collector,
        "version": "1.0.0",
        "ran_at": "2026-10-07T12:00:00+00:00",
        "host": "DEMO-ENDPOINT",
        "platform_detected": True,
        "scope_hash": "abc",
        "summary": {},
        "findings": [],
        "rules": [],
        "raw_pointers": [],
    }
    data.update(overrides)
    data["collector"] = collector
    (evidence / f"{collector}.json").write_text(
        json.dumps(data), encoding="utf-8"
    )


class TestDiffContent(unittest.TestCase):
    def test_findings_rules_mcp_counters_and_flags(self):
        previous = {
            "claude": {
                "collector": "claude",
                "version": "1.0.0",
                "ran_at": "2026-10-01T00:00:00+00:00",
                "host": "DEMO-ENDPOINT",
                "platform_detected": True,
                "summary": {"total_messages": 10, "model_counts": {"demo": 2}},
                "findings": [
                    _finding("claude.old", "high", "Old high"),
                    _finding("claude.same", "medium", "Same"),
                    _finding("claude.rises", "medium", "Rises"),
                    _finding("claude.falls", "high", "Falls"),
                ],
                "rules": [
                    _rule("Bash(curl:*)", risk="high"),
                    _rule("mcp__slack", rule_type="mcp_tool", risk="medium"),
                    _rule("Bash(ls)", decision="deny", risk="low"),
                ],
            },
            "cursor": {
                "collector": "cursor",
                "version": "1.0.0",
                "ran_at": "2026-10-01T00:00:00+00:00",
                "host": "DEMO-ENDPOINT",
                "platform_detected": True,
                "summary": {
                    "state_tokens": 50,
                    "vscdb_keys_scanned": 100,
                },
                "findings": [],
                "rules": [],
            },
            "grok": {
                "collector": "grok",
                "version": "1.0.0",
                "ran_at": "2026-10-01T00:00:00+00:00",
                "host": "DEMO-ENDPOINT",
                "platform_detected": True,
                "summary": {
                    "mcp_servers": ["alpha"],
                    "mcp_runtime_transports": {"Slack": "stdio"},
                },
                "findings": [],
                "rules": [],
            },
        }
        current = {
            "claude": {
                "collector": "claude",
                "version": "1.0.0",
                "ran_at": "2026-10-07T00:00:00+00:00",
                "host": "DEMO-ENDPOINT",
                "platform_detected": True,
                "summary": {"total_messages": 25, "model_counts": {"demo": 4, "other": 1}},
                "findings": [
                    _finding("claude.same", "medium", "Same"),
                    _finding("claude.rises", "critical", "Rises", "Shell Execution"),
                    _finding("claude.falls", "low", "Falls"),
                    _finding("claude.new_high", "high", "Brand new <script>", "Shell Execution"),
                    _finding("claude.new_low", "low", "Quiet addition"),
                ],
                "rules": [
                    _rule("Bash(*)", risk="high"),
                    _rule("mcp__playwright", rule_type="mcp_tool"),
                    _rule("mcp__slack", rule_type="mcp_tool"),
                    _rule("Bash(ls)", decision="deny", risk="low"),
                ],
            },
            "cursor": {
                "collector": "cursor",
                "version": "1.1.0",
                "ran_at": "2026-10-07T00:00:00+00:00",
                "host": "DEMO-ENDPOINT",
                "platform_detected": True,
                "summary": {
                    "state_tokens": 0,
                    "vscdb_keys_scanned": 100,
                },
                "findings": [],
                "rules": [],
            },
            "grok": {
                "collector": "grok",
                "version": "1.0.0",
                "ran_at": "2026-10-07T00:00:00+00:00",
                "host": "DEMO-ENDPOINT",
                "platform_detected": True,
                "summary": {
                    "mcp_servers": ["alpha", "beta"],
                    "mcp_runtime_transports": {"slack": "stdio"},
                },
                "findings": [],
                "rules": [],
            },
            "copilot": {
                "collector": "copilot",
                "version": "1.0.0",
                "ran_at": "2026-10-07T00:00:00+00:00",
                "host": "DEMO-ENDPOINT",
                "platform_detected": True,
                "summary": {"findings": 0},
                "findings": [],
                "rules": [],
            },
        }
        env = scan_diff.diff_envelopes(
            current, previous, current_label="2026-10-07", previous_label="2026-10-01"
        )
        self.assertEqual(env["collector"], "changes")
        self.assertEqual(env["version"], "1.0.0")
        for key in (
            "collector", "version", "ran_at", "host", "platform_detected",
            "scope_hash", "summary", "findings", "rules", "raw_pointers",
        ):
            self.assertIn(key, env)
        self.assertEqual(env["summary"]["comparison"], "diff")
        self.assertNotIn(str(Path("/tmp")), json.dumps(env))

        claude = env["changes"]["collectors"]["claude"]
        added_ids = {item["id"] for item in claude["findings"]["added"]}
        self.assertEqual(added_ids, {"claude.new_high", "claude.new_low"})
        resolved_ids = {item["id"] for item in claude["findings"]["resolved"]}
        self.assertEqual(resolved_ids, {"claude.old"})
        risen = claude["findings"]["severity_changed"]
        self.assertEqual(
            {(item["id"], item["before"], item["after"]) for item in risen},
            {("claude.rises", "medium", "critical"), ("claude.falls", "high", "low")},
        )
        self.assertEqual(
            [rule["rule"] for rule in claude["rules"]["added"]],
            ["Bash(*)", "mcp__playwright"],
        )
        self.assertEqual([rule["rule"] for rule in claude["rules"]["removed"]], ["Bash(curl:*)"])
        self.assertEqual([rule["rule"] for rule in claude["allow_rules"]["added"]], ["Bash(*)", "mcp__playwright"])
        self.assertEqual(claude["mcp_servers"]["added"], ["playwright"])
        self.assertEqual(claude["mcp_servers"]["removed"], [])
        messages = {item["key"]: item for item in claude["counters"]}
        self.assertEqual(messages["total_messages"], {"key": "total_messages", "before": 10, "after": 25})
        self.assertEqual(messages["model_counts.demo"]["before"], 2)
        self.assertEqual(messages["model_counts.other"], {"key": "model_counts.other", "before": None, "after": 1})

        cursor = env["changes"]["collectors"]["cursor"]
        self.assertEqual([item["kind"] for item in cursor["drift"]], ["data_to_zero", "version_changed"])
        self.assertEqual(cursor["platform"]["change"], "unchanged")
        grok = env["changes"]["collectors"]["grok"]
        self.assertEqual(grok["mcp_servers"]["added"], ["beta"])
        self.assertEqual(grok["mcp_servers"]["removed"], [])
        self.assertEqual(grok["drift"], [])
        # Bookkeeping that did not move is not a counter row.
        self.assertNotIn("vscdb_keys_scanned", {item["key"] for item in cursor["counters"]})
        self.assertIn("state_tokens", {item["key"] for item in cursor["counters"]})

        copilot = env["changes"]["collectors"]["copilot"]
        self.assertEqual(copilot["platform"]["change"], "newly_detected")
        self.assertEqual(copilot["drift"], [])

        ids = {f["id"] for f in env["findings"]}
        self.assertIn("changes.finding.new.claude.claude.new_high", ids)
        self.assertNotIn("changes.finding.new.claude.claude.new_low", ids)
        self.assertTrue(any(i.startswith("changes.finding.escalated.claude.claude.rises") for i in ids))
        self.assertFalse(any("claude.falls" in i for i in ids))
        self.assertIn("changes.mcp.added.claude.playwright", ids)
        self.assertIn("changes.mcp.added.grok.beta", ids)
        self.assertTrue(any(i.startswith("changes.allow.added.claude.") for i in ids))
        self.assertFalse(any("mcp__playwright" in (f.get("sample_redacted") or "") and "new_allow_rule" in f["tags"] for f in env["findings"]))
        self.assertIn("changes.drift.cursor.data_to_zero", ids)
        self.assertIn("changes.drift.cursor.version_changed", ids)
        drift_finding = next(f for f in env["findings"] if f["id"] == "changes.drift.cursor.data_to_zero")
        self.assertEqual(drift_finding["severity"], "high")
        self.assertIn("data_location_drift", drift_finding["tags"])
        self.assertIn("Possible data-location drift", drift_finding["title"])
        version_finding = next(f for f in env["findings"] if f["id"] == "changes.drift.cursor.version_changed")
        self.assertEqual(version_finding["severity"], "medium")
        self.assertIn(
            ("new_high_finding",),
            {tuple(f["tags"]) for f in env["findings"] if f["severity"] == "high" and "drift" not in f["id"]},
        )

    def test_not_detected_when_platform_disappears(self):
        previous = {
            "cowork": {
                "collector": "cowork",
                "version": "1.0.0",
                "platform_detected": True,
                "summary": {"sessions": 3},
                "findings": [_finding("cowork.sessions.present", "low", "Sessions")],
                "rules": [],
            }
        }
        current = {
            "cowork": {
                "collector": "cowork",
                "version": "1.0.0",
                "platform_detected": False,
                "summary": {"sessions": 0},
                "findings": [],
                "rules": [],
            }
        }
        env = scan_diff.diff_envelopes(current, previous, current_label="now", previous_label="then")
        drift = env["changes"]["collectors"]["cowork"]["drift"]
        self.assertEqual([item["kind"] for item in drift], ["not_detected"])
        self.assertEqual(env["changes"]["collectors"]["cowork"]["platform"]["change"], "no_longer_detected")
        self.assertEqual(env["summary"]["platforms_no_longer_detected"], 1)

    def test_partial_counter_drop_is_not_drift(self):
        previous = {
            "chat-history": {
                "collector": "chat-history",
                "version": "1.0.0",
                "platform_detected": True,
                "summary": {"total_messages": 10, "state_tokens": 5},
                "findings": [],
                "rules": [],
            }
        }
        current = {
            "chat-history": {
                "collector": "chat-history",
                "version": "1.0.0",
                "platform_detected": True,
                "summary": {"total_messages": 12, "state_tokens": 0},
                "findings": [],
                "rules": [],
            }
        }
        env = scan_diff.diff_envelopes(current, previous)
        entry = env["changes"]["collectors"]["chat-history"]
        self.assertEqual(entry["drift"], [])
        self.assertEqual(len(entry["counters"]), 2)

    def test_identical_scans_have_no_material_changes(self):
        body = {
            "demo": {
                "collector": "demo",
                "version": "1.0.0",
                "platform_detected": True,
                "summary": {"total_messages": 3, "enabled": True},
                "findings": [_finding("demo.one", "low", "One")],
                "rules": [_rule("Bash(ls)")],
            }
        }
        env = scan_diff.diff_envelopes(body, body, current_label="b", previous_label="a")
        self.assertEqual(env["summary"]["comparison"], "diff")
        self.assertEqual(env["summary"]["collectors_changed"], 0)
        self.assertEqual(env["findings"], [])
        self.assertEqual(env["changes"]["collectors"], {})

    def test_first_scan_when_previous_is_none(self):
        current = {
            "claude": {
                "collector": "claude",
                "version": "1.0.0",
                "ran_at": "2026-10-07T00:00:00+00:00",
                "host": "DEMO-ENDPOINT",
                "platform_detected": True,
                "summary": {"rules": 1},
                "findings": [_finding("claude.x", "critical", "Already here")],
                "rules": [],
            }
        }
        env = scan_diff.diff_envelopes(current, None, current_label="2026-10-07")
        self.assertEqual(env["summary"]["comparison"], "first_scan")
        self.assertEqual(env["findings"], [])
        self.assertEqual(env["summary"]["drift_warnings"], 0)
        self.assertEqual(env["summary"]["collectors_compared"], 1)
        self.assertEqual(env["changes"]["collectors"], {})

    def test_empty_previous_dict_is_a_real_diff(self):
        current = {
            "claude": {
                "collector": "claude",
                "version": "1.0.0",
                "platform_detected": True,
                "summary": {},
                "findings": [_finding("claude.x", "high", "New")],
                "rules": [],
            }
        }
        env = scan_diff.diff_envelopes(current, {}, current_label="now", previous_label="empty")
        self.assertEqual(env["summary"]["comparison"], "diff")
        self.assertEqual(env["changes"]["collectors"]["claude"]["platform"]["change"], "newly_detected")
        self.assertIn("changes.finding.new.claude.claude.x", {f["id"] for f in env["findings"]})


class TestHistorySelection(unittest.TestCase):
    def test_auto_pick_skips_newer_and_self_and_non_scans(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            older = root / "2026-10-01"
            middle = root / "2026-10-05"
            current = root / "2026-10-07"
            newer = root / "2026-10-08"
            notes = root / "notes"
            notes.mkdir()
            (notes / "readme.txt").write_text("not a scan", encoding="utf-8")
            _write(older, "claude", ran_at="2026-10-01T00:00:00+00:00", summary={"total_messages": 1})
            _write(middle, "claude", ran_at="2026-10-05T00:00:00+00:00", summary={"total_messages": 2})
            _write(current, "claude", ran_at="2026-10-07T00:00:00+00:00", summary={"total_messages": 3})
            _write(newer, "claude", ran_at="2026-10-08T00:00:00+00:00", summary={"total_messages": 4})
            # A future changes.json must not hide the real earlier ran_at.
            (middle / "evidence" / "changes.json").write_text(json.dumps({
                "collector": "changes",
                "version": "1.0.0",
                "ran_at": "2026-10-09T00:00:00+00:00",
                "summary": {},
                "findings": [],
                "rules": [],
            }), encoding="utf-8")
            picked = scan_diff.resolve_previous(current, root)
            self.assertEqual(picked, middle.resolve())
            loaded = scan_diff.load_scan(middle)
            self.assertEqual(set(loaded), {"claude"})

    def test_main_writes_changes_and_dry_run_does_not(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous = root / "2026-10-01"
            current = root / "2026-10-07"
            _write(previous, "claude", ran_at="2026-10-01T00:00:00+00:00", summary={"total_messages": 1})
            _write(
                current,
                "claude",
                ran_at="2026-10-07T00:00:00+00:00",
                summary={"total_messages": 4},
                findings=[_finding("claude.new_high", "critical", "New critical")],
            )
            buf = io.StringIO()
            err = io.StringIO()
            with redirect_stdout(buf), redirect_stderr(err):
                code = scan_diff.main(["--current", str(current), "--dry-run"])
            self.assertEqual(code, 0)
            self.assertFalse((current / "evidence" / "changes.json").exists())
            self.assertIn('"collector": "changes"', buf.getvalue())

            buf = io.StringIO()
            with redirect_stdout(buf), redirect_stderr(io.StringIO()):
                code = scan_diff.main(["--current", str(current)])
            self.assertEqual(code, 0)
            written = json.loads((current / "evidence" / "changes.json").read_text(encoding="utf-8"))
            self.assertEqual(written["summary"]["previous_label"], "2026-10-01")
            self.assertEqual(written["summary"]["counters_moved"], 1)
            self.assertGreaterEqual(written["summary"]["new_high_or_critical"], 1)
            self.assertNotIn(str(root), json.dumps(written))

    def test_main_first_scan_and_errors(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current = root / "only"
            _write(current, "claude", ran_at="2026-10-07T00:00:00+00:00")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = scan_diff.main(["--current", str(current)])
            self.assertEqual(code, 0)
            written = scan_diff.load_changes_envelope(current)
            self.assertIsNotNone(written)
            self.assertEqual(written["summary"]["comparison"], "first_scan")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(scan_diff.main(["--current", str(root / "missing")]), 1)
                self.assertEqual(
                    scan_diff.main(["--current", str(current), "--previous", str(current)]),
                    1,
                )
                self.assertEqual(
                    scan_diff.main(["--current", str(current), "--history-root", str(root / "nope")]),
                    1,
                )


class TestRenderer(unittest.TestCase):
    def test_empty_without_evidence(self):
        self.assertEqual(changes_section.render_changes_section(None), "")
        self.assertEqual(changes_section.render_changes_section({}), "")
        self.assertEqual(changes_section.render_changes_nav(None), "")
        self.assertEqual(changes_section.render_changes_nav({}), "")

    def test_first_scan_message_and_nav(self):
        env = scan_diff.diff_envelopes(
            {"claude": {
                "collector": "claude",
                "version": "1.0.0",
                "ran_at": "2026-10-07T00:00:00+00:00",
                "host": "DEMO-ENDPOINT",
                "platform_detected": True,
                "summary": {},
                "findings": [],
                "rules": [],
            }},
            None,
            current_label="2026-10-07",
        )
        html = changes_section.render_changes_section(env)
        self.assertIn("first scan", html.lower())
        self.assertIn('id="changes"', html)
        self.assertIn("Nothing to compare yet.", html)
        nav = changes_section.render_changes_nav(env)
        self.assertIn('href="#changes"', nav)
        self.assertIn("Changes", nav)

    def test_section_escapes_and_shows_drift(self):
        previous = {
            "cursor": {
                "collector": "cursor",
                "version": "1.0.0",
                "ran_at": "2026-10-01T08:00:00+00:00",
                "host": "DEMO-ENDPOINT",
                "platform_detected": True,
                "summary": {"state_tokens": 9},
                "findings": [_finding("cursor.tokens", "low", "Tokens <script>alert(1)</script>")],
                "rules": [],
            }
        }
        current = {
            "cursor": {
                "collector": "cursor",
                "version": "1.0.0",
                "ran_at": "2026-10-07T09:30:00+00:00",
                "host": "DEMO-ENDPOINT",
                "platform_detected": True,
                "summary": {"state_tokens": 0},
                "findings": [],
                "rules": [],
            }
        }
        env = scan_diff.diff_envelopes(
            current, previous, current_label="2026-10-07", previous_label="2026-10-01"
        )
        html = changes_section.render_changes_section(env)
        self.assertIn("Possible data-location drift", html)
        self.assertIn("Do not read that as a clean scan.", html)
        self.assertIn("state_tokens", html)
        self.assertIn(">9<", html)
        self.assertIn(">0<", html)
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn('class="section"', html)
        self.assertIn('class="pill high"', html)
        self.assertIn('class="mcp-table"', html)
        self.assertNotEqual(changes_section.render_changes_nav(env), "")

    def test_quiet_diff_is_not_an_empty_string(self):
        body = {
            "demo": {
                "collector": "demo",
                "version": "1.0.0",
                "ran_at": "2026-10-07T00:00:00+00:00",
                "host": "DEMO-ENDPOINT",
                "platform_detected": True,
                "summary": {"total_messages": 1},
                "findings": [],
                "rules": [],
            }
        }
        env = scan_diff.diff_envelopes(body, dict(body), current_label="b", previous_label="a")
        html = changes_section.render_changes_section(env)
        self.assertIn("No material changes", html)
        self.assertNotEqual(html, "")


class TestSyntheticPrevious(unittest.TestCase):
    def test_sample_pair_tells_the_drift_story(self):
        current = REPO / "samples" / "synthetic-demo"
        previous = REPO / "samples" / "synthetic-previous"
        env = scan_diff.build_changes_envelope(current, previous)
        self.assertEqual(env["summary"]["comparison"], "diff")
        self.assertEqual(env["summary"]["previous_label"], "synthetic-previous")
        self.assertEqual(env["summary"]["current_label"], "synthetic-demo")
        collectors = env["changes"]["collectors"]
        self.assertIn("data_to_zero", {item["kind"] for item in collectors["cursor"]["drift"]})
        self.assertIn("not_detected", {item["kind"] for item in collectors["cowork"]["drift"]})
        self.assertIn("version_changed", {item["kind"] for item in collectors["grok"]["drift"]})
        self.assertEqual(collectors["copilot"]["platform"]["change"], "newly_detected")
        added = {item["id"] for item in collectors["claude"]["findings"]["added"]}
        self.assertIn("claude.permission.skip_dangerous_prompt", added)
        resolved = {item["id"] for item in collectors["claude"]["findings"]["resolved"]}
        self.assertIn("claude.permission.bash_curl", resolved)
        self.assertIn("playwright", collectors["claude"]["mcp_servers"]["added"])
        self.assertIn("slack", collectors["claude"]["mcp_servers"]["removed"])
        self.assertIn("filesystem", collectors["cursor"]["mcp_servers"]["removed"])
        severity = {
            (item["id"], item["before"], item["after"])
            for item in collectors["secrets-scan"]["findings"]["severity_changed"]
        }
        self.assertIn(("secrets-scan.hit", "medium", "high"), severity)
        messages = {
            item["key"]: (item["before"], item["after"])
            for item in collectors["chat-history"]["counters"]
        }
        self.assertEqual(messages["total_messages"], (100, 340))
        ids = {f["id"] for f in env["findings"]}
        self.assertIn("changes.drift.cursor.data_to_zero", ids)
        self.assertIn("changes.drift.cowork.not_detected", ids)
        self.assertTrue(any("skip_dangerous_prompt" in i for i in ids))
        blob = json.dumps(env)
        self.assertNotIn("Users", blob)
        self.assertNotIn("C:\\", blob)
        html = changes_section.render_changes_section(env)
        self.assertIn("Possible data-location drift", html)
        self.assertIn("cursor", html)
        self.assertNotEqual(changes_section.render_changes_nav(env), "")


if __name__ == "__main__":
    unittest.main()
