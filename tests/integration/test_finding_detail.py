"""The finding detail panel: what to do, where each value is, and who may see it.

Three builds of the same scan folder are compared. The default build and the
-LocalLinks build must never contain a matched value or transcript text.
Only the -ShowSecrets build may, and -Redact turns that off.
"""

from __future__ import annotations

import csv
import html
import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
BRIEFING_PATH = ROOT / "report" / "build-briefing.py"

GH = "ghp_" + "Zq9" * 12
VENDOR = "sk-ant-" + "api03-" + "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2"
HEX40 = "3f2b9c1d4e5a6b7c8d9e" * 2
CARD = "4539" + " 5787 6362 1486"
PROFILE = "C:\\Users\\Test User"
EXPORT = PROFILE + "\\scan\\raw\\chat-history\\claude\\2026-10-28.md"
SESSION = PROFILE + "\\.claude\\projects\\C--Users-Test-User-code-billing\\7c1f0a52.jsonl"
NATIVE = PROFILE + "\\.codex\\sessions\\2026\\10\\28\\rollout-1.jsonl"
REPO = PROFILE + "\\code\\billing"
BEFORE = "export GITHUB_TOKEN="
AFTER = " # pasted by the operator"


def _load_briefing():
    spec = importlib.util.spec_from_file_location("finding_detail_briefing", BRIEFING_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _envelope(collector: str, findings: list[dict], rules: list[dict] | None = None) -> dict:
    return {
        "collector": collector, "version": "1.0.0", "ran_at": "2026-10-28T12:00:00+00:00",
        "host": "DEMO-ENDPOINT", "platform_detected": True, "scope_hash": "abcd",
        "summary": {}, "findings": findings, "rules": rules or [], "raw_pointers": [],
    }


def _finding(fid: str, title: str, category: str, **extra) -> dict:
    row = {
        "id": fid, "severity": "high", "category": category, "title": title,
        "evidence_count": 1, "first_seen": "", "last_seen": "", "sample_redacted": "",
        "secret_redacted": False, "tags": [],
    }
    row.update(extra)
    return row


def _write_csv(path: Path, header: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)


class TestFindingDetail(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.briefing = _load_briefing()

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        evidence = self.root / "evidence"
        evidence.mkdir()
        (evidence / "chat-history.json").write_text(json.dumps(_envelope("chat-history", [
            _finding(
                "chat_history.secret.claude", "Chat transcripts contain potential secrets (claude)",
                "Secrets Exposure", sample_redacted="1 files flagged", secret_redacted=True,
                raw_evidence_ref="raw/chat-history-hits/secret-hits.csv", hit_count=3,
            ),
        ])), encoding="utf-8")
        (evidence / "pii-scan.json").write_text(json.dumps(_envelope("pii-scan", [
            _finding(
                "pii_scan.secret_vendor_token", "SECRET_VENDOR_TOKEN detected (1 hit(s) across 1 file(s))",
                "PII Exposure", tags=["pii", "secret"], raw_evidence_ref="raw/pii-scan/findings.csv",
            ),
            _finding(
                "pii_scan.credit_card", "CREDIT_CARD detected (1 hit(s) across 1 file(s))",
                "PII Exposure", tags=["pii"], raw_evidence_ref="raw/pii-scan/findings.csv",
            ),
        ])), encoding="utf-8")
        (evidence / "git-posture.json").write_text(json.dumps(_envelope("git-posture", [
            _finding(
                "git.env.in_history", ".env file found in git commit history (1 repo)", "Git Posture",
                sample_redacted="project:billing", raw_evidence_ref="raw/git-posture/locations.csv",
            ),
        ])), encoding="utf-8")
        (evidence / "codex.json").write_text(json.dumps(_envelope("codex", [
            _finding("codex.trust.broad", "Codex has 2 trusted projects", "General Tooling"),
            _finding("codex.made_up.finding", "No guide for this one", "General Tooling"),
        ], rules=[
            {"platform": "codex", "scope": "user", "scope_label_redacted": "user:billing",
             "rule_type": "other", "rule": "trust_level=trusted", "decision": "allow",
             "exposure_category": "General Tooling", "source_kind": "user_config"},
            {"platform": "codex", "scope": "user", "scope_label_redacted": "user:other",
             "rule_type": "bash", "rule": "Bash(ls)", "decision": "allow",
             "exposure_category": "Shell Execution"},
        ])), encoding="utf-8")
        _write_csv(
            self.root / "raw" / "chat-history-hits" / "secret-hits.csv",
            ["tool", "file", "line", "col", "type", "sample", "before", "after", "source", "workspace", "role", "time"],
            [
                ["claude", EXPORT, "13", "21", "github_pat", GH, BEFORE, AFTER, SESSION, "billing", "user", "2026-10-28T09:14:02"],
                ["claude", EXPORT, "40", "7", "github_pat", GH, "again ", "", SESSION, "billing", "assistant", "2026-10-28T09:15:00"],
                ["claude", EXPORT, "52", "9", "hex_secret", HEX40, "commit ", "", SESSION, "billing", "assistant", "2026-10-28T09:16:00"],
            ],
        )
        _write_csv(
            self.root / "raw" / "pii-scan" / "findings.csv",
            ["file", "entity", "score", "line", "sample", "col", "before", "after"],
            [
                [NATIVE, "SECRET_VENDOR_TOKEN", "1.0", "88", VENDOR, "1204", "Bearer ", '"'],
                [NATIVE, "CREDIT_CARD", "1.0", "91", CARD, "33", "card ", " declined"],
            ],
        )
        _write_csv(
            self.root / "raw" / "git-posture" / "locations.csv",
            ["finding", "repo", "path", "commit", "date", "note"],
            [["git.env.in_history", REPO, "config/.env", "0d21db6", "2026-09-01", "removed from HEAD, still in history"]],
        )

    def _html(self, redact: str = "", **kwargs) -> str:
        common = sys.modules["common"]
        with mock.patch.dict(os.environ, {"AISCAN_REDACT": redact}), \
                mock.patch.object(common, "USERPROFILE", Path(PROFILE)), \
                mock.patch("sys.stderr"):
            return self.briefing.build_html(self.root, customer="Acme", operator="Op", **kwargs)

    def _assert_no_values(self, doc: str) -> None:
        for value in (GH, VENDOR, CARD, HEX40):
            self.assertNotIn(value, doc)
            self.assertNotIn(html.escape(value), doc)
        self.assertNotIn(BEFORE, doc)
        self.assertNotIn(AFTER.strip(), doc)
        self.assertNotIn('class="hit-ctx"', doc)
        self.assertNotIn("Copy value", doc)

    def test_default_build_shows_where_and_what_to_do_without_values(self):
        doc = self._html()
        self._assert_no_values(doc)
        # Location: tool, message, line and column, both files.
        self.assertIn("line 13, column 21", doc)
        self.assertIn("Claude Code", doc)
        self.assertIn("user message", doc)
        self.assertIn("Original session log", doc)
        self.assertIn("2 locations in 1 file", doc)
        self.assertIn("3 locations in 1 file, 2 distinct values", doc)
        # Guidance.
        self.assertIn("Rotate before you delete.", doc)
        self.assertIn("~/.claude/projects/", doc)
        self.assertIn("git filter-repo", doc)
        self.assertIn("Values are masked in this copy.", doc)
        # A shareable build has no local paths, no links, and no username,
        # including the dashed form Claude Code uses in project folder names.
        self.assertNotIn("Test User", doc)
        self.assertNotIn("Test-User", doc)
        self.assertNotIn("vscode://", doc)
        self.assertNotIn("Contains secret values", doc)
        self.assertIn("C--Users-&lt;user&gt;-code-billing", doc)

    def test_username_is_scrubbed_in_every_spelling_a_tool_folds_it_into(self):
        common = sys.modules["common"]
        with mock.patch.object(common, "USERPROFILE", Path(PROFILE)):
            scrub = self.briefing._scrub_user_slug
            self.assertEqual(scrub("C--Users-Test-User-code"), "C--Users-<user>-code")
            # Grok percent-encodes the workspace path into a folder name.
            self.assertEqual(scrub("C%3A%5CUsers%5CTest%20User%5Ccode"), "C%3A%5CUsers%5C<user>%5Ccode")
            self.assertEqual(scrub("c%3A%2FUsers%2Ftest%20user%2Fcode"), "c%3A%2FUsers%2F<user>%2Fcode")
            self.assertEqual(scrub("ContestUserland"), "ContestUserland")
        with mock.patch.object(common, "USERPROFILE", Path("C:\\Users\\me")):
            # A one-word name is left to redact_paths: it is too short to
            # replace safely inside other words.
            self.assertEqual(self.briefing._scrub_user_slug("C--Users-me-code"), "C--Users-me-code")

    def test_local_links_build_has_paths_and_editor_links_but_no_values(self):
        doc = self._html(local_links=True)
        self._assert_no_values(doc)
        self.assertIn(html.escape(SESSION), doc)
        self.assertIn(
            'href="vscode://file/C:/Users/Test%20User/scan/raw/chat-history/claude/2026-10-28.md:13:21"',
            doc,
        )
        self.assertIn('href="cursor://file/C:/Users/Test%20User/.codex/sessions/2026/10/28/rollout-1.jsonl:88:1204"', doc)
        self.assertNotIn("Contains secret values", doc)

    def test_show_secrets_build_has_values_context_and_a_warning(self):
        doc = self._html(show_secrets=True)
        self.assertIn(f'<code class="hit-secret">{GH}</code>', doc)
        self.assertIn(
            f'<pre class="hit-ctx">{html.escape(BEFORE)}<mark class="hit-secret">{GH}</mark>{html.escape(AFTER)}</pre>',
            doc,
        )
        self.assertIn(f'data-label="Copy value" data-path="{VENDOR}"', doc)
        self.assertIn(CARD, doc)
        self.assertIn('class="local-links-banner secrets-banner"', doc)
        self.assertIn("Contains secret values", doc)
        self.assertIn('<meta name="robots" content="noindex"', doc)
        self.assertIn("vscode://file/", doc)
        self.assertNotIn("Values are masked in this copy.", doc)
        # The per-type action and the hash-length note sit beside each value.
        self.assertIn("Revoke this token in GitHub", doc)
        self.assertIn("the length of a git commit id", doc)

    def test_redact_turns_show_secrets_off(self):
        doc = self._html(redact="1", show_secrets=True)
        self._assert_no_values(doc)
        self.assertNotIn("Contains secret values", doc)
        self.assertNotIn("vscode://", doc)
        self.assertNotIn("Test User", doc)

    def test_named_credentials_come_before_the_length_only_matches(self):
        doc = self._html(show_secrets=True)
        self.assertLess(doc.index(f'<code class="hit-secret">{GH}</code>'), doc.index(f'<code class="hit-secret">{HEX40}</code>'))
        self.assertIn("hit-group--unlikely", doc)

    def test_git_finding_lists_the_repo_path_and_commit(self):
        doc = self._html(local_links=True)
        self.assertIn(html.escape(REPO), doc)
        self.assertIn("config/.env", doc)
        self.assertIn("added in commit <code>0d21db6</code> on 2026-09-01", doc)
        self.assertIn("removed from HEAD, still in history", doc)

    def test_permission_finding_lists_its_own_rules_only(self):
        doc = self._html()
        self.assertIn("Rules behind this finding", doc)
        block = doc[doc.index("Rules behind this finding"):]
        block = block[: block.index("</table>")]
        self.assertIn("trust_level=trusted", block)
        self.assertNotIn("Bash(ls)", block)

    def test_every_row_still_has_one_card_and_unknown_ids_degrade(self):
        doc = self._html()
        rows = re.findall(r'<tr class="frow"', doc)
        self.assertEqual(doc.count('class="ev-card"'), len(rows))
        self.assertIn("No detail recorded by this collector.", doc)

    def test_hostile_hit_rows_are_escaped(self):
        evil = '<script>alert(1)</script>"\''
        _write_csv(
            self.root / "raw" / "chat-history-hits" / "secret-hits.csv",
            ["tool", "file", "line", "col", "type", "sample", "before", "after", "source", "workspace", "role", "time"],
            [["claude", EXPORT + evil, "1" + evil, "2", "github_pat", GH + evil, evil, evil, evil, evil, evil, evil]],
        )
        for kwargs in ({}, {"local_links": True}, {"show_secrets": True}):
            doc = self._html(**kwargs)
            self.assertNotIn("<script>alert", doc)

    def test_older_scan_without_positions_still_renders(self):
        # Before per-hit rows, a secret was one row per type per file at line 0
        # with the type name in the sample column.
        _write_csv(
            self.root / "raw" / "pii-scan" / "findings.csv",
            ["file", "entity", "score", "line", "sample"],
            [[NATIVE, "SECRET_VENDOR_TOKEN", "1.0", "0", "vendor_token"]],
        )
        (self.root / "raw" / "chat-history-hits" / "secret-hits.csv").unlink()
        doc = self._html(show_secrets=True)
        self.assertIn("position not recorded by this scan", doc)
        self.assertIn("ev-card", doc)


class TestRemediation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _load_briefing()
        import remediation

        cls.remediation = remediation

    def test_every_secret_type_has_a_label_an_action_and_a_guide(self):
        import common

        for name, _pattern in common.SECRET_PATTERNS:
            self.assertIn(name, self.remediation.SECRET_LABELS, name)
            self.assertIn(name, self.remediation.SECRET_ACTIONS, name)
            guide = self.remediation.guidance_for({"id": f"pii_scan.secret_{name}"})
            self.assertTrue(guide and guide["steps"], name)

    def test_lookup_order(self):
        g = self.remediation.guidance_for
        self.assertIn("bypassPermissions", g({"id": "claude.permission.bypass_mode"})["steps"][0])
        self.assertIn("~/.codex/sessions", " ".join(g({"id": "chat_history.secret.codex"})["steps"]))
        self.assertIn("Rotate the credential.", g({"id": "grok.mcp.env_secret"})["steps"])
        self.assertIn("syntax error", g({"id": "vscode.config.parse_error"})["steps"][0])
        self.assertIn("PCI", g({"id": "pii_scan.credit_card"})["risk"])
        fallback = g({"id": "new.unknown.id", "category": "Network Egress"})
        self.assertIn("off the machine", fallback["risk"])
        self.assertIsNone(g({"id": "new.unknown.id", "category": "No Such Category"}))

    def test_guides_are_plain_text_with_https_links(self):
        for guide in self.remediation._EXACT.values():
            self.assertTrue(guide["risk"].strip())
            self.assertTrue(guide["steps"])
            for _label, url in guide.get("links", []):
                self.assertTrue(url.startswith("https://"), url)


if __name__ == "__main__":
    unittest.main()
