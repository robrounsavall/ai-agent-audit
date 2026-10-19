"""Grouping and severity for secrets-scan findings. Synthetic hits only."""

from __future__ import annotations

import csv
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"

import bootstrap  # noqa: E402,F401

_mod_path = Path(__file__).resolve().parent.parent / "secrets-scan.py"
_spec = importlib.util.spec_from_file_location("secrets_scan_grouping", _mod_path)
ss = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(ss)


def _hit(rule: str, file: str, secret: str, line: int = 1) -> dict:
    return {"rule": rule, "file": file, "line": line, "secret": secret, "tags": []}


class TestSeverityMap(unittest.TestCase):
    def test_known_high_impact_rules_are_critical(self):
        critical = (
            "aws-access-token",
            "AWS",
            "AWS Access Token",
            "github-pat",
            "GitHub",
            "private-key",
            "private key",
            "PrivateKey",
            "slack-bot-token",
            "stripe-access-token",
            "openai-api-key",
            "npm-access-token",
            "gitlab-pat",
            "gcp-api-key",
        )
        for rule in critical:
            with self.subTest(rule=rule):
                self.assertEqual(ss.severity_for_rule(rule), "critical")

    def test_unknown_and_substring_lookalikes_stay_high(self):
        high = (
            "generic-api-key",
            "curl-auth-user",
            "jwt",
            "made-up-scanner-rule",
            "aws-docs-example",
            "privateai-api-token",
            "slack-webhook-url",
            "",
        )
        for rule in high:
            with self.subTest(rule=rule):
                self.assertEqual(ss.severity_for_rule(rule), "high")
                self.assertEqual(ss.severity_for_rule(rule), ss.DEFAULT_SECRET_SEVERITY)


class TestGroupSecretHits(unittest.TestCase):
    def test_counts_files_and_severity(self):
        aws = "AKIA" + "C" * 16
        other = "ASIA" + "D" * 16
        generic = "abcd1234" * 4
        hits = [
            _hit("aws-access-token", "notes/a.txt", aws, 1),
            _hit("aws-access-token", "notes/a.txt", other, 2),
            _hit("AWS Access Token", "notes/b.txt", aws, 3),
            _hit("generic-api-key", "notes/c.txt", generic, 4),
            _hit("generic-api-key", "", generic, 5),
            _hit("made-up-scanner-rule", "notes/c.txt", generic, 6),
        ]
        findings = ss.group_secret_hits(hits, "gitleaks")
        self.assertEqual(len(findings), 3)
        by_severity = {item["severity"]: item for item in findings}
        aws_row = next(item for item in findings if item["severity"] == "critical")
        self.assertEqual(aws_row["evidence_count"], 3)
        self.assertIn("3 hit(s) across 2 file(s)", aws_row["title"])
        self.assertIn("Secret detected by gitleaks:", aws_row["title"])
        self.assertNotIn(aws, json.dumps(aws_row))
        self.assertEqual(aws_row["id"], "secrets_scan.aws-access-token")

        generic_row = next(item for item in findings if "generic-api-key" in item["title"])
        self.assertEqual(generic_row["severity"], "high")
        self.assertEqual(generic_row["evidence_count"], 2)
        self.assertIn("2 hit(s) across 1 file(s)", generic_row["title"])

        unknown = next(item for item in findings if "made-up-scanner-rule" in item["title"])
        self.assertEqual(unknown["severity"], "high")
        self.assertEqual(unknown["evidence_count"], 1)
        self.assertIn("1 hit(s) across 1 file(s)", unknown["title"])
        self.assertEqual(findings[0]["evidence_count"], 3)
        self.assertEqual(set(by_severity), {"critical", "high"})

    def test_legacy_id_shape_and_no_zero_file_clause(self):
        self.assertEqual(ss.secret_finding_id("AWS Access Token"), "secrets_scan.aws_access_token")
        self.assertEqual(ss.secret_finding_id("aws-access-token"), "secrets_scan.aws-access-token")
        stem = "r" * 40
        first = ss.secret_finding_id(stem + "-one")
        second = ss.secret_finding_id(stem + "-two")
        self.assertNotEqual(first, second)
        self.assertTrue(first.startswith("secrets_scan." + stem + "_"))
        self.assertTrue(second.startswith("secrets_scan." + stem + "_"))

        findings = ss.group_secret_hits(
            [_hit("generic-api-key", "", "abcd1234" * 4)],
            "gitleaks",
        )
        self.assertEqual(len(findings), 1)
        self.assertIn("(1 hit(s))", findings[0]["title"])
        self.assertNotIn("across", findings[0]["title"])
        self.assertEqual(findings[0]["placeholder_count"], 0)

    def test_placeholder_count_is_every_example_hit(self):
        findings = ss.group_secret_hits(
            [
                _hit("generic-api-key", "a.txt", "YOUR_API_KEY_HERE"),
                _hit("generic-api-key", "b.txt", "YOUR_TOKEN_HERE"),
                _hit("generic-api-key", "c.txt", "abcd1234" * 4),
            ],
            "gitleaks",
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["evidence_count"], 3)
        self.assertEqual(findings[0]["placeholder_count"], 2)
        self.assertEqual(findings[0]["severity"], "high")

    def test_same_rule_splits_when_severity_differs(self):
        calls = {"n": 0}

        def flip(_rule: str) -> str:
            calls["n"] += 1
            return "critical" if calls["n"] == 1 else "high"

        hits = [
            _hit("same-rule", "a.txt", "x" * 12),
            _hit("same-rule", "b.txt", "y" * 12),
        ]
        with mock.patch.object(ss, "severity_for_rule", side_effect=flip):
            findings = ss.group_secret_hits(hits, "gitleaks")
        self.assertEqual(len(findings), 2)
        self.assertEqual({item["severity"] for item in findings}, {"critical", "high"})
        self.assertTrue(all(item["evidence_count"] == 1 for item in findings))


class TestCollectGrouping(unittest.TestCase):
    def test_csv_keeps_one_row_per_hit(self):
        raw = [
            {
                "RuleID": "aws-access-token",
                "File": "notes/a.txt",
                "StartLine": 1,
                "Secret": "AKIA" + "C" * 16,
            },
            {
                "RuleID": "aws-access-token",
                "File": "notes/b.txt",
                "StartLine": 4,
                "Secret": "ASIA" + "D" * 16,
            },
            {
                "RuleID": "generic-api-key",
                "File": "notes/c.txt",
                "StartLine": 8,
                "Secret": "abcd1234" * 4,
            },
        ]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "chat-history").mkdir()
            out = root / "secrets-scan"
            with mock.patch.object(ss, "find_scanner", return_value=("gitleaks", "gitleaks")), mock.patch.object(
                ss, "run_gitleaks", return_value=(raw, None)
            ):
                envelope, ok, hits = ss.collect(root, [], out)
            self.assertTrue(ok)
            self.assertEqual(len(hits), 3)
            secret_rows = [item for item in envelope["findings"] if item["id"].startswith("secrets_scan.")]
            self.assertEqual(len(secret_rows), 2)
            aws_row = next(item for item in secret_rows if item["severity"] == "critical")
            self.assertEqual(aws_row["evidence_count"], 2)
            self.assertIn("2 hit(s) across 2 file(s)", aws_row["title"])
            self.assertNotIn("AKIA" + "C" * 16, json.dumps(envelope))
            self.assertNotIn("ASIA" + "D" * 16, json.dumps(envelope))
            with (out / "findings.csv").open(encoding="utf-8", newline="") as handle:
                rows = list(csv.reader(handle))
            self.assertEqual(rows[0], ["file", "line", "rule", "sample_redacted"])
            self.assertEqual(len(rows), 4)
            self.assertEqual([row[2] for row in rows[1:]], ["aws-access-token", "aws-access-token", "generic-api-key"])


class TestOutputDirExcluded(unittest.TestCase):
    def _run(self, raw: Path, repo: Path, out: Path, exclude: list[Path]) -> list[Path]:
        seen: list[Path] = []

        def fake_gitleaks(target, _bin):
            seen.append(Path(target).resolve())
            return [], None

        with mock.patch.object(ss, "find_scanner", return_value=("gitleaks", "gitleaks")), mock.patch.object(
            ss, "run_gitleaks", side_effect=fake_gitleaks
        ):
            ss.collect(raw, [repo], out, exclude_roots=exclude)
        return seen

    def test_repo_scan_skips_outdir_and_keeps_chat_corpus(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "repo"
            evidence = repo / "aiscan-out"
            raw = evidence / "raw"
            chat = raw / "chat-history"
            chat.mkdir(parents=True)
            (chat / "chat.txt").write_text("hello\n", encoding="utf-8")
            out = raw / "secrets-scan"
            out.mkdir()
            (out / "findings.csv").write_text("file,line,rule\n", encoding="utf-8")
            (evidence / "evidence").mkdir()
            (repo / "src").mkdir()
            (repo / "src" / "app.txt").write_text("code\n", encoding="utf-8")
            seen = self._run(raw, repo, out, [evidence, evidence / "evidence", out])
            self.assertIn(chat.resolve(), seen)
            self.assertIn((repo / "src").resolve(), seen)
            for path in seen:
                if path == chat.resolve():
                    continue
                self.assertFalse(path == evidence.resolve() or evidence.resolve() in path.parents, path)

    def test_repo_used_as_outdir_still_scans_source(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            raw = repo / "raw"
            chat = raw / "chat-history"
            chat.mkdir(parents=True)
            out = raw / "secrets-scan"
            out.mkdir()
            (repo / "evidence").mkdir()
            (repo / "src").mkdir()
            (repo / "src" / "app.txt").write_text("code\n", encoding="utf-8")
            seen = self._run(raw, repo, out, [repo, repo / "evidence", out])
            self.assertIn((repo / "src").resolve(), seen)
            self.assertIn(chat.resolve(), seen)
            for path in seen:
                self.assertNotEqual(path, out.resolve())
                self.assertNotIn(out.resolve(), path.parents)
                self.assertNotEqual(path, (repo / "evidence").resolve())
                self.assertNotIn((repo / "evidence").resolve(), path.parents)


if __name__ == "__main__":
    unittest.main()
