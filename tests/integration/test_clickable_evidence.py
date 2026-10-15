"""Clickable evidence cards and opt-in local links in the briefing."""

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
import urllib.parse
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
BRIEFING_PATH = ROOT / "report" / "build-briefing.py"

SECRET = "ghp_" + "Zq9" * 12
AWS = "AKIA" + "Q7" * 8
PII = "4111" + "1111" + "1111" + "1111"
PROFILE = "C:\\Users\\Test User"
ENV_PATH = PROFILE + "\\proj#1\\.env"
OTHER_PATH = PROFILE + "\\proj#1\\config\\app.env"
PII_PATH = PROFILE + "\\docs\\cards.txt"


def _load_briefing():
    spec = importlib.util.spec_from_file_location("clickable_briefing", BRIEFING_PATH)
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


def _finding(fid: str, title: str, **extra) -> dict:
    row = {
        "id": fid,
        "severity": "high",
        "category": "Secrets",
        "title": title,
        "evidence_count": 1,
        "first_seen": "2026-10-01T00:00:00Z",
        "last_seen": "2026-10-07T00:00:00Z",
        "sample_redacted": "",
        "secret_redacted": False,
        "tags": [],
    }
    row.update(extra)
    return row


def _write_csv(path: Path, header: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)


class TestClickableEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.briefing = _load_briefing()

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.sample = self.briefing.redact_sample(SECRET, "github-pat")
        self.aws_sample = self.briefing.redact_sample(AWS, "aws-access-token")
        self.pii_sample = self.briefing.redact_sample(PII, "CREDIT_CARD")
        self._build_fixture()

    def _build_fixture(self, extra_findings=None):
        evidence = self.root / "evidence"
        evidence.mkdir()
        secret_rows = [
            _finding(
                "secrets-scan.github-pat.1",
                "Secret detected by gitleaks: github-pat",
                sample_redacted=self.sample,
                secret_redacted=True,
                raw_evidence_ref="raw/secrets-scan/findings.csv",
            ),
            _finding(
                "secrets-scan.github-pat.2",
                "Secret detected by gitleaks: github-pat",
                sample_redacted=self.sample,
                secret_redacted=True,
                raw_evidence_ref="raw/secrets-scan/findings.csv",
            ),
            _finding(
                "secrets-scan.aws.1",
                "Secret detected by gitleaks: aws-access-token",
                sample_redacted=self.aws_sample,
                secret_redacted=True,
                raw_evidence_ref="raw/secrets-scan/findings.csv",
            ),
        ]
        (evidence / "secrets-scan.json").write_text(
            json.dumps(_envelope("secrets-scan", findings=secret_rows)), encoding="utf-8"
        )
        pii_rows = [
            _finding(
                "pii_scan.credit_card",
                "CREDIT_CARD detected (1 hit(s) across 1 file(s))",
                category="PII Exposure",
                sample_redacted=self.pii_sample,
                tags=["pii"],
                raw_evidence_ref="raw/pii-scan/findings.csv",
            )
        ]
        (evidence / "pii-scan.json").write_text(
            json.dumps(_envelope("pii-scan", findings=pii_rows)), encoding="utf-8"
        )
        codex = [
            _finding("codex.bare", "Bare finding with nothing", category="General Tooling", severity="low")
        ] + list(extra_findings or [])
        (evidence / "codex.json").write_text(
            json.dumps(_envelope("codex", findings=codex)), encoding="utf-8"
        )
        _write_csv(
            self.root / "raw" / "secrets-scan" / "findings.csv",
            ["file", "line", "rule", "sample_redacted"],
            [
                [ENV_PATH, "3", "github-pat", self.sample],
                [OTHER_PATH, "9", "GitHub-PAT", self.sample],
                [ENV_PATH, "7", "aws-access-token", self.aws_sample],
            ],
        )
        _write_csv(
            self.root / "raw" / "pii-scan" / "findings.csv",
            ["file", "entity", "score", "line", "sample"],
            [[PII_PATH, "CREDIT_CARD", "0.95", "12", PII]],
        )

    def _html(self, **kwargs) -> str:
        with mock.patch.dict(os.environ, {"AISCAN_REDACT": ""}):
            return self.briefing.build_html(self.root, customer="Acme", operator="Op", **kwargs)

    # 1
    def test_local_file_uri(self):
        uri = self.briefing.local_file_uri
        self.assertEqual(
            uri("C:\\Users\\Test User\\.claude\\settings.json"),
            "file:///C:/Users/Test%20User/.claude/settings.json",
        )
        self.assertEqual(
            uri("C:\\Users\\Test User\\proj#1\\100% done\\x.txt"),
            "file:///C:/Users/Test%20User/proj%231/100%25%20done/x.txt",
        )
        self.assertEqual(
            uri("\\\\fileserver\\share\\Team Docs\\a.env"),
            "file://fileserver/share/Team%20Docs/a.env",
        )
        self.assertEqual(uri("D:\\café\\ü.txt"), "file:///D:/caf%C3%A9/%C3%BC.txt")
        self.assertEqual(
            self.briefing.local_folder_uri("C:\\Users\\Test User\\.claude\\settings.json"),
            "file:///C:/Users/Test%20User/.claude/",
        )
        self.assertEqual(uri("C:\\Users\\you", is_dir=True), "file:///C:/Users/you/")
        self.assertEqual(uri("/home/me/dir", is_dir=True), "file:///home/me/dir/")
        self.assertEqual(uri("/home/me/a b.txt"), "file:///home/me/a%20b.txt")
        self.assertIsNone(uri("relative\\path.txt"))
        self.assertIsNone(uri(""))
        self.assertIsNone(uri("\\\\?\\C:\\very\\long"))
        self.assertEqual(uri("/mnt/c/Users/Me/x y.txt"), "file:///C:/Users/Me/x%20y.txt")

    def _assert_no_leaks(self, doc: str):
        for value in (SECRET, AWS, PII):
            for variant in (
                value,
                html.escape(value),
                urllib.parse.quote(value),
                urllib.parse.quote(value, safe=""),
            ):
                self.assertNotIn(variant, doc)
        for part in (self.sample, self.aws_sample, self.pii_sample):
            self.assertIn(html.escape(part), doc)

    # 2
    def test_secrets_and_pii_never_in_html(self):
        self._assert_no_leaks(self._html())
        self._assert_no_leaks(self._html(local_links=True))

    # 3
    def test_local_links_off(self):
        common = sys.modules["common"]
        with mock.patch.object(common, "USERPROFILE", Path(PROFILE)):
            doc = self._html()
        self.assertNotIn("file:", doc)
        self.assertNotIn('class="copy-path"', doc)
        self.assertNotIn("data-path=", doc)
        self.assertNotIn("Test User", doc)
        self.assertNotIn(ENV_PATH, doc)
        self.assertNotIn("noindex", doc)
        self.assertNotIn(str(self.root), doc)
        self.assertIn("&lt;userprofile&gt;", doc)

    def test_local_links_off_hashes_non_profile_paths(self):
        doc = self._html()
        self.assertNotIn("Test User", doc)
        self.assertNotIn("proj#1", doc)
        self.assertIn("&lt;path#", doc)

    # 4
    def test_local_links_on(self):
        doc = self._html(local_links=True)
        folder = "file:///C:/Users/Test%20User/proj%231/"
        self.assertIn(f'<a class="folder-link" href="{folder}" target="_blank" rel="noopener">Folder ↗</a>', doc)
        self.assertIn(f'<button type="button" class="copy-path" data-path="{html.escape(ENV_PATH)}">Copy path</button>', doc)
        self.assertIn('<meta name="robots" content="noindex"', doc)
        self.assertIn("Contains local file paths. Don't share this file. Build without -LocalLinks for a shareable copy.", doc.replace("&#x27;", "'"))
        self.assertIn("local-links-banner", doc)
        raw = (self.root.resolve() / "raw/secrets-scan/findings.csv").as_uri()
        self.assertIn(f'href="{raw}"', doc)

    # 5
    def test_redact_env_forces_links_off(self):
        with mock.patch.dict(os.environ, {"AISCAN_REDACT": "1"}), mock.patch("sys.stderr") as err:
            doc = self.briefing.build_html(self.root, customer="A", operator="B", local_links=True)
        self.assertNotIn("file:", doc)
        self.assertNotIn("data-path=", doc)
        self.assertNotIn("noindex", doc)
        written = "".join(str(c.args[0]) for c in err.write.call_args_list)
        self.assertIn("-Redact turns off -LocalLinks", written)

    # 6
    def test_no_evidence_and_every_row_has_card(self):
        doc = self._html()
        self.assertIn('<p class="ev-none">No detail recorded by this collector.</p>', doc)
        rows = re.findall(r'<tr class="frow".*?</tr>', doc, re.S)
        self.assertTrue(rows)
        for row in rows:
            self.assertIn('<details class="ev"><summary>', row)

    # 7
    def test_grouped_secret_keeps_both_locations(self):
        doc = self._html(local_links=True)
        self.assertIn("2 scanner rows", doc)
        self.assertIn(html.escape(ENV_PATH), doc)
        self.assertIn(html.escape(OTHER_PATH), doc)
        self.assertIn("<details class='hit-files'><summary>2 files</summary>", doc)
        findings, _ = self.briefing.present_findings(
            self.briefing.aggregate_findings(self.briefing.load_evidence(self.root))
        )
        grouped = [f for f in findings if f.get("_grouped_members") == 2]
        self.assertEqual(len(grouped), 1)
        ctx = self.briefing.EvidenceContext(self.root, False)
        self.assertEqual({(l["path"], l["line"]) for l in ctx.locations(grouped[0])}, {(ENV_PATH, "3"), (OTHER_PATH, "9")})

    def test_pii_location_fields(self):
        doc = self._html(local_links=True)
        self.assertIn(html.escape(PII_PATH), doc)
        self.assertIn("line 12", doc)
        self.assertIn("score 0.95", doc)

    # 8
    def test_hostile_strings_are_escaped(self):
        evil = 'C:\\Users\\you\\<script>alert(1)</script>"\'.env'
        self.root.joinpath("evidence", "codex.json").write_text(
            json.dumps(
                _envelope(
                    "codex",
                    findings=[
                        _finding(
                            "codex.evil",
                            "Evil <script>alert(2)</script>",
                            sample_redacted="<script>alert(3)</script>",
                            file=evil,
                            weird_key="<script>alert(4)</script>",
                        )
                    ],
                )
            ),
            encoding="utf-8",
        )
        _write_csv(
            self.root / "raw" / "secrets-scan" / "findings.csv",
            ["file", "line", "rule", "sample_redacted"],
            [[evil, "1", "github-pat", self.sample]],
        )
        for links in (False, True):
            doc = self._html(local_links=links)
            self.assertNotIn("<script>alert", doc)
            self.assertNotIn('"\'.env', doc)

    def test_bad_csv_is_tolerated(self):
        (self.root / "raw" / "pii-scan" / "findings.csv").write_bytes(b"\xef\xbb\xbf\xff\x00garbage\n\"unterminated")
        (self.root / "raw" / "secrets-scan" / "findings.csv").unlink()
        self.assertIn("<details", self._html())

    def _set_codex(self, **extra):
        self.root.joinpath("evidence", "codex.json").write_text(
            json.dumps(_envelope("codex", findings=[_finding("codex.x", "Extra fields", **extra)])),
            encoding="utf-8",
        )

    # fix1 #1
    def test_extra_fields_scalar_only_and_no_secrets(self):
        fake = "ghp_" + "Ab7" * 12
        self._set_codex(
            token=fake,
            nested={"deep": {"value": fake}},
            plain_note="hello " + fake,
            tools=["a", "b"],
            leaked_redacted="kept",
        )
        for links in (False, True):
            doc = self._html(local_links=links)
            self.assertNotIn(fake, doc)
            self.assertNotIn(html.escape(fake), doc)
            self.assertIn("(structured value omitted)", doc)
            self.assertIn("a, b", doc)
            self.assertIn("kept", doc)
            self.assertNotIn("<dt>token</dt>", doc)
            self.assertIn("****REDACTED", doc)

    # fix1 #2
    def test_path_display_links_off(self):
        s = self.briefing._safe_display_path
        self.assertEqual(s("raw/secrets-scan/findings.csv"), "raw/secrets-scan/findings.csv")
        self.assertEqual(s("evidence/x.json"), "evidence/x.json")
        for bad in (
            "\\\\?\\C:\\very\\long\\x.env",
            "file:///home/bob/secret/x.env",
            "\\\\fileserver\\share\\a.env",
            "/var/private/stuff/x.env",
        ):
            out = s(bad)
            self.assertTrue(out.startswith("<path#"), out)
            self.assertNotIn("private", out)
            self.assertNotIn("fileserver", out)
            self.assertNotIn("bob", out)

    def test_card_paths_hidden_links_off(self):
        bad = "/var/private/stuff/x.env"
        self._set_codex(raw_evidence_ref=bad, note="see file:///home/bob/x and " + bad)
        cards = "".join(re.findall(r'<details class="ev">.*?</details>', self._html(), re.S))
        self.assertIn("ev-card", cards)
        self.assertNotIn("/var/private", cards)
        self.assertNotIn("bob", cards)

    def test_overflow_note_hidden_links_off(self):
        ref = "\\\\?\\C:\\Secret Dir\\findings.csv"
        rows = [[f"{PROFILE}\\d{i}\\.env", str(i), "github-pat", self.sample] for i in range(25)]
        _write_csv(self.root / "raw" / "secrets-scan" / "findings.csv", ["file", "line", "rule", "sample_redacted"], rows)
        data = json.loads((self.root / "evidence" / "secrets-scan.json").read_text("utf-8"))
        for f in data["findings"]:
            f["raw_evidence_ref"] = ref
        (self.root / "evidence" / "secrets-scan.json").write_text(json.dumps(data), encoding="utf-8")
        cards = "".join(re.findall(r'<details class="ev">.*?</details>', self._html(), re.S))
        self.assertIn("more in", cards)
        self.assertNotIn("Secret Dir", cards)

    # fix1 #3
    def test_loose_redacted_sample_is_rereducted(self):
        loose = "private...unmasked-password"
        _write_csv(
            self.root / "raw" / "pii-scan" / "findings.csv",
            ["file", "entity", "score", "line", "sample_redacted"],
            [[PII_PATH, "CREDIT_CARD", "0.9", "1", loose]],
        )
        ctx = self.briefing.EvidenceContext(self.root, False)
        samples = [l["sample"] for l in ctx._pii["credit_card"]]
        self.assertEqual(samples, [self.briefing.redact_sample(loose, "CREDIT_CARD")])
        self.assertTrue(self.briefing._looks_redacted(self.sample))
        self.assertTrue(self.briefing._looks_redacted("****REDACTED:x****"))
        self.assertNotIn(loose, self._html())

    def test_secret_sample_equal_to_rule_allowed(self):
        _write_csv(
            self.root / "raw" / "secrets-scan" / "findings.csv",
            ["file", "line", "rule", "sample_redacted"],
            [[ENV_PATH, "1", "github-pat", "github-pat"]],
        )
        ctx = self.briefing.EvidenceContext(self.root, False)
        self.assertEqual(ctx._secrets["github-pat"][0][1]["sample"], "github-pat")

    # fix1 #4
    def test_trailing_space_path_preserved(self):
        self.assertEqual(self.briefing.local_file_uri("/home/me/a "), "file:///home/me/a%20")
        self.assertIsNone(self.briefing.local_file_uri("   "))


    # fix2
    def _cards(self, **kwargs) -> str:
        doc = self._html(**kwargs)
        return "".join(re.findall(r'<details class="ev">.*?</details>', doc, re.S)) + "".join(
            re.findall(r"<details class='hit-files'>.*?</details>", doc, re.S)
        )

    def test_fix2_tokens_and_emails_links_off(self):
        tok = "ghp_" + "Kd4" * 12
        email = "victim.person@example.com"
        self._set_codex(
            tags=[tok, "/var/private/stuff/x.env"],
            raw_evidence_ref="/var/private/" + tok,
            file="C:\\Users\\you\\" + tok,
            owner=email,
            extra_note="mail " + email,
            **{"bad key " + tok: "dropped", "ok.key": "shown", "nest": {"a": 1}},
        )
        _write_csv(
            self.root / "raw" / "pii-scan" / "findings.csv",
            ["file", "entity", "score", "line", "sample"],
            [[PII_PATH, tok, tok, "1" + tok, PII], [PII_PATH, "CREDIT_CARD", "0.123456", "4", PII]],
        )
        _write_csv(
            self.root / "raw" / "secrets-scan" / "findings.csv",
            ["file", "line", "rule", "sample_redacted"],
            [[ENV_PATH, "", "bad/rule!" + tok, self.sample]],
        )
        cards = self._cards()
        for bad in (tok, "victim.person", "example.com", "/var/private", "bob", "bad key", "Test User"):
            self.assertNotIn(bad, cards)
        self.assertIn("ok.key", cards)
        self.assertIn("score 0.123", cards)
        self.assertNotIn("0.123456", cards)
        self.assertIn("(structured value omitted)", cards)
        ctx = self.briefing.EvidenceContext(self.root, False)
        self.assertEqual(ctx._pii[tok.lower()][0]["score"], "")
        self.assertEqual(ctx._pii[tok.lower()][0]["line"], "")
        self.assertIn("unknown rule", ctx._secrets)

    def test_fix2_links_on_masks_text_keeps_clean_links(self):
        tok = "ghp_" + "Kd4" * 12
        email = "victim.person@example.com"
        self._set_codex(owner=email, tags=[tok], raw_evidence_ref="raw/" + tok + ".csv")
        cards = self._cards(local_links=True)
        for bad in (tok, "victim.person", "example.com"):
            self.assertNotIn(bad, cards)
        self.assertIn("(EMAIL)", cards)

    def test_fix2_secret_path_has_no_copy_or_link(self):
        bad_path = "C:\\Users\\Test User\\" + SECRET + "\\x.env"
        _write_csv(
            self.root / "raw" / "secrets-scan" / "findings.csv",
            ["file", "line", "rule", "sample_redacted"],
            [[bad_path, "1", "github-pat", self.sample]],
        )
        doc = self._html(local_links=True)
        self.assertNotIn(SECRET, doc)
        self.assertNotIn(urllib.parse.quote(SECRET), doc)
        self.assertNotIn("Users\\Test User\\ghp_", doc.replace("&#x27;", "'"))
        self.assertNotIn("Users/Test%20User/ghp_", doc)
        self.assertNotIn("Zq9Zq9Zq9Zq9", doc)
        _write_csv(
            self.root / "raw" / "secrets-scan" / "findings.csv",
            ["file", "line", "rule", "sample_redacted"],
            [[bad_path, "1", "github-pat", self.sample]],
        )
        ctx = self.briefing.EvidenceContext(self.root, True)
        self.assertEqual(ctx.path_html(bad_path).count("copy-path"), 0)
        self.assertNotIn("folder-link", ctx.path_html(bad_path))
        self.assertIn("copy-path", ctx.path_html(ENV_PATH))


if __name__ == "__main__":
    unittest.main()
