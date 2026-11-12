"""The bundle gate: what is dropped, what is masked, what is refused."""

from __future__ import annotations

import json
import unittest

import bootstrap
from bootstrap import envelope, finding, raw_bundle

import hub_bundle
from hub_bundle import BundleError, build_bundle, normalize_bundle, scan_uid

T1 = "2026-10-01T12:00:00+00:00"
# Built at run time so the repo's scrub gate does not see a key-shaped literal.
FAKE_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"
FAKE_PATH = "C:" + "\\Users\\" + "someone\\proj\\app.env"


class NormalizeTests(unittest.TestCase):
    def test_raw_fields_never_survive(self):
        raw = raw_bundle(T1, {"claude": [finding("a.b", raw_evidence_ref="raw/x.csv")]})
        raw["collectors"]["claude"]["raw_pointers"] = [{"kind": "chat", "path": "raw/chat/1.md"}]
        raw["collectors"]["claude"]["summary"] = {"n": 1, "nested": {"raw_pointers": ["raw/y"]}}
        clean, _ = normalize_bundle(raw)
        text = json.dumps(clean)
        self.assertNotIn("raw_pointers", text)
        self.assertNotIn("raw_evidence_ref", text)
        self.assertNotIn("raw/", text)

    def test_unknown_fields_are_dropped(self):
        raw = raw_bundle(T1, {"claude": [finding("a.b", surprise="keep me?")]})
        raw["collectors"]["claude"]["transcript"] = "user said hello"
        raw["extra_top_level"] = {"anything": 1}
        clean, _ = normalize_bundle(raw)
        text = json.dumps(clean)
        self.assertNotIn("surprise", text)
        self.assertNotIn("transcript", text)
        self.assertNotIn("extra_top_level", text)

    def test_unsupported_schema_major_is_skipped_with_a_warning(self):
        raw = raw_bundle(T1, {"claude": [finding("a.b")], "future": envelope("future", T1, version="2.0.0")})
        clean, warnings = normalize_bundle(raw)
        self.assertEqual(list(clean["collectors"]), ["claude"])
        self.assertTrue(any("future" in w and "not supported" in w for w in warnings))

    def test_bundle_with_no_readable_collectors_is_refused(self):
        with self.assertRaises(BundleError):
            normalize_bundle(raw_bundle(T1, {"x": envelope("x", T1, version="9.1.0")}))
        with self.assertRaises(BundleError):
            normalize_bundle({"bundle_version": 1, "collectors": {}})
        with self.assertRaises(BundleError):
            normalize_bundle({"bundle_version": 99, "collectors": {"a": {}}})
        with self.assertRaises(BundleError):
            normalize_bundle(["not", "an", "object"])

    def test_unsafe_collector_name_is_skipped(self):
        raw = raw_bundle(T1, {"claude": [finding("a.b")]})
        raw["collectors"]["../../etc"] = envelope("x", T1)
        clean, warnings = normalize_bundle(raw)
        self.assertEqual(list(clean["collectors"]), ["claude"])
        self.assertTrue(warnings)

    def test_local_bundle_keeps_the_text_the_scan_wrote(self):
        sample = f"key={FAKE_KEY} at {FAKE_PATH}"
        clean, _ = normalize_bundle(raw_bundle(T1, {"claude": [finding("a.b", sample_redacted=sample)]}))
        self.assertEqual(clean["collectors"]["claude"]["findings"][0]["sample_redacted"], sample)
        self.assertFalse(clean["share_safe"])

    def test_share_safe_masks_secrets_paths_emails_and_scope_names(self):
        sample = f"key={FAKE_KEY} at {FAKE_PATH} mailto dev@example.com"
        rule = bootstrap.allow_rule("Bash(curl -H 'Authorization: Bearer abcdef123456' https://x.example)")
        rule["scope_label_redacted"] = "project:secret-project-name"
        raw = raw_bundle(T1, {"claude": envelope("claude", T1, [finding("a.b", sample_redacted=sample)], [rule])})
        raw["collectors"]["accounts"] = envelope("accounts", T1, accounts=[
            {"tool": "codex", "signed_in": "yes", "account": "dev@example.com", "access_token": "nope"}
        ])
        clean, _ = normalize_bundle(raw, share_safe=True)
        text = json.dumps(clean)
        self.assertTrue(clean["share_safe"])
        self.assertNotIn(FAKE_KEY, text)
        self.assertNotIn("someone", text)
        self.assertNotIn("dev@example.com", text)
        self.assertNotIn("abcdef123456", text)
        self.assertNotIn("secret-project-name", text)
        self.assertNotIn("access_token", text)
        self.assertRegex(clean["collectors"]["claude"]["rules"][0]["scope_label_redacted"], r"^project#[0-9a-f]{12}$")
        self.assertEqual(clean["collectors"]["accounts"]["accounts"][0]["account"], "<email>")

    def test_share_safe_twice_is_stable(self):
        rule = bootstrap.allow_rule("Bash(ls)")
        rule["scope_label_redacted"] = "project:name"
        raw = raw_bundle(T1, {"claude": envelope("claude", T1, [finding("a.b", sample_redacted=f"x {FAKE_KEY}")], [rule])})
        once, _ = normalize_bundle(raw, share_safe=True)
        twice, _ = normalize_bundle(once, share_safe=True, keep_emails=True, scrub_paths=False)
        self.assertEqual(once["collectors"], twice["collectors"])
        self.assertEqual(scan_uid(once), scan_uid(twice))

    def test_keep_emails(self):
        raw = raw_bundle(T1, {"accounts": envelope("accounts", T1, accounts=[{"tool": "git", "account": "dev@example.com"}])})
        clean, _ = normalize_bundle(raw, share_safe=True, keep_emails=True)
        self.assertEqual(clean["collectors"]["accounts"]["accounts"][0]["account"], "dev@example.com")

    def test_caps_are_applied(self):
        many = [finding(f"f.{i}") for i in range(hub_bundle.MAX_FINDINGS + 5)]
        clean, warnings = normalize_bundle(raw_bundle(T1, {"claude": many}))
        self.assertEqual(len(clean["collectors"]["claude"]["findings"]), hub_bundle.MAX_FINDINGS)
        self.assertTrue(any("kept the first" in w for w in warnings))
        long_title, _ = normalize_bundle(raw_bundle(T1, {"claude": [finding("a.b", title="x" * 9000)]}))
        self.assertEqual(len(long_title["collectors"]["claude"]["findings"][0]["title"]), 500)

    def test_host_is_made_safe(self):
        raw = raw_bundle(T1, {"claude": [finding("a.b")]}, host='bad"><script>host')
        clean, _ = normalize_bundle(raw)
        self.assertRegex(clean["host"], r"^[A-Za-z0-9_.-]+$")

    def test_to_utc(self):
        self.assertEqual(hub_bundle.to_utc("2026-10-01T08:00:00-04:00"), "2026-10-01T12:00:00Z")
        self.assertEqual(hub_bundle.to_utc("2026-10-01T12:00:00"), "2026-10-01T12:00:00Z")
        self.assertEqual(hub_bundle.to_utc("not a time"), "")
        self.assertEqual(hub_bundle.to_utc(None), "")


class BuildBundleTests(unittest.TestCase):
    def test_build_from_the_synthetic_demo_folder(self):
        bundle, _ = build_bundle(bootstrap.REPO_ROOT / "samples" / "synthetic-demo")
        self.assertEqual(bundle["host"], "DEMO-ENDPOINT")
        self.assertIn("claude", bundle["collectors"])
        # The old copilot envelope is stored under its new name.
        self.assertIn("vscode", bundle["collectors"])
        self.assertNotIn("copilot", bundle["collectors"])
        self.assertNotIn("changes", bundle["collectors"])
        self.assertNotIn("agent-summary", bundle["collectors"])
        self.assertEqual(bundle["collector_status"]["claude"], "detected")

    def test_same_folder_gives_the_same_uid(self):
        first, _ = build_bundle(bootstrap.REPO_ROOT / "samples" / "synthetic-demo")
        second, _ = build_bundle(bootstrap.REPO_ROOT / "samples" / "synthetic-demo")
        self.assertEqual(scan_uid(first), scan_uid(second))

    def test_not_a_scan_folder(self):
        with self.assertRaises(BundleError):
            build_bundle(bootstrap.REPO_ROOT / "docs")


if __name__ == "__main__":
    unittest.main()
