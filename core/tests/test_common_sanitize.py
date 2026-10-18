"""Unit tests for core sanitization and envelope helpers."""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"
# These tests exercise masking behavior; redaction is opt-in (default is
# unredacted), so turn it on explicitly.
os.environ["AISCAN_REDACT"] = "1"

import bootstrap  # noqa: E402,F401
import common  # noqa: E402
from common import (  # noqa: E402
    clip_sanitized,
    make_envelope,
    make_finding,
    make_rule,
    mask_secrets,
    redact_paths,
    redact_sample,
    sanitize_text,
    sha256_short,
)


class TestSanitize(unittest.TestCase):
    def test_mask_aws_key(self):
        key = "AKIA" + "C" * 16
        out = mask_secrets(f"export KEY={key}")
        self.assertNotIn(key, out)
        self.assertIn("REDACTED:aws_key", out)

    def test_redact_userprofile_path(self):
        raw = r"C:\Users\Test User\.claude\settings.json"
        out = redact_paths(raw)
        self.assertNotIn("Test User", out)
        self.assertIn("<userprofile>", out.lower().replace("<userprofile>", "<userprofile>") or True)
        self.assertNotIn(r"C:\Users\Test User", out)

    def test_sanitize_combined(self):
        key = "AKIA" + "D" * 16
        raw = rf"C:\Users\Test User\secret {key}"
        out = sanitize_text(raw)
        self.assertNotIn(key, out)
        self.assertNotIn(r"C:\Users\Test User", out)

    def test_make_rule_redacts_sample(self):
        key = "AKIA" + "E" * 16
        rule = make_rule(
            "claude", "user", "global", "bash", f"Bash(curl {key})", "allow",
            command_or_tool="curl",
        )
        self.assertEqual(rule["decision"], "allow")
        self.assertNotIn(key, rule["rule"])
        self.assertTrue(rule["scope_label_redacted"].startswith("user#"))

    def test_make_finding_redacts_sample(self):
        key = "AKIA" + "F" * 16
        f = make_finding(
            "test.id", "high", "Shell Execution", "Test",
            sample_redacted=f"token={key}",
        )
        self.assertNotIn(key, f["sample_redacted"])

    def test_envelope_shape(self):
        env = make_envelope("claude", "1.0.0", "abc", platform_detected=True)
        for key in ("collector", "version", "ran_at", "host", "platform_detected",
                    "scope_hash", "summary", "findings", "rules", "raw_pointers"):
            self.assertIn(key, env)
        self.assertEqual(env["collector"], "claude")

    def test_sha256_short_stable(self):
        self.assertEqual(sha256_short("x"), sha256_short("x"))
        self.assertEqual(len(sha256_short("x")), 12)

    def test_make_finding_redacts_title_and_dates(self):
        token = "sk-ant-" + "test1234"
        path = r"C:\Users\Test User\notes"
        finding = make_finding(
            "test.id",
            "high",
            "Shell Execution",
            f"Server {token} at {path}",
            first_seen=path,
            last_seen=token,
            sample_redacted="plain",
        )
        blob = finding["title"] + finding["first_seen"] + finding["last_seen"]
        self.assertNotIn(token, blob)
        self.assertNotIn("Test User", blob)
        self.assertNotIn(path, blob)
        self.assertEqual(finding["sample_redacted"], "plain")

    def test_make_finding_keeps_title_when_redaction_is_off(self):
        title = "Server " + ("sk-ant-" + "test1234")
        with patch.dict(os.environ, {"AISCAN_REDACT": ""}):
            finding = make_finding(
                "test.id", "low", "General Tooling", title, sample_redacted="plain",
            )
        self.assertEqual(finding["title"], title)

    def test_redact_sample_hides_short_secrets(self):
        for length in (9, 12, 23):
            secret = "k" * length
            self.assertEqual(redact_sample(secret, "demo"), "****REDACTED:demo****")
            self.assertNotIn("k", redact_sample(secret, "demo"))
        self.assertEqual(redact_sample("c" * 24, "demo"), "ccc...ccc (demo)")
        self.assertEqual(redact_sample("c" * 32, "demo"), "cccc...cccc (demo)")
        long = "START" + ("m" * 30) + "END!!"
        shown = redact_sample(long, "demo")
        self.assertEqual(shown, "START...END!! (demo)")
        self.assertNotIn("mmmm", shown)
        visible = shown.split(" (", 1)[0].replace("...", "")
        self.assertLessEqual(len(visible), len(long) // 4)

    def test_mask_dashed_vendor_and_context_secrets(self):
        ant = "sk-ant-" + "test1234"
        proj = "sk-proj-" + "abcd-efgh"
        xai = "xai-" + "synthonly"
        google = "AIza" + "SyDemoKey12345"
        bearer = "Bearer " + "synth-token-99"
        header = "Authorization: Basic " + "abcdef12"
        password = "password=" + "s3cret-demo"
        url = "https://ada:" + "s3cret@files.example/a"
        out = mask_secrets(" ".join((ant, proj, xai, google, bearer, header, password, url)))
        for secret in (ant, proj, xai, google, "synth-token-99", "abcdef12", "s3cret-demo", "ada:s3cret"):
            self.assertNotIn(secret, out)
        self.assertIn("files.example", out)
        self.assertIn("REDACTED:vendor_token", out)
        self.assertIn("REDACTED:google_api", out)
        self.assertIn("REDACTED:bearer", out)
        self.assertIn("REDACTED:authorization", out)
        self.assertIn("REDACTED:password_assign", out)
        self.assertIn("REDACTED:url_userinfo", out)

    def test_unc_quoted_and_spaced_paths(self):
        unc = "\\\\" + "zzunc" + "\\share\\notes.txt"
        wsl = "\\\\wsl$\\Ubuntu\\home\\" + "zzwsl" + "\\proj"
        who = "Other" + " Person"
        quoted = '"C:\\Users\\' + who + '\\notes.txt"'
        spaced = "C:\\Users\\" + who + "\\docs\\a.txt"
        out = redact_paths(f"see {unc} and {wsl} and {quoted} and {spaced}")
        for secret in ("zzunc", "zzwsl", "wsl$", who, "notes.txt"):
            self.assertNotIn(secret, out)
        self.assertIn("<path#", out)

    def test_short_username_does_not_mangle_longer_words(self):
        class _Home:
            name = "dev"

            def __str__(self):
                return "C:\\Users\\" + "de" + "v"

        text = (
            "development uses " + str(_Home()) + "\\code and "
            + "C:\\Users\\" + "de" + "veloper\\proj then dev tool"
        )
        with patch.object(common, "USERPROFILE", _Home()):
            out = redact_paths(text)
        self.assertIn("development", out)
        self.assertIn("<userprofile>\\code", out)
        self.assertNotIn("veloper", out)
        self.assertIn("<user> tool", out)
        self.assertNotIn("C:\\Users\\" + "de" + "v" + "\\code", out)

    def test_clip_sanitized_masks_before_truncate(self):
        secret = "AKIA" + "B" * 16
        text = ("Q" * 76) + secret
        out = clip_sanitized(text, 80)
        self.assertEqual(len(out), 80)
        self.assertNotIn("AKIA", out)
        self.assertNotIn(secret, out)
        with patch.dict(os.environ, {"AISCAN_REDACT": ""}):
            raw = clip_sanitized(text, 80)
        self.assertIn("AKIA", raw)
        self.assertNotIn(secret, raw)


class TestPathMeta(unittest.TestCase):
    def test_safe_path_meta_no_raw_paths(self):
        import paths

        tp = paths.resolve_tool_paths(cli_overrides={
            "claude_home": r"C:\Users\Test User\.claude",
            "codex_home": r"C:\Users\Test User\.codex",
        })
        meta = paths.safe_path_meta(tp)
        blob = str(meta)
        self.assertNotIn("Test User", blob)
        self.assertIn("path_id", meta["claude_projects"])


if __name__ == "__main__":
    unittest.main()
