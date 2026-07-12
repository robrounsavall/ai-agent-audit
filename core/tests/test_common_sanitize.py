"""Unit tests for core sanitization and envelope helpers."""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"
# These tests exercise masking behavior; redaction is opt-in (default is
# unredacted), so turn it on explicitly.
os.environ["AISCAN_REDACT"] = "1"

import bootstrap  # noqa: E402,F401
from common import (  # noqa: E402
    make_envelope,
    make_finding,
    make_rule,
    mask_secrets,
    redact_paths,
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
