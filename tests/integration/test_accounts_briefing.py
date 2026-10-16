"""Briefing rendering for the accounts collector."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT / "report"))


def _load_briefing():
    path = ROOT / "report" / "build-briefing.py"
    spec = importlib.util.spec_from_file_location("briefing_accounts_mod", path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _envelope() -> dict:
    return {
        "collector": "accounts",
        "version": "1.0.0",
        "ran_at": "2026-10-16T00:00:00+00:00",
        "host": "DEMO-ENDPOINT",
        "platform_detected": True,
        "scope_hash": "abc",
        "summary": {
            "tools_reported": 2,
            "signed_in": 1,
            "unknown": 1,
            "not_signed_in": 0,
            "distinct_accounts": 1,
            "api_key_rows": 1,
            "subscription_rows": 1,
            "findings": 0,
        },
        "findings": [],
        "rules": [],
        "raw_pointers": [],
        "accounts": [
            {
                "tool": "claude-code",
                "signed_in": "yes",
                "account": "person@example.com",
                "organization": "Demo Org",
                "plan": "",
                "auth_method": "oauth",
                "source": "~/.claude.json",
                "last_sign_in": "",
            },
            {
                "tool": "grok",
                "signed_in": "unknown",
                "account": "",
                "organization": "",
                "plan": "",
                "auth_method": "api_key",
                "source": "env:XAI_API_KEY",
                "last_sign_in": "",
            },
        ],
        "limits": ["Token values are never written."],
    }


class TestAccountsBriefing(unittest.TestCase):
    def setUp(self) -> None:
        self._old = os.environ.get("AISCAN_REDACT")
        os.environ.pop("AISCAN_REDACT", None)

    def tearDown(self) -> None:
        if self._old is None:
            os.environ.pop("AISCAN_REDACT", None)
        else:
            os.environ["AISCAN_REDACT"] = self._old

    def _html(self) -> str:
        briefing = _load_briefing()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "accounts.json").write_text(
                json.dumps(_envelope()),
                encoding="utf-8",
            )
            return briefing.build_html(root, customer="Example", operator="Test")

    def test_table_shows_email_until_redact(self) -> None:
        html = self._html()
        self.assertIn("Which account each tool is signed in as.", html)
        self.assertIn("person@example.com", html)
        self.assertIn("env:XAI_API_KEY", html)
        self.assertIn("~/.claude.json", html)
        self.assertNotIn("crsr_", html)

    def test_redact_masks_email_in_the_table(self) -> None:
        os.environ["AISCAN_REDACT"] = "1"
        html = self._html()
        self.assertNotIn("person@example.com", html)
        self.assertIn("&lt;email&gt;", html)
        self.assertIn("env:XAI_API_KEY", html)

    def test_missing_envelope_is_a_note(self) -> None:
        briefing = _load_briefing()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "codex.json").write_text(
                json.dumps(
                    {
                        "collector": "codex",
                        "version": "1.0.0",
                        "ran_at": "2026-10-16T00:00:00+00:00",
                        "host": "DEMO-ENDPOINT",
                        "platform_detected": True,
                        "scope_hash": "abc",
                        "summary": {},
                        "findings": [],
                        "rules": [],
                        "raw_pointers": [],
                    }
                ),
                encoding="utf-8",
            )
            html = briefing.build_html(root, customer="Example", operator="Test")
        self.assertIn("Account identities were not collected in this scan.", html)


if __name__ == "__main__":
    unittest.main()
