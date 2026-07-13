"""Unit tests for the stdlib pii-scan detectors and helpers."""

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"

import bootstrap  # noqa: E402,F401

_mod_path = Path(__file__).resolve().parent.parent / "pii-scan.py"
_spec = importlib.util.spec_from_file_location("pii_scan_mod", _mod_path)
pii = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(pii)


class TestDefaultTargets(unittest.TestCase):
    def test_existing_locations_only(self):
        from types import SimpleNamespace

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            raw_root = base / "raw"
            chat = raw_root / "chat-history"
            chat.mkdir(parents=True)
            claude = base / "claude-projects"
            claude.mkdir()
            tp = SimpleNamespace(
                claude_projects=claude,
                codex_sessions=base / "missing-codex",
                cursor_projects=base / "missing-cursor",
                grok_sessions=base / "missing-grok",
            )
            targets = pii.default_targets(raw_root, tp)
            self.assertEqual(targets, [chat, claude])

    def test_nothing_found(self):
        from types import SimpleNamespace

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            tp = SimpleNamespace(
                claude_projects=base / "a",
                codex_sessions=base / "b",
                cursor_projects=base / "c",
                grok_sessions=base / "d",
            )
            self.assertEqual(pii.default_targets(base / "raw", tp), [])


class TestValidators(unittest.TestCase):
    def test_luhn(self):
        self.assertTrue(pii.luhn_ok("4111111111111111"))
        self.assertFalse(pii.luhn_ok("4111111111111112"))

    def test_credit_card_real_test_numbers(self):
        # Standard network test numbers: valid prefix + Luhn.
        for number in ("4111111111111111", "5500-0000-0000-0004", "3400 0000 0000 009", "6011000000000004"):
            self.assertTrue(pii.credit_card_ok(number), number)

    def test_credit_card_rejects_luhn_valid_unknown_prefix(self):
        # Luhn-valid but no known IIN prefix (starts with 1).
        self.assertFalse(pii.credit_card_ok("1400060008000000"))

    def test_credit_card_rejects_repeated_digit(self):
        self.assertFalse(pii.credit_card_ok("4444444444444444444"))

    def test_ssn_rules(self):
        self.assertTrue(pii.ssn_ok("123-45-6789"))
        for bad in ("000-45-6789", "666-45-6789", "900-45-6789", "123-00-6789", "123-45-0000"):
            self.assertFalse(pii.ssn_ok(bad), bad)

    def test_iban_mod97(self):
        self.assertTrue(pii.iban_ok("GB82WEST12345698765432"))
        self.assertFalse(pii.iban_ok("GB82WEST12345698765433"))

    def test_ip_public_vs_private(self):
        self.assertTrue(pii.public_ip_ok("8.8.8.8"))
        for private in ("127.0.0.1", "10.1.2.3", "192.168.0.1", "0.0.0.0"):
            self.assertFalse(pii.public_ip_ok(private), private)


class TestScanFile(unittest.TestCase):
    def _scan(self, text: str, entities=None):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "corpus.md"
            p.write_text(text, encoding="utf-8")
            return pii.scan_file(p, entities or pii.DEFAULT_ENTITIES)

    def test_line_numbers_and_entities(self):
        hits, _ = self._scan("clean line\nreach me at bob@example.com\ncard 4111 1111 1111 1111\n")
        by_entity = {h["entity"]: h for h in hits}
        self.assertEqual(by_entity["EMAIL_ADDRESS"]["line"], 2)
        self.assertEqual(by_entity["CREDIT_CARD"]["line"], 3)

    def test_private_ips_counted_not_hits(self):
        hits, private_ips = self._scan("hosts: 127.0.0.1 and 192.168.1.5 and 8.8.8.8\n")
        ips = [h for h in hits if h["entity"] == "IP_ADDRESS"]
        self.assertEqual(len(ips), 1)
        self.assertEqual(ips[0]["sample"], "8.8.8.8")
        self.assertEqual(private_ips, 2)

    def test_version_string_not_credit_card(self):
        hits, _ = self._scan("release 2.1.205.0 build 1400060008000000\n")
        self.assertFalse([h for h in hits if h["entity"] == "CREDIT_CARD"])

    def test_phone_requires_separators(self):
        hits, _ = self._scan("call 954-644-9370 not 0240956656\n")
        phones = [h for h in hits if h["entity"] == "PHONE_NUMBER"]
        self.assertEqual([h["sample"] for h in phones], ["954-644-9370"])

    def test_timestamp_not_ssn(self):
        hits, _ = self._scan("at 2026-07-12 and ssn 123-45-6789\n")
        ssns = [h["sample"] for h in hits if h["entity"] == "US_SSN"]
        self.assertEqual(ssns, ["123-45-6789"])


class TestSeverity(unittest.TestCase):
    def test_severity_for_known(self):
        self.assertEqual(pii.severity_for("CREDIT_CARD"), "critical")
        self.assertEqual(pii.severity_for("US_SSN"), "critical")
        self.assertEqual(pii.severity_for("EMAIL_ADDRESS"), "medium")
        # Unknown entities (e.g. SECRET_*) default to medium.
        self.assertEqual(pii.severity_for("SECRET_AWS_KEY"), "medium")


if __name__ == "__main__":
    unittest.main()
