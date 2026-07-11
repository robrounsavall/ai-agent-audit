"""Unit tests for pii-scan helpers that do not require Presidio."""

from __future__ import annotations

import importlib.util
import os
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
        import tempfile
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
        import tempfile
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


class TestPiiHelpers(unittest.TestCase):
    def test_severity_for_known(self):
        # Function maps entity types to severity; accept any non-empty for common types
        for entity in ("CREDIT_CARD", "US_SSN", "EMAIL_ADDRESS", "PERSON"):
            sev = pii.severity_for(entity)
            self.assertIn(sev, ("low", "medium", "high", "critical"))

    def test_chunk_text(self):
        text = "a" * 100
        chunks = list(pii.chunk_text(text, size=30))
        self.assertGreaterEqual(len(chunks), 3)
        # offsets + content pairs
        self.assertEqual(chunks[0][0], 0)
        self.assertEqual(len(chunks[0][1]), 30)


if __name__ == "__main__":
    unittest.main()
