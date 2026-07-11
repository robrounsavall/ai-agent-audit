"""Unit tests for chat-history pure helpers."""

from __future__ import annotations

import importlib.util
import os
import unittest
from pathlib import Path

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"

import bootstrap  # noqa: E402,F401

_mod_path = Path(__file__).resolve().parent.parent / "chat-history.py"
_spec = importlib.util.spec_from_file_location("chat_history_mod", _mod_path)
ch = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(ch)


class TestHelpers(unittest.TestCase):
    def test_escape_md_fence(self):
        out = ch.escape_md_fence("a ``` b")
        self.assertIsInstance(out, str)
        self.assertNotEqual(out, "")

    def test_parse_iso(self):
        self.assertTrue(ch.parse_iso("2026-01-01T00:00:00Z") or ch.parse_iso("2026-01-01T00:00:00+00:00"))

    def test_get_content_text_string(self):
        self.assertEqual(ch.get_content_text("hello"), "hello")


if __name__ == "__main__":
    unittest.main()
