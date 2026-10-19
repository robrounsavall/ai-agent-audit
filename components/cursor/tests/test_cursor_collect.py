"""Smoke tests for Cursor collector with synthetic paths."""

from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"

import bootstrap  # noqa: E402,F401
import cursor  # noqa: E402
import paths  # noqa: E402


class TestCursorCollect(unittest.TestCase):
    def test_not_detected_empty_homes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            projects = root / "projects"
            projects.mkdir()
            db = root / "missing.vscdb"
            tp = paths.resolve_tool_paths(cli_overrides={
                "cursor_projects": str(projects),
                "cursor_db": str(db),
            })
            envelope = cursor.collect(tp)
            self.assertEqual(envelope["collector"], "cursor")
            # No db and empty projects -> not detected or empty findings
            self.assertIn("summary", envelope)
            self.assertIsInstance(envelope["findings"], list)
            self.assertIsInstance(envelope["rules"], list)
            for r in envelope["rules"]:
                self.assertIn(r["decision"], ("allow", "deny", "ask"))

    def test_search_transcripts_empty(self):
        with tempfile.TemporaryDirectory() as d:
            count, samples = cursor.search_transcripts(Path(d))
            self.assertEqual(count, 0)
            self.assertEqual(samples, [])

    def test_hash_or_percent_in_db_path_still_opens(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "dir#hash" / "100%done" / "state.vscdb"
            db.parent.mkdir(parents=True)
            con = sqlite3.connect(db)
            con.execute("CREATE TABLE ItemTable (key TEXT, value TEXT)")
            con.execute("INSERT INTO ItemTable VALUES ('k', 'v')")
            con.commit()
            con.close()
            opened = cursor.open_vscdb(db)
            try:
                row = opened.execute("SELECT value FROM ItemTable WHERE key='k'").fetchone()
            finally:
                opened.close()
            self.assertEqual(row[0], "v")


if __name__ == "__main__":
    unittest.main()
