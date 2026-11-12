"""pii-scan records where each hit is: line, column, and the text around it."""

from __future__ import annotations

import csv
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"

import bootstrap  # noqa: E402,F401

_mod_path = Path(__file__).resolve().parent.parent / "pii-scan.py"
_spec = importlib.util.spec_from_file_location("pii_scan_locations", _mod_path)
pii = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(pii)

GH = "ghp_" + "Zq9" * 12
CARD = "4539 5787 6362 1486"


class TestHitLocations(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.target = self.root / "corpus"
        self.target.mkdir()
        self.file = self.target / "chat.md"
        self.file.write_text(
            f"# notes\n\nexport GITHUB_TOKEN={GH} # ci\ncard on file {CARD} ok\nagain {GH}\n",
            encoding="utf-8",
            newline="\n",
        )

    def test_secret_hits_have_a_real_line_column_and_context(self):
        hits, _private = pii.scan_file(self.file, pii.DEFAULT_ENTITIES)
        secrets = [h for h in hits if h["entity"] == "SECRET_GITHUB_PAT"]
        self.assertEqual([(h["line"], h["col"]) for h in secrets], [(3, 21), (5, 7)])
        self.assertEqual(secrets[0]["sample"], GH)
        self.assertEqual(secrets[0]["before"], "export GITHUB_TOKEN=")
        self.assertEqual(secrets[0]["after"], " # ci")
        # The same file is read back at that line and column.
        line = self.file.read_text(encoding="utf-8").split("\n")[secrets[0]["line"] - 1]
        self.assertTrue(line[secrets[0]["col"] - 1:].startswith(GH))
        # One value is one hit: no second row from the length-only matchers.
        self.assertFalse([h for h in hits if h["entity"] in ("SECRET_GENERIC_SECRET", "SECRET_HEX_SECRET")])

    def test_pii_hits_carry_column_and_context(self):
        hits, _private = pii.scan_file(self.file, ["CREDIT_CARD"])
        card = next(h for h in hits if h["entity"] == "CREDIT_CARD")
        self.assertEqual((card["line"], card["col"]), (4, 14))
        self.assertEqual(card["before"], "card on file ")
        self.assertEqual(card["after"], " ok")

    def test_context_is_kept_only_for_the_stored_rows(self):
        many = self.target / "many.txt"
        many.write_text("\n".join(f"mail user{i}@example.test" for i in range(40)), encoding="utf-8")
        hits, _private = pii.scan_file(many, ["EMAIL_ADDRESS"], context_rows=5)
        emails = [h for h in hits if h["entity"] == "EMAIL_ADDRESS"]
        self.assertEqual(len(emails), 40)
        self.assertEqual(sum(1 for h in emails if "before" in h), 5)

    def _rows(self) -> list[dict]:
        with (self.root / "raw" / "findings.csv").open(encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle))

    def test_csv_has_position_and_context_columns(self):
        with mock.patch.dict(os.environ, {"AISCAN_REDACT": ""}):
            env, _hits = pii.collect([self.target], pii.DEFAULT_ENTITIES, self.root / "raw")
        rows = self._rows()
        row = next(r for r in rows if r["entity"] == "SECRET_GITHUB_PAT")
        self.assertEqual((row["line"], row["col"], row["sample"]), ("3", "21", GH))
        self.assertEqual(row["before"], "export GITHUB_TOKEN=")
        self.assertFalse([r for r in rows if r["line"] == "0"])
        # The evidence sample is the shortened value, not the type name.
        finding = next(f for f in env["findings"] if f["id"] == "pii_scan.secret_github_pat")
        self.assertEqual(finding["evidence_count"], 2)
        self.assertNotIn(GH, finding["sample_redacted"])
        self.assertIn("...", finding["sample_redacted"])

    def test_redacted_csv_masks_the_value_and_drops_the_context(self):
        with mock.patch.dict(os.environ, {"AISCAN_REDACT": "1"}):
            pii.collect([self.target], pii.DEFAULT_ENTITIES, self.root / "raw")
        text = (self.root / "raw" / "findings.csv").read_text(encoding="utf-8")
        self.assertNotIn(GH, text)
        self.assertNotIn(CARD, text)
        self.assertNotIn("export GITHUB_TOKEN", text)
        row = next(r for r in self._rows() if r["entity"] == "SECRET_GITHUB_PAT")
        self.assertEqual((row["line"], row["col"], row["before"], row["after"]), ("3", "21", "", ""))
        self.assertIn("sample_redacted", row)


if __name__ == "__main__":
    unittest.main()
