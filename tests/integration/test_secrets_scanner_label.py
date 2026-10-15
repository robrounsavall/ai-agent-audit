"""The briefing names the secrets scanner that actually ran."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BRIEFING_PATH = ROOT / "report" / "build-briefing.py"


def _load_briefing():
    spec = importlib.util.spec_from_file_location("briefing_scanner_label", BRIEFING_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class TestSecretsScannerLabel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.b = _load_briefing()

    def test_purpose_names_the_scanner(self):
        cases = {
            "betterleaks": "Betterleaks scan over chat exports and repo roots",
            "gitleaks": "gitleaks scan over chat exports and repo roots",
            "trufflehog": "trufflehog scan over chat exports and repo roots",
        }
        for scanner, expected in cases.items():
            with self.subTest(scanner=scanner):
                env = {"summary": {"scanner": scanner}}
                self.assertEqual(self.b.secrets_scan_purpose(env), expected)

    def test_no_scanner_and_missing_summary(self):
        self.assertIn("not scanned", self.b.secrets_scan_purpose({"summary": {"scanner": "none"}}))
        self.assertEqual(
            self.b.secrets_scan_purpose({}),
            self.b.COLLECTOR_PURPOSES["secrets-scan"][1],
        )
        self.assertNotIn("gitleaks", self.b.COLLECTOR_PURPOSES["secrets-scan"][1])


if __name__ == "__main__":
    unittest.main()
