"""
Briefing must not embed a bare 64-char SHA-256 (shape-identical to a hex
secret, so it would trip any secrets scanner run over a shared bundle).

build-briefing.py renders only a 16-char fingerprint so a briefing built from
clean evidence contains no unmasked secret-shaped strings.

Run:
    python -m unittest discover -s tests/integration -v
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BRIEFING = ROOT / "report" / "build-briefing.py"
sys.path.insert(0, str(ROOT / "core"))
from common import looks_like_secret  # noqa: E402

# Known-safe placeholders that redaction legitimately leaves in output.
_MASKED_PLACEHOLDER = re.compile(r"\*{2,}REDACTED(?::\w+)?\*{2,}")
_VAR_PLACEHOLDER = re.compile(r"\$\{[A-Za-z0-9_]+\}")


def contains_unmasked_secret(text: str) -> bool:
    cleaned = _VAR_PLACEHOLDER.sub("", _MASKED_PLACEHOLDER.sub("", text))
    return looks_like_secret(cleaned)

EVIDENCE = {
    "collector": "codex", "version": "1.1.0", "ran_at": "2026-05-24T10:00:00-04:00",
    "host": "TESTHOST", "platform_detected": True, "scope_hash": "abcd",
    "summary": {"rules": 1}, "findings": [], "rules": [
        {"platform": "codex", "scope": "user", "scope_label_redacted": "user#abcd1234ef01",
         "rule_type": "other", "rule": "trust_level=trusted", "decision": "allow",
         "command_or_tool_redacted": "trust_level=trusted", "risk": "medium",
         "exposure_category": "General Tooling", "source_kind": "user_config", "confidence": "high"},
    ], "raw_pointers": [],
}


class TestBriefingManifestHash(unittest.TestCase):
    def test_briefing_has_no_secret_shaped_strings(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "evidence").mkdir()
            (root / "evidence" / "codex.json").write_text(json.dumps(EVIDENCE), encoding="utf-8")
            # A manifest whose own digest is a full 64-hex SHA-256.
            (root / "manifest.json").write_text(
                json.dumps({"manifest_version": 1, "files": [
                    {"path": "evidence/codex.json", "sha256": "a" * 64, "size": 10}]}),
                encoding="utf-8",
            )
            full = hashlib.sha256((root / "manifest.json").read_bytes()).hexdigest()
            out = root / "briefing.html"
            res = subprocess.run(
                [sys.executable, str(BRIEFING), "--evidence-root", str(root), "--out", str(out)],
                capture_output=True, text=True,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            html = out.read_text(encoding="utf-8")
            # Full 64-char digest must NOT appear; the 16-char prefix may.
            self.assertNotIn(full, html)
            self.assertIn(full[:16], html)
            # No unmasked secret-shaped strings in the rendered briefing.
            self.assertFalse(
                contains_unmasked_secret(html),
                "briefing contains an unmasked secret-shaped string",
            )
            # And there is no stray 32+ hex run anywhere in the output.
            self.assertIsNone(re.search(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32,}(?![A-Fa-f0-9])", html))


if __name__ == "__main__":
    unittest.main()
