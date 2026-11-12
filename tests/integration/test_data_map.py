"""The data map page stays offline, pinned and free of machine-specific strings.

Run from the repo root:
    python -m unittest discover -s tests/integration -p "test_data_map.py" -v

Citation anchors are checked by `python docs/data-map/build_data_map.py --verify`,
not here: they are pinned to BASE_SHA and must not break when code moves on.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HTML = ROOT / "docs" / "aiscan-data-map.html"
sys.path.insert(0, str(ROOT / "docs" / "data-map"))

import data_map_content as A  # noqa: E402


class TestDataMap(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.html = HTML.read_text(encoding="utf-8")

    def test_base_sha_is_full_commit(self) -> None:
        self.assertRegex(A.BASE_SHA, r"^[0-9a-f]{40}$")

    def test_csp_blocks_network(self) -> None:
        m = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)"', self.html)
        self.assertIsNotNone(m)
        csp = m.group(1)
        for directive in ("default-src 'none'", "connect-src 'none'", "font-src 'none'", "img-src data:"):
            self.assertIn(directive, csp)

    def test_no_external_subresources(self) -> None:
        self.assertNotRegex(self.html, r'<(?:script|img|iframe|link|source|video|audio|embed|object)\b[^>]*\b(?:src|href)="(?:https?:)?//')
        self.assertNotRegex(self.html, r"@import|url\(\s*['\"]?(?:https?:)?//")

    def test_repo_links_pinned_to_base_sha(self) -> None:
        links = re.findall(r'href="(https://github\.com/robrounsavall/ai-agent-audit/[^"]*)"', self.html)
        self.assertTrue(links)
        prefix = f"https://github.com/robrounsavall/ai-agent-audit/blob/{A.BASE_SHA}/"
        for link in links:
            self.assertTrue(link.startswith(prefix), link)

    def test_external_links_open_safely(self) -> None:
        for tag in re.findall(r'<a\b[^>]*href="https?://[^"]*"[^>]*>', self.html):
            self.assertIn('target="_blank"', tag)
            self.assertIn("noopener", tag)

    def test_no_machine_specific_strings(self) -> None:
        patterns = [
            r"[A-Za-z]:\\+Users\\+(?!<)[A-Za-z0-9._-]+",
            r"\bDESKTOP-[A-Z0-9]{7}\b",
            r"\bAKIA[0-9A-Z]{16}\b",
            r"\bgh[pousr]_[A-Za-z0-9]{30,}",
            r"\bsk-[A-Za-z0-9_-]{20,}",
        ]
        sources = [HTML, *sorted((ROOT / "docs" / "data-map").glob("*.py"))]
        for path in sources:
            text = path.read_text(encoding="utf-8")
            for pat in patterns:
                self.assertIsNone(re.search(pat, text), f"{path.name}: {pat}")


if __name__ == "__main__":
    unittest.main()
