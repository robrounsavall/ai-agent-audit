"""The CI scrub gate still catches a real Windows hostname.

The gate lives in ``.github/workflows/ci.yml``. Select-String is
case-insensitive, so a filename such as ``desktop-status.json`` used to
match a ``DESKTOP-`` pattern. The hostname check is now case-sensitive and
requires the 7-character Windows suffix. Documented AWS example keys are
allowlisted only as those exact strings.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CI = ROOT / ".github" / "workflows" / "ci.yml"

DESKTOP_PATTERN = re.compile(r"DESKTOP-[A-Z0-9]{7}(?![A-Za-z0-9])")
# Same expressions the workflow runs, case-insensitive except the hostname.
INSENSITIVE = re.compile(
    "|".join(
        (
            r"C:(?:\\|/)+Users(?:\\|/)+(?!(?:you|me|yourname|example|Test[ %]?User|Test)\b)[A-Za-z]",
            r"AKIA[0-9A-Z]{16}",
            r"ASIA[0-9A-Z]{16}",
            r"xox[baprs]-[0-9]{8,}",
        )
    ),
    re.IGNORECASE,
)
AWS_EXAMPLES = frozenset(
    {
        "AKIAIOSFODNN7EXAMPLE",
        "ASIAIOSFODNN7EXAMPLE",
    }
)
SCAN_SUFFIXES = {".py", ".ps1", ".md", ".html", ".json", ".txt", ".yml", ".toml"}


def _aws_allowed(line: str, value: str) -> bool:
    if value not in AWS_EXAMPLES:
        return False
    return re.search(rf"(?<![A-Z0-9]){re.escape(value)}(?![A-Z0-9])", line) is not None


def _scan() -> list[str]:
    hits: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SCAN_SUFFIXES:
            continue
        rel = path.relative_to(ROOT).as_posix()
        if rel.startswith(".git/") or rel.startswith(".github/"):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for match in INSENSITIVE.finditer(line):
                value = match.group(0)
                if value.startswith(("AKIA", "ASIA", "akia", "asia")) and _aws_allowed(line, value):
                    continue
                # Case-insensitive prefix check: only the exact uppercase example is allowed.
                if _aws_allowed(line, value):
                    continue
                hits.append(f"{rel}:{lineno}: {line.strip()}")
            for _match in DESKTOP_PATTERN.finditer(line):
                hits.append(f"{rel}:{lineno}: {line.strip()}")
    return hits


class TestScrubGate(unittest.TestCase):
    def test_workflow_keeps_a_case_sensitive_desktop_pattern(self) -> None:
        text = CI.read_text(encoding="utf-8")
        self.assertIn("DESKTOP-[A-Z0-9]{7}(?![A-Za-z0-9])", text)
        self.assertIn("-CaseSensitive", text)
        self.assertIn("-ccontains", text)
        for example in sorted(AWS_EXAMPLES):
            self.assertIn(example, text)
        # The old case-insensitive 6-or-more form is what flagged desktop-status.json.
        self.assertNotIn("DESKTOP-(?!XYZ\\b)[A-Z0-9]{6,}", text)

    def test_realistic_hostname_matches_and_filename_does_not(self) -> None:
        host = "DESKTOP-" + "ABC1234"
        self.assertIsNotNone(DESKTOP_PATTERN.search("machine " + host))
        self.assertIsNotNone(DESKTOP_PATTERN.search(host))
        self.assertIsNone(DESKTOP_PATTERN.search("desktop-status.json"))
        self.assertIsNone(DESKTOP_PATTERN.search("DESKTOP-XYZ"))
        self.assertIsNone(DESKTOP_PATTERN.search("desktop-" + "ABC1234"))
        self.assertIsNone(DESKTOP_PATTERN.search("DESKTOP-" + "abc1234"))
        self.assertIsNone(DESKTOP_PATTERN.search("DESKTOP-" + "ABC12345"))

    def test_only_exact_aws_examples_are_allowlisted(self) -> None:
        example = "AKIAIOSFODNN7EXAMPLE"
        other = "AKIA" + "0000000000000000"
        self.assertTrue(_aws_allowed(f'tool_name": "{example}"', example))
        self.assertFalse(_aws_allowed(example + "EXTRA", example))
        self.assertFalse(_aws_allowed(other, other))
        self.assertNotIn(other, AWS_EXAMPLES)
        self.assertIsNotNone(re.search(r"AKIA[0-9A-Z]{16}", other))

    def test_repo_is_clean_under_the_gate(self) -> None:
        hits = _scan()
        self.assertEqual(hits, [])
        self.assertIn("C:(\\\\|/)+Users", CI.read_text(encoding="utf-8"))
        user_path = re.compile(
            r"C:(?:\\|/)+Users(?:\\|/)+(?!(?:you|me|yourname|example|Test[ %]?User|Test)\b)[A-Za-z]",
            re.IGNORECASE,
        )
        allowed = "C:" + "\\Users\\" + "you"
        blocked = "C:" + "\\Users\\" + "alice"
        self.assertIsNone(user_path.search(allowed))
        self.assertIsNotNone(user_path.search(blocked))
