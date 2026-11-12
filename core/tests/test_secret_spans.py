"""Per-hit secret locations: one span per value, at a real line and column."""

from __future__ import annotations

import os
import unittest

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"

import bootstrap  # noqa: E402,F401
from common import (  # noqa: E402
    HIT_CONTEXT_CHARS,
    HIT_MAX_UNSTRUCTURED_LEN,
    LineIndex,
    hit_context,
    secret_spans,
)

GH = "ghp_" + "Zq9" * 12
HEX40 = "3f2b9c1d4e5a6b7c8d9e" * 2
ANT = "sk-ant-" + "api03-" + "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2"


class TestSecretSpans(unittest.TestCase):
    def test_specific_pattern_wins_over_the_length_matchers(self):
        # The tail of a ghp_ token is also a 32+ character run. It is one hit.
        text = f"token={GH} done"
        spans = secret_spans(text)
        self.assertEqual([kind for kind, _s, _e in spans], ["github_pat"])
        kind, start, end = spans[0]
        self.assertEqual(text[start:end], GH)

    def test_hex_is_reported_as_hex_not_generic(self):
        spans = secret_spans(f"SESSION_SECRET={HEX40}")
        self.assertEqual([kind for kind, _s, _e in spans], ["hex_secret"])

    def test_vendor_key_inside_a_bearer_header_is_one_hit(self):
        spans = secret_spans(f'curl -H "Authorization: Bearer {ANT}" https://x.test')
        self.assertEqual([kind for kind, _s, _e in spans], ["vendor_token"])

    def test_spans_are_in_text_order_and_repeat_per_occurrence(self):
        text = f"key={HEX40}\nfirst {GH}\nsecond {GH}\n"
        spans = secret_spans(text)
        self.assertEqual([kind for kind, _s, _e in spans], ["hex_secret", "github_pat", "github_pat"])
        self.assertEqual([s for _k, s, _e in spans], sorted(s for _k, s, _e in spans))

    def test_a_long_blob_is_not_a_hit(self):
        blob = "A1b2" * ((HIT_MAX_UNSTRUCTURED_LEN // 4) + 10)
        self.assertEqual(secret_spans(f"data:image/png;base64,{blob}"), [])
        self.assertEqual(secret_spans(""), [])

    def test_word_only_runs_are_still_rejected(self):
        self.assertEqual(secret_spans("skipDangerousModePermissionPromptSetting="), [])


class TestLineIndexAndContext(unittest.TestCase):
    def test_line_and_column_are_one_based(self):
        text = f"a\nbb\n  key {GH}\n"
        index = LineIndex(text)
        (_kind, start, _end), = secret_spans(text)
        self.assertEqual(index.locate(start), (3, 7))
        self.assertEqual(index.locate(0), (1, 1))
        self.assertEqual(index.locate(2), (2, 1))

    def test_context_stays_on_the_line_and_is_clipped(self):
        long_before = "x" * 500
        text = f"prev line\n{long_before} {GH} tail text\nnext line"
        index = LineIndex(text)
        (_kind, start, end), = secret_spans(text)
        before, after = hit_context(text, start, end, index)
        self.assertEqual(len(before), HIT_CONTEXT_CHARS)
        self.assertEqual(after, " tail text")
        self.assertNotIn("prev line", before)
        self.assertNotIn("next line", after)

    def test_context_flattens_control_characters(self):
        text = f"a\tb\r\x0b{GH}\x00z"
        index = LineIndex(text)
        (_kind, start, end), = secret_spans(text)
        before, after = hit_context(text, start, end, index)
        self.assertEqual(before, "a b ")
        self.assertEqual(after, " z")


if __name__ == "__main__":
    unittest.main()
