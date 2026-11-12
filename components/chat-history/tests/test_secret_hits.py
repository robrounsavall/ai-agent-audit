"""chat-history records each secret-shaped value with its file, line, and message."""

from __future__ import annotations

import csv
import importlib.util
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"

import bootstrap  # noqa: E402,F401

_mod_path = Path(__file__).resolve().parent.parent / "chat-history.py"
_spec = importlib.util.spec_from_file_location("chat_history_hits", _mod_path)
ch = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(ch)

GH = "ghp_" + "Zq9" * 12
SESSION_A = r"C:\Users\Test User\.claude\projects\proj-a\aaaa.jsonl"
SESSION_B = r"C:\Users\Test User\.claude\projects\proj-b\bbbb.jsonl"


def _entry(ts: str, role: str, text: str, source: str, workspace: str) -> dict:
    return {
        "ts": datetime.fromisoformat(ts), "tool": "Claude", "role": role,
        "text": text, "source": source, "workspace": workspace,
    }


class TestSecretHits(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.raw = Path(self._tmp.name) / "raw"
        buckets = {
            "2026-10-28": [
                _entry("2026-10-28T09:00:00", "user", "plain question\nno secrets here", SESSION_A, "proj-a"),
                _entry("2026-10-28T09:05:00", "assistant", f"multi\nline\nreply with {GH} inside", SESSION_A, "proj-a"),
                _entry("2026-10-28T10:00:00", "user", f"GITHUB_TOKEN={GH}", SESSION_B, "proj-b"),
            ],
            "2026-10-29": [_entry("2026-10-29T08:00:00", "user", "nothing to see", SESSION_A, "proj-a")],
        }
        self.result = ch.export_buckets(buckets, "Claude", "claude", self.raw / "chat-history")

    def _hits(self) -> list[dict]:
        return [row for info in self.result["files_info"] for row in info["secret_hits"]]

    def test_each_hit_points_at_the_exact_line_and_its_message(self):
        hits = self._hits()
        self.assertEqual(len(hits), 2)
        by_source = {hit["source"]: hit for hit in hits}
        self.assertEqual(set(by_source), {SESSION_A, SESSION_B})
        for hit in hits:
            lines = Path(hit["file"]).read_text(encoding="utf-8").split("\n")
            self.assertTrue(lines[hit["line"] - 1][hit["col"] - 1:].startswith(GH), hit)
            self.assertEqual(hit["sample"], GH)
            self.assertEqual(hit["type"], "github_pat")
            self.assertEqual(hit["tool"], "claude")
        first = by_source[SESSION_A]
        self.assertEqual((first["role"], first["workspace"], first["time"]), ("assistant", "proj-a", "2026-10-28T09:05:00"))
        self.assertEqual(first["before"], "reply with ")
        self.assertEqual(first["after"], " inside")
        second = by_source[SESSION_B]
        self.assertEqual((second["role"], second["workspace"]), ("user", "proj-b"))

    def test_counts_are_complete_when_rows_are_capped(self):
        content = "\n".join(f"k{i}={GH}" for i in range(40))
        rows, counts = ch.locate_secret_hits(content, [], Path("x.md"), "claude", max_per_type=3)
        self.assertEqual(len(rows), 3)
        self.assertEqual(counts["github_pat"], 40)
        self.assertEqual(rows[0]["source"], "")

    def test_csv_is_written_beside_the_transcripts_not_inside_them(self):
        with mock.patch.dict(os.environ, {"AISCAN_REDACT": ""}):
            written = ch.write_secret_hits(self.raw, [self.result])
        self.assertEqual(written, 2)
        target = self.raw / "chat-history-hits" / "secret-hits.csv"
        self.assertTrue(target.is_file())
        # pii-scan and secrets-scan walk raw/chat-history. The list of values
        # must not be in there or every secret would be counted again.
        self.assertFalse(list((self.raw / "chat-history").rglob("*.csv")))
        with target.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(list(rows[0].keys()), ch.SECRET_HIT_COLUMNS)
        self.assertEqual({row["sample"] for row in rows}, {GH})

    def test_redacted_csv_masks_the_value_and_drops_the_context(self):
        with mock.patch.dict(os.environ, {"AISCAN_REDACT": "1"}):
            ch.write_secret_hits(self.raw, [self.result])
        text = (self.raw / "chat-history-hits" / "secret-hits.csv").read_text(encoding="utf-8")
        self.assertNotIn(GH, text)
        self.assertNotIn("reply with", text)
        self.assertIn("sample_redacted", text.splitlines()[0])

    def test_no_hits_removes_a_stale_file(self):
        target = self.raw / "chat-history-hits" / "secret-hits.csv"
        target.parent.mkdir(parents=True)
        target.write_text("old", encoding="utf-8")
        self.assertEqual(ch.write_secret_hits(self.raw, [{"files_info": [{"secret_hits": []}]}]), 0)
        self.assertFalse(target.exists())

    def test_finding_points_at_the_hit_rows_and_carries_no_values(self):
        tp = SimpleNamespace(
            claude_projects=self.raw / "none", codex_sessions=self.raw / "none",
            cursor_projects=self.raw / "none", cursor_db=self.raw / "none",
            grok_sessions=self.raw / "none",
        )
        with mock.patch.object(ch.paths, "safe_path_meta", return_value={}):
            env = ch.build_evidence([self.result], self.raw, tp, claude_roots=[self.raw / "none"])
        finding = next(f for f in env["findings"] if f["id"] == "chat_history.secret.claude")
        self.assertEqual(finding["raw_evidence_ref"], "raw/chat-history-hits/secret-hits.csv")
        self.assertEqual(finding["hit_count"], 2)
        self.assertEqual(finding["hit_types"], ["github_pat"])
        self.assertEqual(finding["evidence_count"], 1)
        self.assertEqual(env["summary"]["secret_hits"], 2)
        self.assertNotIn(GH, str(env))


if __name__ == "__main__":
    unittest.main()
