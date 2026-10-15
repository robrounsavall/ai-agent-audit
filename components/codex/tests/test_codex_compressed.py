"""
Contract: Codex's compressed session rollouts (*.jsonl.zst) count exactly like
plain *.jsonl rollouts, and a sessions dir with files never reports 0 sessions.

The Codex desktop app compresses rollouts older than seven days in place
(rollout-*.jsonl -> rollout-*.jsonl.zst, mtimes preserved). aiscan 0.2.0 only
globbed *.jsonl and silently reported 0 sessions / 0 approvals on such
machines. All fixtures are synthetic and built in-test.

Real-decompression tests need a zstd backend (stdlib compression.zstd on
Python 3.14+); they skip on older Pythons, where the no-backend fallback tests
still run.

Run:
    scripts/test-component.ps1 -Name codex
"""

from __future__ import annotations

import builtins
import io
import json
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"
import bootstrap  # noqa: E402,F401

import codex  # noqa: E402
import compressed  # noqa: E402
import paths  # noqa: E402

HAS_ZSTD = compressed.zstd_backend() is not None
OLD = 1_759_000_000  # 2025-09-27
NEWER = 1_760_000_000  # 2025-10-09
NEWEST = 1_760_500_000  # 2025-10-15


def _day(stamp: int) -> str:
    return datetime.fromtimestamp(stamp).strftime("%Y-%m-%d")


def _call(ts: str, command: str, prefix_rule=None) -> dict:
    args = {"command": command, "sandbox_permissions": "require_escalated"}
    if prefix_rule:
        args["prefix_rule"] = prefix_rule
    return {
        "timestamp": ts,
        "type": "response_item",
        "payload": {"type": "function_call", "name": "shell", "arguments": json.dumps(args)},
    }


def rollout_a() -> bytes:
    """3 escalated approvals (network + write-outside), 1 prefix snapshot."""
    lines = [
        {"timestamp": "2025-09-20T10:00:00Z", "type": "session_meta", "payload": {"id": "synthetic-a"}},
        _call("2025-09-20T10:01:00Z", "curl -s https://example.test/api", prefix_rule=["curl"]),
        _call("2025-09-20T10:02:00Z", "cp build.log ../outside/build.log"),
        _call("2025-09-20T10:03:00Z", "npm install"),
        {
            "timestamp": "2025-09-20T10:04:00Z",
            "type": "response_item",
            "payload": {
                "type": "message",
                "content": [{"type": "input_text", "text": 'Approved command prefixes: ["git status", "npm test"]'}],
            },
        },
    ]
    return ("\n".join(json.dumps(line) for line in lines) + "\n").encode("utf-8")


def rollout_b() -> bytes:
    """1 escalated network approval on another day."""
    lines = [
        {"timestamp": "2025-09-22T09:00:00Z", "type": "session_meta", "payload": {"id": "synthetic-b"}},
        _call("2025-09-22T09:05:00Z", "wget https://example.test/file"),
    ]
    return ("\n".join(json.dumps(line) for line in lines) + "\n").encode("utf-8")


ROLLOUTS = {
    "2025/09/20/rollout-2025-09-20T10-00-00-synthetic-a.jsonl": rollout_a,
    "2025/09/22/rollout-2025-09-22T09-00-00-synthetic-b.jsonl": rollout_b,
}


def comparable(env: dict) -> dict:
    s = env["summary"]
    return {
        "session_files": s["session_files"],
        "approval_requests": s["approval_requests"],
        "rules": sorted(json.dumps(r, sort_keys=True) for r in env["rules"]),
        "findings": sorted(
            (f["id"], f["severity"], f["evidence_count"], f["first_seen"], f["last_seen"])
            for f in env["findings"]
        ),
    }


class CodexCompressedSessions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.no_localappdata = self.root / "empty-localappdata"
        self.no_localappdata.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def make_home(self, name: str, mode: dict[str, str]) -> paths.ToolPaths:
        """mode maps rollout rel path -> 'plain' | 'zst' | 'garbage-zst'."""
        home = self.root / name
        sessions = home / "sessions"
        sessions.mkdir(parents=True)
        for rel, kind in mode.items():
            data = ROLLOUTS[rel]()
            target = sessions / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            if kind == "plain":
                target.write_bytes(data)
            elif kind == "zst":
                target = target.with_name(target.name + ".zst")
                target.write_bytes(compressed.compress(data))
            else:  # unreadable without a backend; content irrelevant
                target = target.with_name(target.name + ".zst")
                target.write_bytes(b"synthetic placeholder, never decoded")
            os.utime(target, (OLD, OLD))
        return paths.resolve_tool_paths(cli_overrides={"codex_home": str(home)})

    def collect(self, tp, localappdata=None):
        return codex.collect(tp, localappdata=localappdata or self.no_localappdata)

    def all_mode(self, kind: str) -> dict[str, str]:
        return {rel: kind for rel in ROLLOUTS}

    def test_plain_baseline_sanity(self):
        env = self.collect(self.make_home("plain", self.all_mode("plain")))
        self.assertEqual(env["summary"]["session_files"], 2)
        self.assertEqual(env["summary"]["approval_requests"], 4)
        ids = {f["id"] for f in env["findings"]}
        self.assertIn("codex.sandbox.require_escalated", ids)
        self.assertIn("codex.network.escalated", ids)
        self.assertIn("codex.write.outside_root", ids)

    @unittest.skipUnless(HAS_ZSTD, "zstd backend unavailable (Python < 3.14)")
    def test_compressed_counts_match_plain(self):
        plain = self.collect(self.make_home("plain", self.all_mode("plain")))
        packed = self.collect(self.make_home("packed", self.all_mode("zst")))
        self.assertEqual(comparable(packed), comparable(plain))
        self.assertEqual(packed["summary"]["session_files_compressed"], 2)
        self.assertEqual(packed["summary"]["session_files_unreadable"], 0)
        self.assertNotIn("codex.compressed_sessions_unreadable", {f["id"] for f in packed["findings"]})

    @unittest.skipUnless(HAS_ZSTD, "zstd backend unavailable (Python < 3.14)")
    def test_mixed_folder_matches_plain(self):
        a, b = list(ROLLOUTS)
        plain = self.collect(self.make_home("plain", self.all_mode("plain")))
        mixed = self.collect(self.make_home("mixed", {a: "zst", b: "plain"}))
        self.assertEqual(comparable(mixed), comparable(plain))
        self.assertEqual(mixed["summary"]["session_files_compressed"], 1)

    @unittest.skipUnless(HAS_ZSTD, "zstd backend unavailable (Python < 3.14)")
    def test_plain_and_compressed_twin_counted_once_plain_preferred(self):
        a, _b = list(ROLLOUTS)
        tp = self.make_home("twin", {a: "plain"})
        # Twin with DIFFERENT content: if the .zst were read too (or instead),
        # approval counts would change.
        twin = tp.codex_sessions / (a + ".zst")
        twin.write_bytes(compressed.compress(rollout_b()))
        env = self.collect(tp)
        self.assertEqual(env["summary"]["session_files"], 1)
        self.assertEqual(env["summary"]["session_files_compressed"], 0)
        self.assertEqual(env["summary"]["approval_requests"], 3)

    def test_no_backend_counts_files_and_emits_finding(self):
        tp = self.make_home("nobackend", self.all_mode("garbage-zst"))
        with patch.object(compressed, "zstd_backend", return_value=None):
            env = self.collect(tp)
        summary = env["summary"]
        self.assertEqual(summary["session_files"], 2)
        self.assertEqual(summary["session_files_compressed"], 2)
        self.assertEqual(summary["session_files_unreadable"], 2)
        self.assertEqual(summary["zstd_backend"], "none")
        self.assertEqual(summary["last_used"], _day(OLD))
        self.assertEqual(summary["last_used_source"], "sessions")
        finding = next(f for f in env["findings"] if f["id"] == "codex.compressed_sessions_unreadable")
        self.assertEqual(finding["severity"], "medium")
        self.assertEqual(finding["evidence_count"], 2)
        self.assertIn("3.14", finding["title"])
        # Discovery (chat-history's cover fallback) counts them too.
        disc = paths.detected(tp)["codex_sessions"]
        self.assertEqual((disc["file_count"], disc["newest"]), (2, _day(OLD)))

    def test_no_backend_mixed_still_parses_plain(self):
        a, b = list(ROLLOUTS)
        tp = self.make_home("nobackend-mixed", {a: "plain", b: "garbage-zst"})
        with patch.object(compressed, "zstd_backend", return_value=None):
            env = self.collect(tp)
        self.assertEqual(env["summary"]["session_files"], 2)
        self.assertEqual(env["summary"]["session_files_unreadable"], 1)
        self.assertEqual(env["summary"]["approval_requests"], 3)

    def test_last_used_considers_index_and_state_db_by_mtime_only(self):
        tp = self.make_home("activity", self.all_mode("garbage-zst"))
        index = tp.codex_home / "session_index.jsonl"
        state = tp.codex_home / "state_5.sqlite"
        index.write_bytes(b"synthetic, must not be opened")
        state.write_bytes(b"synthetic, must not be opened")
        os.utime(index, (NEWER, NEWER))
        os.utime(state, (NEWEST, NEWEST))
        opened: list[str] = []
        real_open = builtins.open

        def spy(file, *args, **kwargs):
            opened.append(Path(str(file)).name if isinstance(file, (str, os.PathLike)) else "")
            return real_open(file, *args, **kwargs)

        with patch.object(compressed, "zstd_backend", return_value=None), \
                patch("builtins.open", spy), patch.object(io, "open", spy):
            env = self.collect(tp)
        self.assertEqual(env["summary"]["last_used"], _day(NEWEST))
        self.assertEqual(env["summary"]["last_used_source"], "state_db")
        self.assertNotIn("session_index.jsonl", opened)
        self.assertNotIn("state_5.sqlite", opened)

        os.utime(state, (OLD - 10, OLD - 10))
        with patch.object(compressed, "zstd_backend", return_value=None):
            env = self.collect(tp)
        self.assertEqual(env["summary"]["last_used"], _day(NEWER))
        self.assertEqual(env["summary"]["last_used_source"], "session_index")

    def test_desktop_last_opened_from_log_mtime(self):
        tp = self.make_home("desktop", self.all_mode("garbage-zst"))
        local = self.root / "localappdata"
        logs = local / "Packages" / "OpenAI.Codex_synthetic0" / "LocalCache" / "Local" / "Codex" / "Logs"
        for day, stamp in (("2025/10/09", NEWER), ("2025/10/15", NEWEST)):
            log = logs / day / "codex-desktop-synthetic.log"
            log.parent.mkdir(parents=True)
            log.write_bytes(b"synthetic, must not be opened")
            os.utime(log, (stamp, stamp))
        with patch.object(compressed, "zstd_backend", return_value=None):
            env = self.collect(tp, localappdata=local)
        self.assertTrue(env["summary"]["desktop_installed"])
        self.assertEqual(env["summary"]["desktop_last_opened"], _day(NEWEST))
        # Opened is not used: last_used still comes from session activity.
        self.assertEqual(env["summary"]["last_used"], _day(OLD))

    def test_desktop_absent(self):
        tp = self.make_home("nodesktop", self.all_mode("garbage-zst"))
        env = self.collect(tp)
        self.assertFalse(env["summary"]["desktop_installed"])
        self.assertEqual(env["summary"]["desktop_last_opened"], "")

    def test_desktop_installed_without_logs(self):
        local = self.root / "localappdata"
        (local / "Packages" / "OpenAI.Codex_synthetic0").mkdir(parents=True)
        self.assertEqual(
            codex.desktop_activity(local),
            {"desktop_installed": True, "desktop_last_opened": ""},
        )


class NeverSilentlyEmpty(unittest.TestCase):
    """Regression guard: rollout files on disk must never collect as 0 sessions.

    Every rollout-* file under sessions/ (whatever its extension) must be
    counted. If Codex changes its storage format again and the collector
    misses it, this fails instead of the report silently going empty.
    """

    def test_guard_across_storage_layouts(self):
        a, b = list(ROLLOUTS)
        layouts = {"garbage-zst": self._modes("garbage-zst"), "plain": self._modes("plain")}
        if HAS_ZSTD:
            layouts["zst"] = self._modes("zst")
            layouts["mixed"] = {a: "zst", b: "plain"}
        layouts["mixed-nobackend"] = {a: "plain", b: "garbage-zst"}
        for name, mode in layouts.items():
            for backend_patched in (False, True):
                if not backend_patched and name.startswith("garbage") and not HAS_ZSTD:
                    continue
                with self.subTest(layout=name, no_backend=backend_patched), tempfile.TemporaryDirectory() as tmp:
                    case = CodexCompressedSessions()
                    case.root = Path(tmp)
                    case.no_localappdata = case.root / "empty"
                    case.no_localappdata.mkdir()
                    tp = case.make_home("home", mode)
                    on_disk = [p for p in tp.codex_sessions.rglob("rollout-*") if p.is_file()]
                    if backend_patched:
                        with patch.object(compressed, "zstd_backend", return_value=None):
                            env = case.collect(tp)
                    else:
                        env = case.collect(tp)
                    self.assertGreater(len(on_disk), 0)
                    self.assertEqual(env["summary"]["session_files"], len(on_disk))
                    self.assertTrue(env["summary"]["last_used"])
                    unread = env["summary"]["session_files_unreadable"]
                    if unread:
                        self.assertIn(
                            "codex.compressed_sessions_unreadable", {f["id"] for f in env["findings"]}
                        )

    @staticmethod
    def _modes(kind: str) -> dict[str, str]:
        return {rel: kind for rel in ROLLOUTS}


if __name__ == "__main__":
    unittest.main()
