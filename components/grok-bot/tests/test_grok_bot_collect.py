"""Unit tests for the Grok Bot desktop presence collector."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"

import bootstrap  # noqa: E402,F401

_mod_path = Path(__file__).resolve().parent.parent / "grok-bot.py"
_spec = importlib.util.spec_from_file_location("grok_bot_mod", _mod_path)
gb = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(gb)

PLANTED_SECRET = "ghp_" + ("A" * 24)


def ids(findings):
    return {f["id"] for f in findings}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _real_layout(root: Path) -> None:
    """Top-level names from a real Windows install. Contents are never the signal."""
    for name in gb.KNOWN_DIRS:
        (root / name).mkdir(parents=True, exist_ok=True)
    for name in gb.KNOWN_FILES:
        _write(root / name, "")
    _write(root / "sand-secrets.json", json.dumps({"secret": PLANTED_SECRET}))
    _write(root / "box-secrets-push-state.v1.json", PLANTED_SECRET)
    _write(root / "gateway-descriptor.json", json.dumps({"token": PLANTED_SECRET}))
    _write(root / "desktop-status.json", json.dumps({"note": PLANTED_SECRET}))
    _write(root / "Network" / "Cookies", PLANTED_SECRET)
    _write(root / "Local Storage" / "leveldb" / "000001.log", PLANTED_SECRET)
    _write(root / "Session Storage" / "000001.log", PLANTED_SECRET)
    _write(root / "sand-client-persistence" / "state.json", PLANTED_SECRET)


class TestGrokBotCollect(unittest.TestCase):
    def test_missing_root_is_not_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = gb.collect(Path(tmp) / "Grok Bot")
        self.assertFalse(env["platform_detected"])
        self.assertEqual(env["findings"], [])
        self.assertEqual(env["rules"], [])
        self.assertFalse(env["summary"]["app_present"])
        self.assertEqual(env["summary"]["local_execution"], "unknown")
        self.assertEqual(env["summary"]["local_execution_reason"], "not_determinable_offline")
        self.assertEqual(env["summary"]["findings"], 0)
        self.assertNotIn("local_exec_present", env["summary"])

    def test_empty_dir_does_not_call_local_exec_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "Grok Bot"
            root.mkdir()
            env = gb.collect(root)
        self.assertTrue(env["platform_detected"])
        self.assertEqual(env["summary"]["local_execution"], "unknown")
        self.assertFalse(env["summary"]["sand_secrets_present"])
        self.assertFalse(env["summary"]["lockfile_present"])
        self.assertEqual(ids(env["findings"]), {"grok_bot.desktop.present"})
        blob = json.dumps(env)
        self.assertNotIn("local-exec-daemon", blob)
        self.assertNotIn("local_exec_present", blob)

    def test_real_layout_presence_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "Grok Bot"
            _real_layout(root)
            newest = root / "window-state.json"
            os.utime(newest, (1_800_000_000, 1_800_000_000))
            expected_newest = gb._mtime_date(newest)
            env = gb.collect(root)
            blob = json.dumps(env)

        self.assertNotIn(PLANTED_SECRET, blob)
        self.assertNotIn("local-exec", blob)
        summary = env["summary"]
        self.assertTrue(summary["app_present"])
        self.assertEqual(summary["local_execution"], "unknown")
        self.assertEqual(summary["local_execution_reason"], "not_determinable_offline")
        self.assertEqual(summary["known_files_present"], len(gb.KNOWN_FILES))
        self.assertEqual(summary["known_dirs_present"], len(gb.KNOWN_DIRS))
        self.assertTrue(summary["sand_secrets_present"])
        self.assertGreater(summary["sand_secrets_bytes"], 0)
        self.assertTrue(summary["box_secrets_push_state_present"])
        self.assertTrue(summary["lockfile_present"])
        self.assertTrue(summary["browser_state_present"])
        self.assertTrue(summary["client_persistence_present"])
        self.assertGreater(summary["file_count"], len(gb.KNOWN_FILES))
        self.assertEqual(summary["newest_local_activity"], expected_newest)
        self.assertTrue(expected_newest)
        self.assertEqual(
            ids(env["findings"]),
            {
                "grok_bot.desktop.present",
                "grok_bot.secrets.store_present",
                "grok_bot.lockfile.present",
                "grok_bot.state.local_stores_present",
            },
        )
        severities = {item["id"]: item["severity"] for item in env["findings"]}
        self.assertEqual(severities["grok_bot.secrets.store_present"], "medium")
        self.assertEqual(severities["grok_bot.lockfile.present"], "low")
        self.assertEqual(severities["grok_bot.desktop.present"], "low")
        secrets = next(item for item in env["findings"] if item["id"] == "grok_bot.secrets.store_present")
        self.assertIn("sand-secrets.json present", secrets["sample_redacted"])
        self.assertNotIn(PLANTED_SECRET, secrets["sample_redacted"])


if __name__ == "__main__":
    unittest.main()
