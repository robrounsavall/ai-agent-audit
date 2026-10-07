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


class TestGrokBotCollect(unittest.TestCase):
    def test_missing_root_is_not_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = gb.collect(Path(tmp) / "Grok Bot")
        self.assertFalse(env["platform_detected"])
        self.assertEqual(env["findings"], [])
        self.assertEqual(env["rules"], [])
        self.assertFalse(env["summary"]["app_present"])
        self.assertEqual(env["summary"]["findings"], 0)

    def test_settings_only_reports_desktop_presence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "Grok Bot"
            _write(root / "settings.json", json.dumps({"ignored": True}))
            env = gb.collect(root)
        self.assertTrue(env["platform_detected"])
        self.assertTrue(env["summary"]["settings_present"])
        self.assertFalse(env["summary"]["local_exec_present"])
        self.assertEqual(ids(env["findings"]), {"grok_bot.desktop.present"})
        self.assertEqual(env["rules"], [])

    def test_local_exec_artifacts_and_secret_exclusion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "Grok Bot"
            _write(
                root / "settings.json",
                json.dumps({"token": PLANTED_SECRET, "accountScopes": {}}),
            )
            _write(root / "local-exec-daemon.log", f"paired {PLANTED_SECRET}\n")
            _write(
                root / "local-exec-daemon-credential.json",
                json.dumps({"secret": PLANTED_SECRET}),
            )
            _write(
                root / "local-exec-daemon-connection.json",
                json.dumps({"host": "machine", "token": PLANTED_SECRET}),
            )
            (root / "local-exec-daemon").mkdir()
            (root / "local-exec-daemon" / "main.cjs").write_text(
                PLANTED_SECRET, encoding="utf-8"
            )
            env = gb.collect(root)
            blob = json.dumps(env)

        self.assertNotIn(PLANTED_SECRET, blob)
        self.assertTrue(env["summary"]["local_exec_present"])
        self.assertTrue(env["summary"]["local_exec_credential_present"])
        self.assertTrue(env["summary"]["local_exec_connection_present"])
        self.assertTrue(env["summary"]["local_exec_daemon_dir_present"])
        self.assertGreater(env["summary"]["local_exec_log_bytes"], 0)
        self.assertTrue(env["summary"]["newest_local_activity"])
        self.assertEqual(
            ids(env["findings"]),
            {
                "grok_bot.desktop.present",
                "grok_bot.local_exec.capability_present",
                "grok_bot.local_exec.credential_present",
            },
        )
        severities = {f["id"]: f["severity"] for f in env["findings"]}
        self.assertEqual(severities["grok_bot.local_exec.capability_present"], "medium")
        self.assertEqual(severities["grok_bot.local_exec.credential_present"], "low")


if __name__ == "__main__":
    unittest.main()
