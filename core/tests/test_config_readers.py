"""Readers and URL-host checks used by the collectors. Synthetic files only."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import bootstrap  # noqa: E402,F401
from common import (  # noqa: E402
    config_has_remote_url,
    is_loopback_url,
    iter_jsonl,
    load_json,
    read_json_object,
    read_toml_table,
)


class TestLoadJson(unittest.TestCase):
    def test_bom_and_jsonc(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "settings.json"
            path.write_bytes(b'\xef\xbb\xbf{\n  // note\n  "on": true,\n}\n')
            self.assertEqual(load_json(path), {"on": True})
            data, err = read_json_object(path)
            self.assertEqual(data, {"on": True})
            self.assertIsNone(err)

    def test_bad_byte_is_not_fatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "settings.json"
            path.write_bytes(b"\xff")
            self.assertIsNone(load_json(path))
            data, err = read_json_object(path)
            self.assertIsNone(data)
            self.assertEqual(err, "not UTF-8")

    def test_missing_is_not_an_error(self):
        data, err = read_json_object(Path(r"C:\nope\missing.json"))
        self.assertEqual((data, err), (None, None))

    def test_list_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "settings.json"
            path.write_text("[1]", encoding="utf-8")
            data, err = read_json_object(path)
            self.assertIsNone(data)
            self.assertEqual(err, "expected object")


class TestIterJsonl(unittest.TestCase):
    def test_bom_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "t.jsonl"
            path.write_bytes(b'\xef\xbb\xbf{"a": 1}\n')
            self.assertEqual(list(iter_jsonl(path)), [(1, {"a": 1})])

    def test_bad_byte_does_not_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "t.jsonl"
            path.write_bytes(b'{"a": 1}\n\xff\n')
            rows = list(iter_jsonl(path))
            self.assertEqual(rows[0][1], {"a": 1})


class TestLoopback(unittest.TestCase):
    def test_exact_hosts(self):
        for url in (
            "http://localhost:9000",
            "http://LOCALHOST:9",
            "http://127.0.0.1:1",
            "http://[::1]:8080",
            "https://user:pass@127.0.0.1/mcp",
        ):
            self.assertTrue(is_loopback_url(url), url)

    def test_lookalikes_are_not_local(self):
        for url in (
            "http://localhost.evil.example/mcp",
            "https://evil.example/mcp?h=127.0.0.1",
            "http://127.0.0.1.evil.example",
            5,
            None,
        ):
            self.assertFalse(is_loopback_url(url), url)

    def test_malformed_ipv6_does_not_raise(self):
        self.assertFalse(is_loopback_url("http://[::1"))

    def test_config_remote_detection(self):
        self.assertFalse(config_has_remote_url({"command": "python", "args": ["srv.py"]}))
        self.assertFalse(config_has_remote_url({"url": "http://localhost:9000", "note": "localhost"}))
        self.assertFalse(config_has_remote_url({"url": 5}))
        self.assertTrue(
            config_has_remote_url({"url": "http://localhost.evil.example/mcp", "note": "localhost"})
        )
        self.assertTrue(
            config_has_remote_url({"url": "https://evil.example/mcp?h=127.0.0.1"})
        )
        self.assertTrue(
            config_has_remote_url({"args": ["mcp-remote", "https://evil.example/mcp"]})
        )


class TestToml(unittest.TestCase):
    def test_bom(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_bytes(b'\xef\xbb\xbf[ui]\npermission_mode = "default"\n')
            data, err = read_toml_table(path)
            self.assertIsNone(err)
            self.assertEqual(data["ui"]["permission_mode"], "default")

    def test_bad_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_bytes(b"\xff")
            data, err = read_toml_table(path)
            self.assertIsNone(data)
            self.assertEqual(err, "not UTF-8")


if __name__ == "__main__":
    unittest.main()
