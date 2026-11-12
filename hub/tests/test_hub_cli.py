"""The command line: ingest, status, push, tokens, demo."""

from __future__ import annotations

import io
import json
import os
import shutil
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import bootstrap
from bootstrap import envelope, finding

import aiscan_hub
import hub_db
import hub_queries as q
import hub_web

SAMPLES = bootstrap.REPO_ROOT / "samples"
FAKE_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = aiscan_hub.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = str(self.tmp / "hub.db")

    def scan_folder(self, name="scan", findings=()):
        root = self.tmp / name
        (root / "evidence").mkdir(parents=True)
        (root / "raw" / "chat-history").mkdir(parents=True)
        (root / "raw" / "chat-history" / "day.md").write_text("TRANSCRIPT-MARKER", encoding="utf-8")
        env = envelope("claude", "2026-10-01T12:00:00+00:00", list(findings) or [finding("a.one")])
        env["raw_pointers"] = [{"kind": "chat", "path": "raw/chat-history/day.md"}]
        (root / "evidence" / "claude.json").write_text(json.dumps(env), encoding="utf-8")
        return root


class IngestCommandTests(CliCase):
    def test_ingest_a_folder_of_scans_then_status(self):
        code, out, _ = run("--db", self.db, "ingest", str(SAMPLES))
        self.assertEqual(code, 0)
        self.assertIn("2 scan(s) added", out)
        code, out, _ = run("--db", self.db, "ingest", str(SAMPLES / "synthetic-demo"))
        self.assertIn("0 scan(s) added, 1 already stored", out)
        code, out, _ = run("--db", self.db, "status", "--json")
        self.assertEqual(json.loads(out)["scans"], 2)

    def test_ingest_never_reads_raw(self):
        root = self.scan_folder()
        self.assertEqual(run("--db", self.db, "ingest", str(root))[0], 0)
        conn = hub_db.connect(self.db)
        try:
            dump = "\n".join(conn.iterdump())
        finally:
            conn.close()
        self.assertNotIn("TRANSCRIPT-MARKER", dump)
        self.assertNotIn("raw/chat-history", dump)

    def test_messages_do_not_repeat_full_paths(self):
        missing = self.tmp / "not-a-scan"
        missing.mkdir()
        code, out, err = run("--db", self.db, "ingest", str(missing))
        self.assertEqual(code, 1)
        self.assertNotIn(str(self.tmp), out + err)
        self.assertIn("not-a-scan", err)

    def test_ingest_with_no_paths_uses_the_default_scans_root(self):
        scans = self.tmp / "scans"
        first = self.scan_folder("scans/2026-11-12_1500")
        second = self.scan_folder("scans/2026-11-12_1515", findings=[finding("a.two")])
        env = json.loads((second / "evidence" / "claude.json").read_text(encoding="utf-8"))
        env["ran_at"] = "2026-11-12T15:15:00+00:00"
        (second / "evidence" / "claude.json").write_text(json.dumps(env), encoding="utf-8")
        pointer = scans / "latest"
        (pointer / "evidence").mkdir(parents=True)
        (pointer / "evidence" / "claude.json").write_text(
            (first / "evidence" / "claude.json").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        with mock.patch.dict(os.environ, {"AISCAN_SCANS_ROOT": str(scans)}, clear=False):
            code, out, err = run("--db", self.db, "ingest")
        self.assertEqual(code, 0, out + err)
        self.assertIn("2 scan(s) added", out)
        conn = hub_db.connect(self.db)
        try:
            count = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(count, 2)

    def test_ingest_default_hints_at_legacy_aiscan_results(self):
        scans = self.tmp / "scans"
        scans.mkdir()
        legacy = self.tmp / "local" / "aiscan-results"
        self.scan_folder("local/aiscan-results/20261018-090000")
        env = {
            "AISCAN_SCANS_ROOT": str(scans),
            "LOCALAPPDATA": str(self.tmp / "local"),
        }
        with mock.patch.dict(os.environ, env, clear=False):
            code, out, err = run("--db", self.db, "ingest")
        self.assertEqual(code, 1, out + err)
        self.assertIn("aiscan-results", err)
        self.assertIn("were not moved", err)
        self.assertNotIn(str(self.tmp), out + err)

    def test_ingest_default_root_helper_imports_scans(self):
        scans = self.tmp / "scans"
        self.scan_folder("scans/2026-11-12_1500")
        with mock.patch.dict(os.environ, {"AISCAN_SCANS_ROOT": str(scans)}, clear=False):
            added, duplicate, failed = aiscan_hub.ingest_default_root(Path(self.db))
        self.assertEqual((added, duplicate, failed), (1, 0, 0))
        with mock.patch.dict(os.environ, {"AISCAN_SCANS_ROOT": str(scans)}, clear=False):
            added, duplicate, failed = aiscan_hub.ingest_default_root(Path(self.db))
        self.assertEqual((added, duplicate, failed), (0, 1, 0))


class PushTests(CliCase):
    def test_push_url_rules(self):
        ok = aiscan_hub.push_url("https://hub.example:8765/", insecure_http=False)
        self.assertEqual(ok, "https://hub.example:8765/api/v1/scans")
        self.assertTrue(aiscan_hub.push_url("http://127.0.0.1:8765", insecure_http=False).startswith("http://127.0.0.1"))
        self.assertTrue(aiscan_hub.push_url("http://hub.lan", insecure_http=True).startswith("http://hub.lan"))
        for bad in ("http://hub.example", "ftp://hub.example", "hub.example", "https://user:pw@hub.example",
                    "https://hub.example/?x=1", "http://localhost.evil.example"):
            with self.assertRaises(ValueError, msg=bad):
                aiscan_hub.push_url(bad, insecure_http=False)

    def test_dry_run_prints_a_share_safe_bundle_and_sends_nothing(self):
        root = self.scan_folder(findings=[finding("a.one", sample_redacted=f"key {FAKE_KEY}")])
        with mock.patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("network call")):
            code, out, err = run("push", str(root), "--dry-run")
        self.assertEqual(code, 0)
        bundle = json.loads(out)
        self.assertTrue(bundle["share_safe"])
        self.assertNotIn(FAKE_KEY, out)
        self.assertNotIn("raw_pointers", out)
        self.assertNotIn("TRANSCRIPT-MARKER", out)
        self.assertIn("Nothing was sent", err)

    def test_push_needs_a_token_in_the_environment(self):
        root = self.scan_folder()
        with mock.patch.dict(os.environ, {"AISCAN_HUB_TOKEN": ""}):
            code, _, err = run("push", str(root), "--server", "http://127.0.0.1:9")
        self.assertEqual(code, 1)
        self.assertIn("AISCAN_HUB_TOKEN", err)

    def test_push_round_trip_to_a_local_hub(self):
        conn = hub_db.connect(self.db)
        token = hub_db.create_token(conn, "laptop")
        conn.close()
        config = hub_web.HubConfig(db_path=Path(self.db), ui_token="ui-token-for-tests-0123456789", port=0)
        server = hub_web.make_server(config)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            root = self.scan_folder(findings=[finding("a.one", sample_redacted=f"key {FAKE_KEY}")])
            with mock.patch.dict(os.environ, {"AISCAN_HUB_TOKEN": token}):
                code, out, err = run("push", str(root), "--server", f"http://127.0.0.1:{config.port}")
                self.assertEqual(code, 0, err)
                self.assertIn("stored as #", out)
                self.assertNotIn(token, out + err)
                code, out, _ = run("push", str(root), "--server", f"http://127.0.0.1:{config.port}")
                self.assertIn("already stored", out)
            with mock.patch.dict(os.environ, {"AISCAN_HUB_TOKEN": "aish_wrong"}):
                code, _, err = run("push", str(root), "--server", f"http://127.0.0.1:{config.port}")
                self.assertEqual(code, 2)
                self.assertIn("401", err)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        conn = hub_db.connect(self.db)
        try:
            self.assertEqual(q.overview(conn)["scans"], 1)
            self.assertNotIn(FAKE_KEY, "\n".join(conn.iterdump()))
        finally:
            conn.close()


class OtherCommandTests(CliCase):
    def test_token_create_list_revoke(self):
        code, out, _ = run("--db", self.db, "token", "create", "--name", "laptop")
        self.assertEqual(code, 0)
        token = next(line for line in out.splitlines() if line.startswith("aish_"))
        code, out, _ = run("--db", self.db, "token", "list")
        self.assertIn("laptop\tactive", out)
        self.assertNotIn(token, out)
        self.assertEqual(run("--db", self.db, "token", "create", "--name", "laptop")[0], 1)
        self.assertEqual(run("--db", self.db, "token", "revoke", "--name", "laptop")[0], 0)
        self.assertEqual(run("--db", self.db, "token", "revoke", "--name", "laptop")[0], 1)

    def test_serve_refuses_plain_http_off_loopback(self):
        code, _, err = run("--db", self.db, "serve", "--bind", "0.0.0.0", "--no-browser")
        self.assertEqual(code, 1)
        self.assertIn("plain HTTP", err)

    def test_ui_token_is_created_once_and_can_be_rotated(self):
        first = aiscan_hub.load_ui_token(self.tmp)
        self.assertGreaterEqual(len(first), 32)
        self.assertEqual(aiscan_hub.load_ui_token(self.tmp), first)
        self.assertNotEqual(aiscan_hub.load_ui_token(self.tmp, rotate=True), first)

    def test_demo_builds_a_separate_database(self):
        demo_db = str(self.tmp / "demo.db")
        code, out, _ = run("--db", demo_db, "demo", "--no-serve")
        self.assertEqual(code, 0)
        conn = hub_db.connect(demo_db)
        try:
            overview = q.overview(conn)
        finally:
            conn.close()
        self.assertEqual(overview["hosts"], 3)
        self.assertGreater(overview["scans"], 20)

    def test_prune_needs_a_rule(self):
        self.assertEqual(run("--db", self.db, "prune")[0], 1)
        self.assertEqual(run("--db", self.db, "prune", "--keep-days", "30", "--dry-run")[0], 0)


if __name__ == "__main__":
    unittest.main()
