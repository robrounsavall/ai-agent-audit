"""Store behavior: dedupe, current posture, finding lifecycle, triage, prune."""

from __future__ import annotations

import unittest

import bootstrap  # noqa: F401
from bootstrap import allow_rule, envelope, finding, raw_bundle

import hub_db
import hub_queries as q
from hub_bundle import normalize_bundle

DAY = "2026-10-{:02d}T12:00:00+00:00"


def ingest(conn, day: int, collectors: dict, host: str = "TEST-HOST") -> dict:
    bundle, _ = normalize_bundle(raw_bundle(DAY.format(day), collectors, host=host))
    return hub_db.ingest_bundle(conn, bundle)


def states(conn, **filters) -> dict:
    rows, _ = q.findings(conn, status="all", **filters)
    return {(r["collector"], r["finding_key"]): r for r in rows}


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.conn = hub_db.connect(":memory:")
        self.addCleanup(self.conn.close)

    def test_same_scan_is_stored_once(self):
        first = ingest(self.conn, 1, {"claude": [finding("a.one")]})
        again = ingest(self.conn, 1, {"claude": [finding("a.one")]})
        self.assertFalse(first["duplicate"])
        self.assertTrue(again["duplicate"])
        self.assertEqual(first["scan_id"], again["scan_id"])
        self.assertEqual(q.overview(self.conn)["scans"], 1)

    def test_finding_opens_resolves_and_reopens(self):
        ingest(self.conn, 1, {"claude": [finding("a.one", "critical")]})
        ingest(self.conn, 2, {"claude": []})
        row = states(self.conn)[("claude", "a.one")]
        self.assertEqual(row["status"], "resolved")
        self.assertEqual(row["first_seen_at"], "2026-10-01T12:00:00Z")
        self.assertEqual(row["resolved_at"], "2026-10-02T12:00:00Z")
        ingest(self.conn, 3, {"claude": [finding("a.one", "critical")]})
        row = states(self.conn)[("claude", "a.one")]
        self.assertEqual(row["status"], "open")
        self.assertEqual(row["first_seen_at"], "2026-10-01T12:00:00Z")
        self.assertEqual(row["occurrences"], 2)

    def test_one_collector_rerun_leaves_other_collectors_open(self):
        ingest(self.conn, 1, {"claude": [finding("a.one")], "codex": [finding("c.one", "critical")]})
        ingest(self.conn, 2, {"claude": []})
        got = states(self.conn)
        self.assertEqual(got[("claude", "a.one")]["status"], "resolved")
        self.assertEqual(got[("codex", "c.one")]["status"], "open")
        self.assertEqual(q.overview(self.conn)["open"]["critical"], 1)
        # Posture after the second scan still counts codex from the first.
        latest = q.scans(self.conn)[0]
        self.assertEqual(latest["posture_critical"], 1)
        self.assertEqual(latest["posture_high"], 0)

    def test_scan_ingested_out_of_order_lands_in_time_order(self):
        ingest(self.conn, 5, {"claude": []})
        ingest(self.conn, 1, {"claude": [finding("a.one")]})
        row = states(self.conn)[("claude", "a.one")]
        self.assertEqual(row["status"], "resolved")
        self.assertEqual(row["resolved_at"], "2026-10-05T12:00:00Z")
        self.assertEqual(q.overview(self.conn)["open_total"], 0)

    def test_severity_and_count_follow_the_newest_run(self):
        ingest(self.conn, 1, {"claude": [finding("a.one", "medium", evidence_count=2)]})
        ingest(self.conn, 2, {"claude": [finding("a.one", "critical", evidence_count=7)]})
        row = states(self.conn)[("claude", "a.one")]
        self.assertEqual((row["severity"], row["evidence_count"]), ("critical", 7))

    def test_finding_without_an_id_is_tracked_by_title(self):
        ingest(self.conn, 1, {"claude": [finding("", title="No id here")]})
        ingest(self.conn, 2, {"claude": [finding("", title="No id here")]})
        rows, total = q.findings(self.conn, status="open")
        self.assertEqual(total, 1)
        self.assertEqual(rows[0]["occurrences"], 2)

    def test_hosts_are_separate(self):
        ingest(self.conn, 1, {"claude": [finding("a.one")]}, host="ONE")
        ingest(self.conn, 1, {"claude": [finding("a.one")]}, host="TWO")
        ingest(self.conn, 2, {"claude": []}, host="ONE")
        self.assertEqual(q.overview(self.conn)["hosts"], 2)
        rows, _ = q.findings(self.conn, status="open")
        self.assertEqual([r["host"] for r in rows], ["TWO"])
        self.assertEqual([p["high"] for p in q.fleet_trend(self.conn)], [1, 2, 1])

    def test_triage_survives_later_scans_and_filters_attention(self):
        ingest(self.conn, 1, {"claude": [finding("a.one", "critical"), finding("a.two", "critical")]})
        host_id = q.hosts(self.conn)[0]["id"]
        hub_db.set_triage(self.conn, host_id, "claude", "a.one", "accepted_risk", "known, lab box")
        ingest(self.conn, 2, {"claude": [finding("a.one", "critical"), finding("a.two", "critical")]})
        item = q.finding(self.conn, host_id, "claude", "a.one")
        self.assertEqual((item["triage"], item["note"]), ("accepted_risk", "known, lab box"))
        rows, _total = q.findings(self.conn, status="open", triage="attention")
        self.assertEqual([r["finding_key"] for r in rows], ["a.two"])
        overview = q.overview(self.conn)
        self.assertEqual((overview["open"]["critical"], overview["attention"]["critical"]), (2, 1))
        with self.assertRaises(ValueError):
            hub_db.set_triage(self.conn, host_id, "claude", "a.one", "made_up")
        with self.assertRaises(LookupError):
            hub_db.set_triage(self.conn, host_id, "claude", "no.such", "acknowledged")

    def test_current_rules_and_mcp_come_from_the_newest_run(self):
        old = [allow_rule("Bash(curl:*)"), allow_rule("mcp__old", "medium", "mcp_tool")]
        new = [allow_rule("Bash(ls)", "low"), allow_rule("mcp__new", "medium", "mcp_tool")]
        ingest(self.conn, 1, {"claude": envelope("claude", DAY.format(1), [], old)})
        ingest(self.conn, 2, {"claude": envelope("claude", DAY.format(2), [], new)})
        rows, _total = q.rules(self.conn)
        self.assertEqual(sorted(r["rule"] for r in rows), ["Bash(ls)", "mcp__new"])
        self.assertEqual([m["name"] for m in q.mcp_servers(self.conn)], ["new"])

    def test_changes_use_scan_diff_and_pick_the_previous_full_scan(self):
        first = ingest(self.conn, 1, {"claude": [finding("a.one")], "codex": []})
        second = ingest(self.conn, 2, {"claude": [finding("a.one"), finding("a.two", "critical")], "codex": []})
        retry = ingest(self.conn, 3, {"claude": []})
        self.assertEqual(q.scan_changes(self.conn, first["scan_id"])["summary"]["comparison"], "first_scan")
        changes = q.scan_changes(self.conn, second["scan_id"])
        self.assertEqual(changes["previous_scan_id"], first["scan_id"])
        self.assertEqual(changes["summary"]["findings_added"], 1)
        self.assertEqual(changes["summary"]["new_high_or_critical"], 1)
        self.assertIsNone(q.scan_changes(self.conn, retry["scan_id"]))
        self.assertEqual([c["scan_id"] for c in q.recent_changes(self.conn)], [second["scan_id"]])

    def test_prune_keeps_each_hosts_newest_scan(self):
        for day in (1, 2, 3):
            ingest(self.conn, day, {"claude": [finding("a.one")]})
        self.assertEqual(hub_db.prune(self.conn, keep_days=0, dry_run=True), 2)
        self.assertEqual(q.overview(self.conn)["scans"], 3)
        self.assertEqual(hub_db.prune(self.conn, keep_days=0), 2)
        self.assertEqual(q.overview(self.conn)["scans"], 1)
        row = states(self.conn)[("claude", "a.one")]
        self.assertEqual((row["status"], row["first_seen_at"]), ("open", "2026-10-03T12:00:00Z"))
        self.assertEqual(hub_db.prune(self.conn, keep_last=1), 0)

    def test_ingest_tokens(self):
        token = hub_db.create_token(self.conn, "laptop")
        self.assertIsNotNone(hub_db.find_token(self.conn, token))
        self.assertIsNone(hub_db.find_token(self.conn, token + "x"))
        self.assertIsNone(hub_db.find_token(self.conn, ""))
        stored = [row[0] for row in self.conn.execute("SELECT token_hash FROM tokens")]
        self.assertNotIn(token, stored)
        self.assertTrue(hub_db.revoke_token(self.conn, "laptop"))
        self.assertIsNone(hub_db.find_token(self.conn, token))

    def test_newer_schema_is_refused(self):
        self.conn.execute(f"PRAGMA user_version = {hub_db.SCHEMA_VERSION + 1}")
        with self.assertRaises(RuntimeError):
            hub_db._migrate(self.conn)


if __name__ == "__main__":
    unittest.main()
