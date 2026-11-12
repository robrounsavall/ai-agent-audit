"""Read models for the hub dashboard and JSON API.

Every function takes an open connection and returns plain dicts and lists,
so the HTML pages and the API serve the same numbers.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

import hub_paths  # noqa: F401

from hub_bundle import SEVERITIES
from hub_db import AGENT_COLLECTORS, TRIAGE_STATES

PAGE_SIZE = 100
# Triage states that take a finding off the "needs attention" list.
_SETTLED = ("acknowledged", "accepted_risk", "false_positive")
_SEV_CASE = "CASE {col} WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"


def _rows(cur: sqlite3.Cursor) -> list[dict[str, Any]]:
    return [dict(row) for row in cur.fetchall()]


def _like(text: str) -> str:
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


# ---- fleet ----------------------------------------------------------------

def overview(conn: sqlite3.Connection) -> dict[str, Any]:
    counts = dict.fromkeys(SEVERITIES, 0)
    attention = dict.fromkeys(SEVERITIES, 0)
    for row in conn.execute(
        "SELECT s.severity, COALESCE(t.state, 'open') AS triage, COUNT(*) AS n"
        " FROM finding_state s LEFT JOIN triage t ON t.host_id = s.host_id"
        " AND t.collector = s.collector AND t.finding_key = s.finding_key"
        " WHERE s.status = 'open' GROUP BY s.severity, triage"
    ):
        if row["severity"] not in counts:
            continue
        counts[row["severity"]] += row["n"]
        if row["triage"] not in _SETTLED:
            attention[row["severity"]] += row["n"]
    totals = conn.execute(
        "SELECT (SELECT COUNT(*) FROM hosts) AS hosts, (SELECT COUNT(*) FROM scans) AS scans,"
        " (SELECT MAX(scanned_at) FROM scans) AS last_scan,"
        " (SELECT COUNT(*) FROM finding_state WHERE status = 'resolved') AS resolved"
    ).fetchone()
    agents = conn.execute(
        "SELECT COUNT(*) FROM current_runs c JOIN collector_runs r ON r.id = c.run_id"
        " WHERE r.platform_detected = 1 AND c.collector IN (%s)" % ",".join("?" * len(AGENT_COLLECTORS)),
        tuple(AGENT_COLLECTORS),
    ).fetchone()[0]
    current = conn.execute(
        "SELECT (SELECT COUNT(*) FROM rules x JOIN current_runs c ON c.run_id = x.run_id"
        " WHERE x.decision = 'allow') AS allow_rules,"
        " (SELECT COUNT(DISTINCT lower(m.name)) FROM mcp_servers m JOIN current_runs c"
        " ON c.run_id = m.run_id) AS mcp_servers"
    ).fetchone()
    return {
        "hosts": totals["hosts"], "scans": totals["scans"], "last_scan": totals["last_scan"] or "",
        "resolved": totals["resolved"], "open": counts, "attention": attention,
        "open_total": sum(counts.values()), "agents": agents,
        "allow_rules": current["allow_rules"], "mcp_servers": current["mcp_servers"],
    }


def fleet_trend(conn: sqlite3.Connection, limit: int = 40) -> list[dict[str, Any]]:
    """Open findings by severity across every host, one point per scan.

    Each point is the sum of every host's posture as of that scan, so a
    host that did not scan that day still counts at its last known value.
    """
    scans = conn.execute(
        "SELECT s.id, s.host_id, h.name AS host, s.scanned_at, s.posture_critical AS critical,"
        " s.posture_high AS high, s.posture_medium AS medium, s.posture_low AS low"
        " FROM scans s JOIN hosts h ON h.id = s.host_id ORDER BY s.scanned_at, s.id"
    ).fetchall()
    held: dict[int, sqlite3.Row] = {}
    points = []
    for scan in scans:
        held[scan["host_id"]] = scan
        point = {"scan_id": scan["id"], "scanned_at": scan["scanned_at"], "host": scan["host"]}
        for sev in SEVERITIES:
            point[sev] = sum(row[sev] for row in held.values())
        points.append(point)
    return points[-limit:]


def hosts(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = _rows(conn.execute(
        "SELECT h.id, h.name, h.first_seen, h.last_seen,"
        " (SELECT COUNT(*) FROM scans s WHERE s.host_id = h.id) AS scan_count"
        " FROM hosts h ORDER BY h.last_seen DESC, h.name"
    ))
    for host in rows:
        host["open"] = dict.fromkeys(SEVERITIES, 0)
        for row in conn.execute(
            "SELECT severity, COUNT(*) AS n FROM finding_state WHERE host_id = ? AND status = 'open'"
            " GROUP BY severity", (host["id"],)
        ):
            if row["severity"] in host["open"]:
                host["open"][row["severity"]] = row["n"]
        host["agents"] = [
            AGENT_COLLECTORS[row["collector"]]
            for row in conn.execute(
                "SELECT c.collector FROM current_runs c JOIN collector_runs r ON r.id = c.run_id"
                " WHERE c.host_id = ? AND r.platform_detected = 1 ORDER BY c.collector", (host["id"],)
            )
            if row["collector"] in AGENT_COLLECTORS
        ]
        latest = conn.execute(
            "SELECT id, aiscan_version FROM scans WHERE host_id = ? ORDER BY scanned_at DESC, id DESC LIMIT 1",
            (host["id"],),
        ).fetchone()
        host["latest_scan_id"] = latest["id"] if latest else None
        host["aiscan_version"] = latest["aiscan_version"] if latest else ""
    return rows


def host(conn: sqlite3.Connection, host_id: int) -> dict[str, Any] | None:
    for item in hosts(conn):
        if item["id"] == host_id:
            return item
    return None


def host_trend(conn: sqlite3.Connection, host_id: int, limit: int = 40) -> list[dict[str, Any]]:
    rows = _rows(conn.execute(
        "SELECT s.id AS scan_id, s.scanned_at, h.name AS host, s.posture_critical AS critical,"
        " s.posture_high AS high, s.posture_medium AS medium, s.posture_low AS low"
        " FROM scans s JOIN hosts h ON h.id = s.host_id WHERE s.host_id = ?"
        " ORDER BY s.scanned_at DESC, s.id DESC LIMIT ?", (host_id, limit)
    ))
    return rows[::-1]


def current_runs(conn: sqlite3.Connection, host_id: int) -> list[dict[str, Any]]:
    rows = _rows(conn.execute(
        "SELECT r.id AS run_id, r.scan_id, r.collector, r.version, r.ran_at, r.platform_detected,"
        " r.detection_status, r.finding_count, r.rule_count FROM current_runs c"
        " JOIN collector_runs r ON r.id = c.run_id WHERE c.host_id = ? ORDER BY r.collector",
        (host_id,),
    ))
    for row in rows:
        row["label"] = AGENT_COLLECTORS.get(row["collector"], row["collector"])
        row["is_agent"] = row["collector"] in AGENT_COLLECTORS
    return rows


# ---- scans ----------------------------------------------------------------

_SCAN_COLUMNS = (
    "s.id, s.uid, s.host_id, h.name AS host, s.scanned_at, s.ingested_at, s.aiscan_version,"
    " s.launched_by, s.started, s.reason, s.source_label, s.share_safe, s.via, s.collector_count,"
    " s.finding_count, s.errors_json, s.posture_critical, s.posture_high, s.posture_medium,"
    " s.posture_low, s.posture_allow_rules, s.posture_mcp_servers, s.posture_agents"
)


def scans(
    conn: sqlite3.Connection, *, host_id: int | None = None, limit: int = PAGE_SIZE, offset: int = 0
) -> list[dict[str, Any]]:
    where, args = ("WHERE s.host_id = ?", [host_id]) if host_id is not None else ("", [])
    return _rows(conn.execute(
        f"SELECT {_SCAN_COLUMNS} FROM scans s JOIN hosts h ON h.id = s.host_id {where}"
        " ORDER BY s.scanned_at DESC, s.id DESC LIMIT ? OFFSET ?",
        (*args, limit, offset),
    ))


def scan(conn: sqlite3.Connection, scan_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        f"SELECT {_SCAN_COLUMNS} FROM scans s JOIN hosts h ON h.id = s.host_id WHERE s.id = ?",
        (scan_id,),
    ).fetchone()
    if row is None:
        return None
    out = dict(row)
    out["errors"] = json.loads(out.pop("errors_json") or "[]")
    out["runs"] = _rows(conn.execute(
        "SELECT id AS run_id, collector, version, ran_at, platform_detected, detection_status,"
        " finding_count, rule_count FROM collector_runs WHERE scan_id = ? ORDER BY collector",
        (scan_id,),
    ))
    out["findings"] = _rows(conn.execute(
        "SELECT collector, finding_key, finding_id, severity, category, title, evidence_count,"
        " sample, tags_json FROM findings WHERE scan_id = ? ORDER BY "
        + _SEV_CASE.format(col="severity") + ", evidence_count DESC, collector, title",
        (scan_id,),
    ))
    out["rule_count"] = conn.execute("SELECT COUNT(*) FROM rules WHERE scan_id = ?", (scan_id,)).fetchone()[0]
    return out


def _envelopes(conn: sqlite3.Connection, scan_id: int) -> dict[str, dict[str, Any]]:
    return {
        row["collector"]: json.loads(row["envelope_json"])
        for row in conn.execute(
            "SELECT collector, envelope_json FROM collector_runs WHERE scan_id = ?", (scan_id,)
        )
    }


def baseline_scan_id(conn: sqlite3.Connection, scan_id: int) -> int | None:
    """Earlier scan on the same host to compare against.

    Same rule as ``scan_diff.resolve_previous``: the newest earlier scan
    with the same collectors, else the newest with at least half as many.
    A one-collector scan has no automatic baseline.
    """
    import scan_diff

    current = conn.execute("SELECT host_id, scanned_at FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if current is None:
        return None
    names: dict[int, set[str]] = {}
    for row in conn.execute(
        "SELECT r.scan_id, r.collector FROM collector_runs r WHERE r.host_id = ?", (current["host_id"],)
    ):
        names.setdefault(row["scan_id"], set()).add(row["collector"])
    mine = names.get(scan_id, set())
    if len(mine) <= 1:
        return None
    fallback = None
    for row in conn.execute(
        "SELECT id FROM scans WHERE host_id = ? AND (scanned_at < ? OR (scanned_at = ? AND id < ?))"
        " ORDER BY scanned_at DESC, id DESC",
        (current["host_id"], current["scanned_at"], current["scanned_at"], scan_id),
    ):
        theirs = names.get(row["id"], set())
        if theirs == mine:
            return int(row["id"])
        if fallback is None and not scan_diff.baseline_too_small(len(theirs), len(mine)):
            fallback = int(row["id"])
    return fallback


def scan_changes(conn: sqlite3.Connection, scan_id: int) -> dict[str, Any] | None:
    """Changes envelope for a scan versus its baseline, cached per scan.

    Built by ``core/scan_diff.py``, the same code that writes
    ``evidence/changes.json``, so the hub and the briefing agree.
    """
    import scan_diff

    cached = conn.execute("SELECT changes_json FROM scan_diffs WHERE scan_id = ?", (scan_id,)).fetchone()
    if cached is not None:
        return json.loads(cached["changes_json"])
    current = _envelopes(conn, scan_id)
    if not current:
        return None
    base_id = baseline_scan_id(conn, scan_id)
    if base_id is None and len(current) <= 1:
        return None
    labels = {
        row["id"]: row["scanned_at"]
        for row in conn.execute("SELECT id, scanned_at FROM scans WHERE id IN (?, ?)", (scan_id, base_id or -1))
    }
    envelope = scan_diff.diff_envelopes(
        current,
        _envelopes(conn, base_id) if base_id is not None else None,
        current_label=labels.get(scan_id, ""),
        previous_label=labels.get(base_id, "") if base_id is not None else "",
    )
    envelope["previous_scan_id"] = base_id
    conn.execute(
        "INSERT OR REPLACE INTO scan_diffs(scan_id, previous_scan_id, changes_json) VALUES (?, ?, ?)",
        (scan_id, base_id, json.dumps(envelope, ensure_ascii=False)),
    )
    conn.commit()
    return envelope


def recent_changes(conn: sqlite3.Connection, limit: int = 8) -> list[dict[str, Any]]:
    """Newest scans that differ from their baseline, with the change counts."""
    out = []
    for row in scans(conn, limit=limit * 3):
        changes = scan_changes(conn, row["id"])
        if not changes:
            continue
        summary = changes.get("summary") or {}
        if summary.get("comparison") != "diff":
            continue
        keys = ("new_high_or_critical", "findings_added", "findings_resolved", "mcp_servers_added",
                "allow_rules_added", "drift_warnings")
        if not any(summary.get(key) for key in keys):
            continue
        out.append({"scan_id": row["id"], "host": row["host"], "scanned_at": row["scanned_at"],
                    **{key: int(summary.get(key) or 0) for key in keys}})
        if len(out) >= limit:
            break
    return out


# ---- findings -------------------------------------------------------------

def findings(
    conn: sqlite3.Connection,
    *,
    status: str = "open",
    severity: str = "",
    collector: str = "",
    host_id: int | None = None,
    triage: str = "",
    query: str = "",
    limit: int = PAGE_SIZE,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """Finding lifecycle rows across the fleet. Returns ``(rows, total)``."""
    where = ["1 = 1"]
    args: list[Any] = []
    if status in ("open", "resolved"):
        where.append("s.status = ?")
        args.append(status)
    if severity in SEVERITIES:
        where.append("s.severity = ?")
        args.append(severity)
    if collector:
        where.append("s.collector = ?")
        args.append(collector)
    if host_id is not None:
        where.append("s.host_id = ?")
        args.append(host_id)
    if triage == "attention":
        where.append("COALESCE(t.state, 'open') = 'open'")
    elif triage in TRIAGE_STATES:
        where.append("COALESCE(t.state, 'open') = ?")
        args.append(triage)
    if query:
        where.append("(s.title LIKE ? ESCAPE '\\' OR s.finding_id LIKE ? ESCAPE '\\' OR s.category LIKE ? ESCAPE '\\')")
        args.extend([_like(query)] * 3)
    base = (
        " FROM finding_state s JOIN hosts h ON h.id = s.host_id LEFT JOIN triage t"
        " ON t.host_id = s.host_id AND t.collector = s.collector AND t.finding_key = s.finding_key"
        " WHERE " + " AND ".join(where)
    )
    total = conn.execute("SELECT COUNT(*)" + base, args).fetchone()[0]
    rows = _rows(conn.execute(
        "SELECT s.*, h.name AS host, COALESCE(t.state, 'open') AS triage, COALESCE(t.note, '') AS note"
        + base + " ORDER BY " + _SEV_CASE.format(col="s.severity")
        + ", s.first_seen_at DESC, s.evidence_count DESC, s.title LIMIT ? OFFSET ?",
        (*args, limit, offset),
    ))
    return rows, total


def finding(conn: sqlite3.Connection, host_id: int, collector: str, key: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT s.*, h.name AS host, COALESCE(t.state, 'open') AS triage, COALESCE(t.note, '') AS note,"
        " COALESCE(t.updated_at, '') AS triage_at FROM finding_state s JOIN hosts h ON h.id = s.host_id"
        " LEFT JOIN triage t ON t.host_id = s.host_id AND t.collector = s.collector"
        " AND t.finding_key = s.finding_key WHERE s.host_id = ? AND s.collector = ? AND s.finding_key = ?",
        (host_id, collector, key),
    ).fetchone()
    if row is None:
        return None
    out = dict(row)
    # Every run of this collector on this host, with the finding's values
    # when it was present. A run with no row is a scan where it was absent.
    out["history"] = _rows(conn.execute(
        "SELECT r.id AS run_id, r.scan_id, r.ran_at, r.platform_detected,"
        " (SELECT COUNT(*) FROM findings f WHERE f.run_id = r.id AND f.finding_key = ?) AS present,"
        " (SELECT SUM(f.evidence_count) FROM findings f WHERE f.run_id = r.id AND f.finding_key = ?) AS evidence_count,"
        " (SELECT f.severity FROM findings f WHERE f.run_id = r.id AND f.finding_key = ? LIMIT 1) AS severity,"
        " (SELECT f.sample FROM findings f WHERE f.run_id = r.id AND f.finding_key = ? LIMIT 1) AS sample"
        " FROM collector_runs r WHERE r.host_id = ? AND r.collector = ? ORDER BY r.ran_at DESC, r.id DESC LIMIT 60",
        (key, key, key, key, host_id, collector),
    ))
    latest = conn.execute(
        "SELECT f.sample, f.tags_json FROM findings f JOIN collector_runs r ON r.id = f.run_id"
        " WHERE f.host_id = ? AND f.collector = ? AND f.finding_key = ? ORDER BY r.ran_at DESC, f.id LIMIT 1",
        (host_id, collector, key),
    ).fetchone()
    out["sample"] = latest["sample"] if latest else ""
    out["tags"] = json.loads(latest["tags_json"]) if latest else []
    return out


def collectors_with_findings(conn: sqlite3.Connection) -> list[str]:
    return [row[0] for row in conn.execute("SELECT DISTINCT collector FROM finding_state ORDER BY collector")]


# ---- current inventory ----------------------------------------------------

def rules(
    conn: sqlite3.Connection,
    *,
    decision: str = "allow",
    risk: str = "",
    host_id: int | None = None,
    query: str = "",
    limit: int = PAGE_SIZE,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """Permission rules from the newest run of each collector on each host."""
    where = ["1 = 1"]
    args: list[Any] = []
    if decision in ("allow", "deny", "ask"):
        where.append("x.decision = ?")
        args.append(decision)
    if risk in SEVERITIES:
        where.append("x.risk = ?")
        args.append(risk)
    if host_id is not None:
        where.append("x.host_id = ?")
        args.append(host_id)
    if query:
        where.append("(x.rule LIKE ? ESCAPE '\\' OR x.command LIKE ? ESCAPE '\\' OR x.scope_label LIKE ? ESCAPE '\\')")
        args.extend([_like(query)] * 3)
    base = (
        " FROM rules x JOIN current_runs c ON c.run_id = x.run_id JOIN hosts h ON h.id = x.host_id"
        " WHERE " + " AND ".join(where)
    )
    group = " GROUP BY x.host_id, x.collector, x.scope, x.scope_label, x.rule_type, x.rule, x.decision"
    total = conn.execute("SELECT COUNT(*) FROM (SELECT 1" + base + group + ")", args).fetchone()[0]
    rows = _rows(conn.execute(
        "SELECT h.name AS host, x.host_id, x.collector, x.platform, x.scope, x.scope_label, x.rule_type,"
        " x.rule, x.decision, x.risk, x.exposure_category, x.source_kind, COUNT(*) AS n"
        + base + group + " ORDER BY " + _SEV_CASE.format(col="x.risk")
        + ", h.name, x.collector, x.rule LIMIT ? OFFSET ?",
        (*args, limit, offset),
    ))
    return rows, total


def rule_totals(conn: sqlite3.Connection) -> dict[str, dict[str, int]]:
    out = {decision: dict.fromkeys(SEVERITIES, 0) for decision in ("allow", "deny", "ask")}
    for row in conn.execute(
        "SELECT x.decision, x.risk, COUNT(*) AS n FROM rules x JOIN current_runs c ON c.run_id = x.run_id"
        " GROUP BY x.decision, x.risk"
    ):
        if row["decision"] in out and row["risk"] in out[row["decision"]]:
            out[row["decision"]][row["risk"]] = row["n"]
    return out


def mcp_servers(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """MCP servers in current posture, one row per server name."""
    grouped: dict[str, dict[str, Any]] = {}
    for row in conn.execute(
        "SELECT m.name, m.collector, h.name AS host, m.host_id,"
        " (SELECT MIN(r2.ran_at) FROM mcp_servers m2 JOIN collector_runs r2 ON r2.id = m2.run_id"
        "  WHERE m2.host_id = m.host_id AND lower(m2.name) = lower(m.name)) AS first_seen"
        " FROM mcp_servers m JOIN current_runs c ON c.run_id = m.run_id JOIN hosts h ON h.id = m.host_id"
        " ORDER BY lower(m.name), h.name, m.collector"
    ):
        entry = grouped.setdefault(row["name"].casefold(), {
            "name": row["name"], "hosts": [], "tools": [], "first_seen": row["first_seen"] or "",
        })
        if row["host"] not in entry["hosts"]:
            entry["hosts"].append(row["host"])
        label = AGENT_COLLECTORS.get(row["collector"], row["collector"])
        if label not in entry["tools"]:
            entry["tools"].append(label)
        if row["first_seen"] and row["first_seen"] < entry["first_seen"]:
            entry["first_seen"] = row["first_seen"]
    return list(grouped.values())


def accounts(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return _rows(conn.execute(
        "SELECT h.name AS host, a.host_id, a.tool, a.signed_in, a.account, a.organization, a.plan,"
        " a.auth_method, a.source, a.last_sign_in FROM accounts a JOIN current_runs c"
        " ON c.run_id = a.run_id JOIN hosts h ON h.id = a.host_id ORDER BY h.name, a.tool"
    ))


def tokens(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return _rows(conn.execute(
        "SELECT name, created_at, last_used_at, revoked_at FROM tokens ORDER BY created_at DESC"
    ))
