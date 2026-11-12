"""SQLite store for the hub: schema, ingest, and derived state.

One file, opened with the stdlib ``sqlite3`` module. Nothing here listens on
a socket. The web server and the CLI both call ``ingest_bundle``.

Tables hold three kinds of rows:

- what a scan said: ``scans``, ``collector_runs``, ``findings``, ``rules``,
  ``accounts``, ``mcp_servers``, ``metrics``. Written once, never edited.
- what follows from those: ``current_runs``, ``finding_state``, the
  ``posture_*`` columns on ``scans``, and ``scan_diffs``. Rebuilt for a host
  whenever that host gets a new scan, so a scan ingested out of order still
  lands in the right place.
- what a person decided: ``triage`` and ``tokens``. Never rebuilt.

"Current posture" for a host is the newest run of each collector, not the
newest scan. A one-collector re-run then updates that collector and leaves
the others in place, and a collector that failed to write evidence does not
make its earlier findings look resolved.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from pathlib import Path
from typing import Any

import hub_paths  # noqa: F401

from hub_bundle import SEVERITIES, now_utc, scan_uid, to_utc

SCHEMA_VERSION = 1

# Collectors that describe an AI agent installed on the machine. The rest
# (chat-history, secrets-scan, ...) scan what those agents left behind.
AGENT_COLLECTORS = {
    "claude": "Claude Code",
    "cowork": "Claude Cowork",
    "cursor": "Cursor",
    "codex": "Codex",
    "vscode": "VS Code / Copilot",
    "copilot": "GitHub Copilot",
    "grok": "Grok Build",
    "grok-bot": "Grok Bot",
    "cloud-agents": "Cursor cloud agents",
}

TRIAGE_STATES = ("open", "acknowledged", "accepted_risk", "false_positive")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hosts(
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens(
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS scans(
    id INTEGER PRIMARY KEY,
    uid TEXT NOT NULL UNIQUE,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    scanned_at TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    aiscan_version TEXT NOT NULL DEFAULT '',
    launched_by TEXT NOT NULL DEFAULT 'unknown',
    started TEXT NOT NULL DEFAULT 'unknown',
    reason TEXT NOT NULL DEFAULT 'unknown',
    source_label TEXT NOT NULL DEFAULT '',
    share_safe INTEGER NOT NULL DEFAULT 0,
    via TEXT NOT NULL DEFAULT 'local',
    token_id INTEGER REFERENCES tokens(id) ON DELETE SET NULL,
    collector_count INTEGER NOT NULL DEFAULT 0,
    finding_count INTEGER NOT NULL DEFAULT 0,
    errors_json TEXT NOT NULL DEFAULT '[]',
    posture_critical INTEGER NOT NULL DEFAULT 0,
    posture_high INTEGER NOT NULL DEFAULT 0,
    posture_medium INTEGER NOT NULL DEFAULT 0,
    posture_low INTEGER NOT NULL DEFAULT 0,
    posture_allow_rules INTEGER NOT NULL DEFAULT 0,
    posture_mcp_servers INTEGER NOT NULL DEFAULT 0,
    posture_agents INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS scans_host_time ON scans(host_id, scanned_at);
CREATE TABLE IF NOT EXISTS collector_runs(
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    collector TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '',
    ran_at TEXT NOT NULL,
    platform_detected INTEGER NOT NULL DEFAULT 0,
    detection_status TEXT NOT NULL DEFAULT '',
    scope_hash TEXT NOT NULL DEFAULT '',
    finding_count INTEGER NOT NULL DEFAULT 0,
    rule_count INTEGER NOT NULL DEFAULT 0,
    envelope_json TEXT NOT NULL,
    UNIQUE(scan_id, collector)
);
CREATE INDEX IF NOT EXISTS runs_host_collector ON collector_runs(host_id, collector, ran_at);
CREATE TABLE IF NOT EXISTS findings(
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    run_id INTEGER NOT NULL REFERENCES collector_runs(id) ON DELETE CASCADE,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    collector TEXT NOT NULL,
    finding_key TEXT NOT NULL,
    finding_id TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    evidence_count INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL DEFAULT '',
    last_seen TEXT NOT NULL DEFAULT '',
    sample TEXT NOT NULL DEFAULT '',
    secret_redacted INTEGER NOT NULL DEFAULT 0,
    tags_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS findings_key ON findings(host_id, collector, finding_key);
CREATE TABLE IF NOT EXISTS rules(
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    run_id INTEGER NOT NULL REFERENCES collector_runs(id) ON DELETE CASCADE,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    collector TEXT NOT NULL,
    platform TEXT NOT NULL DEFAULT '',
    scope TEXT NOT NULL DEFAULT '',
    scope_label TEXT NOT NULL DEFAULT '',
    rule_type TEXT NOT NULL DEFAULT '',
    rule TEXT NOT NULL DEFAULT '',
    decision TEXT NOT NULL DEFAULT '',
    command TEXT NOT NULL DEFAULT '',
    risk TEXT NOT NULL DEFAULT '',
    exposure_category TEXT NOT NULL DEFAULT '',
    source_kind TEXT NOT NULL DEFAULT '',
    confidence TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS rules_run ON rules(run_id);
CREATE TABLE IF NOT EXISTS accounts(
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    run_id INTEGER NOT NULL REFERENCES collector_runs(id) ON DELETE CASCADE,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    tool TEXT NOT NULL,
    signed_in TEXT NOT NULL DEFAULT '',
    account TEXT NOT NULL DEFAULT '',
    organization TEXT NOT NULL DEFAULT '',
    plan TEXT NOT NULL DEFAULT '',
    auth_method TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    last_sign_in TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS accounts_run ON accounts(run_id);
CREATE TABLE IF NOT EXISTS mcp_servers(
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    run_id INTEGER NOT NULL REFERENCES collector_runs(id) ON DELETE CASCADE,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    collector TEXT NOT NULL,
    name TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS mcp_run ON mcp_servers(run_id);
CREATE TABLE IF NOT EXISTS metrics(
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    run_id INTEGER NOT NULL REFERENCES collector_runs(id) ON DELETE CASCADE,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    collector TEXT NOT NULL,
    key TEXT NOT NULL,
    value REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS metrics_series ON metrics(host_id, collector, key);
CREATE INDEX IF NOT EXISTS metrics_run ON metrics(run_id);
CREATE TABLE IF NOT EXISTS current_runs(
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    collector TEXT NOT NULL,
    run_id INTEGER NOT NULL REFERENCES collector_runs(id) ON DELETE CASCADE,
    PRIMARY KEY(host_id, collector)
);
CREATE TABLE IF NOT EXISTS finding_state(
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    collector TEXT NOT NULL,
    finding_key TEXT NOT NULL,
    finding_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    evidence_count INTEGER NOT NULL DEFAULT 0,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    resolved_at TEXT NOT NULL DEFAULT '',
    occurrences INTEGER NOT NULL DEFAULT 0,
    first_scan_id INTEGER,
    last_scan_id INTEGER,
    PRIMARY KEY(host_id, collector, finding_key)
);
CREATE INDEX IF NOT EXISTS finding_state_status ON finding_state(status, severity);
CREATE TABLE IF NOT EXISTS triage(
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    collector TEXT NOT NULL,
    finding_key TEXT NOT NULL,
    state TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    PRIMARY KEY(host_id, collector, finding_key)
);
CREATE TABLE IF NOT EXISTS scan_diffs(
    scan_id INTEGER PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    previous_scan_id INTEGER,
    changes_json TEXT NOT NULL
);
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Open (and create or migrate) the database."""
    path = Path(db_path)
    if str(path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    if str(path) != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL")
    _migrate(conn)
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version > SCHEMA_VERSION:
        raise RuntimeError(
            f"hub database is schema {version}; this aiscan reads up to {SCHEMA_VERSION}. "
            "Update aiscan before opening it."
        )
    if version < 1:
        conn.executescript(_SCHEMA)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        conn.commit()
    # Later versions: add `if version < 2:` steps here, each ending with its
    # own PRAGMA user_version, so an old file upgrades in order.


# ---- tokens ---------------------------------------------------------------

def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_token(conn: sqlite3.Connection, name: str) -> str:
    """Create an ingest token. The plain value is returned once, never stored."""
    token = "aish_" + secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO tokens(name, token_hash, created_at) VALUES (?, ?, ?)",
        (name, hash_token(token), now_utc()),
    )
    conn.commit()
    return token


def find_token(conn: sqlite3.Connection, token: str) -> int | None:
    """Row id of a live ingest token, or None."""
    if not token:
        return None
    row = conn.execute(
        "SELECT id FROM tokens WHERE token_hash = ? AND revoked_at IS NULL",
        (hash_token(token),),
    ).fetchone()
    return int(row["id"]) if row else None


def revoke_token(conn: sqlite3.Connection, name: str) -> bool:
    cur = conn.execute(
        "UPDATE tokens SET revoked_at = ? WHERE name = ? AND revoked_at IS NULL",
        (now_utc(), name),
    )
    conn.commit()
    return cur.rowcount > 0


# ---- ingest ---------------------------------------------------------------

def finding_key(finding: dict[str, Any]) -> str:
    """Identity of a finding across scans: its id, or a hash of its title."""
    fid = str(finding.get("id") or "").strip()
    if fid:
        return fid
    title = str(finding.get("title") or "")
    return "title:" + hashlib.sha256(title.encode("utf-8")).hexdigest()[:16]


def _host_id(conn: sqlite3.Connection, name: str, when: str) -> int:
    row = conn.execute("SELECT id, first_seen, last_seen FROM hosts WHERE name = ?", (name,)).fetchone()
    if row is None:
        cur = conn.execute(
            "INSERT INTO hosts(name, first_seen, last_seen) VALUES (?, ?, ?)", (name, when, when)
        )
        return int(cur.lastrowid)
    conn.execute(
        "UPDATE hosts SET first_seen = ?, last_seen = ? WHERE id = ?",
        (min(row["first_seen"], when), max(row["last_seen"], when), row["id"]),
    )
    return int(row["id"])


def ingest_bundle(
    conn: sqlite3.Connection,
    bundle: dict[str, Any],
    *,
    via: str = "local",
    token_id: int | None = None,
) -> dict[str, Any]:
    """Store one normalized bundle. Returns ``{scan_id, duplicate, host}``.

    The bundle must already have passed ``hub_bundle.normalize_bundle``.
    The same scan sent twice is stored once.
    """
    import scan_diff

    uid = scan_uid(bundle)
    existing = conn.execute("SELECT id FROM scans WHERE uid = ?", (uid,)).fetchone()
    if existing is not None:
        return {"scan_id": int(existing["id"]), "duplicate": True, "host": bundle["host"]}

    collectors: dict[str, dict[str, Any]] = bundle["collectors"]
    ingested = now_utc()
    run_times = {name: to_utc(env.get("ran_at")) or ingested for name, env in collectors.items()}
    scanned_at = max(run_times.values())
    origin = bundle.get("run_origin") or {}
    status = bundle.get("collector_status") or {}

    try:
        conn.execute("BEGIN IMMEDIATE")
        host_id = _host_id(conn, bundle["host"], scanned_at)
        cur = conn.execute(
            "INSERT INTO scans(uid, host_id, scanned_at, ingested_at, aiscan_version, launched_by,"
            " started, reason, source_label, share_safe, via, token_id, collector_count,"
            " finding_count, errors_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                uid, host_id, scanned_at, ingested, bundle.get("aiscan_version") or "",
                origin.get("launched_by") or "unknown", origin.get("started") or "unknown",
                origin.get("reason") or "unknown", bundle.get("source_label") or "",
                1 if bundle.get("share_safe") else 0, via, token_id, len(collectors),
                sum(len(env["findings"]) for env in collectors.values()),
                json.dumps(bundle.get("collector_errors") or []),
            ),
        )
        scan_id = int(cur.lastrowid)
        for name, env in collectors.items():
            detected = bool(env.get("platform_detected"))
            cur = conn.execute(
                "INSERT INTO collector_runs(scan_id, host_id, collector, version, ran_at,"
                " platform_detected, detection_status, scope_hash, finding_count, rule_count,"
                " envelope_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    scan_id, host_id, name, env.get("version") or "", run_times[name],
                    1 if detected else 0,
                    status.get(name) or ("detected" if detected else "not detected"),
                    env.get("scope_hash") or "", len(env["findings"]), len(env["rules"]),
                    json.dumps(env, ensure_ascii=False, separators=(",", ":")),
                ),
            )
            run_id = int(cur.lastrowid)
            conn.executemany(
                "INSERT INTO findings(scan_id, run_id, host_id, collector, finding_key, finding_id,"
                " severity, category, title, evidence_count, first_seen, last_seen, sample,"
                " secret_redacted, tags_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [
                    (
                        scan_id, run_id, host_id, name, finding_key(f), f["id"], f["severity"],
                        f["category"], f["title"], f["evidence_count"], f["first_seen"],
                        f["last_seen"], f["sample_redacted"], 1 if f["secret_redacted"] else 0,
                        json.dumps(f["tags"]),
                    )
                    for f in env["findings"]
                ],
            )
            rule_rows = []
            for r in env["rules"]:
                row = (
                    scan_id, run_id, host_id, name, r.get("platform", ""), r.get("scope", ""),
                    r.get("scope_label_redacted", ""), r.get("rule_type", ""), r.get("rule", ""),
                    r.get("decision", ""), r.get("command_or_tool_redacted", ""),
                    r.get("risk", ""), r.get("exposure_category", ""), r.get("source_kind", ""),
                    r.get("confidence", ""),
                )
                rule_rows.extend([row] * min(int(r.get("count") or 1), 50))
            conn.executemany(
                "INSERT INTO rules(scan_id, run_id, host_id, collector, platform, scope, scope_label,"
                " rule_type, rule, decision, command, risk, exposure_category, source_kind,"
                " confidence) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                rule_rows,
            )
            conn.executemany(
                "INSERT INTO accounts(scan_id, run_id, host_id, tool, signed_in, account,"
                " organization, plan, auth_method, source, last_sign_in)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                [
                    (scan_id, run_id, host_id, a["tool"], a["signed_in"], a["account"],
                     a["organization"], a["plan"], a["auth_method"], a["source"], a["last_sign_in"])
                    for a in env.get("accounts") or []
                ],
            )
            conn.executemany(
                "INSERT INTO mcp_servers(scan_id, run_id, host_id, collector, name) VALUES (?,?,?,?,?)",
                [
                    (scan_id, run_id, host_id, name, display)
                    for display in sorted(scan_diff.mcp_server_names(env).values())
                ],
            )
            conn.executemany(
                "INSERT INTO metrics(scan_id, run_id, host_id, collector, key, value) VALUES (?,?,?,?,?,?)",
                [
                    (scan_id, run_id, host_id, name, key[:128], float(value))
                    for key, value in scan_diff.numeric_counters(env.get("summary")).items()
                ],
            )
        if token_id is not None:
            conn.execute("UPDATE tokens SET last_used_at = ? WHERE id = ?", (ingested, token_id))
        rebuild_host(conn, host_id)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return {"scan_id": scan_id, "duplicate": False, "host": bundle["host"]}


# ---- derived state --------------------------------------------------------

def rebuild_host(conn: sqlite3.Connection, host_id: int) -> None:
    """Recompute everything derived for one host. The caller commits.

    Walks the host's scans oldest first and keeps the newest run of each
    collector. From that it writes the posture columns on each scan (what was
    open as of that scan), ``current_runs``, and ``finding_state``.
    """
    scans = conn.execute(
        "SELECT id, scanned_at FROM scans WHERE host_id = ? ORDER BY scanned_at, id", (host_id,)
    ).fetchall()
    runs = conn.execute(
        "SELECT id, scan_id, collector, ran_at, platform_detected FROM collector_runs"
        " WHERE host_id = ? ORDER BY ran_at, id",
        (host_id,),
    ).fetchall()
    run_info: dict[int, dict[str, Any]] = {
        int(r["id"]): {
            "collector": r["collector"], "ran_at": r["ran_at"], "scan_id": int(r["scan_id"]),
            "detected": bool(r["platform_detected"]),
            "sev": dict.fromkeys(SEVERITIES, 0), "allow": 0, "mcp": 0,
        }
        for r in runs
    }
    for row in conn.execute(
        "SELECT run_id, severity, COUNT(*) AS n FROM findings WHERE host_id = ? GROUP BY run_id, severity",
        (host_id,),
    ):
        if row["severity"] in SEVERITIES:
            run_info[int(row["run_id"])]["sev"][row["severity"]] = int(row["n"])
    for row in conn.execute(
        "SELECT run_id, COUNT(*) AS n FROM rules WHERE host_id = ? AND decision = 'allow' GROUP BY run_id",
        (host_id,),
    ):
        run_info[int(row["run_id"])]["allow"] = int(row["n"])
    for row in conn.execute(
        "SELECT run_id, COUNT(*) AS n FROM mcp_servers WHERE host_id = ? GROUP BY run_id", (host_id,)
    ):
        run_info[int(row["run_id"])]["mcp"] = int(row["n"])

    runs_by_scan: dict[int, list[int]] = {}
    for run_id, info in run_info.items():
        runs_by_scan.setdefault(info["scan_id"], []).append(run_id)

    latest: dict[str, int] = {}
    for scan in scans:
        for run_id in runs_by_scan.get(int(scan["id"]), []):
            info = run_info[run_id]
            held = latest.get(info["collector"])
            if held is None or info["ran_at"] >= run_info[held]["ran_at"]:
                latest[info["collector"]] = run_id
        held_runs = [run_info[run_id] for run_id in latest.values()]
        conn.execute(
            "UPDATE scans SET posture_critical = ?, posture_high = ?, posture_medium = ?,"
            " posture_low = ?, posture_allow_rules = ?, posture_mcp_servers = ?,"
            " posture_agents = ? WHERE id = ?",
            (
                sum(r["sev"]["critical"] for r in held_runs),
                sum(r["sev"]["high"] for r in held_runs),
                sum(r["sev"]["medium"] for r in held_runs),
                sum(r["sev"]["low"] for r in held_runs),
                sum(r["allow"] for r in held_runs),
                sum(r["mcp"] for r in held_runs),
                sum(1 for r in held_runs if r["detected"] and r["collector"] in AGENT_COLLECTORS),
                scan["id"],
            ),
        )

    conn.execute("DELETE FROM current_runs WHERE host_id = ?", (host_id,))
    conn.executemany(
        "INSERT INTO current_runs(host_id, collector, run_id) VALUES (?, ?, ?)",
        [(host_id, collector, run_id) for collector, run_id in latest.items()],
    )

    # Finding lifecycle. For each collector, its runs in time order; a
    # finding is open when the newest run of that collector still reports it.
    order: dict[str, list[int]] = {}
    for r in runs:
        order.setdefault(r["collector"], []).append(int(r["id"]))
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for row in conn.execute(
        "SELECT f.run_id, f.collector, f.finding_key, f.finding_id, f.severity, f.category,"
        " f.title, f.evidence_count FROM findings f JOIN collector_runs r ON r.id = f.run_id"
        " WHERE f.host_id = ? ORDER BY r.ran_at, r.id, f.id",
        (host_id,),
    ):
        key = (row["collector"], row["finding_key"])
        run_id = int(row["run_id"])
        entry = seen.get(key)
        if entry is None:
            entry = seen[key] = {"first_run": run_id, "runs": set(), "last_run": None}
        if entry["last_run"] != run_id:
            # A newer run of this collector: its values replace the older ones.
            entry["last_run"] = run_id
            entry["count"] = 0
            entry["severity"] = None
        entry["runs"].add(run_id)
        entry["count"] += int(row["evidence_count"])
        entry["finding_id"] = row["finding_id"]
        entry["category"] = row["category"]
        entry["title"] = row["title"]
        # Two rows can share an id inside one run. Keep the worse severity.
        entry["severity"] = _worse(entry["severity"], row["severity"])

    conn.execute("DELETE FROM finding_state WHERE host_id = ?", (host_id,))
    rows = []
    for (collector, key), entry in seen.items():
        collector_runs_ = order[collector]
        last_run = entry["last_run"]
        is_open = collector_runs_[-1] == last_run
        resolved_at = ""
        if not is_open:
            next_run = collector_runs_[collector_runs_.index(last_run) + 1]
            resolved_at = run_info[next_run]["ran_at"]
        rows.append((
            host_id, collector, key, entry["finding_id"], "open" if is_open else "resolved",
            entry["severity"], entry["category"], entry["title"], entry["count"],
            run_info[entry["first_run"]]["ran_at"], run_info[last_run]["ran_at"], resolved_at,
            len(entry["runs"]), run_info[entry["first_run"]]["scan_id"], run_info[last_run]["scan_id"],
        ))
    conn.executemany(
        "INSERT INTO finding_state(host_id, collector, finding_key, finding_id, status, severity,"
        " category, title, evidence_count, first_seen_at, last_seen_at, resolved_at, occurrences,"
        " first_scan_id, last_scan_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        rows,
    )
    # A cached diff can name a baseline that is no longer the right one.
    conn.execute("DELETE FROM scan_diffs WHERE scan_id IN (SELECT id FROM scans WHERE host_id = ?)", (host_id,))
    if scans:
        conn.execute(
            "UPDATE hosts SET first_seen = ?, last_seen = ? WHERE id = ?",
            (scans[0]["scanned_at"], scans[-1]["scanned_at"], host_id),
        )


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _worse(a: str | None, b: str) -> str:
    if a is None:
        return b
    return a if _SEV_ORDER.get(a, 9) <= _SEV_ORDER.get(b, 9) else b


# ---- triage and retention -------------------------------------------------

def set_triage(
    conn: sqlite3.Connection, host_id: int, collector: str, key: str, state: str, note: str = ""
) -> None:
    if state not in TRIAGE_STATES:
        raise ValueError("unknown triage state")
    exists = conn.execute(
        "SELECT 1 FROM finding_state WHERE host_id = ? AND collector = ? AND finding_key = ?",
        (host_id, collector, key),
    ).fetchone()
    if exists is None:
        raise LookupError("no such finding")
    conn.execute(
        "INSERT INTO triage(host_id, collector, finding_key, state, note, updated_at)"
        " VALUES (?,?,?,?,?,?) ON CONFLICT(host_id, collector, finding_key)"
        " DO UPDATE SET state = excluded.state, note = excluded.note, updated_at = excluded.updated_at",
        (host_id, collector, key, state, note[:2000], now_utc()),
    )
    conn.commit()


def prune(
    conn: sqlite3.Connection, *, keep_days: int | None = None, keep_last: int | None = None,
    dry_run: bool = False,
) -> int:
    """Delete old scans. Returns how many scans matched.

    ``keep_last`` always protects that many of each host's newest scans, so
    a host that has not reported for a while keeps its last known posture.
    """
    from datetime import datetime, timedelta, timezone

    doomed: list[int] = []
    cutoff = ""
    if keep_days is not None:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=keep_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    hosts = [int(r["id"]) for r in conn.execute("SELECT id FROM hosts")]
    for host_id in hosts:
        scans = conn.execute(
            "SELECT id, scanned_at FROM scans WHERE host_id = ? ORDER BY scanned_at DESC, id DESC",
            (host_id,),
        ).fetchall()
        protect = max(keep_last if keep_last is not None else 1, 1)
        for index, scan in enumerate(scans):
            if index < protect:
                continue
            if keep_days is None or scan["scanned_at"] < cutoff:
                doomed.append(int(scan["id"]))
    if dry_run or not doomed:
        return len(doomed)
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.executemany("DELETE FROM scans WHERE id = ?", [(i,) for i in doomed])
        for host_id in hosts:
            rebuild_host(conn, host_id)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return len(doomed)
