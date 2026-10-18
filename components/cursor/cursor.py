"""
Cursor permission and state collector.

Usage:
    python cursor.py --evidence-root ./audit-run [--repo-roots ...] [--dry-run]

Searches Cursor state.vscdb, MCP registries (mcp.json), and agent-transcripts
for durable permission allow-lists and MCP posture.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
from pathlib import Path

import cursor_permissions as cperm
import paths
from common import (
    add_base_args,
    compute_scope_hash,
    config_has_remote_url,
    default_repo_roots,
    finish_collector,
    make_envelope,
    make_finding,
    make_rule,
    nested_text,
    read_json_object,
    secret_types_in,
    validate_evidence_root,
)

__version__ = "1.3.0"

COLLECTOR = "cursor"

PERMISSION_KEY_RE = re.compile(
    r"permission|allowlist|allow.?list|auto.?run|mcp|terminal.?allow|"
    r"trusted.?command|composer\.(agent|auto)|yolo|skip.?confirm",
    re.I,
)
DURABLE_VALUE_RE = re.compile(
    r"always.?allow|allowlist|allowedTools|deniedTools|autoRun|"
    r"terminal\.allow|mcp\.|trustedCommands|permissionMode",
    re.I,
)
KEYWORD_RE = re.compile(
    r"always allow|permission|allowlist|approval|auto.?run|mcp",
    re.I,
)
# Controlled settings_source labels — never full filesystem paths.
MCP_SOURCE_LABELS = {
    "cursor_user": "user mcp.json",
    "cursor_appdata": "appdata mcp.json",
    "shared": "shared mcp.json",
    "project": "project mcp.json",
}


def _parse_json_value(value):
    try:
        return json.loads(value) if value is not None else None
    except (json.JSONDecodeError, TypeError):
        return None


def _cursor_mcp_server_name(server_id: str) -> str:
    text = str(server_id or "")
    if ":" in text:
        text = text.split(":", 1)[0]
    parts = [p for p in text.split("-") if p]
    if len(parts) >= 4 and parts[0] == "project" and parts[1].isdigit():
        return "-".join(parts[3:])
    return text or "unknown"


def open_vscdb(path: Path):
    uri = "file:" + str(path).replace("\\", "/") + "?mode=ro&immutable=1"
    return sqlite3.connect(uri, uri=True)


def _emit_mcp_server_rule(
    server_name: str,
    *,
    scope: str,
    scope_label: str,
    source_kind: str,
    settings_source: str,
    confidence: str = "high",
) -> dict:
    return make_rule(
        "cursor",
        scope,
        scope_label,
        "mcp_tool",
        f"mcp__{server_name}",
        "allow",
        command_or_tool=server_name,
        risk="medium",
        source_kind=source_kind,
        settings_source=settings_source,
        confidence=confidence,
    )


def _mcp_config_findings(server_name: str, config: dict) -> list[dict]:
    """External URL / secret findings for one MCP server config. Never embeds secrets."""
    findings: list[dict] = []
    if config_has_remote_url(config):
        findings.append(
            make_finding(
                "cursor.mcp.external_server",
                "high",
                "MCP Tooling",
                f"MCP server {server_name} may point outside localhost",
                sample_redacted=f"mcpServers.{server_name}",
                tags=["mcp_external"],
            )
        )

    env_vars = config.get("env")
    if isinstance(env_vars, dict):
        for env_val in env_vars.values():
            if isinstance(env_val, str) and secret_types_in(env_val):
                findings.append(
                    make_finding(
                        "cursor.mcp.env_secret",
                        "critical",
                        "Secrets Exposure",
                        f"MCP server {server_name} env contains secrets",
                        secret_redacted=True,
                    )
                )
                break

    # Args / headers often carry bearer tokens (e.g. mcp-remote --header Authorization).
    args = config.get("args")
    arg_blob = " ".join(str(a) for a in args) if isinstance(args, list) else ""
    command = str(config.get("command") or "")
    url = str(config.get("url") or "")
    auth_hint = bool(
        re.search(r"(?i)\bAuthorization\s*:|\bBearer\s+[A-Za-z0-9._\-+=/]{8,}", arg_blob)
    )
    for blob in (arg_blob, command, url):
        if (blob and secret_types_in(blob)) or (blob is arg_blob and auth_hint):
            findings.append(
                make_finding(
                    "cursor.mcp.args_secret",
                    "critical",
                    "Secrets Exposure",
                    f"MCP server {server_name} command/args contain secrets",
                    secret_redacted=True,
                )
            )
            break
    return findings


def parse_mcp_json_file(
    path: Path,
    *,
    scope: str,
    scope_label: str,
    source_kind: str,
    settings_source: str,
) -> tuple[list[dict], list[dict], set[str]]:
    """Parse one mcp.json. Returns (rules, findings, registered_names)."""
    rules: list[dict] = []
    findings: list[dict] = []
    names: set[str] = set()
    data, err = read_json_object(path)
    if err:
        findings.append(
            make_finding(
                "cursor.config.parse_error",
                "low",
                "General Tooling",
                f"Cursor {settings_source} is present but could not be parsed",
                sample_redacted=err,
                tags=["config_parse_error"],
            )
        )
        return rules, findings, names
    if not data:
        return rules, findings, names
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        return rules, findings, names
    for server_name, config in servers.items():
        if not isinstance(server_name, str) or not server_name.strip():
            continue
        name = server_name.strip()
        names.add(name)
        rules.append(
            _emit_mcp_server_rule(
                name,
                scope=scope,
                scope_label=scope_label,
                source_kind=source_kind,
                settings_source=settings_source,
                confidence="high",
            )
        )
        if isinstance(config, dict):
            findings.extend(_mcp_config_findings(name, config))
    return rules, findings, names


def collect_mcp_registrations(
    tp: paths.ToolPaths,
    repo_roots: list[Path],
) -> tuple[list[dict], list[dict], set[str], list[str]]:
    """Collect MCP rules/findings from global + project mcp.json files."""
    rules: list[dict] = []
    findings: list[dict] = []
    registered: set[str] = set()
    searched: list[str] = []

    globals_ = [
        (tp.cursor_user_mcp, "user", "global", "user_config", MCP_SOURCE_LABELS["cursor_user"]),
        (tp.cursor_appdata_mcp, "user", "global", "user_config", MCP_SOURCE_LABELS["cursor_appdata"]),
        (tp.shared_mcp, "user", "global", "user_config", MCP_SOURCE_LABELS["shared"]),
    ]
    for path, scope, scope_label, source_kind, settings_source in globals_:
        searched.append(settings_source)
        r, f, names = parse_mcp_json_file(
            path,
            scope=scope,
            scope_label=scope_label,
            source_kind=source_kind,
            settings_source=settings_source,
        )
        rules.extend(r)
        findings.extend(f)
        registered |= names

    seen_project: set[str] = set()
    for root in repo_roots:
        if not root.exists():
            continue
        # Direct children that are git repos, plus root itself if it is one.
        candidates: list[Path] = []
        if (root / ".git").exists():
            candidates.append(root)
        try:
            for child in root.iterdir():
                if child.is_dir() and (child / ".git").exists():
                    candidates.append(child)
        except OSError:
            continue
        for repo in candidates:
            mcp_path = repo / ".cursor" / "mcp.json"
            key = str(mcp_path.resolve()) if mcp_path.exists() else str(mcp_path)
            if key in seen_project:
                continue
            seen_project.add(key)
            if not mcp_path.exists():
                continue
            searched.append(MCP_SOURCE_LABELS["project"])
            r, f, names = parse_mcp_json_file(
                mcp_path,
                scope="project",
                scope_label="project",
                source_kind="project_config",
                settings_source=MCP_SOURCE_LABELS["project"],
            )
            rules.extend(r)
            findings.extend(f)
            registered |= names

    return rules, findings, registered, searched


def _resolve_registered_name(known_name: str, registered: set[str]) -> str | None:
    """Map a Cursor runtime/approved ID to a registered mcp.json server key.

    Cursor often stores IDs as `<project-slug>-<server>` (e.g.
    `04-acme-mcp-acme-mcp` or `02-content-production-system-acme-mcp`) while
    mcp.json uses the short key (`acme-mcp`). Prefer the longest registered
    suffix match so `acme-mcp` wins over a shorter accidental hit.
    """
    if not known_name or not registered:
        return None
    lower = known_name.lower()
    # Preserve original casing from the registered set.
    by_lower = {n.lower(): n for n in registered}
    if lower in by_lower:
        return by_lower[lower]

    best: str | None = None
    best_len = -1
    for reg_lower, reg_orig in by_lower.items():
        matched = False
        if lower.endswith("-" + reg_lower) or lower.endswith("_" + reg_lower):
            matched = True
        elif "-" in lower:
            parts = lower.split("-")
            for i in range(len(parts)):
                if "-".join(parts[i:]) == reg_lower:
                    matched = True
                    break
        if matched and len(reg_lower) > best_len:
            best = reg_orig
            best_len = len(reg_lower)
    return best


def _known_matches_registered(known_name: str, registered: set[str]) -> bool:
    return _resolve_registered_name(known_name, registered) is not None


def search_vscdb(
    db_path: Path,
    registered_names: set[str] | None = None,
) -> tuple[list[dict], list[str], bool, dict]:
    """Return (candidate_rules, searched_locations, durable_found, summary).

    Dedupes targeted keys across ItemTable and cursorDiskKV (first table wins).
    Known server IDs that do not match a registered mcp.json name become
    low-confidence mcp_tool rules so they appear in the briefing table.
    """
    rules: list[dict] = []
    searched: list[str] = []
    durable_found = False
    registered = registered_names or set()
    summary = {
        "approved_project_mcp_servers": 0,
        "known_mcp_servers": 0,
        "known_mcp_matched": 0,
        "known_mcp_unmatched": 0,
        "composer_auto_accept_workspaces": 0,
        "agent_autorun_default_attempted": False,
        "ide_state_read": False,
    }
    known_ids: list[str] = []
    seen_targeted: set[str] = set()

    if not db_path.exists():
        return rules, searched, durable_found, summary

    searched.append(str(db_path))
    try:
        con = open_vscdb(db_path)
    except sqlite3.Error:
        return rules, searched, durable_found, summary

    try:
        cur = con.cursor()
        targeted = {
            "cursor/approvedProjectMcpServers",
            "mcpService.knownServerIds",
            "cursor/agentAutorunBrandNewDefaultAttempted",
            "composer.autoAccept.lastSeenHeadSha",
        }
        for table in ("ItemTable", "cursorDiskKV"):
            for key in targeted:
                if key in seen_targeted:
                    continue
                try:
                    row = cur.execute(f"SELECT value FROM {table} WHERE key=?", (key,)).fetchone()
                except sqlite3.Error:
                    row = None
                if not row:
                    continue
                seen_targeted.add(key)
                searched.append(f"{table}:{key}")
                parsed = _parse_json_value(row[0])
                if key == "cursor/approvedProjectMcpServers" and isinstance(parsed, list):
                    summary["approved_project_mcp_servers"] = len(parsed)
                    for item in parsed:
                        if not isinstance(item, str):
                            continue
                        raw_name = _cursor_mcp_server_name(item)
                        server = _resolve_registered_name(raw_name, registered) or raw_name
                        rules.append(
                            _emit_mcp_server_rule(
                                server,
                                scope="project",
                                scope_label="approval",
                                source_kind="project_config",
                                settings_source="state.vscdb approvedProjectMcpServers",
                                confidence="medium",
                            )
                        )
                elif key == "mcpService.knownServerIds" and isinstance(parsed, list):
                    known_ids = [str(x) for x in parsed if isinstance(x, str)]
                    summary["known_mcp_servers"] = len(known_ids)
                elif key == "composer.autoAccept.lastSeenHeadSha" and isinstance(parsed, dict):
                    summary["composer_auto_accept_workspaces"] = len(parsed)
                elif key == "cursor/agentAutorunBrandNewDefaultAttempted":
                    summary["agent_autorun_default_attempted"] = bool(parsed)

        # Enrich known IDs against registered names; emit unmatched as rules.
        matched = 0
        unmatched = 0
        for raw_id in known_ids:
            name = _cursor_mcp_server_name(raw_id)
            resolved = _resolve_registered_name(name, registered)
            if resolved:
                matched += 1
                continue
            unmatched += 1
            rules.append(
                _emit_mcp_server_rule(
                    name,
                    scope="user",
                    scope_label="global",
                    source_kind="user_config",
                    settings_source="state.vscdb knownServerIds",
                    confidence="low",
                )
            )
        summary["known_mcp_matched"] = matched
        summary["known_mcp_unmatched"] = unmatched

        # Legacy allow-list parse: keys only, never cursorDiskKV, never chat/auth rows.
        for key_str in cperm.legacy_permission_keys(con, PERMISSION_KEY_RE, extra_skip=targeted):
            val_str = cperm.fetch_value_text(con, key_str)
            searched.append(f"ItemTable:{key_str}")
            if DURABLE_VALUE_RE.search(val_str):
                durable_found = True
                try:
                    parsed = json.loads(val_str)
                except (ValueError, TypeError, RecursionError):
                    parsed = None
                if isinstance(parsed, dict):
                    for allow_key in ("allowedTools", "allowlist", "allowList", "trustedCommands"):
                        items = parsed.get(allow_key)
                        if isinstance(items, list):
                            for item in items:
                                if isinstance(item, str):
                                    rules.append(
                                        make_rule(
                                            "cursor",
                                            "user",
                                            "global",
                                            "other",
                                            item,
                                            "allow",
                                            command_or_tool=item,
                                            risk="medium",
                                        )
                                    )
                elif isinstance(parsed, list):
                    for item in parsed:
                        if isinstance(item, str):
                            rules.append(
                                make_rule(
                                    "cursor",
                                    "user",
                                    "global",
                                    "other",
                                    item,
                                    "allow",
                                    command_or_tool=item,
                                    risk="medium",
                                )
                            )
    finally:
        con.close()

    return rules, searched, durable_found, summary


def search_transcripts(cursor_root: Path) -> tuple[int, list[str]]:
    """Return (permission_event_count, searched_dirs)."""
    count = 0
    searched: list[str] = []
    if not cursor_root.exists():
        return count, searched

    for project_dir in cursor_root.iterdir():
        if not project_dir.is_dir():
            continue
        transcripts_dir = project_dir / "agent-transcripts"
        if not transcripts_dir.exists():
            continue
        searched.append(str(transcripts_dir))
        for jsonl in transcripts_dir.rglob("*.jsonl"):
            try:
                with jsonl.open("r", encoding="utf-8-sig") as handle:
                    for raw in handle:
                        raw = raw.strip()
                        if not raw:
                            continue
                        try:
                            obj = json.loads(raw)
                        except (json.JSONDecodeError, ValueError, RecursionError):
                            continue
                        if KEYWORD_RE.search(nested_text(obj)):
                            count += 1
            except (OSError, UnicodeDecodeError):
                continue
    return count, searched


def collect(
    tp: paths.ToolPaths,
    repo_roots: list[Path] | None = None,
    *,
    cursor_home: Path | None = None,
    install_dirs=None,
) -> dict:
    roots = repo_roots if repo_roots is not None else default_repo_roots()
    if cursor_home is None:
        env_home = os.environ.get("CURSOR_CONFIG_DIR", "").strip()
        cursor_home = Path(env_home) if env_home else Path(tp.cursor_user_mcp).parent
    scanned = [
        str(tp.cursor_db),
        str(tp.cursor_projects),
        str(tp.cursor_user_mcp),
        str(tp.cursor_appdata_mcp),
        str(tp.shared_mcp),
    ]
    scope_hash = compute_scope_hash(scanned)
    platform_detected = (
        tp.cursor_db.exists()
        or tp.cursor_projects.exists()
        or tp.cursor_user_mcp.exists()
        or tp.shared_mcp.exists()
        or (cursor_home / "cli-config.json").exists()
    )

    envelope = make_envelope(
        COLLECTOR,
        __version__,
        scope_hash,
        platform_detected=platform_detected,
    )

    if not platform_detected:
        envelope["summary"] = {
            "durable_rules": 0,
            "mcp_rules": 0,
            "mcp_registered": 0,
            "permission_events": 0,
            "known_mcp_servers": 0,
            "known_mcp_matched": 0,
            "known_mcp_unmatched": 0,
            "approved_project_mcp_servers": 0,
        }
        return envelope

    mcp_rules, mcp_findings, registered, mcp_searched = collect_mcp_registrations(tp, roots)
    vscdb_rules, vscdb_searched, durable_found, state_summary = search_vscdb(
        tp.cursor_db, registered_names=registered
    )
    perm_events, transcript_searched = search_transcripts(tp.cursor_projects)
    ide_state, admin_state = cperm.read_permission_state(tp.cursor_db)
    perm = cperm.collect_permission_sources(
        cursor_home, roots, ide_state, admin_state, install_dirs=install_dirs
    )

    rules = mcp_rules + perm["rules"] + vscdb_rules
    envelope["rules"] = rules
    findings: list[dict] = list(mcp_findings) + perm["findings"]

    non_mcp_rules = [
        r for r in rules if r.get("rule_type") != "mcp_tool" and r.get("decision") == "allow"
    ]
    legacy_allowlist = any(r.get("decision") == "allow" for r in vscdb_rules
                          if r.get("rule_type") != "mcp_tool")
    if not (perm["has_allowlist"] or legacy_allowlist) and not perm["run_mode_finding"]:
        findings.append(
            make_finding(
                "cursor.permissions.no_durable_allowlist",
                "medium",
                "General Tooling",
                "No Cursor command allow-list found in cli-config.json or IDE state",
                evidence_count=len(vscdb_searched) + len(transcript_searched),
                tags=["history_retention"],
            )
        )
    if perm_events:
        findings.append(
            make_finding(
                "cursor.permissions.events_observed",
                "low",
                "General Tooling",
                "Cursor permission or approval events observed in local transcripts",
                evidence_count=perm_events,
                sample_redacted=f"{perm_events} permission/approval events",
                tags=["approval_event"],
            )
        )

    envelope["findings"] = findings
    envelope["summary"] = {
        "durable_rules": len(non_mcp_rules),
        "mcp_rules": sum(1 for r in rules if r.get("rule_type") == "mcp_tool"),
        "mcp_registered": len(registered),
        "permission_events": perm_events,
        "vscdb_keys_scanned": len(vscdb_searched),
        "transcript_dirs_scanned": len(transcript_searched),
        "mcp_files_scanned": len(mcp_searched),
        "durable_allowlist_found": bool(non_mcp_rules),
        "durable_state_candidates_found": durable_found,
        "searched_vscdb": tp.cursor_db.exists(),
        "searched_transcripts": tp.cursor_projects.exists(),
        "searched_mcp_json": bool(registered) or any(
            p.exists() for p in (tp.cursor_user_mcp, tp.cursor_appdata_mcp, tp.shared_mcp)
        ),
        **state_summary,
        **perm["summary"],
    }
    return envelope


def main() -> None:
    parser = argparse.ArgumentParser(description="Cursor permission collector")
    add_base_args(parser)
    paths.add_path_args(parser)
    parser.add_argument(
        "--repo-roots",
        default=None,
        help="Comma-separated repo scan roots for project .cursor/mcp.json "
        "(default: common code dirs under the user profile, e.g. ~/repos, "
        "~/projects, ~/cursor-projects; see common.DEFAULT_REPO_ROOT_NAMES)",
    )
    args = parser.parse_args()
    evidence_root = validate_evidence_root(args.evidence_root)
    tp = paths.resolve_from_args(args)

    if args.repo_roots:
        repo_roots = [Path(p.strip()) for p in args.repo_roots.split(",") if p.strip()]
    else:
        repo_roots = default_repo_roots()

    envelope = collect(tp, repo_roots=repo_roots)
    if not envelope["platform_detected"]:
        finish_collector(envelope, evidence_root, dry_run=args.dry_run)
        sys.exit(2)

    finish_collector(envelope, evidence_root, dry_run=args.dry_run)
    sys.exit(0)


if __name__ == "__main__":
    main()
