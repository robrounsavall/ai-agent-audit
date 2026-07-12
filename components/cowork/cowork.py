"""
Cowork (Claude desktop app) local session collector.

Usage:
    python cowork.py --evidence-root ./audit-run [--cowork-root DIR] [--dry-run]

Cowork sessions run out of %APPDATA%\\Claude, not ~/.claude. Each session keeps
a full workspace on disk:

    local-agent-mode-sessions/<account>/<org>/local_<uuid>/
        .claude/projects/**/*.jsonl   conversation transcripts
        audit.jsonl                   per-session action audit log
        outputs/ uploads/             files the agent produced or received
    claude-code-sessions/<account>/<org>/local_*.json   session metadata
    cowork-file-preview/office-cache/*.pdf   rendered previews of Office docs
    bridge-state.json                 local -> remote cloud session mapping

This collector inventories that surface and reports persistence and egress
findings. Read-only; no session content is read, only structure and counts.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path
from typing import Iterable

from common import (
    APPDATA,
    add_base_args,
    compute_scope_hash,
    finish_collector,
    load_json,
    make_envelope,
    make_finding,
    validate_evidence_root,
)

__version__ = "1.0.0"

COLLECTOR = "cowork"

RETENTION_DAYS = 90


def default_root() -> Path:
    return APPDATA / "Claude"


def _mtime_date(path: Path) -> str:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d")
    except OSError:
        return ""


def _count_files(root: Path) -> int:
    if not root.exists():
        return 0
    return sum(1 for p in root.rglob("*") if p.is_file())


def iter_session_dirs(agent_sessions_root: Path) -> Iterable[Path]:
    """Yield local_<uuid> session dirs under <account>/<org>/."""
    if not agent_sessions_root.exists():
        return
    for account in agent_sessions_root.iterdir():
        if not account.is_dir():
            continue
        for org in account.iterdir():
            if not org.is_dir():
                continue
            for sess in org.glob("local_*"):
                if sess.is_dir():
                    yield sess


def scan_sessions(agent_sessions_root: Path) -> dict:
    sessions = 0
    transcript_files = 0
    audit_logs = 0
    output_files = 0
    upload_files = 0
    newest = ""
    oldest_mtime: float | None = None

    for sess in iter_session_dirs(agent_sessions_root):
        sessions += 1
        projects = sess / ".claude" / "projects"
        if projects.exists():
            transcript_files += sum(1 for _ in projects.rglob("*.jsonl"))
        if (sess / "audit.jsonl").exists():
            audit_logs += 1
        output_files += _count_files(sess / "outputs")
        upload_files += _count_files(sess / "uploads")
        try:
            mtime = sess.stat().st_mtime
        except OSError:
            continue
        if oldest_mtime is None or mtime < oldest_mtime:
            oldest_mtime = mtime
        stamp = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d")
        if stamp > newest:
            newest = stamp

    oldest_age_days = 0
    if oldest_mtime is not None:
        oldest_age_days = max(0, int((datetime.now().timestamp() - oldest_mtime) // 86400))

    return {
        "sessions": sessions,
        "transcript_files": transcript_files,
        "audit_logs": audit_logs,
        "output_files": output_files,
        "upload_files": upload_files,
        "newest_session": newest,
        "oldest_session_age_days": oldest_age_days,
    }


def scan_office_cache(root: Path) -> dict:
    cache = root / "cowork-file-preview" / "office-cache"
    pdfs = list(cache.glob("*.pdf")) if cache.exists() else []
    newest = max((_mtime_date(p) for p in pdfs), default="")
    return {"preview_pdfs": len(pdfs), "newest_preview": newest}


def scan_bridge_state(root: Path) -> dict:
    data = load_json(root / "bridge-state.json") or {}
    synced = 0
    if isinstance(data, dict):
        for entry in data.values():
            if isinstance(entry, dict) and entry.get("enabled"):
                synced += 1
    return {"bridge_synced_sessions": synced}


def scan_metadata(root: Path) -> int:
    meta_root = root / "claude-code-sessions"
    if not meta_root.exists():
        return 0
    return sum(1 for _ in meta_root.rglob("local_*.json"))


def build_findings(session_info: dict, office: dict, bridge: dict) -> list[dict]:
    findings: list[dict] = []

    if session_info["transcript_files"] > 0:
        findings.append(
            make_finding(
                "cowork.sessions.transcripts_on_disk",
                "medium",
                "Cross-Agent Visibility",
                "Cowork session transcripts persist under AppData",
                evidence_count=session_info["transcript_files"],
                sample_redacted=(
                    f"sessions={session_info['sessions']}; "
                    f"transcripts={session_info['transcript_files']}; "
                    f"newest={session_info['newest_session'] or 'unknown'}"
                ),
                tags=["chat_history"],
            )
        )

    artifact_count = session_info["output_files"] + session_info["upload_files"]
    if artifact_count > 0:
        findings.append(
            make_finding(
                "cowork.workspace.artifacts_on_disk",
                "low",
                "Cross-Agent Visibility",
                "Cowork session outputs/uploads persist on disk",
                evidence_count=artifact_count,
                sample_redacted=(
                    f"outputs={session_info['output_files']}; "
                    f"uploads={session_info['upload_files']}"
                ),
                tags=["chat_history"],
            )
        )

    if office["preview_pdfs"] > 0:
        findings.append(
            make_finding(
                "cowork.office_cache.previews",
                "medium",
                "Cross-Agent Visibility",
                "Cowork caches rendered PDF previews of Office documents unredacted",
                evidence_count=office["preview_pdfs"],
                sample_redacted=(
                    f"pdfs={office['preview_pdfs']}; "
                    f"newest={office['newest_preview'] or 'unknown'}"
                ),
                tags=["chat_history"],
            )
        )

    if bridge["bridge_synced_sessions"] > 0:
        findings.append(
            make_finding(
                "cowork.bridge.remote_sync",
                "low",
                "Network Egress",
                "Cowork session(s) bridged to a remote cloud environment",
                evidence_count=bridge["bridge_synced_sessions"],
                sample_redacted=f"synced_sessions={bridge['bridge_synced_sessions']}",
                tags=["network_egress"],
            )
        )

    if session_info["oldest_session_age_days"] > RETENTION_DAYS:
        findings.append(
            make_finding(
                "cowork.retention.exceeds_90d",
                "medium",
                "Cross-Agent Visibility",
                f"Oldest Cowork session workspace is {session_info['oldest_session_age_days']} days old",
                evidence_count=session_info["sessions"],
                sample_redacted=f"oldest_age_days={session_info['oldest_session_age_days']}",
                tags=["chat_history"],
            )
        )

    return findings


def collect(root: Path) -> dict:
    agent_sessions_root = root / "local-agent-mode-sessions"
    scanned = [
        agent_sessions_root,
        root / "claude-code-sessions",
        root / "cowork-file-preview" / "office-cache",
        root / "bridge-state.json",
    ]
    scope_hash = compute_scope_hash(str(p) for p in scanned)

    platform_detected = agent_sessions_root.exists()
    envelope = make_envelope(
        COLLECTOR,
        __version__,
        scope_hash,
        platform_detected=platform_detected,
    )

    if not platform_detected:
        envelope["summary"] = {"sessions": 0, "findings": 0}
        return envelope

    session_info = scan_sessions(agent_sessions_root)
    office = scan_office_cache(root)
    bridge = scan_bridge_state(root)
    metadata_files = scan_metadata(root)

    findings = build_findings(session_info, office, bridge)

    envelope["findings"] = findings
    envelope["summary"] = {
        **session_info,
        **office,
        **bridge,
        "metadata_files": metadata_files,
        "findings": len(findings),
    }
    return envelope


def main() -> None:
    parser = argparse.ArgumentParser(description="Cowork local session collector")
    add_base_args(parser)
    parser.add_argument(
        "--cowork-root",
        default=None,
        help="Claude desktop app data dir (default %%APPDATA%%\\Claude)",
    )
    args = parser.parse_args()
    evidence_root = validate_evidence_root(args.evidence_root)

    root = Path(args.cowork_root) if args.cowork_root else default_root()
    envelope = collect(root)
    finish_collector(envelope, evidence_root, dry_run=args.dry_run)
    sys.exit(0 if envelope["platform_detected"] else 2)


if __name__ == "__main__":
    main()
