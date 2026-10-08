"""
Grok Bot (Cursor desktop assistant) local presence collector.

Usage:
    python grok-bot.py --evidence-root ./audit-run [--grok-bot-root DIR] [--dry-run]

Grok Bot is not Grok Build. Grok Build lives in ~/.grok and is collected by
components/grok. Grok Bot is Cursor's desktop and mobile assistant: chat runs
in the desktop app, and Bot work runs on a per-user cloud computer.

This collector only stats %APPDATA%\\Grok Bot. It never opens or parses file
contents. Names below are the top-level entries observed on a real Windows
install. Local execution (commands on this machine) is not among them, so
the summary says unknown rather than absent.

Cloud controls stay out of this evidence on purpose. Connector grants, Cloud
Agent delegation, outbound messaging, network policy, and Auto-review
enforcement live in Cursor's cloud.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path

from common import (
    APPDATA,
    add_base_args,
    compute_scope_hash,
    finish_collector,
    make_envelope,
    make_finding,
    validate_evidence_root,
)

__version__ = "1.1.0"

COLLECTOR = "grok-bot"

# Top-level names from a real %APPDATA%\Grok Bot install. Presence and size
# only; none of these files are opened.
KNOWN_FILES = (
    "box-secrets-push-state.v1.json",
    "desktop-status.json",
    "DIPS",
    "DIPS-wal",
    "gateway-descriptor.json",
    "Local State",
    "lockfile",
    "notification-permission-sent.json",
    "Preferences",
    "sand-secrets.json",
    "sand-statsig-bootstrap.json",
    "SharedStorage",
    "SharedStorage-wal",
    "window-state.json",
)
KNOWN_DIRS = (
    "attachment-image-cache",
    "blob_storage",
    "Cache",
    "Code Cache",
    "Crashpad",
    "DawnGraphiteCache",
    "DawnWebGPUCache",
    "dune-reliability",
    "GPUCache",
    "link-preview-cache",
    "Local Storage",
    "Network",
    "Partitions",
    "plugin-logo-cache",
    "sand-client-persistence",
    "sentry",
    "Session Storage",
    "Shared Dictionary",
    "v8-code-cache",
)

SECRET_FILES = (
    "sand-secrets.json",
    "box-secrets-push-state.v1.json",
)
LOCKFILE_NAME = "lockfile"
# Browser and client stores. Stat the directory only; never walk into contents
# for evidence text. Counts below still come from a size-only tree walk.
STATE_DIRS = (
    "Local Storage",
    "Session Storage",
    "Network",
    "sand-client-persistence",
)

LOCAL_EXECUTION = "unknown"
LOCAL_EXECUTION_REASON = "not_determinable_offline"


def default_root() -> Path:
    return APPDATA / "Grok Bot"


def _mtime_date(path: Path) -> str:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d")
    except OSError:
        return ""


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size if path.is_file() else 0
    except OSError:
        return 0


def _walk_stats(root: Path) -> tuple[int, int, int, str]:
    """Return (file_count, dir_count, total_bytes, newest YYYY-MM-DD).

    os.walk lists names and stat reads sizes and mtimes. File bytes are not read.
    """
    files = 0
    dirs = 0
    total_bytes = 0
    newest = _mtime_date(root)
    try:
        walker = os.walk(root, followlinks=False)
    except OSError:
        return 0, 0, 0, newest
    for dirpath, dirnames, filenames in walker:
        dirs += len(dirnames)
        for name in filenames:
            files += 1
            path = Path(dirpath) / name
            total_bytes += _file_size(path)
            stamp = _mtime_date(path)
            if stamp > newest:
                newest = stamp
        for name in dirnames:
            stamp = _mtime_date(Path(dirpath) / name)
            if stamp > newest:
                newest = stamp
    return files, dirs, total_bytes, newest


def scan_root(root: Path) -> dict:
    app_present = root.is_dir()
    info: dict = {
        "app_present": app_present,
        "local_execution": LOCAL_EXECUTION,
        "local_execution_reason": LOCAL_EXECUTION_REASON,
        "file_count": 0,
        "dir_count": 0,
        "total_bytes": 0,
        "newest_local_activity": "",
        "known_files_present": 0,
        "known_dirs_present": 0,
        "sand_secrets_present": False,
        "sand_secrets_bytes": 0,
        "box_secrets_push_state_present": False,
        "box_secrets_push_state_bytes": 0,
        "lockfile_present": False,
        "lockfile_bytes": 0,
        "browser_state_present": False,
        "client_persistence_present": False,
    }
    if not app_present:
        return info

    files, dirs, total_bytes, newest = _walk_stats(root)
    info["file_count"] = files
    info["dir_count"] = dirs
    info["total_bytes"] = total_bytes
    info["newest_local_activity"] = newest

    known_files = 0
    for name in KNOWN_FILES:
        if (root / name).is_file():
            known_files += 1
    known_dirs = 0
    for name in KNOWN_DIRS:
        if (root / name).is_dir():
            known_dirs += 1
    info["known_files_present"] = known_files
    info["known_dirs_present"] = known_dirs

    sand_secrets = root / "sand-secrets.json"
    box_secrets = root / "box-secrets-push-state.v1.json"
    lockfile = root / LOCKFILE_NAME
    info["sand_secrets_present"] = sand_secrets.is_file()
    info["sand_secrets_bytes"] = _file_size(sand_secrets)
    info["box_secrets_push_state_present"] = box_secrets.is_file()
    info["box_secrets_push_state_bytes"] = _file_size(box_secrets)
    info["lockfile_present"] = lockfile.is_file()
    info["lockfile_bytes"] = _file_size(lockfile)
    info["browser_state_present"] = any((root / name).is_dir() for name in STATE_DIRS[:3])
    info["client_persistence_present"] = (root / "sand-client-persistence").is_dir()
    return info


def _present_names(root: Path, names: tuple[str, ...]) -> list[str]:
    found = []
    for name in names:
        path = root / name
        if path.is_file() or path.is_dir():
            found.append(name)
    return found


def build_findings(root: Path, info: dict) -> list[dict]:
    findings: list[dict] = []
    if not info["app_present"]:
        return findings

    newest = info["newest_local_activity"] or "unknown"
    findings.append(
        make_finding(
            "grok_bot.desktop.present",
            "low",
            "Cross-Agent Visibility",
            "Grok Bot desktop app data is present on this endpoint",
            evidence_count=1,
            sample_redacted=(
                f"files={info['file_count']}; newest={newest}"
            ),
            tags=["desktop_app"],
        )
    )

    secret_names = _present_names(root, SECRET_FILES)
    if secret_names:
        findings.append(
            make_finding(
                "grok_bot.secrets.store_present",
                "medium",
                "Secrets Exposure",
                "Grok Bot secrets store is present on this endpoint (contents excluded)",
                evidence_count=len(secret_names),
                sample_redacted="; ".join(f"{name} present" for name in secret_names),
                tags=["auth_excluded"],
            )
        )

    if info["lockfile_present"]:
        findings.append(
            make_finding(
                "grok_bot.lockfile.present",
                "low",
                "Cross-Agent Visibility",
                "Grok Bot lockfile is present (app is running or ran recently)",
                evidence_count=1,
                sample_redacted="lockfile present",
                tags=["desktop_app"],
            )
        )

    state_names = _present_names(root, STATE_DIRS)
    if state_names:
        findings.append(
            make_finding(
                "grok_bot.state.local_stores_present",
                "low",
                "Cross-Agent Visibility",
                "Grok Bot keeps browser and client state on disk (contents excluded)",
                evidence_count=len(state_names),
                sample_redacted="; ".join(f"{name} present" for name in state_names),
                tags=["chat_history"],
            )
        )

    return findings


def collect(root: Path) -> dict:
    markers = [root, *(root / name for name in (*KNOWN_FILES, *KNOWN_DIRS))]
    scope_hash = compute_scope_hash(str(path) for path in markers)
    info = scan_root(root)
    envelope = make_envelope(
        COLLECTOR,
        __version__,
        scope_hash,
        platform_detected=bool(info["app_present"]),
    )
    if not info["app_present"]:
        envelope["summary"] = {
            "app_present": False,
            "local_execution": LOCAL_EXECUTION,
            "local_execution_reason": LOCAL_EXECUTION_REASON,
            "findings": 0,
        }
        return envelope

    findings = build_findings(root, info)
    envelope["findings"] = findings
    envelope["summary"] = {**info, "findings": len(findings)}
    return envelope


def main() -> None:
    parser = argparse.ArgumentParser(description="Grok Bot desktop presence collector")
    add_base_args(parser)
    parser.add_argument(
        "--grok-bot-root",
        default=None,
        help="Grok Bot roaming data dir (default %%APPDATA%%\\Grok Bot)",
    )
    args = parser.parse_args()
    evidence_root = validate_evidence_root(args.evidence_root)
    root = Path(args.grok_bot_root) if args.grok_bot_root else default_root()
    envelope = collect(root)
    finish_collector(envelope, evidence_root, dry_run=args.dry_run)
    sys.exit(0 if envelope["platform_detected"] else 2)


if __name__ == "__main__":
    main()
