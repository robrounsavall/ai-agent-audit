"""
Grok Bot (Cursor desktop assistant) local presence collector.

Usage:
    python grok-bot.py --evidence-root ./audit-run [--grok-bot-root DIR] [--dry-run]

Grok Bot is not Grok Build. Grok Build lives in ~/.grok and is collected by
components/grok. Grok Bot is Cursor's desktop and mobile assistant: chat runs
in the desktop app, and Bot work runs on a per-user cloud computer. This
collector is the Cowork-style endpoint check for the Windows desktop client.

It reports whether the roaming app directory exists and whether the
local-execution channel has left artifacts. Those artifacts mean this machine
can run commands and move files for a Bot. It does not open settings,
credential, connection, or log contents. The ask / always / never policy is
not read: Cursor documents it as an in-app and dashboard control, not as a
published local file schema.

Cloud controls stay out of this evidence on purpose. Connector grants, Cloud
Agent delegation, outbound messaging, network policy, and Auto-review
enforcement live in Cursor's cloud. An offline scan cannot see them, and this
collector does not invent rules for them.
"""

from __future__ import annotations

import argparse
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

__version__ = "1.0.0"

COLLECTOR = "grok-bot"

SETTINGS_NAME = "settings.json"
LOCAL_EXEC_LOG = "local-exec-daemon.log"
LOCAL_EXEC_CREDENTIAL = "local-exec-daemon-credential.json"
LOCAL_EXEC_CONNECTION = "local-exec-daemon-connection.json"
LOCAL_EXEC_DIR = "local-exec-daemon"


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


def scan_root(root: Path) -> dict:
    settings = root / SETTINGS_NAME
    log_file = root / LOCAL_EXEC_LOG
    credential = root / LOCAL_EXEC_CREDENTIAL
    connection = root / LOCAL_EXEC_CONNECTION
    daemon_dir = root / LOCAL_EXEC_DIR

    settings_present = settings.is_file()
    log_present = log_file.is_file()
    credential_present = credential.is_file()
    connection_present = connection.is_file()
    daemon_dir_present = daemon_dir.is_dir()
    local_exec_present = any(
        (log_present, credential_present, connection_present, daemon_dir_present)
    )

    newest = ""
    for path in (settings, log_file, credential, connection, daemon_dir):
        if not path.exists():
            continue
        stamp = _mtime_date(path)
        if stamp > newest:
            newest = stamp

    return {
        "app_present": root.is_dir(),
        "settings_present": settings_present,
        "local_exec_present": local_exec_present,
        "local_exec_log_present": log_present,
        "local_exec_log_bytes": _file_size(log_file),
        "local_exec_credential_present": credential_present,
        "local_exec_connection_present": connection_present,
        "local_exec_daemon_dir_present": daemon_dir_present,
        "newest_local_activity": newest,
    }


def build_findings(info: dict) -> list[dict]:
    findings: list[dict] = []
    if not info["app_present"]:
        return findings

    findings.append(
        make_finding(
            "grok_bot.desktop.present",
            "low",
            "Cross-Agent Visibility",
            "Grok Bot desktop app data is present on this endpoint",
            evidence_count=1,
            sample_redacted=(
                f"settings={'present' if info['settings_present'] else 'absent'}"
            ),
            tags=["desktop_app"],
        )
    )

    if info["local_exec_present"]:
        findings.append(
            make_finding(
                "grok_bot.local_exec.capability_present",
                "medium",
                "Shell Execution",
                "Grok Bot local-execution channel is present on this endpoint",
                evidence_count=1,
                sample_redacted=(
                    "log="
                    + ("present" if info["local_exec_log_present"] else "absent")
                    + " credential="
                    + ("present" if info["local_exec_credential_present"] else "absent")
                    + " connection="
                    + ("present" if info["local_exec_connection_present"] else "absent")
                ),
                tags=["local_exec"],
            )
        )

    if info["local_exec_credential_present"]:
        findings.append(
            make_finding(
                "grok_bot.local_exec.credential_present",
                "low",
                "Identity & SSO",
                "Grok Bot local-exec credential file present (contents excluded)",
                evidence_count=1,
                sample_redacted="local-exec-daemon-credential.json present",
                tags=["auth_excluded"],
            )
        )

    return findings


def collect(root: Path) -> dict:
    markers = [
        root,
        root / SETTINGS_NAME,
        root / LOCAL_EXEC_LOG,
        root / LOCAL_EXEC_CREDENTIAL,
        root / LOCAL_EXEC_CONNECTION,
        root / LOCAL_EXEC_DIR,
    ]
    scope_hash = compute_scope_hash(str(p) for p in markers)
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
            "settings_present": False,
            "local_exec_present": False,
            "local_exec_credential_present": False,
            "findings": 0,
        }
        return envelope

    findings = build_findings(info)
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
