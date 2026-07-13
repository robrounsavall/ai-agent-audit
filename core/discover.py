"""
Discovery command for phase1-audit.

Tester-facing entry point and data source for the orchestrator. Resolves tool
data paths via paths.py, reports detection status, and optionally writes a
safe evidence envelope.

Three modes (mutually compatible; default is console):

  (default)              Human-readable console report — full local paths.
                         Nothing read or written.
  --json                 Machine-readable JSON to stdout — full paths included.
                         Marked _sensitive; local tooling only; do not persist.
  --write-discovery DIR  Write safe evidence envelope to DIR/evidence/discovery.json.
                         No raw paths in the written file.

Capability preflight (shown at top of console report):
  gitleaks/trufflehog on PATH?  Secrets scan available?
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

# When run as a script Python adds the script dir to sys.path automatically.
import paths
from common import compute_scope_hash, hostname_short, make_envelope, write_evidence

__version__ = "1.0.0"


# --------------------------------------------------------------------------- #
# Capability preflight
# --------------------------------------------------------------------------- #

def _check_secrets_scanner() -> tuple[bool, str]:
    """Return (available, label). Checks gitleaks then trufflehog."""
    for tool in ("gitleaks", "trufflehog"):
        if shutil.which(tool):
            return True, f"{tool} found"
    return False, "NOT available"


def preflight_lines() -> list[str]:
    """Return preflight status lines (no trailing newline).

    pii-scan went pure stdlib in v2 (no Presidio), so the only external
    capability left to check is the secrets scanner binary.
    """
    _sec_ok, sec_label = _check_secrets_scanner()
    return [
        f"Secrets scan: {sec_label}",
    ]


# --------------------------------------------------------------------------- #
# Console report
# --------------------------------------------------------------------------- #

_LABEL_MAP = {
    "claude_projects": "Claude Code",
    "cursor_projects": "Cursor",
    "cursor_db":       "Cursor (DB)",
    "codex_sessions":  "Codex",
    "grok_sessions":   "Grok Build",
}

_ATTR_MAP = {
    "claude_projects": "claude_projects",
    "cursor_projects": "cursor_projects",
    "cursor_db":       "cursor_db",
    "codex_sessions":  "codex_sessions",
    "grok_sessions":   "grok_sessions",
}

_ORDER = ["claude_projects", "cursor_projects", "cursor_db", "codex_sessions", "grok_sessions"]


def _console_report(p: paths.ToolPaths) -> str:
    """Build the human-readable console report string (full local paths)."""
    lines: list[str] = []

    # Preflight
    for line in preflight_lines():
        lines.append(line)
    lines.append("")

    lines.append("AI coding tool history found on this machine:")
    lines.append("")

    det = paths.detected(p)

    for key in _ORDER:
        label = _LABEL_MAP[key]
        attr = _ATTR_MAP[key]
        full_path = getattr(p, attr)
        info = det[key]
        source_tag = f"[{info['source']}]"

        if info["detected"]:
            count = info["file_count"]
            newest = info["newest"]
            if count == 1 and key == "cursor_db":
                detail = "present"
            elif newest:
                detail = f"{count} file(s), newest {newest}"
            else:
                detail = f"{count} file(s)"
            lines.append(f"  {label:<14} {str(full_path):<56} {detail:<32} {source_tag}")
        else:
            lines.append(f"  {label:<14} not found (looked: {full_path}){' ' * 4}{source_tag}")

    lines.append("")
    lines.append(
        "Nothing was read or written. "
        "(--json = local machine output, contains paths; do not share.)"
    )
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# JSON output (sensitive — full paths)
# --------------------------------------------------------------------------- #

def _json_output(p: paths.ToolPaths) -> dict:
    return {
        "_sensitive": "local_only_contains_filesystem_paths",
        "cli_args": paths.paths_to_cli_args(p),
        "native_dirs": {
            "claude_projects": str(p.claude_projects),
            "codex_sessions":  str(p.codex_sessions),
            "cursor_projects": str(p.cursor_projects),
            "grok_sessions":   str(p.grok_sessions),
        },
        "evidence_meta": paths.safe_path_meta(p),
    }


# --------------------------------------------------------------------------- #
# Evidence write (safe — no raw paths)
# --------------------------------------------------------------------------- #

def _write_discovery(p: paths.ToolPaths, evidence_root: str) -> Path:
    root = Path(evidence_root)

    # Scope hash over resolved data paths (hashing is safe).
    scope_hash = compute_scope_hash([
        p.claude_projects,
        p.codex_sessions,
        p.cursor_projects,
        p.cursor_db,
        p.grok_sessions,
    ])

    meta = paths.safe_path_meta(p)
    detected_count = sum(1 for v in meta.values() if v.get("detected"))

    envelope = make_envelope(
        collector="discovery",
        version=__version__,
        scope_hash=scope_hash,
        platform_detected=detected_count > 0,
        host=hostname_short(),
    )

    # Safe metadata only — no raw paths.
    envelope["summary"]["history_roots"] = meta
    envelope["summary"]["tools_detected"] = detected_count

    # Preflight capability flags (no paths involved).
    sec_ok, sec_label = _check_secrets_scanner()
    envelope["summary"]["capabilities"] = {
        "secrets_scanner": sec_label if sec_ok else None,
    }

    # findings/rules/raw_pointers stay empty lists (make_envelope sets them).
    dest = write_evidence(envelope, root)
    return dest


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="discover",
        description=(
            "Discover AI coding tool data paths on this machine. "
            "Default: console report (full paths, nothing written). "
            "--json: machine-readable output (SENSITIVE — local only). "
            "--write-discovery: write safe evidence envelope."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    # Mode flags (mutually compatible).
    parser.add_argument(
        "--json",
        action="store_true",
        dest="output_json",
        help="Print JSON to stdout (full paths — LOCAL SENSITIVE; do not share or persist).",
    )
    parser.add_argument(
        "--write-discovery",
        metavar="EVIDENCE_ROOT",
        dest="write_discovery",
        default=None,
        help="Write safe evidence envelope to EVIDENCE_ROOT/evidence/discovery.json (no raw paths).",
    )

    # Shared path-override flags from paths.py.
    paths.add_path_args(parser)

    return parser


def main() -> None:
    # Reconfigure stdout for UTF-8 on Windows consoles (Python 3.7+).
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = build_parser()
    args = parser.parse_args()

    # Resolve paths once; all modes share the result.
    p = paths.resolve_from_args(args)

    # Mode: --write-discovery (evidence envelope, safe).
    if args.write_discovery is not None:
        dest = _write_discovery(p, args.write_discovery)
        print(f"Wrote {dest}")
        sys.exit(0)

    # Mode: --json (machine-readable, sensitive).
    if args.output_json:
        out = _json_output(p)
        print(json.dumps(out, indent=2, ensure_ascii=False))
        sys.exit(0)

    # Default: console report (full paths, nothing written).
    print(_console_report(p))
    sys.exit(0)


if __name__ == "__main__":
    main()
