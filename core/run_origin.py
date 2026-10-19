#!/usr/bin/env python3
"""One line saying who started a scan, when, and why.

The scan folder gets ``run-origin.txt`` next to ``evidence/``. The summary
JSON copies the same three fields as ``run_origin``. The briefing prints
that line near the top of the page.

``-LaunchedBy`` and ``-Reason`` win over ``AISCAN_LAUNCHED_BY`` and
``AISCAN_REASON``. A blank field is ``unknown``. The computer name and the
account name are never used to fill one in.

Each field is a single line. Control characters are removed, then the
value goes through ``redact_paths`` and ``mask_secrets`` (the same helpers
the agent summary uses). A directory tail left after ``<userprofile>`` or
``<user>`` is dropped. That masking runs even when ``-Redact`` is off, so
a secret or a user path cannot land in the line. The field is then capped
at 120 characters. This module does not set ``AISCAN_REDACT``.

``agent-summary.json`` is not a versioned collector envelope, so this field
does not bump a schema version. A folder with no ``run-origin.txt`` still
loads: readers return ``unknown`` and do not raise.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Mapping

from common import mask_secrets, redact_paths

FILENAME = "run-origin.txt"
UNKNOWN = "unknown"
FIELD_LIMIT = 120

# C0 controls (including CR, LF, and tab), DEL, C1, and the Unicode line
# separators. Stripped, not turned into spaces, so the field stays one line.
_CONTROL_RE = re.compile(r"[\x00-\x1F\x7F-\x9F\u2028\u2029]")

# redact_paths keeps the tail after <userprofile> or <user> ("\work\notes").
# The origin line must not keep that tail.
_PATH_TAIL_RE = re.compile(
    r"(?i)(<(?:userprofile|user|path#[0-9a-f]{6,})>)(?:[\\/]\S*)?"
)

# ISO 8601 with a numeric offset (or Z). Seconds, optional fraction.
_STARTED_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})"
)
_LINE_RE = re.compile(
    r"^launched_by=(?P<launched_by>.*?) \| "
    r"started=(?P<started>" + _STARTED_RE.pattern + r") \| "
    r"reason=(?P<reason>.*)$"
)

ENV_LAUNCHED_BY = "AISCAN_LAUNCHED_BY"
ENV_REASON = "AISCAN_REASON"


def unknown_origin() -> dict[str, str]:
    return {"launched_by": UNKNOWN, "started": UNKNOWN, "reason": UNKNOWN}


def sanitize_origin_field(value: object) -> str:
    """One line, masked, capped. Empty becomes ``unknown``.

    Paths are masked before secrets, matching ``sanitize_text``, and the
    cap is applied after masking so a token is not cut in half first.
    ``AISCAN_REDACT`` is not consulted: the origin line is always masked.
    """
    text = "" if value is None else str(value)
    text = _CONTROL_RE.sub("", text).strip()
    if not text:
        return UNKNOWN
    text = mask_secrets(redact_paths(text))
    text = _PATH_TAIL_RE.sub(r"\1", text).strip()
    if not text:
        return UNKNOWN
    if len(text) > FIELD_LIMIT:
        text = text[:FIELD_LIMIT]
    return text


def _started_now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def clean_started(value: object, *, generate: bool) -> str:
    """Keep a real ISO timestamp. Otherwise now, or ``unknown`` when reading."""
    text = "" if value is None else _CONTROL_RE.sub("", str(value)).strip()
    if _STARTED_RE.fullmatch(text):
        return text
    if generate:
        return _started_now()
    return UNKNOWN


def _from_sources(
    explicit: str | None,
    env_name: str,
    environ: Mapping[str, str],
) -> str:
    """Parameter, then environment variable, then ``unknown``.

    ``explicit is None`` means the parameter was not passed. An empty
    string was passed on purpose and does not fall through to the variable.
    """
    if explicit is not None:
        raw: object = explicit
    elif env_name in environ:
        raw = environ.get(env_name, "")
    else:
        raw = ""
    return sanitize_origin_field(raw)


def build_run_origin(
    launched_by: str | None,
    reason: str | None,
    started: str | None,
    *,
    environ: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Resolve the three fields. Does not read the host or the account name."""
    env = os.environ if environ is None else environ
    return {
        "launched_by": _from_sources(launched_by, ENV_LAUNCHED_BY, env),
        "started": clean_started(started, generate=True),
        "reason": _from_sources(reason, ENV_REASON, env),
    }


def format_origin_line(origin: Mapping[str, str]) -> str:
    launched = origin.get("launched_by") or UNKNOWN
    started = origin.get("started") or UNKNOWN
    reason = origin.get("reason") or UNKNOWN
    return f"launched_by={launched} | started={started} | reason={reason}"


def parse_origin_text(text: str) -> dict[str, str] | None:
    """Parse one origin line. More than one line, or a bad line, is None."""
    lines = [line.strip() for line in str(text).splitlines() if line.strip()]
    if len(lines) != 1:
        return None
    match = _LINE_RE.fullmatch(lines[0])
    if match is None:
        return None
    return {
        "launched_by": sanitize_origin_field(match.group("launched_by")),
        "started": clean_started(match.group("started"), generate=False),
        "reason": sanitize_origin_field(match.group("reason")),
    }


def load_run_origin(root: str | Path) -> dict[str, str]:
    """Read ``run-origin.txt``. Missing, unreadable, or malformed is unknown.

    Does not raise. An older scan folder has no file, and that is normal.
    """
    path = Path(root) / FILENAME
    try:
        if not path.is_file():
            return unknown_origin()
        # utf-8-sig tolerates a BOM. This writer does not emit one.
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError):
        return unknown_origin()
    parsed = parse_origin_text(text)
    if parsed is None:
        return unknown_origin()
    return parsed


def write_run_origin(root: str | Path, origin: Mapping[str, str]) -> Path:
    """Write exactly one UTF-8 line, no BOM, with a single trailing LF.

    Same atomic replace as ``write_evidence``. ``newline="\\n"`` keeps the
    file one LF-terminated line on Windows too.
    """
    folder = Path(root)
    folder.mkdir(parents=True, exist_ok=True)
    dest = folder / FILENAME
    line = format_origin_line(origin)
    fd, tmp_name = tempfile.mkstemp(prefix="run-origin-", suffix=".tmp", dir=folder)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")
        tmp_path.replace(dest)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
    return dest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Write run-origin.txt for one scan folder.",
    )
    parser.add_argument("--root", required=True, help="Scan folder (aiscan -OutDir).")
    parser.add_argument(
        "--started",
        default=None,
        help="Scan start time, ISO 8601 with a numeric offset.",
    )
    parser.add_argument(
        "--launched-by",
        default=None,
        help="Who or what started the scan. Omit to use AISCAN_LAUNCHED_BY.",
    )
    parser.add_argument(
        "--reason",
        default=None,
        help="Why the scan was started. Omit to use AISCAN_REASON.",
    )
    args = parser.parse_args(argv)
    root = Path(args.root)
    if not root.is_dir():
        print("Output folder not found.", file=sys.stderr)
        return 1
    origin = build_run_origin(args.launched_by, args.reason, args.started)
    try:
        write_run_origin(root, origin)
    except OSError:
        print("Could not write the run origin.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
