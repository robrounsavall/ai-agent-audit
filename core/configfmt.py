"""
Tolerant, stdlib-only readers for agent config files.

Agent harnesses write JSON that is often JSONC in practice (comments and
trailing commas), sometimes with a UTF-8 BOM, and TOML that a user may have
hand-edited into an invalid state. Collectors need to tell three cases apart:
the file is missing, the file parsed, or the file exists but could not be
parsed. Silently treating a broken file as "unset" hides real settings.

Every loader returns (data, error):
    (None, None)        file missing / not a file
    (data, None)        parsed
    (None, "reason")    present but unreadable or unparseable

Error strings never contain file content, so they are safe to put in evidence.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import Any

# Config files larger than this are not agent settings; refuse to slurp them.
MAX_CONFIG_BYTES = 8 * 1024 * 1024


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas outside of strings."""
    out: list[str] = []
    i = 0
    n = len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] not in "\r\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue
        if ch == ",":
            # Drop the comma when the next significant character closes a container.
            j = i + 1
            while j < n:
                if text[j] in " \t\r\n":
                    j += 1
                    continue
                if text.startswith("//", j):
                    while j < n and text[j] not in "\r\n":
                        j += 1
                    continue
                if text.startswith("/*", j):
                    end = text.find("*/", j + 2)
                    j = n if end == -1 else end + 2
                    continue
                break
            if j < n and text[j] in "]}":
                i += 1
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def _read_text(path: Path) -> tuple[str | None, str | None]:
    try:
        if not path.is_file():
            return None, None
        if path.stat().st_size > MAX_CONFIG_BYTES:
            return None, "file too large"
        raw = path.read_bytes()
    except OSError as exc:
        return None, f"unreadable ({type(exc).__name__})"
    try:
        return raw.decode("utf-8-sig"), None
    except UnicodeDecodeError:
        return None, "not UTF-8"


def parse_jsonc_text(text: str) -> tuple[Any, str | None]:
    try:
        return json.loads(text), None
    except json.JSONDecodeError:
        pass
    try:
        return json.loads(strip_jsonc(text)), None
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON (line {exc.lineno})"


def load_jsonc(path: Path) -> tuple[Any, str | None]:
    """Load JSON or JSONC. See module docstring for the return contract."""
    text, err = _read_text(Path(path))
    if text is None:
        return None, err
    if not text.strip():
        return None, "empty file"
    return parse_jsonc_text(text)


def load_toml(path: Path) -> tuple[dict | None, str | None]:
    """Load TOML. See module docstring for the return contract."""
    text, err = _read_text(Path(path))
    if text is None:
        return None, err
    try:
        return tomllib.loads(text), None
    except tomllib.TOMLDecodeError as exc:
        line = getattr(exc, "lineno", None)
        return None, f"invalid TOML (line {line})" if line else "invalid TOML"
