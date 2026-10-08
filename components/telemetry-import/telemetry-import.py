#!/usr/bin/env python3
"""Opt-in telemetry import collector.

Reads export files the operator already saved. It does not contact Splunk,
an OTel collector, or any other network service.

Usage:
    python components/telemetry-import/telemetry-import.py \\
        --evidence-root ./audit-run \\
        [--otel-file PATH] [--splunk-export PATH] [--raw-root PATH] [--dry-run]

    --otel-file       OTLP JSON (resourceLogs) or JSON-lines logs export.
                      Repeat the flag to pass more than one file.
    --splunk-export   Splunk results export, JSON or CSV. Repeatable.
    --evidence-root   Parent directory. Writes evidence/telemetry.json.
    --raw-root        Defaults to <evidence-root>/raw. Receives a redacted
                      JSONL copy (tool name, decision, tokens, cost only).
    --dry-run         Print the envelope and write nothing.

Exit codes match the other collectors: 0 when an export was read, 2 when
no export was provided or none of the paths could be read, 1 when
--evidence-root does not exist.

Public integration surface:
    COLLECTOR = "telemetry"          # evidence file is evidence/telemetry.json
    collect(otel_files, splunk_files, raw_root=None) -> envelope
    build_parser() -> argparse.ArgumentParser
    run(argv=None) -> int
    main() -> None

Claude Code OpenTelemetry attribute names
------------------------------------------
Confirmed from the Claude Code monitoring reference, "Tool decision event"
(https://code.claude.com/docs/en/monitoring-usage), as published on the
docs site on 2026-10-07:

    Event name: claude_code.tool_decision
    event.name: "tool_decision"
    event.timestamp: ISO 8601
    event.sequence: per-process ordering counter (not required for this rollup)
    tool_name
    tool_use_id
    decision: "accept" or "reject"
    source: "config" | "hook" | "user_permanent" | "user_temporary"
            | "user_abort" | "user_reject"
    tool_source: "builtin" | "mcp" | "sdk_host_builtin_mcp"
                 (tool_source requires Claude Code v2.1.214+)
    tool_parameters: JSON string, only when OTEL_LOG_TOOL_DETAILS=1
                     (mcp_server_name / mcp_tool_name for MCP tools; for
                     Claude Desktop built-in MCP servers those two names are
                     present even with the flag off, v2.1.214+).
                     This collector discards the payload after reading
                     mcp_tool_name. Command text, prompts, and URLs are not
                     stored.
    Log body and prompt / prompt_text / response attributes are not stored.
    user_prompt events are ignored.

    source meanings used for the rollup, from that same section:
    - config: decided automatically, no prompt (settings, allow/deny rules,
      managed policy, CLI flags, permission mode, session grant, or an
      inherently safe tool). The event does not say which of those matched.
    - hook: a PreToolUse or PermissionRequest hook returned the decision.
    - user_permanent / user_temporary: the user answered a prompt (accept).
    - user_abort / user_reject: the user dismissed or refused a prompt.

Assumed, because they are not Claude Code attribute names:
    - OTLP/JSON encoding (resourceLogs, scopeLogs, logRecords, stringValue)
      follows the OpenTelemetry proto JSON mapping. JSON-lines may be one
      OTLP log record or one flat object per line.
    - Splunk exports flatten those attributes to columns, and _time is the
      Splunk event time. Decision words approve/approved/allow and
      deny/denied are accepted as synonyms of accept and reject.
    - Cursor usage rows match the owner's collector: event=cursor_usage_event,
      sourcetype=cursor:usage_events, fields model, kind, input_tokens,
      output_tokens, cache_read_tokens, cache_write_tokens, total_tokens,
      cost_cents. cost_cents is labeled as the Cursor dashboard export.
    - Generic usage rows have harness, model, and a tokens column. Dollars
      are not computed from tokens. A cost column on those rows is ignored.
    - "config rule" / "user" / "hook" are this collector's groupings of the
      documented source values, not attribute values Claude emits.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

_CORE_DIR = Path(__file__).resolve().parents[2] / "core"
if str(_CORE_DIR) not in sys.path:
    sys.path.insert(0, str(_CORE_DIR))

from common import (  # noqa: E402
    add_base_args,
    compute_scope_hash,
    finish_collector,
    make_envelope,
    make_finding,
    parse_iso,
    resolve_raw_root,
    sanitize_text,
    validate_evidence_root,
)

__version__ = "1.0.0"
COLLECTOR = "telemetry"

# Confirmed Claude Code event / attribute names. See module docstring.
CONFIRMED_EVENT_NAME = "claude_code.tool_decision"
CONFIRMED_EVENT_NAME_VALUE = "tool_decision"
CONFIRMED_DECISIONS = ("accept", "reject")
CONFIRMED_SOURCES = (
    "config",
    "hook",
    "user_permanent",
    "user_temporary",
    "user_abort",
    "user_reject",
)
CONFIRMED_TOOL_SOURCES = ("builtin", "mcp", "sdk_host_builtin_mcp")

COST_LABEL = "from the Cursor dashboard usage export"
TOKENS_ONLY_LABEL = "tokens only"
NOTE_NO_EXPORT = "Approvals are not on disk without OTel tool_decision."
NOTE_UNREADABLE = "Telemetry export could not be read."
NOTE_NO_DECISIONS = "Export had no tool_decision events."
NOTE_IMPORTED = "Counts come from imported tool_decision events."

# Keys that may carry prompt text, command arguments, or other content.
# tool_parameters is read only for mcp_tool_name, then discarded.
SENSITIVE_KEYS = frozenset(
    {
        "prompt",
        "prompt_text",
        "response",
        "tool_parameters",
        "tool_input",
        "tool_result",
        "bash_command",
        "full_command",
        "command",
        "arguments",
        "args",
        "query",
        "content",
        "message",
        "error",
        "url",
        "file_path",
        "path",
        "description",
        "input",
        "output",
        "user.email",
        "user.id",
        "user.account_id",
        "user.account_uuid",
    }
)

KEEP_KEYS = frozenset(
    {
        "event.name",
        "event_name",
        "event",
        "name",
        "event.timestamp",
        "event_timestamp",
        "timestamp",
        "_time",
        "time",
        "tool_name",
        "tool.name",
        "tool",
        "toolname",
        "decision",
        "source",
        "decision_source",
        "tool_source",
        "tool_use_id",
        "mcp_tool_name",
        "mcp_server_name",
        "harness",
        "platform",
        "service.name",
        "model",
        "kind",
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
        "cache_write_tokens",
        "total_tokens",
        "tokens",
        "cost_cents",
        "sourcetype",
        "_sourcetype",
    }
)

KNOWN_EVENTS = frozenset(
    {
        CONFIRMED_EVENT_NAME,
        CONFIRMED_EVENT_NAME_VALUE,
        "cursor_usage_event",
        "user_prompt",
    }
)

SOURCE_GROUP = {
    "config": "config rule",
    "hook": "hook",
    "user_permanent": "user",
    "user_temporary": "user",
    "user_abort": "user",
    "user_reject": "user",
    "user": "user",
}
SOURCE_ORDER = (
    "config",
    "hook",
    "user_permanent",
    "user_temporary",
    "user_reject",
    "user_abort",
    "user",
    "unknown",
)
GROUP_ORDER = ("config rule", "user", "hook", "unknown")

HARNESS_MAP = {
    "claude": "claude",
    "claude-code": "claude",
    "claude_code": "claude",
    "claudecode": "claude",
    "cursor": "cursor",
    "codex": "codex",
    "grok": "grok",
    "grok-build": "grok",
}
_HARNESS_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")

RISKY_FAMILIES = (
    (
        "shell",
        "telemetry.approval.unprompted_shell",
        "Shell Execution",
        "Bash or PowerShell",
        frozenset({"bash", "powershell"}),
    ),
    (
        "write",
        "telemetry.approval.unprompted_write",
        "Data Access",
        "Write",
        frozenset({"write"}),
    ),
    (
        "webfetch",
        "telemetry.approval.unprompted_webfetch",
        "Network Egress",
        "WebFetch",
        frozenset({"webfetch", "web_fetch"}),
    ),
    (
        "mcp",
        "telemetry.approval.unprompted_mcp",
        "MCP Tooling",
        "MCP",
        frozenset({"mcp", "mcp_tool"}),
    ),
)

CSV_HINTS = frozenset(
    {
        "tool_name",
        "tool",
        "decision",
        "model",
        "tokens",
        "total_tokens",
        "input_tokens",
        "cost_cents",
        "event.name",
        "event",
        "harness",
        "kind",
        "source",
    }
)

TOOL_KEYS = ("tool_name", "tool.name", "tool", "toolname")
DECISION_KEYS = ("decision",)
SOURCE_KEYS = ("source", "decision_source")
TIME_KEYS = ("event.timestamp", "event_timestamp", "timestamp", "_time", "time")
TOKEN_PARTS = (
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
)


@dataclass
class ParseStats:
    sensitive_dropped: int = 0


@dataclass
class Approval:
    harness: str
    tool: str
    decision: str
    source: str
    group: str
    day: str
    timestamp: str
    tool_use_id: str


@dataclass
class Usage:
    harness: str
    tool: str
    model: str
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    total_tokens: int
    cost_cents: int | None
    day: str


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Import Claude Code tool_decision exports and usage/cost exports "
            "into evidence/telemetry.json. Reads local files only."
        )
    )
    add_base_args(parser)
    parser.add_argument(
        "--otel-file",
        action="append",
        default=None,
        help=(
            "OTLP JSON (resourceLogs) or JSON-lines logs export. "
            "Repeat to import more than one file."
        ),
    )
    parser.add_argument(
        "--splunk-export",
        action="append",
        default=None,
        help=(
            "Splunk results export in JSON or CSV (approval rows and/or "
            "cursor:usage_events / generic token rows). Repeatable."
        ),
    )
    return parser


def _norm_key(key: Any) -> str:
    return str(key).strip().lower()


def clean_token(value: Any, fallback: str, *, max_spaces: int = 2, max_len: int = 64) -> str:
    """Keep a short label. Drop anything that looks like a command or prose."""
    raw = str(value or "").strip()
    if not raw:
        return fallback
    collapsed = " ".join(raw.split())
    unsafe = (
        len(collapsed) > max_len
        or collapsed.count(" ") > max_spaces
        or any(ch in collapsed for ch in "\"'`$|&;<>\\")
    )
    if unsafe:
        return "redacted"
    cleaned = sanitize_text(collapsed)
    if not cleaned:
        return "redacted"
    return cleaned[:max_len]


def clean_tool(value: Any) -> str:
    return clean_token(value, "unknown", max_spaces=0)


def clean_harness(value: Any, default: str) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return default
    mapped = HARNESS_MAP.get(text)
    if mapped:
        return mapped
    if _HARNESS_RE.match(text):
        return text
    return default


def as_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value.is_integer():
            return int(value)
        return None
    text = str(value).strip().replace(",", "")
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if re.fullmatch(r"-?\d+\.0+", text):
        return int(float(text))
    return None


def nonneg(value: Any) -> int | None:
    number = as_int(value)
    if number is None or number < 0:
        return None
    return number


def first(row: dict[str, Any], keys: Iterable[str]) -> str:
    for key in keys:
        value = row.get(key)
        if value is None or isinstance(value, (dict, list, bool)):
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def normalize_decision(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"accept", "approve", "approved", "allow"}:
        return "accept"
    if text in {"reject", "deny", "denied"}:
        return "reject"
    return ""


def normalize_source(value: Any) -> str:
    text = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    if text in {"config_rule", "configrule"}:
        return "config"
    if text in SOURCE_GROUP:
        return text
    return "unknown"


def event_name(row: dict[str, Any]) -> str:
    for key in ("event.name", "event_name", "event"):
        value = str(row.get(key) or "").strip().lower()
        if value:
            return value
    name = str(row.get("name") or "").strip().lower()
    if name in KNOWN_EVENTS:
        return name
    return ""


def sourcetype_of(row: dict[str, Any]) -> str:
    return str(row.get("sourcetype") or row.get("_sourcetype") or "").strip().lower()


def nano_to_iso(value: Any) -> str:
    try:
        nanos = int(str(value).strip())
    except (TypeError, ValueError):
        return ""
    if nanos < 0:
        return ""
    seconds, _frac = divmod(nanos, 1_000_000_000)
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


def epoch_to_iso(seconds: float) -> str:
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


def parse_time(value: Any) -> str:
    if value is None or isinstance(value, bool):
        return ""
    if isinstance(value, (int, float)):
        return epoch_to_iso(float(value))
    text = str(value).strip()
    if not text:
        return ""
    if re.fullmatch(r"\d{16,}", text):
        return nano_to_iso(text)
    if re.fullmatch(r"\d{13}", text):
        return epoch_to_iso(int(text) / 1000.0)
    if re.fullmatch(r"\d{10}(?:\.\d+)?", text):
        return epoch_to_iso(float(text))
    parsed = parse_iso(text)
    if _DAY_RE.match(parsed):
        return parsed
    return ""


def day_of(timestamp: str) -> str:
    if _DAY_RE.match(timestamp or ""):
        return timestamp[:10]
    return "unknown"


def _otlp_scalar(value_obj: Any) -> Any:
    if not isinstance(value_obj, dict):
        return value_obj
    for key in ("stringValue", "string_value"):
        if key in value_obj:
            return value_obj[key]
    for key in ("intValue", "int_value"):
        if key in value_obj:
            return value_obj[key]
    for key in ("doubleValue", "double_value"):
        if key in value_obj:
            return value_obj[key]
    for key in ("boolValue", "bool_value"):
        if key in value_obj:
            return value_obj[key]
    return None


def _extract_mcp_names(value: Any) -> tuple[str, str]:
    data = value
    if isinstance(value, str):
        text = value.strip()
        if not text.startswith("{"):
            return "", ""
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return "", ""
    if not isinstance(data, dict):
        return "", ""
    server = data.get("mcp_server_name")
    tool = data.get("mcp_tool_name")
    server_text = server if isinstance(server, str) else ""
    tool_text = tool if isinstance(tool, str) else ""
    return server_text, tool_text


def _take_known(merged: dict[str, Any], key: str, value: Any, stats: ParseStats) -> None:
    norm = _norm_key(key)
    if norm in {"attributes", "body", "resource", "scope", "instrumentationscope"}:
        return
    if norm == "tool_parameters":
        server, tool = _extract_mcp_names(value)
        if tool and "mcp_tool_name" not in merged:
            merged["mcp_tool_name"] = tool
        if server and "mcp_server_name" not in merged:
            merged["mcp_server_name"] = server
        stats.sensitive_dropped += 1
        return
    if norm in SENSITIVE_KEYS:
        stats.sensitive_dropped += 1
        return
    if norm not in KEEP_KEYS:
        return
    if isinstance(value, (dict, list)) or value is None:
        return
    merged[norm] = value


def flatten_record(data: dict[str, Any], stats: ParseStats) -> dict[str, Any]:
    """Project one export record onto the allowlisted fields."""
    merged: dict[str, Any] = {}
    for key, value in data.items():
        if key == "attributes":
            continue
        _take_known(merged, key, value, stats)
    attrs = data.get("attributes")
    if isinstance(attrs, dict):
        for key, value in attrs.items():
            _take_known(merged, key, value, stats)
    elif isinstance(attrs, list):
        for item in attrs:
            if not isinstance(item, dict) or "key" not in item:
                continue
            _take_known(merged, item.get("key"), _otlp_scalar(item.get("value")), stats)

    body = data.get("body")
    body_text = ""
    if isinstance(body, dict):
        raw_body = body.get("stringValue", body.get("string_value"))
        if isinstance(raw_body, str):
            body_text = raw_body
    elif isinstance(body, str):
        body_text = body
    body_token = body_text.strip().lower()
    if body_text:
        if body_token in KNOWN_EVENTS and "event.name" not in merged:
            merged["event.name"] = body_token
        elif body_token not in KNOWN_EVENTS:
            stats.sensitive_dropped += 1

    if not any(key in merged for key in TIME_KEYS):
        nano = data.get("timeUnixNano", data.get("time_unix_nano"))
        if nano is not None and not isinstance(nano, (dict, list)):
            iso = nano_to_iso(nano)
            if iso:
                merged["event.timestamp"] = iso
    return merged


def _service_name(resource: Any) -> str:
    if not isinstance(resource, dict):
        return ""
    attrs = resource.get("attributes")
    if isinstance(attrs, list):
        for item in attrs:
            if not isinstance(item, dict):
                continue
            if _norm_key(item.get("key")) == "service.name":
                value = _otlp_scalar(item.get("value"))
                return str(value or "")
    if isinstance(attrs, dict):
        for key, value in attrs.items():
            if _norm_key(key) == "service.name" and not isinstance(value, (dict, list)):
                return str(value or "")
    return ""


def _is_otlp_log_record(data: dict[str, Any]) -> bool:
    if "resourceLogs" in data or "resource_logs" in data:
        return False
    if "timeUnixNano" in data or "time_unix_nano" in data:
        return True
    attrs = data.get("attributes")
    if (
        isinstance(attrs, list)
        and attrs
        and isinstance(attrs[0], dict)
        and "key" in attrs[0]
    ):
        return True
    return False


def expand_document(data: Any, stats: ParseStats) -> list[dict[str, Any]]:
    if isinstance(data, list):
        rows: list[dict[str, Any]] = []
        for item in data:
            rows.extend(expand_document(item, stats))
        return rows
    if not isinstance(data, dict):
        return []
    resource_logs = data.get("resourceLogs", data.get("resource_logs"))
    if isinstance(resource_logs, list):
        rows = []
        for resource_log in resource_logs:
            if not isinstance(resource_log, dict):
                continue
            service = _service_name(resource_log.get("resource"))
            scopes = (
                resource_log.get("scopeLogs")
                or resource_log.get("scope_logs")
                or resource_log.get("instrumentationLibraryLogs")
                or []
            )
            if not isinstance(scopes, list):
                continue
            for scope in scopes:
                if not isinstance(scope, dict):
                    continue
                records = scope.get("logRecords") or scope.get("log_records") or []
                if not isinstance(records, list):
                    continue
                for record in records:
                    if not isinstance(record, dict):
                        continue
                    flat = flatten_record(record, stats)
                    if service and "service.name" not in flat:
                        flat["service.name"] = service
                    rows.append(flat)
        return rows
    results = data.get("results")
    if isinstance(results, list):
        return [
            flatten_record(item, stats) for item in results if isinstance(item, dict)
        ]
    result = data.get("result")
    if isinstance(result, dict) and any(
        key in data for key in ("preview", "offset", "lastrow")
    ):
        return [flatten_record(result, stats)]
    if _is_otlp_log_record(data):
        return [flatten_record(data, stats)]
    return [flatten_record(data, stats)]


def _looks_like_csv(text: str) -> bool:
    first = next((line for line in text.splitlines() if line.strip()), "")
    stripped = first.lstrip()
    if not stripped or stripped[0] in "{[":
        return False
    try:
        header = [cell.strip().lower() for cell in next(csv.reader([first]))]
    except csv.Error:
        return False
    return bool(set(header) & CSV_HINTS)


def _csv_rows(text: str) -> list[dict[str, Any]]:
    reader = csv.DictReader(io.StringIO(text))
    rows: list[dict[str, Any]] = []
    for raw in reader:
        if not raw:
            continue
        row: dict[str, Any] = {}
        for key, value in raw.items():
            if key is None:
                continue
            row[_norm_key(key)] = "" if value is None else value
        if any(str(value).strip() for value in row.values()):
            rows.append(row)
    return rows


def _json_lines(text: str) -> tuple[list[Any], int]:
    docs: list[Any] = []
    nonempty = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        nonempty += 1
        try:
            docs.append(json.loads(stripped))
        except json.JSONDecodeError:
            continue
    return docs, nonempty


class ExportReadError(ValueError):
    pass


def load_export(path: Path) -> tuple[list[dict[str, Any]], ParseStats]:
    """Load one export file into allowlisted flat records."""
    if not path.is_file():
        raise ExportReadError("missing")
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as exc:
        raise ExportReadError("unreadable") from exc
    stats = ParseStats()
    suffix = path.suffix.lower()
    stripped = text.strip()
    if not stripped:
        return [], stats
    if suffix == ".csv" or _looks_like_csv(text):
        return [flatten_record(row, stats) for row in _csv_rows(text)], stats
    docs: list[Any]
    if stripped[0] in "{[":
        try:
            docs = [json.loads(stripped)]
        except json.JSONDecodeError:
            docs, nonempty = _json_lines(text)
            if nonempty and not docs:
                raise ExportReadError("parse_error")
    else:
        docs, nonempty = _json_lines(text)
        if nonempty and not docs:
            raise ExportReadError("parse_error")
    rows: list[dict[str, Any]] = []
    for doc in docs:
        rows.extend(expand_document(doc, stats))
    return rows, stats


def _display_tool(row: dict[str, Any]) -> str:
    tool = clean_tool(first(row, TOOL_KEYS))
    tool_source = str(row.get("tool_source") or "").strip().lower()
    mcp_name = clean_tool(row.get("mcp_tool_name"))
    mcpish = tool_source in {"mcp", "sdk_host_builtin_mcp"} or tool.lower() in {
        "mcp",
        "mcp_tool",
    }
    if mcpish:
        if mcp_name not in {"", "unknown", "redacted"}:
            return f"mcp:{mcp_name}"
        return "mcp_tool"
    return tool


def _approval_harness(row: dict[str, Any]) -> str:
    for key in ("harness", "platform", "service.name"):
        harness = clean_harness(row.get(key), "")
        if harness:
            return harness
    return "claude"


def _timestamp(row: dict[str, Any]) -> str:
    return parse_time(first(row, TIME_KEYS))


def is_tool_decision(row: dict[str, Any]) -> bool:
    return event_name(row) in {CONFIRMED_EVENT_NAME, CONFIRMED_EVENT_NAME_VALUE}


def is_cursor_usage(row: dict[str, Any]) -> bool:
    if event_name(row) == "cursor_usage_event":
        return True
    if "cursor:usage" in sourcetype_of(row):
        return True
    harness = clean_harness(row.get("harness"), "")
    if harness == "cursor" and (
        str(row.get("kind") or "").strip()
        or "cost_cents" in row
        or "cache_read_tokens" in row
    ):
        return True
    return False


def is_generic_usage(row: dict[str, Any]) -> bool:
    if not str(row.get("harness") or "").strip():
        return False
    if not str(row.get("model") or "").strip():
        return False
    return any(key in row and str(row.get(key) or "").strip() for key in ("tokens", *TOKEN_PARTS, "total_tokens"))


def is_cursor_shape(row: dict[str, Any]) -> bool:
    if normalize_decision(first(row, DECISION_KEYS)):
        return False
    if not str(row.get("kind") or "").strip():
        return False
    if not str(row.get("model") or "").strip():
        return False
    return any(
        key in row and str(row.get(key) or "").strip()
        for key in ("cost_cents", "cache_read_tokens", "cache_write_tokens", "input_tokens", "total_tokens")
    )


def is_approval_shape(row: dict[str, Any]) -> bool:
    name = event_name(row)
    if name and name not in {CONFIRMED_EVENT_NAME, CONFIRMED_EVENT_NAME_VALUE}:
        return False
    if not first(row, TOOL_KEYS):
        return False
    return bool(normalize_decision(first(row, DECISION_KEYS)))


def to_approval(row: dict[str, Any]) -> Approval | None:
    decision = normalize_decision(first(row, DECISION_KEYS))
    if not decision:
        return None
    source = normalize_source(first(row, SOURCE_KEYS))
    timestamp = _timestamp(row)
    tool_use_id = clean_token(row.get("tool_use_id"), "", max_spaces=0, max_len=80)
    if tool_use_id == "redacted":
        tool_use_id = ""
    return Approval(
        harness=_approval_harness(row),
        tool=_display_tool(row),
        decision=decision,
        source=source,
        group=SOURCE_GROUP.get(source, "unknown"),
        day=day_of(timestamp),
        timestamp=timestamp,
        tool_use_id=tool_use_id,
    )


def _usage_numbers(row: dict[str, Any]) -> dict[str, int | None]:
    parts = {key: nonneg(row.get(key)) for key in TOKEN_PARTS}
    total = nonneg(row.get("total_tokens"))
    tokens_col = nonneg(row.get("tokens"))
    if total is None:
        if tokens_col is not None:
            total = tokens_col
        elif any(value is not None for value in parts.values()):
            total = sum(value or 0 for value in parts.values())
    return {
        "input_tokens": parts["input_tokens"],
        "output_tokens": parts["output_tokens"],
        "cache_read_tokens": parts["cache_read_tokens"],
        "cache_write_tokens": parts["cache_write_tokens"],
        "total_tokens": total,
    }


def to_usage(row: dict[str, Any], *, cursor: bool) -> Usage | None:
    numbers = _usage_numbers(row)
    cost = nonneg(row.get("cost_cents")) if cursor else None
    if numbers["total_tokens"] is None and cost is None:
        return None
    if cursor:
        harness = "cursor"
        tool = clean_tool(row.get("kind") or row.get("tool") or "usage")
    else:
        harness = clean_harness(row.get("harness"), "unknown")
        tool = clean_tool(row.get("tool") or row.get("kind") or harness)
    timestamp = _timestamp(row)
    return Usage(
        harness=harness,
        tool=tool,
        model=clean_token(row.get("model"), "unknown", max_spaces=2),
        input_tokens=numbers["input_tokens"] or 0,
        output_tokens=numbers["output_tokens"] or 0,
        cache_read_tokens=numbers["cache_read_tokens"] or 0,
        cache_write_tokens=numbers["cache_write_tokens"] or 0,
        total_tokens=numbers["total_tokens"] or 0,
        cost_cents=cost,
        day=day_of(timestamp),
    )


def classify(row: dict[str, Any]) -> Approval | Usage | None:
    if is_tool_decision(row) or (is_approval_shape(row) and not is_cursor_usage(row)):
        return to_approval(row)
    if is_cursor_usage(row) or is_cursor_shape(row):
        return to_usage(row, cursor=True)
    if is_generic_usage(row):
        return to_usage(row, cursor=False)
    if is_approval_shape(row):
        return to_approval(row)
    return None


def _risky_family(tool: str) -> str | None:
    lowered = tool.lower()
    if lowered.startswith("mcp:"):
        return "mcp"
    for family, _fid, _cat, _label, names in RISKY_FAMILIES:
        if lowered in names:
            return family
    return None


def _span(items: list[Approval]) -> tuple[str, str]:
    stamps = sorted(item.timestamp for item in items if item.timestamp)
    if not stamps:
        return "", ""
    return stamps[0], stamps[-1]


def _finding(
    finding_id: str,
    severity: str,
    category: str,
    title: str,
    items: list[Approval],
    *,
    sample: str = "",
    tags: list[str],
) -> dict[str, Any]:
    first_seen, last_seen = _span(items)
    return make_finding(
        finding_id,
        severity,
        category,
        title,
        evidence_count=max(1, len(items)),
        first_seen=first_seen,
        last_seen=last_seen,
        sample_redacted=sample,
        tags=tags,
    )


def _build_findings(
    approvals: list[Approval],
    *,
    platform_detected: bool,
    inputs_failed: int,
    had_paths: bool,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if inputs_failed:
        findings.append(
            make_finding(
                "telemetry.import.unreadable",
                "low",
                "Telemetry Configuration",
                "A telemetry export path could not be read or parsed.",
                evidence_count=inputs_failed,
                tags=["otel_tool_decision"],
            )
        )
    if not platform_detected:
        title = (
            "No telemetry export provided. " + NOTE_NO_EXPORT
            if not had_paths
            else NOTE_UNREADABLE + " " + NOTE_NO_EXPORT
        )
        findings.append(
            make_finding(
                "telemetry.coverage.approvals_require_otel",
                "low",
                "Telemetry Configuration",
                title,
                tags=["otel_tool_decision", "coverage"],
            )
        )
        return findings

    accepts = [item for item in approvals if item.decision == "accept"]
    if not approvals:
        findings.append(
            make_finding(
                "telemetry.coverage.approvals_require_otel",
                "low",
                "Telemetry Configuration",
                "This export had no tool_decision events. " + NOTE_NO_EXPORT,
                tags=["otel_tool_decision", "coverage"],
            )
        )
        return findings

    findings.append(
        make_finding(
            "telemetry.coverage.approvals_require_otel",
            "low",
            "Telemetry Configuration",
            "Approve clicks are not in Claude Code transcripts. " + NOTE_IMPORTED,
            evidence_count=len(approvals),
            first_seen=_span(approvals)[0],
            last_seen=_span(approvals)[1],
            tags=["otel_tool_decision", "coverage"],
        )
    )

    config_accepts = [item for item in accepts if item.source == "config"]
    if accepts and len(config_accepts) * 2 >= len(accepts):
        percent = (100 * len(config_accepts)) // len(accepts)
        severity = "high" if len(accepts) >= 4 else "medium"
        findings.append(
            _finding(
                "telemetry.approval.blanket_allow_share",
                severity,
                "General Tooling",
                (
                    f"{percent}% of approvals came from config rules, "
                    "which apply without a prompt"
                ),
                config_accepts,
                sample="source=config",
                tags=["blanket_allow", "otel_tool_decision"],
            )
        )

    for family, finding_id, category, label, _names in RISKY_FAMILIES:
        matched = [
            item
            for item in accepts
            if item.source in {"config", "hook"} and _risky_family(item.tool) == family
        ]
        if not matched:
            continue
        tools = sorted({item.tool for item in matched})
        findings.append(
            _finding(
                finding_id,
                "high",
                category,
                f"{label} approved without a prompt",
                matched,
                sample=", ".join(tools[:5]),
                tags=["unprompted_approval", "otel_tool_decision"],
            )
        )
    return findings


def _group_rows(approvals: list[Approval]) -> list[dict[str, Any]]:
    counts: dict[str, dict[str, int]] = {
        group: {"approvals": 0, "denials": 0} for group in GROUP_ORDER
    }
    for item in approvals:
        bucket = counts.setdefault(item.group, {"approvals": 0, "denials": 0})
        if item.decision == "accept":
            bucket["approvals"] += 1
        else:
            bucket["denials"] += 1
    rows = []
    for group in GROUP_ORDER:
        bucket = counts.get(group) or {"approvals": 0, "denials": 0}
        if bucket["approvals"] or bucket["denials"]:
            rows.append({"group": group, **bucket})
    return rows


def _source_rows(approvals: list[Approval]) -> list[dict[str, Any]]:
    counts: dict[str, dict[str, int]] = defaultdict(lambda: {"approvals": 0, "denials": 0})
    for item in approvals:
        key = "approvals" if item.decision == "accept" else "denials"
        counts[item.source][key] += 1
    ordered = [source for source in SOURCE_ORDER if source in counts]
    ordered.extend(sorted(set(counts) - set(ordered)))
    return [
        {
            "source": source,
            "group": SOURCE_GROUP.get(source, "unknown"),
            "approvals": counts[source]["approvals"],
            "denials": counts[source]["denials"],
        }
        for source in ordered
    ]


def _tool_rows(approvals: list[Approval]) -> list[dict[str, Any]]:
    counts: dict[tuple[str, str], dict[str, int]] = defaultdict(
        lambda: {"approvals": 0, "denials": 0, "auto_approved": 0, "unprompted": 0}
    )
    for item in approvals:
        bucket = counts[(item.harness, item.tool)]
        if item.decision == "accept":
            bucket["approvals"] += 1
            if item.source == "config":
                bucket["auto_approved"] += 1
            if item.source in {"config", "hook"}:
                bucket["unprompted"] += 1
        else:
            bucket["denials"] += 1
    rows = [
        {"harness": harness, "tool": tool, **bucket}
        for (harness, tool), bucket in counts.items()
    ]
    rows.sort(key=lambda row: (-row["approvals"], -row["auto_approved"], row["tool"], row["harness"]))
    return rows


def _day_rows(approvals: list[Approval]) -> list[dict[str, Any]]:
    counts: dict[str, dict[str, int]] = defaultdict(lambda: {"approvals": 0, "denials": 0})
    for item in approvals:
        key = "approvals" if item.decision == "accept" else "denials"
        counts[item.day][key] += 1
    rows = [{"day": day, **bucket} for day, bucket in counts.items()]
    rows.sort(key=lambda row: (row["day"] == "unknown", row["day"]))
    return rows


def _top_auto(tool_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ranked = [row for row in tool_rows if row["auto_approved"]]
    ranked.sort(key=lambda row: (-row["auto_approved"], row["tool"], row["harness"]))
    return [
        {"tool": row["tool"], "harness": row["harness"], "count": row["auto_approved"]}
        for row in ranked[:8]
    ]


def _usage_rows(usages: list[Usage], *, by: str) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for item in usages:
        label = item.tool if by == "tool" else item.model
        key = (item.harness, label)
        bucket = groups.get(key)
        if bucket is None:
            bucket = {
                "harness": item.harness,
                by: label,
                "events": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "cache_read_tokens": 0,
                "cache_write_tokens": 0,
                "total_tokens": 0,
                "cost_cents": 0,
                "cost_rows": 0,
                "tokens_only_rows": 0,
            }
            groups[key] = bucket
        bucket["events"] += 1
        bucket["input_tokens"] += item.input_tokens
        bucket["output_tokens"] += item.output_tokens
        bucket["cache_read_tokens"] += item.cache_read_tokens
        bucket["cache_write_tokens"] += item.cache_write_tokens
        bucket["total_tokens"] += item.total_tokens
        if item.cost_cents is None:
            bucket["tokens_only_rows"] += 1
        else:
            bucket["cost_cents"] += item.cost_cents
            bucket["cost_rows"] += 1
    rows = []
    for bucket in groups.values():
        emitted = {
            "harness": bucket["harness"],
            by: bucket[by],
            "events": bucket["events"],
            "input_tokens": bucket["input_tokens"],
            "output_tokens": bucket["output_tokens"],
            "cache_read_tokens": bucket["cache_read_tokens"],
            "cache_write_tokens": bucket["cache_write_tokens"],
            "total_tokens": bucket["total_tokens"],
            "tokens_only_rows": bucket["tokens_only_rows"],
        }
        if bucket["cost_rows"]:
            emitted["cost_cents"] = bucket["cost_cents"]
            emitted["cost_basis"] = "cursor_dashboard"
            emitted["cost_label"] = COST_LABEL
        else:
            emitted["cost_basis"] = "tokens_only"
            emitted["cost_label"] = TOKENS_ONLY_LABEL
        rows.append(emitted)
    rows.sort(key=lambda row: (-row["total_tokens"], -row["events"], row[by], row["harness"]))
    return rows


def _dedupe_approvals(items: list[Approval]) -> list[Approval]:
    seen: set[str] = set()
    kept: list[Approval] = []
    for item in items:
        if not item.tool_use_id:
            kept.append(item)
            continue
        if item.tool_use_id in seen:
            continue
        seen.add(item.tool_use_id)
        kept.append(item)
    return kept


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
            handle.write("\n")


def _write_raw(
    raw_root: Path,
    approvals: list[Approval],
    usages: list[Usage],
) -> list[dict[str, str]]:
    pointers: list[dict[str, str]] = []
    folder = raw_root / "telemetry-import"
    if approvals:
        dest = folder / "decisions.jsonl"
        _write_jsonl(
            dest,
            [
                {
                    "day": item.day,
                    "decision": item.decision,
                    "group": item.group,
                    "harness": item.harness,
                    "source": item.source,
                    "timestamp": item.timestamp,
                    "tool": item.tool,
                }
                for item in approvals
            ],
        )
        pointers.append(
            {
                "kind": "telemetry_decisions",
                "path": "raw/telemetry-import/decisions.jsonl",
                "sha256": _file_sha256(dest),
            }
        )
    if usages:
        dest = folder / "usage.jsonl"
        _write_jsonl(
            dest,
            [
                {
                    "cache_read_tokens": item.cache_read_tokens,
                    "cache_write_tokens": item.cache_write_tokens,
                    "cost_basis": "cursor_dashboard" if item.cost_cents is not None else "tokens_only",
                    "cost_cents": item.cost_cents,
                    "day": item.day,
                    "harness": item.harness,
                    "input_tokens": item.input_tokens,
                    "model": item.model,
                    "output_tokens": item.output_tokens,
                    "tool": item.tool,
                    "total_tokens": item.total_tokens,
                }
                for item in usages
            ],
        )
        pointers.append(
            {
                "kind": "telemetry_usage",
                "path": "raw/telemetry-import/usage.jsonl",
                "sha256": _file_sha256(dest),
            }
        )
    return pointers


def _empty_summary(*, note: str, inputs_read: int, inputs_failed: int) -> dict[str, Any]:
    return {
        "status": "not_detected",
        "note": note,
        "inputs_read": inputs_read,
        "inputs_failed": inputs_failed,
        "approval_events": 0,
        "approvals": 0,
        "denials": 0,
        "usage_events": 0,
        "total_tokens": 0,
        "cost_basis": "none",
        "sensitive_attributes_dropped": 0,
    }


def collect(
    otel_files: list[str | Path] | None = None,
    splunk_files: list[str | Path] | None = None,
    *,
    raw_root: str | Path | None = None,
) -> dict[str, Any]:
    """Build the telemetry evidence envelope from local export files."""
    paths = [Path(path) for path in (otel_files or [])] + [
        Path(path) for path in (splunk_files or [])
    ]
    readable: list[Path] = []
    inputs_failed = 0
    stats = ParseStats()
    approvals: list[Approval] = []
    usages: list[Usage] = []

    for path in paths:
        try:
            rows, file_stats = load_export(path)
        except ExportReadError:
            inputs_failed += 1
            continue
        readable.append(path)
        stats.sensitive_dropped += file_stats.sensitive_dropped
        for row in rows:
            item = classify(row)
            if isinstance(item, Approval):
                approvals.append(item)
            elif isinstance(item, Usage):
                usages.append(item)

    approvals = _dedupe_approvals(approvals)
    platform_detected = bool(readable)
    scope_hash = compute_scope_hash(str(path) for path in readable)
    envelope = make_envelope(
        COLLECTOR,
        __version__,
        scope_hash,
        platform_detected=platform_detected,
    )
    findings = _build_findings(
        approvals,
        platform_detected=platform_detected,
        inputs_failed=inputs_failed,
        had_paths=bool(paths),
    )
    envelope["findings"] = findings
    envelope["rules"] = []

    if not platform_detected:
        note = NOTE_NO_EXPORT if not paths else NOTE_UNREADABLE
        envelope["summary"] = _empty_summary(
            note=note,
            inputs_read=0,
            inputs_failed=inputs_failed,
        )
        envelope["summary"]["sensitive_attributes_dropped"] = stats.sensitive_dropped
        return envelope

    tool_rows = _tool_rows(approvals)
    group_rows = _group_rows(approvals)
    accepts = [item for item in approvals if item.decision == "accept"]
    denials = [item for item in approvals if item.decision == "reject"]
    config_accepts = [item for item in accepts if item.source == "config"]
    cost_rows = [item for item in usages if item.cost_cents is not None]
    tokens_only_rows = [item for item in usages if item.cost_cents is None]
    cost_cents = sum(item.cost_cents or 0 for item in cost_rows)
    if cost_rows:
        cost_basis = "cursor_dashboard"
        cost_label = COST_LABEL
    elif usages:
        cost_basis = "tokens_only"
        cost_label = TOKENS_ONLY_LABEL
    else:
        cost_basis = "none"
        cost_label = TOKENS_ONLY_LABEL

    if approvals:
        note = NOTE_IMPORTED
    elif usages:
        note = NOTE_NO_DECISIONS
    else:
        note = NOTE_NO_DECISIONS

    summary: dict[str, Any] = {
        "status": "imported",
        "note": note,
        "inputs_read": len(readable),
        "inputs_failed": inputs_failed,
        "approval_events": len(approvals),
        "approvals": len(accepts),
        "denials": len(denials),
        "config_approvals": len(config_accepts),
        "user_approvals": sum(1 for item in accepts if item.group == "user"),
        "hook_approvals": sum(1 for item in accepts if item.group == "hook"),
        "config_approval_percent": (
            (100 * len(config_accepts)) // len(accepts) if accepts else 0
        ),
        "approvals_by_tool": tool_rows,
        "approvals_by_source": _source_rows(approvals),
        "approvals_by_group": group_rows,
        "approvals_by_day": _day_rows(approvals),
        "top_auto_approved": _top_auto(tool_rows),
        "usage_events": len(usages),
        "usage_rows_with_cost": len(cost_rows),
        "usage_rows_tokens_only": len(tokens_only_rows),
        "input_tokens": sum(item.input_tokens for item in usages),
        "output_tokens": sum(item.output_tokens for item in usages),
        "cache_read_tokens": sum(item.cache_read_tokens for item in usages),
        "cache_write_tokens": sum(item.cache_write_tokens for item in usages),
        "total_tokens": sum(item.total_tokens for item in usages),
        "cost_basis": cost_basis,
        "cost_label": cost_label,
        "usage_by_tool": _usage_rows(usages, by="tool"),
        "usage_by_model": _usage_rows(usages, by="model"),
        "sensitive_attributes_dropped": stats.sensitive_dropped,
    }
    if cost_rows:
        summary["cost_cents"] = cost_cents
    envelope["summary"] = summary

    if raw_root is not None:
        envelope["raw_pointers"] = _write_raw(Path(raw_root), approvals, usages)
    return envelope


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    evidence_root = validate_evidence_root(args.evidence_root)
    raw_root = None if args.dry_run else resolve_raw_root(evidence_root, args.raw_root)
    envelope = collect(args.otel_file or [], args.splunk_export or [], raw_root=raw_root)
    finish_collector(envelope, evidence_root, dry_run=args.dry_run)
    if not envelope["platform_detected"]:
        note = str((envelope.get("summary") or {}).get("note") or "not detected")
        print(note, file=sys.stderr)
        return 2
    return 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
