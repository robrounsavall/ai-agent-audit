"""Scan bundle: the one payload the hub stores.

A bundle is a scan folder's ``evidence/`` layer packed into one JSON object.
``build_bundle`` makes one from a scan folder. ``normalize_bundle`` is the
single gate every bundle passes before it reaches the database, whether it
came from a local folder or over HTTP. It is an allowlist: a field that is
not named here is dropped.

Two rules hold for every bundle:

- ``raw/`` is never read. ``raw_pointers`` and ``raw_evidence_ref`` are
  dropped. The SCHEMA.md contract says those never leave the machine.
- An envelope whose schema major version is not 1 is skipped, the same rule
  the briefing uses.

A share-safe bundle (``share_safe=True``) is what ``push`` sends to another
machine. Every free-text field is masked for secrets and paths on the way
out, whether or not the scan used ``-Redact``, and account emails become
``<email>``. A local ingest keeps the text the scan wrote, because the
database then sits on the same disk as the scan folder.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import hub_paths  # noqa: F401  (puts core/ on sys.path)

from common import mask_secrets, redact_paths, sha256_short

BUNDLE_VERSION = 1
SUPPORTED_MAJOR = 1

MAX_COLLECTORS = 64
MAX_FINDINGS = 5000
MAX_RULES = 20000
MAX_ROWS = 2000
MAX_DEPTH = 6

SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_HOST_RE = re.compile(r"[^A-Za-z0-9_.-]")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_HASHED_SCOPE_RE = re.compile(r"^[A-Za-z_]+#[0-9a-f]{12}$")

SEVERITIES = ("critical", "high", "medium", "low")

_FINDING_TEXT = {"title": 500, "sample_redacted": 2000}
_FINDING_PLAIN = {"id": 200, "severity": 16, "category": 64, "first_seen": 40, "last_seen": 40}
_RULE_TEXT = {"rule": 1000, "command_or_tool_redacted": 500, "settings_source": 300}
_RULE_PLAIN = {
    "platform": 32, "scope": 32, "rule_type": 32, "decision": 16, "risk": 16,
    "exposure_category": 64, "source_kind": 32, "confidence": 32,
}
_ACCOUNT_FIELDS = (
    "tool", "signed_in", "account", "organization", "plan", "auth_method",
    "source", "last_sign_in",
)
# Envelope keys beyond the base contract that SCHEMA.md marks take-home.
_EXTRA_LISTS = ("agents", "limits", "mcp_servers")


class BundleError(ValueError):
    """The payload is not a usable bundle. The message is safe to return."""


def to_utc(value: Any) -> str:
    """ISO 8601 in UTC with a Z suffix, or ``""`` when the value is not a time.

    One format for every stored time keeps string order equal to time order.
    A time with no offset is read as UTC.
    """
    if not isinstance(value, str) or not value.strip():
        return ""
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def scrub_text(text: str, *, keep_emails: bool = False, paths: bool = True) -> str:
    """Mask secrets, and optionally paths and emails, in one string."""
    out = redact_paths(text) if paths else text
    out = mask_secrets(out)
    if not keep_emails:
        out = _EMAIL_RE.sub("<email>", out)
    return out


def _clip(value: Any, limit: int) -> str:
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    return text[:limit]


def _int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _walk(value: Any, scrub: Callable[[str], str] | None, depth: int = 0) -> Any:
    """Copy JSON data with a depth cap, a row cap, and optional scrubbing."""
    if depth > MAX_DEPTH:
        return None
    if isinstance(value, str):
        text = value[:2000]
        return scrub(text) if scrub else text
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    if isinstance(value, list):
        return [_walk(item, scrub, depth + 1) for item in value[:MAX_ROWS]]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in list(value.items())[:MAX_ROWS]:
            if key in ("raw_pointers", "raw_evidence_ref"):
                continue
            out[_clip(key, 128)] = _walk(item, scrub, depth + 1)
        return out
    return None


def _clean_finding(item: Any, scrub: Callable[[str], str] | None) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    out: dict[str, Any] = {}
    for field, limit in _FINDING_PLAIN.items():
        out[field] = _clip(item.get(field), limit)
    for field, limit in _FINDING_TEXT.items():
        text = _clip(item.get(field), limit)
        out[field] = scrub(text) if scrub else text
    out["severity"] = out["severity"].strip().lower() or "low"
    count = item.get("evidence_count")
    out["evidence_count"] = 1 if count is None else max(_int(count, 1), 0)
    out["secret_redacted"] = bool(item.get("secret_redacted"))
    tags = item.get("tags")
    out["tags"] = [_clip(tag, 64) for tag in tags[:32] if isinstance(tag, str)] if isinstance(tags, list) else []
    if not out["id"] and not out["title"]:
        return None
    return out


def _clean_rule(item: Any, scrub: Callable[[str], str] | None) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    out: dict[str, Any] = {}
    for field, limit in _RULE_PLAIN.items():
        if field in item:
            out[field] = _clip(item.get(field), limit)
    for field, limit in _RULE_TEXT.items():
        if field in item:
            text = _clip(item.get(field), limit)
            out[field] = scrub(text) if scrub else text
    label = _clip(item.get("scope_label_redacted"), 200)
    if scrub and label and not _HASHED_SCOPE_RE.fullmatch(label):
        # An unredacted label is "<scope>:<last folder name>". That name can
        # be a project or a username, so a share-safe bundle hashes it.
        scope, _sep, name = label.partition(":")
        label = f"{scope or 'scope'}#{sha256_short(name or label)}"
    out["scope_label_redacted"] = label
    if "count" in item:
        out["count"] = max(_int(item.get("count"), 1), 1)
    if not out.get("rule"):
        return None
    return out


def _clean_account(item: Any, scrub: Callable[[str], str] | None) -> dict[str, str] | None:
    if not isinstance(item, dict):
        return None
    out = {}
    for field in _ACCOUNT_FIELDS:
        text = _clip(item.get(field), 300)
        out[field] = scrub(text) if scrub else text
    return out if out.get("tool") else None


def _version_major(value: Any) -> int | None:
    match = re.match(r"^\s*(\d+)\.", str(value or ""))
    return int(match.group(1)) if match else None


def _clean_envelope(
    name: str,
    env: Any,
    scrub: Callable[[str], str] | None,
    warnings: list[str],
) -> dict[str, Any] | None:
    if not isinstance(env, dict):
        warnings.append(f"{name}: not an envelope, skipped")
        return None
    major = _version_major(env.get("version"))
    if major != SUPPORTED_MAJOR:
        warnings.append(f"{name}: schema version {_clip(env.get('version'), 20) or 'missing'} is not supported, skipped")
        return None
    findings_in = env.get("findings") if isinstance(env.get("findings"), list) else []
    rules_in = env.get("rules") if isinstance(env.get("rules"), list) else []
    if len(findings_in) > MAX_FINDINGS:
        warnings.append(f"{name}: kept the first {MAX_FINDINGS} of {len(findings_in)} findings")
    if len(rules_in) > MAX_RULES:
        warnings.append(f"{name}: kept the first {MAX_RULES} of {len(rules_in)} rules")
    out: dict[str, Any] = {
        "collector": name,
        "version": _clip(env.get("version"), 32),
        "aiscan_version": _clip(env.get("aiscan_version"), 64),
        "ran_at": _clip(env.get("ran_at"), 40),
        "host": _HOST_RE.sub("_", _clip(env.get("host"), 64)),
        "platform_detected": bool(env.get("platform_detected")),
        "scope_hash": _clip(env.get("scope_hash"), 64),
        "summary": _walk(env.get("summary"), scrub) if isinstance(env.get("summary"), dict) else {},
        "findings": [f for f in (_clean_finding(i, scrub) for i in findings_in[:MAX_FINDINGS]) if f],
        "rules": [r for r in (_clean_rule(i, scrub) for i in rules_in[:MAX_RULES]) if r],
    }
    if isinstance(env.get("accounts"), list):
        out["accounts"] = [a for a in (_clean_account(i, scrub) for i in env["accounts"][:MAX_ROWS]) if a]
    for key in _EXTRA_LISTS:
        if isinstance(env.get(key), (list, dict)):
            out[key] = _walk(env[key], scrub)
    return out


def normalize_bundle(
    bundle: Any,
    *,
    share_safe: bool = False,
    keep_emails: bool = False,
    scrub_paths: bool = True,
) -> tuple[dict[str, Any], list[str]]:
    """Validate a bundle and return ``(clean copy, warnings)``.

    ``share_safe`` masks every free-text field. The sender calls it with
    ``scrub_paths=True``, where the running user's profile is the one in the
    evidence. The receiving server calls it again with ``scrub_paths=False``
    as a backstop: secrets are masked a second time, and the server's own
    username is not searched for in someone else's text.
    """
    if not isinstance(bundle, dict):
        raise BundleError("bundle must be a JSON object")
    if bundle.get("bundle_version") != BUNDLE_VERSION:
        raise BundleError(f"unsupported bundle_version (this hub reads {BUNDLE_VERSION})")
    collectors_in = bundle.get("collectors")
    if not isinstance(collectors_in, dict) or not collectors_in:
        raise BundleError("bundle has no collectors")
    if len(collectors_in) > MAX_COLLECTORS:
        raise BundleError("too many collectors in one bundle")

    scrub: Callable[[str], str] | None = None
    if share_safe:
        def scrub(text: str) -> str:
            return scrub_text(text, keep_emails=keep_emails, paths=scrub_paths)

    warnings: list[str] = []
    collectors: dict[str, dict[str, Any]] = {}
    for name in sorted(collectors_in, key=str):
        if not isinstance(name, str) or not SAFE_NAME.fullmatch(name):
            warnings.append("a collector with an unsafe name was skipped")
            continue
        clean = _clean_envelope(name, collectors_in[name], scrub, warnings)
        if clean is not None:
            collectors[name] = clean
    if not collectors:
        raise BundleError("no readable collector envelopes (schema major 1) in bundle")

    host = _HOST_RE.sub("_", _clip(bundle.get("host"), 64))
    if not host:
        hosts = [env["host"] for env in collectors.values() if env["host"]]
        host = max(set(hosts), key=hosts.count) if hosts else "unknown"

    origin_in = bundle.get("run_origin") if isinstance(bundle.get("run_origin"), dict) else {}
    # run_origin.py already masks these two fields on every scan. Masking
    # again costs nothing and covers a hand-built bundle.
    origin = {
        "launched_by": scrub_text(_clip(origin_in.get("launched_by"), 120), keep_emails=not share_safe, paths=False) or "unknown",
        "started": _clip(origin_in.get("started"), 40) or "unknown",
        "reason": scrub_text(_clip(origin_in.get("reason"), 120), keep_emails=not share_safe, paths=False) or "unknown",
    }

    status_in = bundle.get("collector_status") if isinstance(bundle.get("collector_status"), dict) else {}
    status = {
        name: _clip(value, 40)
        for name, value in status_in.items()
        if isinstance(name, str) and SAFE_NAME.fullmatch(name)
    }
    errors_in = bundle.get("collector_errors") if isinstance(bundle.get("collector_errors"), list) else []
    errors = []
    for row in errors_in[:MAX_COLLECTORS]:
        if isinstance(row, dict) and isinstance(row.get("collector"), str) and SAFE_NAME.fullmatch(row["collector"]):
            errors.append({
                "collector": row["collector"],
                "detection_status": _clip(row.get("detection_status"), 40),
            })

    label = _clip(bundle.get("source_label"), 120)
    clean = {
        "bundle_version": BUNDLE_VERSION,
        "share_safe": bool(share_safe or bundle.get("share_safe")),
        "created_at": to_utc(bundle.get("created_at")) or now_utc(),
        "source_label": scrub_text(label, paths=False) if share_safe else label,
        "host": host,
        "aiscan_version": _clip(bundle.get("aiscan_version"), 64),
        "run_origin": origin,
        "collector_status": status,
        "collector_errors": errors,
        "collectors": collectors,
    }
    return clean, warnings


def scan_uid(bundle: dict[str, Any]) -> str:
    """Stable id for a normalized bundle. The same scan ingested twice matches."""
    payload = json.dumps(
        {"host": bundle.get("host"), "collectors": bundle.get("collectors")},
        sort_keys=True, ensure_ascii=False, separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def is_scan_folder(path: str | Path) -> bool:
    return (Path(path) / "evidence").is_dir()


def build_bundle(
    scan_root: str | Path,
    *,
    share_safe: bool = False,
    keep_emails: bool = False,
) -> tuple[dict[str, Any], list[str]]:
    """Pack ``<scan_root>/evidence`` into a normalized bundle.

    Reads ``evidence/*.json`` and ``run-origin.txt`` only. ``raw/`` and
    ``briefing/`` are not opened.
    """
    import agent_summary
    import run_origin
    import scan_diff

    root = Path(scan_root)
    if not is_scan_folder(root):
        raise BundleError("not a scan folder (expected an evidence directory)")
    envelopes = scan_diff.load_scan(root)
    if not envelopes:
        raise BundleError("no collector evidence in this scan folder")

    summary = agent_summary.build_agent_summary(root)
    alias = scan_diff.LEGACY_COLLECTOR_ALIASES
    status: dict[str, str] = {}
    for row in summary.get("collectors") or []:
        name = alias.get(row.get("collector"), row.get("collector"))
        if name not in status or row.get("collector") == name:
            status[name] = row.get("detection_status") or ""
    errors = [
        {"collector": alias.get(row.get("collector"), row.get("collector")),
         "detection_status": row.get("detection_status") or "error"}
        for row in summary.get("collector_errors") or []
    ]
    for row in errors:
        status[row["collector"]] = row["detection_status"]

    versions = [env.get("aiscan_version") for env in envelopes.values() if env.get("aiscan_version")]
    raw = {
        "bundle_version": BUNDLE_VERSION,
        "created_at": now_utc(),
        "source_label": root.resolve().name,
        "host": scan_diff._host_for(envelopes) if envelopes else "",
        "aiscan_version": versions[0] if versions else "",
        "run_origin": run_origin.load_run_origin(root),
        "collector_status": status,
        "collector_errors": errors,
        "collectors": envelopes,
    }
    return normalize_bundle(raw, share_safe=share_safe, keep_emails=keep_emails)
