#!/usr/bin/env python3
"""
Scan-to-scan change tracking for aiscan evidence.

Compares two evidence roots (each a folder that contains ``evidence/*.json``)
and writes ``<current>/evidence/changes.json``. The file is a normal collector
envelope (``collector`` = ``changes``) plus a ``changes`` object that holds the
per-collector diff.

History is just a directory of past scan folders. When ``--previous`` is
omitted, the most recent sibling folder under ``--history-root`` (default: the
parent of ``--current``) is chosen by the latest ``ran_at`` strictly before
the current scan. ``changes.json`` is never used as a timestamp source.

A collector that used to report data and now reports nothing, or is no longer
detected, is flagged as possible data-location drift. A collector version
change is a separate drift warning. An empty result is not treated as clean.

Public entry points for the integration step
--------------------------------------------
``run(current_root, previous_root=None, history_root=None, dry_run=False)``
    Resolve the previous scan if needed, build the envelope, and write
    ``evidence/changes.json`` unless ``dry_run`` is set. Returns the envelope.

``main(argv=None)``
    CLI. Exit 0 on success, 1 on a bad path.

``build_changes_envelope(current_root, previous_root=None)``
    Build the envelope without writing. ``previous_root=None`` is a first scan.
    A previous root that exists but has no collectors is a real diff against
    an empty scan.

``resolve_previous(current_root, history_root=None)``
    Pick the previous scan folder, or None.

``load_scan(root)``
    Load ``evidence/*.json`` except ``changes.json``. Keyed by collector name.

``load_changes_envelope(evidence_root)``
    Read ``evidence/changes.json``, or None.

``diff_envelopes(current, previous, *, current_label="", previous_label="")``
    Pure diff. ``previous is None`` means first scan; ``previous == {}`` means
    an empty previous scan.

HTML (separate module, so this file stays stdlib-only and report-free):
``report/sections/changes.py``
    ``render_changes_section(env)`` and ``render_changes_nav(env)``.

The briefing loader reads every ``evidence/*.json`` with major version 1.
Until the section is wired in, that loop should skip collector ``changes``
so the diff is not rendered as another tool.

CLI
---
    python core/scan_diff.py --current <evidence root> [--previous <root>]
        [--history-root <dir>] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from common import (
    hostname_short,
    load_json,
    make_envelope,
    make_finding,
    sanitize_text,
    sha256_full,
    write_evidence,
)

COLLECTOR = "changes"
VERSION = "1.0.0"
CHANGES_FILENAME = "changes.json"

# Summary numbers that describe observed data, as opposed to how hard the
# collector looked (keys_scanned, targets, and similar).
_DATA_HINTS = (
    "message",
    "token",
    "agent",
    "session",
    "transcript",
    "composer",
    "hit",
    "rule",
    "finding",
    "mcp",
    "event",
    "repo",
    "file",
    "byte",
    "bubble",
    "chat",
    "tool",
    "secret",
)
_EFFORT_HINTS = ("scanned", "searched", "roots_checked", "targets", "cap_minutes")
_SKIP_SUMMARY_KEYS = {"discovery", "history_roots", "capabilities"}

_SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_HIGH_SEVS = {"high", "critical"}

_RULE_FIELDS = (
    "platform",
    "scope",
    "scope_label_redacted",
    "rule_type",
    "rule",
    "decision",
    "command_or_tool_redacted",
    "risk",
    "exposure_category",
)


def load_scan(root: str | Path) -> dict[str, dict[str, Any]]:
    """Load collector envelopes from ``<root>/evidence``, skipping changes.json."""
    evidence = Path(root) / "evidence"
    envelopes: dict[str, dict[str, Any]] = {}
    if not evidence.is_dir():
        return envelopes
    for path in sorted(evidence.glob("*.json")):
        if path.name == CHANGES_FILENAME or path.stem == COLLECTOR:
            continue
        data = load_json(path)
        if not isinstance(data, dict):
            continue
        name = str(data.get("collector") or path.stem)
        if name == COLLECTOR:
            continue
        envelopes[name] = data
    return envelopes


def load_changes_envelope(evidence_root: str | Path) -> dict[str, Any] | None:
    """Return the changes envelope if it has been written, else None."""
    path = Path(evidence_root) / "evidence" / CHANGES_FILENAME
    if not path.is_file():
        return None
    data = load_json(path)
    return data if isinstance(data, dict) else None


def _parse_ran_at(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _latest_ran_at(envelopes: dict[str, dict[str, Any]]) -> tuple[datetime | None, str]:
    best: datetime | None = None
    raw = ""
    for env in envelopes.values():
        text = env.get("ran_at")
        parsed = _parse_ran_at(text)
        if parsed is None:
            continue
        if best is None or parsed > best:
            best = parsed
            raw = str(text)
    return best, raw


def resolve_previous(
    current_root: str | Path,
    history_root: str | Path | None = None,
) -> Path | None:
    """Pick the newest sibling scan whose ``ran_at`` is strictly earlier.

    ``history_root`` defaults to the parent of ``current_root``. Folders
    without collector evidence are ignored. A sibling whose latest ``ran_at``
    is the same as or later than the current scan is ignored, so a newer
    folder sitting next to an older re-diff is not treated as the baseline.
    """
    current_resolved = Path(current_root).resolve()
    history = Path(history_root).resolve() if history_root else current_resolved.parent
    if not history.is_dir():
        return None
    current_when, _current_raw = _latest_ran_at(load_scan(current_resolved))
    best: tuple[datetime, str, Path] | None = None
    try:
        children = list(history.iterdir())
    except OSError:
        return None
    for child in children:
        if not child.is_dir():
            continue
        try:
            resolved = child.resolve()
        except OSError:
            continue
        if resolved == current_resolved:
            continue
        when, _raw = _latest_ran_at(load_scan(resolved))
        if when is None:
            continue
        if current_when is not None and when >= current_when:
            continue
        candidate = (when, child.name, resolved)
        if best is None or (candidate[0], candidate[1]) > (best[0], best[1]):
            best = candidate
    return best[2] if best else None


def _as_dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _finding_index(env: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not env:
        return {}
    indexed: dict[str, dict[str, Any]] = {}
    for finding in _as_dict_list(env.get("findings")):
        finding_id = str(finding.get("id") or "").strip()
        if finding_id:
            indexed[finding_id] = finding
    return indexed


def _rules_of(env: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not env:
        return []
    return _as_dict_list(env.get("rules"))


def _rule_key(rule: dict[str, Any]) -> tuple[str, ...]:
    return tuple(str(rule.get(field) or "") for field in (
        "platform",
        "scope",
        "scope_label_redacted",
        "rule_type",
        "rule",
        "decision",
    ))


def _rule_public(rule: dict[str, Any]) -> dict[str, Any]:
    public: dict[str, Any] = {}
    for field in _RULE_FIELDS:
        if field in rule:
            public[field] = rule.get(field)
    return public


def _multiset_diff(
    previous: list[dict[str, Any]],
    current: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    prev_counts: Counter[tuple[str, ...]] = Counter(_rule_key(rule) for rule in previous)
    curr_counts: Counter[tuple[str, ...]] = Counter(_rule_key(rule) for rule in current)
    prev_sample = {_rule_key(rule): rule for rule in previous}
    curr_sample = {_rule_key(rule): rule for rule in current}
    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    for key in sorted(set(prev_counts) | set(curr_counts)):
        extra_now = curr_counts.get(key, 0) - prev_counts.get(key, 0)
        extra_then = prev_counts.get(key, 0) - curr_counts.get(key, 0)
        if extra_now > 0:
            item = _rule_public(curr_sample[key])
            if extra_now > 1:
                item["count"] = extra_now
            added.append(item)
        if extra_then > 0:
            item = _rule_public(prev_sample[key])
            if extra_then > 1:
                item["count"] = extra_then
            removed.append(item)
    return added, removed


def _server_from_rule(rule: dict[str, Any]) -> str:
    text = str(rule.get("rule") or "")
    if text.lower().startswith("mcp__"):
        parts = text.split("__")
        if len(parts) >= 2 and parts[1].strip():
            return parts[1].strip()
    tool = str(rule.get("command_or_tool_redacted") or "").strip()
    if tool and tool.lower() not in {"*", "mcp"}:
        return tool
    return ""


def _add_server_name(names: dict[str, str], raw: Any) -> None:
    if not isinstance(raw, str):
        return
    display = raw.strip()
    if not display or len(display) > 128:
        return
    names.setdefault(display.casefold(), display)


def mcp_server_names(env: dict[str, Any] | None) -> dict[str, str]:
    """Map case-folded server name to the display form seen in evidence.

    Names come from ``mcp_tool`` rules, a ``mcp_servers`` list or map on the
    summary or envelope, and ``summary.mcp_runtime_transports`` keys. A bare
    integer ``mcp_servers`` count is not a name list; that count is handled
    with the other summary counters.
    """
    names: dict[str, str] = {}
    if not env:
        return names
    for rule in _rules_of(env):
        if str(rule.get("rule_type") or "") != "mcp_tool":
            continue
        _add_server_name(names, _server_from_rule(rule))
    blobs: list[Any] = []
    summary = env.get("summary")
    if isinstance(summary, dict):
        blobs.append(summary.get("mcp_servers"))
        blobs.append(summary.get("mcp_server_names"))
        transports = summary.get("mcp_runtime_transports")
        if isinstance(transports, dict):
            for key in transports:
                _add_server_name(names, str(key))
    blobs.append(env.get("mcp_servers"))
    for blob in blobs:
        if isinstance(blob, list):
            for item in blob:
                if isinstance(item, str):
                    _add_server_name(names, item)
                elif isinstance(item, dict):
                    _add_server_name(names, item.get("name") or item.get("server"))
        elif isinstance(blob, dict):
            # A count is an int. A map of server configs is a dict of dicts
            # or strings, and its keys are the server names.
            if blob and all(isinstance(v, (dict, str, type(None))) for v in blob.values()):
                for key in blob:
                    _add_server_name(names, str(key))
    return names


def numeric_counters(summary: Any) -> dict[str, int | float]:
    """Flatten numeric summary fields one level (``messages``, ``model.gpt``)."""
    if not isinstance(summary, dict):
        return {}
    out: dict[str, int | float] = {}
    for key, value in summary.items():
        if str(key) in _SKIP_SUMMARY_KEYS:
            continue
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            out[str(key)] = value
            continue
        if isinstance(value, dict):
            for sub, subval in value.items():
                if isinstance(subval, bool) or not isinstance(subval, (int, float)):
                    continue
                sub_name = str(sub)
                if not sub_name or len(sub_name) > 64:
                    continue
                out[f"{key}.{sub_name}"] = subval
    return out


def _is_data_counter(key: str) -> bool:
    low = key.lower()
    if any(hint in low for hint in _EFFORT_HINTS):
        return False
    return any(hint in low for hint in _DATA_HINTS)


def _positive_data_counters(env: dict[str, Any]) -> dict[str, float]:
    return {
        key: float(value)
        for key, value in numeric_counters(env.get("summary")).items()
        if _is_data_counter(key) and float(value) > 0
    }


def _has_named_records(env: dict[str, Any] | None) -> bool:
    if not env:
        return False
    return bool(_finding_index(env) or _rules_of(env) or mcp_server_names(env))


def _had_observed_data(env: dict[str, Any] | None) -> bool:
    if not env or not bool(env.get("platform_detected", True)):
        return False
    if _has_named_records(env):
        return True
    return bool(_positive_data_counters(env))


def _location_drift_kind(
    previous: dict[str, Any] | None,
    current: dict[str, Any] | None,
) -> str | None:
    """``not_detected``, ``data_to_zero``, or None.

    Drift means the collector previously had findings, rules, named MCP
    servers, or a positive data counter, and this scan either does not detect
    the platform or reports none of that data. Bookkeeping counters such as
    ``keys_scanned`` can stay non-zero; they do not count as the data still
    being there. Named MCP servers that are still present mean the collector
    found something, so a token counter dropping to zero on its own is a
    counter change, not a wipe.
    """
    if not _had_observed_data(previous):
        return None
    detected = current is not None and bool(current.get("platform_detected", True))
    if not detected:
        return "not_detected"
    # `detected` is true only when current is an envelope, so this is a dict.
    current_env = current or {}
    if _has_named_records(current_env):
        return None
    previous_positive = _positive_data_counters(previous or {})
    current_numbers = numeric_counters(current_env.get("summary"))
    if previous_positive and not all(
        float(current_numbers.get(key) or 0) == 0 for key in previous_positive
    ):
        return None
    return "data_to_zero"


def _counter_moved(before: Any, after: Any) -> bool:
    if before == after:
        return False
    before_empty = before is None or before == 0
    after_empty = after is None or after == 0
    if before_empty and after_empty:
        return False
    return True


def _finding_brief(finding: dict[str, Any]) -> dict[str, str]:
    return {
        "id": str(finding.get("id") or ""),
        "severity": str(finding.get("severity") or "low").lower(),
        "title": str(finding.get("title") or ""),
        "category": str(finding.get("category") or ""),
    }


def _safe_id(prefix: str, collector: str, suffix: str) -> str:
    raw = f"{prefix}.{collector}.{suffix}"
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("._")
    return (safe or "changes.item")[:180]


def _severity_or(value: Any, default: str = "medium") -> str:
    text = str(value or "").lower()
    if text in _SEV_RANK:
        return text
    return default


def _diff_collector(
    name: str,
    previous: dict[str, Any] | None,
    current: dict[str, Any] | None,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    prev_findings = _finding_index(previous)
    curr_findings = _finding_index(current)
    added_findings = [
        _finding_brief(curr_findings[fid])
        for fid in sorted(curr_findings)
        if fid not in prev_findings
    ]
    resolved_findings = [
        _finding_brief(prev_findings[fid])
        for fid in sorted(prev_findings)
        if fid not in curr_findings
    ]
    severity_changed: list[dict[str, str]] = []
    for fid in sorted(curr_findings):
        if fid not in prev_findings:
            continue
        before = _severity_or(prev_findings[fid].get("severity"), "low")
        after = _severity_or(curr_findings[fid].get("severity"), "low")
        if before == after:
            continue
        severity_changed.append({
            "id": fid,
            "title": str(curr_findings[fid].get("title") or ""),
            "category": str(curr_findings[fid].get("category") or ""),
            "before": before,
            "after": after,
        })

    prev_rules = _rules_of(previous)
    curr_rules = _rules_of(current)
    rules_added, rules_removed = _multiset_diff(prev_rules, curr_rules)
    allow_added, allow_removed = _multiset_diff(
        [rule for rule in prev_rules if str(rule.get("decision") or "").lower() == "allow"],
        [rule for rule in curr_rules if str(rule.get("decision") or "").lower() == "allow"],
    )

    prev_mcp = mcp_server_names(previous)
    curr_mcp = mcp_server_names(current)
    mcp_added = [curr_mcp[key] for key in sorted(curr_mcp) if key not in prev_mcp]
    mcp_removed = [prev_mcp[key] for key in sorted(prev_mcp) if key not in curr_mcp]

    prev_numbers = numeric_counters(previous.get("summary")) if previous else {}
    curr_numbers = numeric_counters(current.get("summary")) if current else {}
    counters: list[dict[str, Any]] = []
    for key in sorted(set(prev_numbers) | set(curr_numbers)):
        before = prev_numbers.get(key)
        after = curr_numbers.get(key)
        if not _counter_moved(before, after):
            continue
        counters.append({"key": key, "before": before, "after": after})

    prev_detected = None if previous is None else bool(previous.get("platform_detected", True))
    curr_detected = None if current is None else bool(current.get("platform_detected", True))
    if curr_detected is True and prev_detected is not True:
        platform_change = "newly_detected"
    elif prev_detected is True and curr_detected is not True:
        platform_change = "no_longer_detected"
    else:
        platform_change = "unchanged"

    prev_version = None if previous is None else str(previous.get("version") or "")
    curr_version = None if current is None else str(current.get("version") or "")
    version_changed = (
        previous is not None
        and current is not None
        and prev_version != curr_version
    )

    drift: list[dict[str, str]] = []
    location_kind = _location_drift_kind(previous, current)
    if location_kind == "not_detected":
        if current is None:
            detail = f"{name} evidence was present last scan and is missing now"
        else:
            detail = f"{name} platform_detected went from true to false"
        drift.append({"kind": "not_detected", "detail": detail})
    elif location_kind == "data_to_zero":
        dropped = sorted(_positive_data_counters(previous or {}))[:8]
        if dropped:
            detail = (
                f"{name} previously reported data ({', '.join(dropped)}) "
                "and now reports none"
            )
        else:
            detail = f"{name} previously reported findings or rules and now reports none"
        drift.append({"kind": "data_to_zero", "detail": detail})
    if version_changed:
        drift.append({
            "kind": "version_changed",
            "detail": f"{name} collector version {prev_version} -> {curr_version}",
        })

    entry = {
        "platform": {
            "previous_detected": prev_detected,
            "current_detected": curr_detected,
            "change": platform_change,
        },
        "version": {
            "previous": prev_version,
            "current": curr_version,
            "changed": version_changed,
        },
        "findings": {
            "added": added_findings,
            "resolved": resolved_findings,
            "severity_changed": severity_changed,
        },
        "rules": {"added": rules_added, "removed": rules_removed},
        "allow_rules": {"added": allow_added, "removed": allow_removed},
        "mcp_servers": {"added": mcp_added, "removed": mcp_removed},
        "counters": counters,
        "drift": drift,
    }
    changed = any((
        platform_change != "unchanged",
        version_changed,
        added_findings,
        resolved_findings,
        severity_changed,
        rules_added,
        rules_removed,
        allow_added,
        allow_removed,
        mcp_added,
        mcp_removed,
        counters,
        drift,
    ))
    if not changed:
        return None, []

    findings: list[dict[str, Any]] = []
    for item in added_findings:
        if item["severity"] not in _HIGH_SEVS:
            continue
        findings.append(make_finding(
            _safe_id("changes.finding.new", name, item["id"]),
            item["severity"],
            item["category"] or "General Tooling",
            sanitize_text(f"New {item['severity']} finding in {name}: {item['title']}"),
            sample_redacted=f"id={item['id']}",
            tags=["new_high_finding"],
        ))
    for item in severity_changed:
        before_rank = _SEV_RANK.get(item["before"], 0)
        after_rank = _SEV_RANK.get(item["after"], 0)
        if item["after"] not in _HIGH_SEVS or after_rank <= before_rank:
            continue
        findings.append(make_finding(
            _safe_id("changes.finding.escalated", name, item["id"]),
            item["after"],
            item["category"] or "General Tooling",
            sanitize_text(
                f"Finding in {name} rose from {item['before']} to {item['after']}: {item['title']}"
            ),
            sample_redacted=f"id={item['id']}; {item['before']} -> {item['after']}",
            tags=["new_high_finding", "severity_escalated"],
        ))
    for server in mcp_added:
        findings.append(make_finding(
            _safe_id("changes.mcp.added", name, server),
            "medium",
            "MCP Tooling",
            sanitize_text(f"New MCP server on {name}: {server}"),
            sample_redacted=server,
            tags=["new_mcp_server"],
        ))
    for rule in allow_added:
        if str(rule.get("rule_type") or "") == "mcp_tool":
            continue
        rule_text = str(rule.get("rule") or "")
        risk = _severity_or(rule.get("risk"), "medium")
        category = str(rule.get("exposure_category") or "General Tooling")
        findings.append(make_finding(
            _safe_id("changes.allow.added", name, sha256_full(rule_text or name)[:12]),
            risk,
            category,
            sanitize_text(f"New allow rule on {name}"),
            sample_redacted=rule_text or "(empty rule)",
            tags=["new_allow_rule"],
        ))
    for item in drift:
        if item["kind"] == "version_changed":
            findings.append(make_finding(
                _safe_id("changes.drift", name, item["kind"]),
                "medium",
                "Cross-Agent Visibility",
                sanitize_text(f"Collector version changed for {name}"),
                sample_redacted=item["detail"],
                tags=["collector_version_changed"],
            ))
        else:
            findings.append(make_finding(
                _safe_id("changes.drift", name, item["kind"]),
                "high",
                "Cross-Agent Visibility",
                sanitize_text(f"Possible data-location drift in {name}"),
                sample_redacted=item["detail"],
                tags=["data_location_drift"],
            ))
    return entry, findings


def _host_for(envelopes: dict[str, dict[str, Any]]) -> str:
    hosts = []
    for env in envelopes.values():
        host = env.get("host")
        if isinstance(host, str) and host.strip():
            hosts.append(host.strip())
    if hosts and all(host == hosts[0] for host in hosts):
        return hosts[0]
    return hostname_short()


def _count_rules(collectors: dict[str, dict[str, Any]], bucket: str, side: str) -> int:
    total = 0
    for entry in collectors.values():
        for item in entry[bucket][side]:
            total += int(item.get("count") or 1)
    return total


def diff_envelopes(
    current: dict[str, dict[str, Any]],
    previous: dict[str, dict[str, Any]] | None,
    *,
    current_label: str = "",
    previous_label: str = "",
) -> dict[str, Any]:
    """Build a changes envelope from in-memory collector maps.

    ``previous is None`` records a first scan and does not invent a diff.
    An empty dict is a previous scan that contained no collectors.
    """
    current = {
        name: env
        for name, env in current.items()
        if name != COLLECTOR and isinstance(env, dict)
    }
    if previous is not None:
        previous = {
            name: env
            for name, env in previous.items()
            if name != COLLECTOR and isinstance(env, dict)
        }
    _current_when, current_ran = _latest_ran_at(current)
    previous_ran = ""
    if previous is not None:
        _previous_when, previous_ran = _latest_ran_at(previous)

    names = sorted(set(current) | (set(previous) if previous is not None else set()))
    scope_hash = sha256_full("\n".join([current_label, previous_label, *names]))
    envelope = make_envelope(
        COLLECTOR,
        VERSION,
        scope_hash,
        platform_detected=True,
        host=_host_for(current or (previous or {})),
    )
    changes_body: dict[str, Any] = {
        "current_label": current_label,
        "previous_label": previous_label,
        "current_ran_at": current_ran,
        "previous_ran_at": previous_ran,
        "collectors": {},
    }
    if previous is None:
        envelope["summary"] = {
            "comparison": "first_scan",
            "current_label": current_label,
            "previous_label": "",
            "current_ran_at": current_ran,
            "previous_ran_at": "",
            "collectors_compared": len(current),
            "collectors_changed": 0,
            "platforms_newly_detected": 0,
            "platforms_no_longer_detected": 0,
            "findings_added": 0,
            "findings_resolved": 0,
            "findings_severity_changed": 0,
            "rules_added": 0,
            "rules_removed": 0,
            "allow_rules_added": 0,
            "allow_rules_removed": 0,
            "mcp_servers_added": 0,
            "mcp_servers_removed": 0,
            "counters_moved": 0,
            "drift_warnings": 0,
            "new_high_or_critical": 0,
        }
        envelope["findings"] = []
        envelope["changes"] = changes_body
        return envelope

    collectors: dict[str, dict[str, Any]] = {}
    findings: list[dict[str, Any]] = []
    for name in names:
        entry, entry_findings = _diff_collector(
            name,
            previous.get(name),
            current.get(name),
        )
        if entry is None:
            continue
        collectors[name] = entry
        findings.extend(entry_findings)
    findings.sort(key=lambda item: (
        _SEV_RANK.get(str(item.get("severity") or ""), 9),
        str(item.get("id") or ""),
    ))
    changes_body["collectors"] = collectors

    def _platform_count(kind: str) -> int:
        return sum(1 for entry in collectors.values() if entry["platform"]["change"] == kind)

    new_high = sum(
        1
        for finding in findings
        if "new_high_finding" in (finding.get("tags") or [])
    )
    envelope["summary"] = {
        "comparison": "diff",
        "current_label": current_label,
        "previous_label": previous_label,
        "current_ran_at": current_ran,
        "previous_ran_at": previous_ran,
        "collectors_compared": len(names),
        "collectors_changed": len(collectors),
        "platforms_newly_detected": _platform_count("newly_detected"),
        "platforms_no_longer_detected": _platform_count("no_longer_detected"),
        "findings_added": sum(len(entry["findings"]["added"]) for entry in collectors.values()),
        "findings_resolved": sum(
            len(entry["findings"]["resolved"]) for entry in collectors.values()
        ),
        "findings_severity_changed": sum(
            len(entry["findings"]["severity_changed"]) for entry in collectors.values()
        ),
        "rules_added": _count_rules(collectors, "rules", "added"),
        "rules_removed": _count_rules(collectors, "rules", "removed"),
        "allow_rules_added": _count_rules(collectors, "allow_rules", "added"),
        "allow_rules_removed": _count_rules(collectors, "allow_rules", "removed"),
        "mcp_servers_added": sum(
            len(entry["mcp_servers"]["added"]) for entry in collectors.values()
        ),
        "mcp_servers_removed": sum(
            len(entry["mcp_servers"]["removed"]) for entry in collectors.values()
        ),
        "counters_moved": sum(len(entry["counters"]) for entry in collectors.values()),
        "drift_warnings": sum(len(entry["drift"]) for entry in collectors.values()),
        "new_high_or_critical": new_high,
    }
    envelope["findings"] = findings
    envelope["changes"] = changes_body
    return envelope


def build_changes_envelope(
    current_root: str | Path,
    previous_root: str | Path | None = None,
) -> dict[str, Any]:
    """Load one or two evidence roots and return the changes envelope.

    Does not write. Pass ``previous_root=None`` for a first scan.
    """
    current_path = Path(current_root)
    current = load_scan(current_path)
    if previous_root is None:
        return diff_envelopes(
            current,
            None,
            current_label=current_path.name,
            previous_label="",
        )
    previous_path = Path(previous_root)
    return diff_envelopes(
        current,
        load_scan(previous_path),
        current_label=current_path.name,
        previous_label=previous_path.name,
    )


def run(
    current_root: str | Path,
    previous_root: str | Path | None = None,
    history_root: str | Path | None = None,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Resolve, diff, and write ``evidence/changes.json`` unless ``dry_run``."""
    current_path = Path(current_root)
    if previous_root is None:
        resolved = resolve_previous(current_path, history_root)
    else:
        resolved = Path(previous_root)
    envelope = build_changes_envelope(current_path, resolved)
    if not dry_run:
        write_evidence(envelope, current_path)
    return envelope


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Diff two aiscan evidence roots and write evidence/changes.json.",
    )
    parser.add_argument(
        "--current",
        required=True,
        help="Evidence root for the scan just completed (the folder that contains evidence/)",
    )
    parser.add_argument(
        "--previous",
        default=None,
        help="Evidence root for the prior scan. If omitted, pick the latest earlier sibling under --history-root",
    )
    parser.add_argument(
        "--history-root",
        default=None,
        help="Directory of dated scan folders. Default: the parent of --current. Ignored when --previous is set",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the changes envelope and do not write it",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    current = Path(args.current)
    if not current.is_dir():
        print(f"Error: --current does not exist: {current}", file=sys.stderr)
        return 1
    if not (current / "evidence").is_dir():
        print(f"Error: no evidence directory under --current: {current}", file=sys.stderr)
        return 1
    previous: Path | None = None
    if args.previous:
        previous = Path(args.previous)
        if not previous.is_dir() or not (previous / "evidence").is_dir():
            print(f"Error: --previous is not an evidence root: {previous}", file=sys.stderr)
            return 1
        try:
            if previous.resolve() == current.resolve():
                print("Error: --previous is the same folder as --current", file=sys.stderr)
                return 1
        except OSError:
            pass
    elif args.history_root and not Path(args.history_root).is_dir():
        print(f"Error: --history-root does not exist: {args.history_root}", file=sys.stderr)
        return 1

    envelope = run(
        current,
        previous,
        args.history_root,
        dry_run=args.dry_run,
    )
    summary = envelope.get("summary") or {}
    if summary.get("comparison") == "first_scan":
        print(
            "No previous scan found; this is a first-scan changes envelope.",
            file=sys.stderr,
        )
    compared = summary.get("previous_label") or "(none)"
    print(f"Compared {current.name} to {compared}")
    if args.dry_run:
        print(json.dumps(envelope, indent=2, ensure_ascii=False))
    else:
        print(f"Wrote {current / 'evidence' / CHANGES_FILENAME}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
