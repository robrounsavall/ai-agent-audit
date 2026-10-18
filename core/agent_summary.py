#!/usr/bin/env python3
"""Safe summary of an aiscan scan folder.

Agents read this instead of collector envelopes. The JSON has four lists:

- ``collectors``: collector name, ``platform_detected``, detection status
- ``findings``: collector, severity, title, category, evidence count.
  Sorted by severity (critical, high, medium, low, then unknown), then
  real findings before test data, then evidence count descending
- ``collector_errors``: collectors that failed or did not produce a readable envelope
- ``coverage_caveats``: findings that describe a gap in what was scanned

Coverage findings are not repeated in ``findings``. Titles and categories
are masked even when the original scan was unredacted. ``evidence_count``
is whatever that collector counted; collectors do not share one unit.

Paths, hostnames, samples, rules, raw pointers, and every other envelope
field are dropped. Nothing here shells out, and the CLI is a script file
so PowerShell 5.1 does not have to pass a ``python -c`` string.

    python core/agent_summary.py --evidence-root <scan folder>
    python core/agent_summary.py --results-root <parent of scan folders>

``--results-root`` picks the newest child folder that contains ``evidence``.
A child named ``yyyyMMdd-HHmmss`` is dated from that name. Any other child
is dated from its modification time.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

SUMMARY_FILENAME = "agent-summary.json"
RUN_STATUS_FILENAME = "run-status.json"

_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
_STAMP = re.compile(r"^\d{8}-\d{6}$")
_EXIT_IN_TEXT = re.compile(r"exit\s+(-?\d+)")

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_SEVERITIES = frozenset(_SEV_RANK)

# Tags or ids collectors already use when a scan looked at less than it could.
# Those findings are listed only in ``coverage_caveats``, not in ``findings``.
_COVERAGE_TAGS = frozenset({"coverage_gap", "coverage", "collection_gap"})
_COVERAGE_IDS = frozenset({
    "secrets-scan.tool_unavailable",
    "secrets-scan.chat_corpus_not_scanned",
    "secrets-scan.no_repo_roots",
    "secrets-scan.scanner_error",
    "git.scan.no_repo_roots",
    "git.scan.no_repos_in_roots",
    "telemetry.import.unreadable",
    "cloud_agents.read_error",
})

_NO_SCANNER_TITLE = "No secrets scanner found"
_NO_SCANNER_CATEGORY = "Secrets Exposure"


def newest_scan_dir(results_root: str | Path) -> Path | None:
    """Return the newest scan folder under ``results_root``, or None.

    A scan folder is a child directory that contains ``evidence``. Timestamp
    names (``yyyyMMdd-HHmmss``, local time) sort by that clock. Other names
    sort by modification time. The later moment wins. Equal moments use the
    folder name.
    """
    root = Path(results_root)
    if not root.is_dir():
        return None
    candidates: list[tuple[float, str, Path]] = []
    try:
        children = list(root.iterdir())
    except OSError:
        return None
    for child in children:
        try:
            if not child.is_dir():
                continue
            if not (child / "evidence").is_dir():
                continue
            when = _folder_when(child)
        except OSError:
            continue
        candidates.append((when, child.name, child))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[0], item[1]))
    return candidates[-1][2]


def _folder_when(path: Path) -> float:
    if _STAMP.fullmatch(path.name):
        try:
            parsed = datetime.strptime(path.name, "%Y%m%d-%H%M%S")
        except ValueError:
            parsed = None
        if parsed is not None:
            # Naive local time, same clock ``Get-Date`` uses for the folder name.
            return parsed.timestamp()
    return path.stat().st_mtime


def build_agent_summary(
    evidence_root: str | Path,
    statuses: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build the safe summary for one scan folder.

    ``statuses`` maps a collector name to ``exit_code`` and ``raw_status``
    recorded while the collectors ran. Pass the merged map (file plus any
    new rows) so a later write keeps stored exit codes.

    A known non-zero exit is a collector error, including when an envelope
    was written. The exception is exit 2 with a parsed envelope: collectors
    use that for "not detected", and status then follows
    ``platform_detected``. Exit 2 with no file is still an error. When the
    exit was not stored, status follows ``platform_detected``. See
    ``_collector_failed``.
    """
    root = Path(evidence_root)
    evidence = root / "evidence"
    merged = load_run_status(evidence)
    for name, row in (statuses or {}).items():
        if _SAFE_NAME.fullmatch(name):
            merged[name] = row

    collectors: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    caveats: list[dict[str, Any]] = []
    seen: set[str] = set()

    files = _evidence_files(evidence)
    for path in files:
        name = path.stem
        if not _SAFE_NAME.fullmatch(name):
            continue
        seen.add(name)
        envelope, file_bad = _read_envelope(path)
        row = merged.get(name) or {}
        exit_code = _exit_code(row.get("exit_code"))
        if file_bad or envelope is None:
            errors.append(_error_row(name, "parse error"))
            continue
        if _collector_failed(exit_code, True, True):
            errors.append(_error_row(name, f"error (exit {exit_code})", envelope))
            _take_findings(name, envelope, findings, caveats)
            continue
        detected = envelope.get("platform_detected") is True
        collectors.append({
            "collector": name,
            "platform_detected": detected,
            "detection_status": "detected" if detected else "not detected",
        })
        _take_findings(name, envelope, findings, caveats)

    for name in sorted(merged):
        if name in seen or not _SAFE_NAME.fullmatch(name):
            continue
        row = merged[name]
        exit_code = _exit_code(row.get("exit_code"))
        raw_status = str(row.get("raw_status") or "")
        if _collector_failed(exit_code, False, False):
            errors.append(_error_row(name, f"error (exit {exit_code})"))
            continue
        status = _status_without_envelope(exit_code, raw_status)
        collectors.append({
            "collector": name,
            "platform_detected": False,
            "detection_status": status,
        })

    collectors.sort(key=lambda item: item["collector"])
    findings.sort(key=_finding_sort_key)
    caveats.sort(key=_finding_sort_key)
    errors.sort(key=lambda item: item["collector"])
    for row in findings:
        row.pop("_test_data", None)
    for row in caveats:
        row.pop("_test_data", None)
    return {
        "collectors": collectors,
        "findings": findings,
        "collector_errors": errors,
        "coverage_caveats": caveats,
    }


def load_run_status(evidence_dir: Path) -> dict[str, dict[str, Any]]:
    """Read ``run-status.json`` into collector -> exit code and raw status."""
    path = evidence_dir / RUN_STATUS_FILENAME
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    rows = data.get("collectors") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return {}
    loaded: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = row.get("collector")
        if not isinstance(name, str) or not _SAFE_NAME.fullmatch(name):
            continue
        loaded[name] = {
            "exit_code": _exit_code(row.get("exit_code")),
            "raw_status": row.get("detection_status") if isinstance(row.get("detection_status"), str) else "",
        }
    return loaded


def parse_status_token(token: str) -> dict[str, Any] | None:
    """Parse ``name|exit|status`` from the PowerShell wrapper.

    The status text is kept only long enough to classify the collector.
    It is never copied into the summary.
    """
    parts = str(token).split("|", 2)
    if len(parts) != 3:
        return None
    name, code_text, raw_status = (part.strip() for part in parts)
    if not _SAFE_NAME.fullmatch(name):
        return None
    code = _exit_code(code_text)
    if code is None:
        return None
    return {"collector": name, "exit_code": code, "raw_status": raw_status}


def write_summary_files(
    evidence_root: str | Path,
    summary: dict[str, Any],
    statuses: dict[str, dict[str, Any]] | None = None,
) -> Path:
    """Write ``agent-summary.json`` and a path-free ``run-status.json``."""
    evidence = Path(evidence_root) / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    dest = evidence / SUMMARY_FILENAME
    _atomic_json(dest, summary)
    _atomic_json(evidence / RUN_STATUS_FILENAME, _run_status_payload(summary, statuses or {}))
    return dest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Print a safe summary of an aiscan scan folder.",
    )
    parser.add_argument(
        "--evidence-root",
        help="Scan folder (the same path passed to aiscan -OutDir).",
    )
    parser.add_argument(
        "--results-root",
        help="Parent of scan folders. The newest child that contains evidence/ is used.",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Also write evidence/agent-summary.json inside the scan folder.",
    )
    parser.add_argument(
        "--print-id",
        action="store_true",
        help="With --results-root, print only the chosen folder name and exit.",
    )
    parser.add_argument(
        "--collector-status",
        action="append",
        default=[],
        metavar="NAME|EXIT|STATUS",
        help="Collector result recorded by aiscan.ps1. Repeat for each collector.",
    )
    args = parser.parse_args(argv)

    if args.print_id:
        if not args.results_root or args.evidence_root:
            print("Pass --results-root with --print-id.", file=sys.stderr)
            return 1
        chosen = newest_scan_dir(args.results_root)
        if chosen is None:
            print("No scan folders found.", file=sys.stderr)
            return 1
        name = chosen.name.replace("\r", "").replace("\n", "").strip()
        if not name or "/" in name or "\\" in name:
            print("No scan folders found.", file=sys.stderr)
            return 1
        sys.stdout.write(name + "\n")
        return 0

    if args.evidence_root and args.results_root:
        print("Pass only one of --evidence-root or --results-root.", file=sys.stderr)
        return 1
    if args.evidence_root:
        root = Path(args.evidence_root)
        if not root.is_dir():
            print("Output folder not found.", file=sys.stderr)
            return 1
    elif args.results_root:
        chosen = newest_scan_dir(args.results_root)
        if chosen is None:
            print("No scan folders found.", file=sys.stderr)
            return 1
        root = chosen
    else:
        print("Pass --evidence-root or --results-root.", file=sys.stderr)
        return 1

    statuses: dict[str, dict[str, Any]] = {}
    for token in args.collector_status:
        parsed = parse_status_token(token)
        if parsed is None:
            print("A collector status was not readable.", file=sys.stderr)
            return 1
        statuses[parsed["collector"]] = parsed

    # File rows fill in exit codes the command line did not repeat, then
    # the command line wins. The same map is what gets written back.
    merged = load_run_status(root / "evidence")
    for name, row in statuses.items():
        merged[name] = row

    summary = build_agent_summary(root, merged)
    json.dump(summary, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    sys.stdout.flush()
    if args.write:
        try:
            write_summary_files(root, summary, merged)
        except OSError:
            print("Could not write the agent summary.", file=sys.stderr)
    return 0


def _evidence_files(evidence: Path) -> list[Path]:
    if not evidence.is_dir():
        return []
    files: list[Path] = []
    try:
        derived = _derived_filenames()
        for path in sorted(evidence.glob("*.json")):
            if path.name in derived or path.stem in _derived_stems():
                continue
            files.append(path)
    except OSError:
        return []
    return files


def _read_envelope(path: Path) -> tuple[dict[str, Any] | None, bool]:
    """Return (envelope, file_bad). Missing is not bad; unreadable JSON is."""
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None, True
    if not isinstance(data, dict):
        return None, True
    return data, False


def _finding_list(envelope: dict[str, Any]) -> list[Any]:
    findings = envelope.get("findings")
    if isinstance(findings, list):
        return findings
    return []


def _safe_finding(collector: str, finding: Any) -> dict[str, Any] | None:
    if not isinstance(finding, dict):
        return None
    title = finding.get("title")
    category = finding.get("category")
    severity = finding.get("severity")
    return {
        "collector": collector,
        "severity": severity.lower() if isinstance(severity, str) and severity.lower() in _SEVERITIES else "unknown",
        "title": _mask_summary_text(title) if isinstance(title, str) else "",
        "category": _mask_summary_text(category) if isinstance(category, str) else "",
        "evidence_count": _evidence_count(finding.get("evidence_count")),
        "_test_data": _is_test_data(finding),
    }


def _evidence_count(value: Any) -> int:
    if isinstance(value, bool) or value is None:
        return 0
    if isinstance(value, int):
        return value if value > 0 else 0
    if isinstance(value, float):
        if not math.isfinite(value) or value <= 0:
            return 0
        try:
            return int(value)
        except (OverflowError, ValueError):
            return 0
    if isinstance(value, str):
        try:
            parsed = int(value.strip())
        except ValueError:
            return 0
        return parsed if parsed > 0 else 0
    return 0


def _mask_summary_text(text: str) -> str:
    """Mask paths and secrets even when the scan itself was unredacted.

    ``sanitize_text`` no-ops unless AISCAN_REDACT is set. The summary is what
    an agent reads, so this always runs the same two steps.
    """
    from common import mask_secrets, redact_paths

    return mask_secrets(redact_paths(text))


def _derived_stems() -> frozenset[str]:
    from common import DERIVED_EVIDENCE_STEMS

    return DERIVED_EVIDENCE_STEMS


def _derived_filenames() -> frozenset[str]:
    return frozenset(f"{stem}.json" for stem in _derived_stems())


def _is_coverage(finding: dict[str, Any]) -> bool:
    finding_id = finding.get("id")
    if isinstance(finding_id, str):
        if finding_id in _COVERAGE_IDS or "coverage" in finding_id.lower():
            return True
    tags = finding.get("tags")
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, str) and tag.lower() in _COVERAGE_TAGS:
                return True
    return False


def _scanner_missing(envelope: dict[str, Any]) -> bool:
    summary = envelope.get("summary")
    return isinstance(summary, dict) and summary.get("scanner") == "none"


def _no_scanner_finding(collector: str) -> dict[str, Any]:
    return {
        "collector": collector,
        "severity": "medium",
        "title": _NO_SCANNER_TITLE,
        "category": _NO_SCANNER_CATEGORY,
        "evidence_count": 0,
        "_test_data": False,
    }


def _take_findings(
    collector: str,
    envelope: dict[str, Any],
    findings: list[dict[str, Any]],
    caveats: list[dict[str, Any]],
) -> None:
    """Coverage gaps go only to caveats. Everything else is a ranked finding."""
    for finding in _finding_list(envelope):
        safe = _safe_finding(collector, finding)
        if safe is None:
            continue
        if isinstance(finding, dict) and _is_coverage(finding):
            caveats.append(safe)
        else:
            findings.append(safe)
    if _scanner_missing(envelope) and not any(item["collector"] == collector for item in caveats):
        caveats.append(_no_scanner_finding(collector))


def _error_row(
    collector: str,
    status: str,
    envelope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    detected = False
    if isinstance(envelope, dict):
        detected = envelope.get("platform_detected") is True
    return {
        "collector": collector,
        "platform_detected": detected,
        "detection_status": status,
    }


def _collector_failed(exit_code: int | None, has_evidence: bool, parsed: bool) -> bool:
    """True when a stored exit code means this collector is an error.

    After PR #23 merges, replace the body below with
    ``return run_status.collector_failed(exit_code, has_evidence, parsed)``
    for a known exit. Do not vendor that module into this branch.
    ``None`` means this folder has no stored exit, so an older scan is not
    marked failed just because the code is missing.
    """
    if exit_code is None:
        return False
    if has_evidence and not parsed:
        return True
    if exit_code == 2 and has_evidence and parsed:
        return False
    return exit_code != 0


def _status_without_envelope(exit_code: int | None, raw_status: str) -> str:
    """Status for a collector that left no file and whose exit is not a failure."""
    text = " ".join(raw_status.strip().lower().split())
    if text in {"parse error", "parse_error"}:
        return "parse error"
    if text.startswith("error"):
        match = _EXIT_IN_TEXT.search(text)
        if match:
            return f"error (exit {int(match.group(1))})"
        if exit_code not in (None, 0):
            return f"error (exit {exit_code})"
        return "error (exit 1)"
    if text in {"not detected", "not_detected", "false"}:
        return "not detected"
    if text in {"detected", "true"}:
        return "detected"
    return "not collected"


def _exit_code(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _is_test_data(finding: dict[str, Any]) -> bool:
    tags = finding.get("tags")
    if not isinstance(tags, list):
        return False
    return any(isinstance(tag, str) and tag.lower() == "test_data" for tag in tags)


def _finding_sort_key(item: dict[str, Any]) -> tuple[Any, ...]:
    # test_data sorts after real findings of the same severity, even when
    # its count is higher. Equal rows then break on collector, category, title.
    return (
        _SEV_RANK.get(item["severity"], 9),
        1 if item.get("_test_data") else 0,
        -item["evidence_count"],
        item["collector"],
        item["category"],
        item["title"],
    )


def _run_status_payload(
    summary: dict[str, Any],
    statuses: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Path-free note so a later summary still sees collector errors."""
    by_name: dict[str, dict[str, Any]] = {}
    for row in summary["collectors"]:
        by_name[row["collector"]] = {
            "collector": row["collector"],
            "detection_status": row["detection_status"],
        }
    for row in summary["collector_errors"]:
        by_name[row["collector"]] = {
            "collector": row["collector"],
            "detection_status": row["detection_status"],
        }
    for name, row in by_name.items():
        code = _exit_code((statuses.get(name) or {}).get("exit_code"))
        if code is not None:
            row["exit_code"] = code
    collectors = [by_name[name] for name in sorted(by_name)]
    return {"collectors": collectors}


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(suffix=".json", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        tmp_path.replace(path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


if __name__ == "__main__":
    sys.exit(main())
