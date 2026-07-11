"""
Secrets scanner collector (gitleaks / trufflehog wrapper).

Usage:
    python secrets-scan.py --evidence-root ./audit-run [--raw-root ./raw] [--repo-roots ~/code] [--dry-run]

Runs gitleaks (preferred) or trufflehog against chat-history raw dir and repo roots.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

from common import (
    add_base_args,
    compute_scope_hash,
    default_repo_roots,
    finish_collector,
    make_envelope,
    make_finding,
    redact_sample,
    resolve_raw_root,
    validate_evidence_root,
)

__version__ = "1.0.0"

COLLECTOR = "secrets-scan"


def find_scanner() -> tuple[str, str] | None:
    gitleaks = os.environ.get("GITLEAKS_PATH") or shutil.which("gitleaks")
    if gitleaks:
        return "gitleaks", gitleaks
    trufflehog = os.environ.get("TRUFFLEHOG_PATH") or shutil.which("trufflehog")
    if trufflehog:
        return "trufflehog", trufflehog
    return None


def run_gitleaks(target: Path, gitleaks: str) -> list[dict]:
    proc = subprocess.run(
        [gitleaks, "detect", "--source", str(target), "--no-git", "--report-format", "json", "--report-path", "-"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
    )
    out = proc.stdout or ""
    if not out.strip():
        return []
    try:
        data = json.loads(out)
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []


def run_trufflehog(target: Path, trufflehog: str) -> list[dict]:
    proc = subprocess.run(
        [trufflehog, "filesystem", str(target), "--json"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
    )
    hits: list[dict] = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            hits.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return hits


def normalize_hit(scanner: str, hit: dict) -> dict:
    if scanner == "gitleaks":
        return {
            "rule": hit.get("RuleID") or hit.get("Description") or "unknown",
            "file": hit.get("File", ""),
            "line": hit.get("StartLine", 0),
            "secret": hit.get("Secret") or hit.get("Match", ""),
            "tags": hit.get("Tags") or [],
        }
    detector = hit.get("DetectorName") or hit.get("SourceMetadata", {}).get("Data", {}).get("DetectorName", "unknown")
    raw = hit.get("Raw") or hit.get("Redacted") or ""
    file_path = ""
    meta = hit.get("SourceMetadata", {})
    if isinstance(meta, dict):
        data = meta.get("Data", {})
        if isinstance(data, dict):
            file_path = data.get("Filesystem", {}).get("file", "") or data.get("file", "")
    return {
        "rule": detector,
        "file": file_path,
        "line": 0,
        "secret": raw,
        "tags": [],
    }


def write_raw_outputs(raw_dir: Path, hits: list[dict], rule_counts: Counter, file_counts: Counter) -> None:
    raw_dir.mkdir(parents=True, exist_ok=True)
    csv_path = raw_dir / "findings.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["file", "line", "rule", "sample_redacted"])
        for hit in hits:
            writer.writerow(
                [
                    hit["file"],
                    hit["line"],
                    hit["rule"],
                    redact_sample(hit["secret"], hit["rule"]) if hit.get("secret") else hit["rule"],
                ]
            )

    summary_path = raw_dir / "summary.md"
    lines = ["# Secrets scan summary", ""]
    lines.append(f"- Total hits: {len(hits)}")
    lines.append(f"- Files with hits: {len(file_counts)}")
    lines.append("")
    lines.append("## Hits by rule")
    lines.append("")
    lines.append("| Rule | Count |")
    lines.append("|---|---|")
    for rule, count in rule_counts.most_common():
        lines.append(f"| {rule} | {count} |")
    lines.append("")
    lines.append("## Top files")
    lines.append("")
    lines.append("| File | Hits |")
    lines.append("|---|---|")
    for file_path, count in file_counts.most_common(25):
        lines.append(f"| {file_path} | {count} |")
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def collect(
    raw_root: Path,
    repo_roots: list[Path],
    raw_out_dir: Path | None = None,
    native_roots: list[Path] | None = None,
) -> tuple[dict, bool, list[dict]]:
    scanner_info = find_scanner()
    targets: list[Path] = []
    coverage_findings: list[dict] = []
    chat_dir = raw_root / "chat-history"
    if chat_dir.exists():
        targets.append(chat_dir)
    else:
        coverage_findings.append(
            make_finding(
                "secrets-scan.chat_corpus_not_scanned",
                "low",
                "Secrets Exposure",
                "No chat-history export found under the raw root; the extracted "
                "chat corpus was not scanned (run chat-history first, or rely on "
                "the native transcript dirs passed via --native-roots)",
                tags=["env_read"],
            )
        )
    existing_repo_roots = [root for root in repo_roots if root.exists()]
    targets.extend(existing_repo_roots)
    if repo_roots is not None and not existing_repo_roots:
        coverage_findings.append(
            make_finding(
                "secrets-scan.no_repo_roots",
                "low",
                "Secrets Exposure",
                "No repo roots exist to scan; pass --repo-roots (or -RepoRoots "
                "via aiscan.ps1) to include your code directories",
                tags=["env_read"],
            )
        )
    if native_roots:
        for root in native_roots:
            if root.exists():
                targets.append(root)

    scope_hash = compute_scope_hash(str(t) for t in targets)
    envelope = make_envelope(COLLECTOR, __version__, scope_hash, platform_detected=bool(targets))

    if scanner_info is None:
        envelope["findings"] = coverage_findings + [
            make_finding(
                "secrets-scan.tool_unavailable",
                "medium",
                "Secrets Exposure",
                "Neither gitleaks nor trufflehog found on PATH",
                tags=["env_read"],
            )
        ]
        envelope["summary"] = {"scanner": "none", "hits": 0, "targets": len(targets)}
        return envelope, False, []

    scanner_name, scanner_bin = scanner_info
    all_hits: list[dict] = []
    rule_counts: Counter[str] = Counter()
    file_counts: Counter[str] = Counter()

    for target in targets:
        if scanner_name == "gitleaks":
            hits = run_gitleaks(target, scanner_bin)
        else:
            hits = run_trufflehog(target, scanner_bin)
        for hit in hits:
            normalized = normalize_hit(scanner_name, hit)
            all_hits.append(normalized)
            rule_counts[normalized["rule"]] += 1
            if normalized["file"]:
                file_counts[normalized["file"]] += 1

    if raw_out_dir is not None:
        write_raw_outputs(raw_out_dir, all_hits, rule_counts, file_counts)

    findings = list(coverage_findings)
    for hit in all_hits:
        secret = hit.get("secret", "")
        rule = hit.get("rule", "unknown")
        severity = "critical" if any(t in rule.lower() for t in ("aws", "github", "private key")) else "high"
        findings.append(
            make_finding(
                f"secrets_scan.{rule.lower().replace(' ', '_')[:40]}",
                severity,
                "Secrets Exposure",
                f"Secret detected by {scanner_name}: {rule}",
                sample_redacted=redact_sample(secret, rule) if secret else rule,
                secret_redacted=True,
                tags=["gh_token_present" if "github" in rule.lower() else "env_read"],
                raw_evidence_ref="raw/secrets-scan/findings.csv",
            )
        )

    envelope["findings"] = findings
    envelope["summary"] = {
        "scanner": scanner_name,
        "hits": len(all_hits),
        "targets": len(targets),
        **{f"rule_{k}": v for k, v in rule_counts.items()},
    }
    return envelope, True, all_hits


def main() -> None:
    parser = argparse.ArgumentParser(description="Secrets scan collector")
    add_base_args(parser)
    parser.add_argument(
        "--repo-roots",
        default=None,
        help="Comma-separated repo scan roots",
    )
    parser.add_argument(
        "--native-roots",
        action="append",
        dest="native_roots",
        metavar="DIR",
        help="Native source dir to scan directly (repeatable; e.g. ~/.claude/projects, ~/.codex/sessions)",
    )
    args = parser.parse_args()
    evidence_root = validate_evidence_root(args.evidence_root)
    raw_root = resolve_raw_root(evidence_root, args.raw_root)

    if args.repo_roots:
        repo_roots = [Path(p.strip()) for p in args.repo_roots.split(",") if p.strip()]
    else:
        repo_roots = default_repo_roots()

    native_roots = [Path(p).expanduser().resolve() for p in args.native_roots] if args.native_roots else None

    envelope, tool_ok, _ = collect(raw_root, repo_roots, raw_root / "secrets-scan", native_roots=native_roots)
    finish_collector(envelope, evidence_root, dry_run=args.dry_run)

    if not tool_ok:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
