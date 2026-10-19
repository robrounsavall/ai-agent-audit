"""
Secrets scanner collector (Betterleaks / gitleaks / trufflehog wrapper).

Usage:
    python secrets-scan.py --evidence-root ./audit-run [--raw-root ./raw] [--repo-roots ~/code] [--dry-run]

Runs the first scanner it finds against the chat-history raw dir and repo
roots: Betterleaks (BETTERLEAKS_PATH or PATH), then gitleaks, then trufflehog.

Betterleaks can check found credentials against live provider APIs
(--validate / --analyze, or BETTERLEAKS_VALIDATE / BETTERLEAKS_ANALYZE).
aiscan never turns that on: the command line forces both off, and the
environment variables that could turn them on are removed from the child
process. The scan stays local.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

import compressed
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


# Environment variables removed before Betterleaks runs. VALIDATE / ANALYZE
# turn on live credential checks in v2. The config variables could point the
# scan at a config the user did not mean for aiscan, so aiscan always uses the
# built-in rules.
BETTERLEAKS_BLOCKED_ENV = (
    "BETTERLEAKS_VALIDATE",
    "BETTERLEAKS_ANALYZE",
    "BETTERLEAKS_CONFIG",
    "BETTERLEAKS_CONFIG_TOML",
    "GITLEAKS_CONFIG",
    "GITLEAKS_CONFIG_TOML",
)

# Flags that would let Betterleaks contact credential providers. They must
# never appear in a command aiscan builds, except in their forced-off form.
BETTERLEAKS_FORBIDDEN_FLAGS = ("-v", "--validate", "-a", "--analyze", "--validation")


def betterleaks_major(binary: str) -> int | None:
    """Return the Betterleaks major version (1, 2, ...) or None if unknown."""
    for args in (["version"], ["--version"]):
        try:
            proc = subprocess.run(
                [binary, *args],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                env=betterleaks_env(),
            )
        except (OSError, subprocess.SubprocessError):
            return None
        match = re.search(r"\bv?(\d+)\.\d+\.\d+", (proc.stdout or "") + " " + (proc.stderr or ""))
        if match:
            return int(match.group(1))
    return None


def find_scanner() -> tuple[str, str] | None:
    """Return (scanner, binary). scanner is betterleaks-v2, betterleaks-v1,
    gitleaks, or trufflehog. A Betterleaks binary whose version cannot be read
    is skipped so the scan falls back to gitleaks or trufflehog."""
    betterleaks = os.environ.get("BETTERLEAKS_PATH") or shutil.which("betterleaks")
    if betterleaks:
        major = betterleaks_major(betterleaks)
        if major == 1:
            return "betterleaks-v1", betterleaks
        if major is not None and major >= 2:
            return "betterleaks-v2", betterleaks
    gitleaks = os.environ.get("GITLEAKS_PATH") or shutil.which("gitleaks")
    if gitleaks:
        return "gitleaks", gitleaks
    trufflehog = os.environ.get("TRUFFLEHOG_PATH") or shutil.which("trufflehog")
    if trufflehog:
        return "trufflehog", trufflehog
    return None


def scanner_family(scanner: str) -> str:
    """Name reported in the evidence summary and finding titles."""
    return "betterleaks" if scanner.startswith("betterleaks") else scanner


def betterleaks_env(base: dict[str, str] | None = None) -> dict[str, str]:
    """Copy of the environment with every validation / config switch removed."""
    env = dict(os.environ if base is None else base)
    blocked = {name.upper() for name in BETTERLEAKS_BLOCKED_ENV}
    for key in list(env):
        if key.upper() in blocked:
            del env[key]
    return env


def betterleaks_command(binary: str, target: Path, major: int) -> list[str]:
    """Build the Betterleaks scan command. Validation is always forced off."""
    if major >= 2:
        # v2: `filesystem` scans files without git history. --validate=false and
        # --analyze=false override any environment setting (docs/scanning.md).
        return [
            binary, "filesystem", str(target),
            "--validate=false", "--analyze=false",
            "--no-banner", "--no-color", "--log-level", "error",
            "--output", "-", "--exit-code", "0",
        ]
    # v1 keeps the gitleaks report format. `dir` is its no-git scan.
    return [
        binary, "dir", str(target),
        "--validation=false",
        "--no-banner", "--no-color", "--log-level", "error",
        "--report-format", "json", "--report-path", "-", "--exit-code", "0",
    ]


def _load_json(text: str):
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Tolerate a stray log line before the report.
    for opener in ("{", "["):
        idx = text.find(opener)
        if idx > 0:
            try:
                return json.loads(text[idx:])
            except json.JSONDecodeError:
                continue
    return None


def run_betterleaks(target: Path, binary: str, major: int) -> tuple[list[dict], str | None]:
    """Run Betterleaks on one target. Returns (raw hits, error or None)."""
    try:
        proc = subprocess.run(
            betterleaks_command(binary, target, major),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
            env=betterleaks_env(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return [], f"{type(exc).__name__}"
    data = _load_json(proc.stdout or "")
    if major >= 2:
        if isinstance(data, dict) and isinstance(data.get("findings"), list):
            return [h for h in data["findings"] if isinstance(h, dict)], None
    elif isinstance(data, list):
        return [h for h in data if isinstance(h, dict)], None
    if proc.returncode == 0 and data is None and not (proc.stdout or "").strip():
        return [], None
    # Only the exit code goes into evidence: scanner stderr can carry local paths.
    return [], f"exit code {proc.returncode}, no readable report"


# Gitleaks exits 1 for leaks and for real failures. --exit-code 2 makes a
# finished scan with leaks distinguishable from a failed run (still exit 1).
_GITLEAKS_LEAK_EXIT = 2


def _scanner_failure(exc: BaseException) -> str:
    # The exception text can carry a local path. The type name cannot.
    return type(exc).__name__


def run_gitleaks(target: Path, gitleaks: str) -> tuple[list[dict], str | None]:
    """Return (raw hits, error or None). A readable report is a finished scan."""
    try:
        proc = subprocess.run(
            [
                gitleaks, "detect", "--source", str(target), "--no-git",
                "--report-format", "json", "--report-path", "-",
                "--exit-code", str(_GITLEAKS_LEAK_EXIT),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return [], _scanner_failure(exc)
    data = _load_json(proc.stdout or "")
    if proc.returncode in (0, _GITLEAKS_LEAK_EXIT) and (
        isinstance(data, list) or not (proc.stdout or "").strip()
    ):
        hits = [hit for hit in data if isinstance(hit, dict)] if isinstance(data, list) else []
        return hits, None
    # Only the exit code goes into evidence: scanner stderr can carry local paths.
    return [], f"exit code {proc.returncode}, no readable report"


def run_trufflehog(target: Path, trufflehog: str) -> tuple[list[dict], str | None]:
    # --no-verification is the current trufflehog v3 flag (still present in
    # 3.99) that sets Verify=false. Without it, trufflehog calls provider
    # APIs. --results only filters printed hits and still verifies.
    # --no-update skips the update check, which also uses the network.
    try:
        proc = subprocess.run(
            [trufflehog, "filesystem", str(target), "--json", "--no-verification", "--no-update"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return [], _scanner_failure(exc)
    # Trufflehog exits 0 when the scan finishes, including when it found
    # secrets. We do not pass --fail, so a non-zero exit is a failed run.
    if proc.returncode != 0:
        return [], f"exit code {proc.returncode}, no readable report"
    hits: list[dict] = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            hits.append(parsed)
    return hits, None


def normalize_hit(scanner: str, hit: dict) -> dict:
    if scanner == "betterleaks-v2":
        match = hit.get("match") if isinstance(hit.get("match"), dict) else {}
        location = hit.get("location") if isinstance(hit.get("location"), dict) else {}
        tags = hit.get("tags")
        return {
            "rule": hit.get("rule_id") or hit.get("description") or "unknown",
            "file": location.get("path", "") or "",
            "line": location.get("start_line", 0) or 0,
            "secret": match.get("value") or match.get("full") or "",
            "tags": tags if isinstance(tags, list) else [],
        }
    if scanner in ("gitleaks", "betterleaks-v1"):
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
                "No secrets scanner found (looked for betterleaks, gitleaks, "
                "and trufflehog on PATH and in BETTERLEAKS_PATH / GITLEAKS_PATH / "
                "TRUFFLEHOG_PATH)",
                tags=["env_read"],
            )
        ]
        envelope["summary"] = {"scanner": "none", "hits": 0, "targets": len(targets)}
        return envelope, False, []

    scanner_kind, scanner_bin = scanner_info
    scanner_name = scanner_family(scanner_kind)
    all_hits: list[dict] = []
    rule_counts: Counter[str] = Counter()
    file_counts: Counter[str] = Counter()
    scan_errors: list[str] = []

    # Compressed Codex rollouts are opaque to the scanners. Stage decompressed
    # copies in a temp directory (never next to the originals and never under
    # raw/), scan them, report the original .zst path, and always delete the
    # copies. Repo roots are not walked for .zst. With no stdlib zstd backend
    # the files are counted and not opened.
    staging = Path(tempfile.mkdtemp(prefix="aiscan-secrets-zst-"))
    zst_sources = [target for target in targets if target not in existing_repo_roots]
    staged: list[Path] = []
    staged_map: dict[str, str] = {}
    zst_unreadable = 0
    zstd_ok = compressed.zstd_backend() is not None
    try:
        staged, staged_map, zst_unreadable = compressed.stage_compressed(zst_sources, staging)
        for target in targets + staged:
            if scanner_kind.startswith("betterleaks"):
                major = 1 if scanner_kind == "betterleaks-v1" else 2
                hits, error = run_betterleaks(target, scanner_bin, major)
                if error:
                    scan_errors.append(error)
            elif scanner_kind == "gitleaks":
                hits, error = run_gitleaks(target, scanner_bin)
                if error:
                    scan_errors.append(error)
            else:
                hits, error = run_trufflehog(target, scanner_bin)
                if error:
                    scan_errors.append(error)
            for hit in hits:
                normalized = normalize_hit(scanner_kind, hit)
                reported = Path(normalized["file"]) if normalized["file"] else None
                if reported is not None and not reported.is_absolute():
                    reported = Path(target) / reported
                if (
                    reported is not None
                    and target not in staged
                    and compressed.is_under(reported, staging)
                ):
                    continue
                normalized["file"] = compressed.map_back(normalized["file"], staged_map, target)
                all_hits.append(normalized)
                rule_counts[normalized["rule"]] += 1
                if normalized["file"]:
                    file_counts[normalized["file"]] += 1
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    if zst_unreadable:
        if zstd_ok:
            title = (
                f"{zst_unreadable} compressed transcript file(s) (.jsonl.zst) "
                "could not be read"
            )
        else:
            title = (
                f"{zst_unreadable} compressed transcript file(s) (.jsonl.zst) "
                "were not scanned for secrets"
            )
        coverage_findings.append(
            make_finding(
                "secrets-scan.compressed_files_unreadable",
                "low",
                "Secrets Exposure",
                title,
                evidence_count=zst_unreadable,
                tags=["coverage_gap"],
            )
        )

    if raw_out_dir is not None:
        write_raw_outputs(raw_out_dir, all_hits, rule_counts, file_counts)

    findings = list(coverage_findings)
    if scan_errors:
        findings.append(
            make_finding(
                "secrets-scan.scanner_error",
                "medium",
                "Secrets Exposure",
                f"{scanner_name} did not finish on {len(scan_errors)} of {len(targets) + len(staged)} "
                f"scan targets; hits from those targets are missing ({scan_errors[0]})",
                tags=["env_read"],
            )
        )
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
        **({"scanner_mode": scanner_kind} if scanner_kind != scanner_name else {}),
        "hits": len(all_hits),
        "targets": len(targets),
        "compressed_files_staged": len(staged_map),
        "compressed_files_unreadable": zst_unreadable,
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

    # --dry-run prints the envelope and writes nothing, including raw/.
    raw_out = None if args.dry_run else raw_root / "secrets-scan"
    envelope, tool_ok, _ = collect(raw_root, repo_roots, raw_out, native_roots=native_roots)
    finish_collector(envelope, evidence_root, dry_run=args.dry_run)

    if not tool_ok:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
