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

Evidence is one finding per rule and severity. evidence_count is the number
of hits, and the title includes how many files were involved. Per-hit detail
stays in raw/secrets-scan/findings.csv.
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
    format_secret_hit_title,
    make_envelope,
    make_finding,
    redact_sample,
    resolve_raw_root,
    rule_key,
    secret_placeholder_reason,
    sha256_short,
    validate_evidence_root,
)

__version__ = "1.1.0"

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


# Severity is an exact rule id, not a substring of the name. "aws" inside an
# unrelated rule stays at the default. Keys are rule_key() form (lowercase,
# spaces and underscores as hyphens). Trufflehog names have no hyphens
# ("PrivateKey"); those match the compact form of the same entry.
DEFAULT_SECRET_SEVERITY = "high"

_CRITICAL_SECRET_RULES = (
    # Cloud accounts
    "aws",
    "aws-access-token",
    "aws-session-key",
    "awssessionkey",
    "aws-amazon-bedrock-api-key-long-lived",
    "aws-amazon-bedrock-api-key-short-lived",
    "gcp",
    "gcp-api-key",
    "gcpapplicationdefaultcredentials",
    "azure",
    "azure-ad-client-secret",
    "alibaba-access-key-id",
    "alibaba-secret-key",
    "digitalocean",
    "digitalocean-access-token",
    "digitalocean-pat",
    "digitalocean-refresh-token",
    "heroku",
    "heroku-api-key",
    "heroku-api-key-v2",
    "yandex-access-token",
    "yandex-api-key",
    "yandex-aws-access-token",
    # Source hosts and package registries
    "github",
    "github-app-token",
    "github-fine-grained-pat",
    "github-oauth",
    "github-pat",
    "github-refresh-token",
    "gitlab",
    "gitlab-pat",
    "gitlab-pat-routable",
    "gitlab-deploy-token",
    "gitlab-oauth-app-secret",
    "gitlab-runner-authentication-token",
    "gitlab-runner-authentication-token-routable",
    "bitbucket",
    "bitbucket-client-secret",
    "npm",
    "npm-access-token",
    "pypi",
    "pypi-upload-token",
    "rubygems-api-token",
    # Private keys and password-manager secrets
    "private-key",
    "privatekey",
    "age",
    "age-secret-key",
    "pkcs12-file",
    "1password-secret-key",
    "1password-service-account-token",
    # Identity, vault, and payments
    "vault",
    "vault-service-token",
    "vault-batch-token",
    "hashicorp-tf-api-token",
    "okta",
    "okta-access-token",
    "stripe",
    "stripe-access-token",
    "square",
    "square-access-token",
    "shopify",
    "shopify-access-token",
    "shopify-custom-access-token",
    "shopify-private-app-access-token",
    "shopify-shared-secret",
    # Org chat, mail, and AI-provider credentials
    "slack",
    "slack-app-token",
    "slack-bot-token",
    "slack-user-token",
    "slack-config-access-token",
    "slack-config-refresh-token",
    "slack-legacy-bot-token",
    "slack-legacy-token",
    "slack-legacy-workspace-token",
    "discord",
    "discord-api-token",
    "discord-client-secret",
    "sendgrid",
    "sendgrid-api-token",
    "twilio",
    "twilio-api-key",
    "openai",
    "openai-api-key",
    "anthropic",
    "anthropic-api-key",
    "anthropic-admin-api-key",
    "huggingface",
    "huggingface-access-token",
    "huggingface-organization-api-token",
    "databricks",
    "databricks-api-token",
    "cloudflare",
    "cloudflare-api-key",
    "cloudflare-global-api-key",
    "cloudflare-origin-ca-key",
)


def _compact_rule_key(key: str) -> str:
    return key.replace("-", "")


_CRITICAL_KEYS = frozenset(rule_key(rule) for rule in _CRITICAL_SECRET_RULES)
_CRITICAL_COMPACT = frozenset(_compact_rule_key(key) for key in _CRITICAL_KEYS)


def severity_for_rule(rule: str) -> str:
    """Critical for listed high-impact rules; every other rule is high."""
    key = rule_key(rule)
    if key and (key in _CRITICAL_KEYS or _compact_rule_key(key) in _CRITICAL_COMPACT):
        return "critical"
    return DEFAULT_SECRET_SEVERITY


def secret_finding_id(rule: str) -> str:
    """Keep the pre-grouping id shape so a scan diff does not re-add every secret.

    The old id was the rule lowercased, with spaces turned into underscores,
    cut at 40 characters. Hyphens stayed hyphens. A rule longer than 40
    characters used to share an id with any other rule that had the same
    prefix; those ids now end with a short hash of the full rule.
    """
    text = str(rule or "").strip()
    legacy = text.lower().replace(" ", "_") if text else "unknown"
    slug = legacy[:40]
    if len(legacy) > 40:
        slug = f"{slug}_{sha256_short(rule_key(text) or legacy)}"
    return f"secrets_scan.{slug}"


def group_secret_hits(hits: list[dict], scanner_name: str) -> list[dict]:
    """One finding per rule and severity.

    evidence_count is the number of hits. The title carries the distinct file
    count in the same shape pii-scan uses. Per-hit rows stay in findings.csv.
    """
    groups: dict[tuple[str, str], dict] = {}
    for hit in hits:
        rule = str(hit.get("rule") or "unknown")
        severity = severity_for_rule(rule)
        key = (rule_key(rule) or "unknown", severity)
        bucket = groups.get(key)
        if bucket is None:
            bucket = {
                "rule": rule,
                "severity": severity,
                "count": 0,
                "files": set(),
                "placeholder_count": 0,
                "sample_secret": "",
                "sample_rule": rule,
            }
            groups[key] = bucket
        bucket["count"] += 1
        file_path = str(hit.get("file") or "").strip()
        if file_path:
            bucket["files"].add(file_path)
        secret = str(hit.get("secret") or "")
        if secret:
            redacted = redact_sample(secret, rule)
            if secret_placeholder_reason(rule, redacted):
                bucket["placeholder_count"] += 1
            if not bucket["sample_secret"]:
                bucket["sample_secret"] = secret
                bucket["sample_rule"] = rule

    findings: list[dict] = []
    ordered = sorted(groups.values(), key=lambda item: (-item["count"], str(item["rule"]).lower()))
    for bucket in ordered:
        rule = str(bucket["rule"])
        count = int(bucket["count"])
        file_count = len(bucket["files"])
        secret = str(bucket["sample_secret"] or "")
        finding = make_finding(
            secret_finding_id(rule),
            bucket["severity"],
            "Secrets Exposure",
            format_secret_hit_title(scanner_name, rule, count, file_count),
            evidence_count=count,
            sample_redacted=redact_sample(secret, bucket["sample_rule"]) if secret else rule,
            secret_redacted=True,
            tags=["gh_token_present" if "github" in rule.lower() else "env_read"],
            raw_evidence_ref="raw/secrets-scan/findings.csv",
        )
        # How many hits in this rule look like examples. The briefing
        # downgrades the row only when this equals evidence_count.
        finding["placeholder_count"] = int(bucket["placeholder_count"])
        findings.append(finding)
    return findings


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


def _same_location(left: Path, right: Path) -> bool:
    """True when both paths name the same file.

    ``Path.resolve()`` on Windows expands an 8.3 short name such as
    ``RUNNER~1`` to the long name. A repo root passed in one spelling and
    scanned in the other is still that repo root.
    """
    try:
        return left.resolve() == right.resolve()
    except OSError:
        return os.path.normcase(str(left)) == os.path.normcase(str(right))


def _same_or_within(path: Path, root: Path) -> bool:
    if path == root:
        return True
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _strictly_within(path: Path, root: Path) -> bool:
    if path == root:
        return False
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def scan_targets_excluding(targets: list[Path], excluded: list[Path]) -> list[Path]:
    """Scan targets with excluded output directories left out.

    When the OutDir sits inside a repository, the scanner must not walk that
    folder: it would read raw/secrets-scan and evidence from the previous
    run. If a target is itself an excluded directory, it is still scanned,
    minus any excluded directory nested under it.
    """
    excluded_resolved: list[Path] = []
    for path in excluded:
        try:
            excluded_resolved.append(path.resolve())
        except OSError:
            continue
    expanded: list[Path] = []
    for target in targets:
        try:
            resolved = target.resolve()
        except OSError:
            expanded.append(target)
            continue
        active = [root for root in excluded_resolved if root != resolved]
        expanded.extend(_expand_scan_target(resolved, active))
    return expanded


def _expand_scan_target(resolved: Path, excluded: list[Path]) -> list[Path]:
    for root in excluded:
        if _same_or_within(resolved, root):
            return []
    nested = [root for root in excluded if _strictly_within(root, resolved)]
    if not nested or not resolved.is_dir():
        return [resolved]
    try:
        entries = list(resolved.iterdir())
    except OSError:
        return []
    children: list[Path] = []
    for entry in entries:
        try:
            child = entry.resolve()
        except OSError:
            continue
        children.extend(_expand_scan_target(child, excluded))
    return children


def collect(
    raw_root: Path,
    repo_roots: list[Path],
    raw_out_dir: Path | None = None,
    native_roots: list[Path] | None = None,
    exclude_roots: list[Path] | None = None,
) -> tuple[dict, bool, list[dict]]:
    scanner_info = find_scanner()
    targets: list[Path] = []
    coverage_findings: list[dict] = []
    # The chat corpus lives under the raw root on purpose. Output folders
    # (the evidence root, evidence/, raw/secrets-scan) are excluded only from
    # repo and native targets, so a corpus inside an OutDir is still scanned.
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
    skip_roots = list(exclude_roots or [])
    existing_repo_roots = [root for root in repo_roots if root.exists()]
    targets.extend(scan_targets_excluding(existing_repo_roots, skip_roots))
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
        existing_native = [root for root in native_roots if root.exists()]
        targets.extend(scan_targets_excluding(existing_native, skip_roots))

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
    # Repo roots are not walked for .zst. Compare resolved paths so a Windows
    # short name and its long name are not treated as two different folders.
    zst_sources = [
        target
        for target in targets
        if not any(_same_location(target, root) for root in existing_repo_roots)
    ]
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
    # One row per rule. The CSV written above still has one row per hit.
    findings.extend(group_secret_hits(all_hits, scanner_name))

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
    # The output folder is still excluded from the scan so a previous run's
    # findings are not picked up when that folder sits inside a repository.
    secrets_out = raw_root / "secrets-scan"
    raw_out = None if args.dry_run else secrets_out
    envelope, tool_ok, _ = collect(
        raw_root,
        repo_roots,
        raw_out,
        native_roots=native_roots,
        exclude_roots=[evidence_root, evidence_root / "evidence", secrets_out],
    )
    finish_collector(envelope, evidence_root, dry_run=args.dry_run)

    if not tool_ok:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
