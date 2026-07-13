"""
PII scanner collector (pure stdlib: patterns + checksum validation).

Scans one or more target directory trees for regulated-data indicators using
regex patterns backed by real validation (Luhn for cards, mod-97 for IBANs,
SSN issuance rules), plus the secret patterns from common. No models, no pip
install, runs in `aiscan all`.

v2 dropped Microsoft Presidio. Its NER entities (PERSON, LOCATION) tagged code
identifiers and paths as people and places (~89% of hit volume, near-zero true
PII on a dev corpus), and its pattern-only entities (US_DRIVER_LICENSE,
MEDICAL_LICENSE) matched version strings and git hashes. What survived triage
was exactly the validatable, structured set below — all detectable in stdlib.

Entities:
    CREDIT_CARD     IIN prefix + Luhn checksum          critical
    US_SSN          ddd-dd-dddd + issuance rules        critical
    IBAN_CODE       pattern + mod-97 checksum           critical
    EMAIL_ADDRESS   pattern                             medium
    PHONE_NUMBER    NANP with separators or +intl       medium
    IP_ADDRESS      public/global only (private and     medium
                    loopback are counted in the summary
                    but are not findings)

Usage:
    python pii-scan.py --evidence-root ./out
    python pii-scan.py --evidence-root ./out --target ./corpus --entities EMAIL_ADDRESS,CREDIT_CARD

With no --target, scans the chat-history export (<raw-root>/chat-history, if a
chat-history run left one) plus the native chat-history locations resolved via
paths.py (Claude projects, Codex sessions, Cursor projects, Grok sessions).

Outputs:
    <evidence-root>/evidence/pii-scan.json  (envelope, severity findings only)
    <evidence-root>/raw/pii-scan/findings.csv  (one row per stored hit)
    <evidence-root>/raw/pii-scan/summary.md  (human-readable rollup)
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Callable, Iterable

import paths
from common import (
    add_base_args,
    compute_scope_hash,
    finish_collector,
    make_envelope,
    make_finding,
    redact_sample,
    redaction_disabled,
    resolve_raw_root,
    secret_types_in,
    validate_evidence_root,
)

# Major stays 1: the envelope version doubles as the evidence schema major
# (build-briefing.py gates on it) and the envelope shape is unchanged. The
# Presidio->stdlib engine swap is internal to the collector.
__version__ = "1.3.0"

COLLECTOR = "pii-scan"

TEXT_EXTENSIONS = {
    ".md", ".markdown", ".txt", ".json", ".jsonl", ".ndjson",
    ".csv", ".tsv", ".log", ".yaml", ".yml", ".html", ".htm",
}

SEVERITY_BY_ENTITY = {
    "CREDIT_CARD": "critical",
    "US_SSN": "critical",
    "IBAN_CODE": "critical",
    "EMAIL_ADDRESS": "medium",
    "PHONE_NUMBER": "medium",
    "IP_ADDRESS": "medium",
}

MAX_FILE_BYTES = 5 * 1024 * 1024


# --------------------------------------------------------------------------- #
# Validators
# --------------------------------------------------------------------------- #
def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# Major-network IIN prefixes. A Luhn pass alone is 1-in-10 on random digit
# runs; requiring a known prefix keeps sequential fixture numbers out.
_CC_PREFIX_RE = re.compile(
    r"^(?:4\d*|5[1-5]\d*|2(?:22[1-9]|2[3-9]\d|[3-6]\d{2}|7[01]\d|720)\d*"
    r"|3[47]\d*|6011\d*|64[4-9]\d*|65\d*|35\d*)$"
)


def credit_card_ok(raw: str) -> bool:
    digits = re.sub(r"[ -]", "", raw)
    if not 13 <= len(digits) <= 19:
        return False
    if len(set(digits)) == 1:
        return False
    return bool(_CC_PREFIX_RE.match(digits)) and luhn_ok(digits)


def ssn_ok(raw: str) -> bool:
    area, group, serial = raw.split("-")
    if area in ("000", "666") or area >= "900":
        return False
    return group != "00" and serial != "0000"


def iban_ok(raw: str) -> bool:
    rearranged = raw[4:] + raw[:4]
    try:
        numeric = int("".join(str(int(c, 36)) for c in rearranged))
    except ValueError:
        return False
    return numeric % 97 == 1


def public_ip_ok(raw: str) -> bool:
    try:
        return ipaddress.ip_address(raw).is_global
    except ValueError:
        return False


def private_ip(raw: str) -> bool:
    try:
        return not ipaddress.ip_address(raw).is_global
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# Detectors: entity -> (regex, validator or None, score)
# Score 1.0 = checksum/rule validated, 0.9 = pattern-only.
# --------------------------------------------------------------------------- #
DETECTORS: dict[str, tuple[re.Pattern, Callable[[str], bool] | None, float]] = {
    "CREDIT_CARD": (
        re.compile(r"(?<![\d.])(?:\d[ -]?){12,18}\d(?![\d.])"),
        credit_card_ok,
        1.0,
    ),
    "US_SSN": (
        re.compile(r"(?<![\d-])(\d{3}-\d{2}-\d{4})(?![\d-])"),
        ssn_ok,
        1.0,
    ),
    "IBAN_CODE": (
        re.compile(r"\b([A-Z]{2}\d{2}[A-Z0-9]{10,30})\b"),
        iban_ok,
        1.0,
    ),
    "EMAIL_ADDRESS": (
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"),
        None,
        0.9,
    ),
    # Separators or +intl prefix required: bare 10-digit runs are timestamps
    # and IDs far more often than phone numbers in a dev corpus.
    "PHONE_NUMBER": (
        re.compile(
            r"(?:\+1[-. ]?)?\(\d{3}\)\s?\d{3}[-.]\d{4}"
            r"|(?<![\d-])\d{3}[-.]\d{3}[-.]\d{4}(?![\d-])"
            r"|\+\d{1,3}[-. ]\d{2,4}[-. ]\d{3,4}[-. ]\d{3,4}"
        ),
        None,
        0.9,
    ),
    "IP_ADDRESS": (
        re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"),
        public_ip_ok,
        0.9,
    ),
}

DEFAULT_ENTITIES = list(DETECTORS)


def iter_text_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in TEXT_EXTENSIONS:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def severity_for(entity: str) -> str:
    return SEVERITY_BY_ENTITY.get(entity, "medium")


def scan_file(path: Path, entities: list[str]) -> tuple[list[dict], int]:
    """Return (hits, private_ip_count) for one file."""
    text = read_text(path)
    if not text:
        return [], 0

    hits: list[dict] = []
    private_ips = 0
    for line_no, line in enumerate(text.splitlines(), start=1):
        for entity in entities:
            pattern, validator, score = DETECTORS[entity]
            for match in pattern.finditer(line):
                value = match.group(0)
                if validator is not None and not validator(value):
                    if entity == "IP_ADDRESS" and private_ip(value):
                        private_ips += 1
                    continue
                hits.append(
                    {
                        "file": str(path),
                        "entity": entity,
                        "score": score,
                        "line": line_no,
                        "sample": value,
                    }
                )

    for secret_type in secret_types_in(text):
        hits.append(
            {
                "file": str(path),
                "entity": f"SECRET_{secret_type.upper()}",
                "score": 1.0,
                "line": 0,
                "sample": secret_type,
            }
        )

    return hits, private_ips


def write_raw_outputs(
    raw_dir: Path,
    hits: list[dict],
    entity_counts: Counter,
    file_counts: Counter,
    samples_truncated: int = 0,
) -> None:
    raw_dir.mkdir(parents=True, exist_ok=True)
    csv_path = raw_dir / "findings.csv"
    # findings.csv lives under raw/, which never leaves the machine (SCHEMA.md).
    # In the default unredacted local mode show the real matched text so hits
    # can be triaged; -Redact (AISCAN_REDACT=1) restores masking.
    show_raw = redaction_disabled()
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            ["file", "entity", "score", "line",
             "sample" if show_raw else "sample_redacted"]
        )
        for hit in hits:
            writer.writerow(
                [
                    hit["file"],
                    hit["entity"],
                    hit["score"],
                    hit["line"],
                    hit["sample"] if show_raw else redact_sample(hit["sample"], hit["entity"]),
                ]
            )

    summary_path = raw_dir / "summary.md"
    lines = ["# PII scan summary", ""]
    lines.append(f"- Total hits: {sum(entity_counts.values())}")
    lines.append(f"- Files with hits: {len(file_counts)}")
    if samples_truncated:
        lines.append(
            f"- Sample rows stored in findings.csv: {len(hits)} "
            f"({samples_truncated} over the per-file/per-entity cap omitted; counts above are complete)"
        )
    lines.append("")
    lines.append("## Hits by entity")
    lines.append("")
    lines.append("| Entity | Count |")
    lines.append("|---|---|")
    for entity, count in entity_counts.most_common():
        lines.append(f"| {entity} | {count} |")
    lines.append("")
    lines.append("## Top files")
    lines.append("")
    lines.append("| File | Hits |")
    lines.append("|---|---|")
    for file_path, count in file_counts.most_common(25):
        lines.append(f"| {file_path} | {count} |")
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def collect(
    targets: list[Path],
    entities: list[str],
    raw_dir: Path,
    max_samples_per_file: int = 25,
) -> tuple[dict, list[dict]]:
    existing_targets = [t for t in targets if t.exists()]
    missing_targets = [t for t in targets if not t.exists()]

    scope_hash = compute_scope_hash(str(t) for t in targets)
    envelope = make_envelope(COLLECTOR, __version__, scope_hash, platform_detected=bool(existing_targets))

    findings: list[dict] = []

    for t in missing_targets:
        findings.append(
            make_finding(
                "pii-scan.target_missing",
                "low",
                "PII Exposure",
                f"Target path not found: {t}",
                tags=["env_read"],
            )
        )

    if not existing_targets:
        envelope["findings"] = findings
        envelope["summary"] = {
            "targets": [str(t) for t in targets],
            "files_scanned": 0,
            "hits": 0,
        }
        return envelope, []

    all_hits: list[dict] = []
    files_scanned = 0
    total_hits = 0
    samples_truncated = 0
    private_ip_total = 0
    entity_counts: Counter[str] = Counter()
    file_counts: Counter[str] = Counter()
    per_entity_files: dict[str, set[str]] = defaultdict(set)

    # Progress goes to stderr: aiscan.ps1 suppresses collector stdout but
    # passes stderr through.
    for target in existing_targets:
        target_files = list(iter_text_files(target))
        print(
            f"pii-scan: scanning {len(target_files)} file(s) in target "
            f"{existing_targets.index(target) + 1}/{len(existing_targets)}",
            file=sys.stderr, flush=True,
        )
        for file_path in target_files:
            files_scanned += 1
            if files_scanned % 200 == 0:
                print(
                    f"pii-scan: {files_scanned} files scanned, {total_hits} hits so far",
                    file=sys.stderr, flush=True,
                )
            hits, private_ips = scan_file(file_path, entities)
            private_ip_total += private_ips
            if not hits:
                continue
            total_hits += len(hits)
            file_counts[str(file_path)] += len(hits)
            # True counts always accumulate; stored sample rows are capped per
            # (file, entity) so one noisy entity cannot flood memory or the CSV.
            per_file_entity: Counter[str] = Counter()
            for hit in hits:
                entity_counts[hit["entity"]] += 1
                per_entity_files[hit["entity"]].add(str(file_path))
                per_file_entity[hit["entity"]] += 1
                if per_file_entity[hit["entity"]] <= max_samples_per_file:
                    all_hits.append(hit)
                else:
                    samples_truncated += 1
    print(
        f"pii-scan: done. {files_scanned} files scanned, {total_hits} hits"
        f" ({samples_truncated} sample rows over the per-file cap not stored;"
        f" {private_ip_total} private/loopback IPs counted, not findings).",
        file=sys.stderr, flush=True,
    )

    write_raw_outputs(raw_dir, all_hits, entity_counts, file_counts, samples_truncated)

    for entity, count in entity_counts.most_common():
        sample_hit = next((h for h in all_hits if h["entity"] == entity), None)
        sample = redact_sample(sample_hit["sample"], entity) if sample_hit else ""
        findings.append(
            make_finding(
                f"pii_scan.{entity.lower()}",
                severity_for(entity),
                "PII Exposure",
                f"{entity} detected ({count} hit(s) across {len(per_entity_files[entity])} file(s))",
                evidence_count=count,
                sample_redacted=sample,
                secret_redacted=entity.startswith("SECRET_"),
                tags=["pii"] if not entity.startswith("SECRET_") else ["pii", "secret"],
                raw_evidence_ref="raw/pii-scan/findings.csv",
            )
        )

    envelope["findings"] = findings
    envelope["summary"] = {
        "targets": [str(t) for t in targets],
        "files_scanned": files_scanned,
        "files_with_hits": len(file_counts),
        "hits": total_hits,
        "sample_rows_stored": len(all_hits),
        "sample_rows_truncated": samples_truncated,
        "max_samples_per_file": max_samples_per_file,
        "private_ips_skipped": private_ip_total,
        "entities_scanned": entities,
        **{f"entity_{k}": v for k, v in entity_counts.items()},
    }
    return envelope, all_hits


def default_targets(raw_root: Path, tp: paths.ToolPaths) -> list[Path]:
    """Resolve scan targets when no --target is given.

    The chat-history export under raw_root (when a chat-history run produced
    one) plus every native chat-history location that exists on this machine.
    """
    candidates = [
        raw_root / "chat-history",
        tp.claude_projects,
        tp.codex_sessions,
        tp.cursor_projects,
        tp.grok_sessions,
    ]
    return [c for c in candidates if c.exists()]


def main() -> None:
    parser = argparse.ArgumentParser(description="Stdlib PII scan collector")
    add_base_args(parser)
    paths.add_path_args(parser)
    parser.add_argument(
        "--target",
        action="append",
        dest="targets",
        metavar="DIR",
        help="Directory tree to scan (repeatable). Default: <raw-root>/chat-history "
        "plus native chat locations (Claude/Codex/Cursor/Grok) that exist.",
    )
    parser.add_argument(
        "--entities",
        default=",".join(DEFAULT_ENTITIES),
        help=f"Comma-separated entity types (supported: {', '.join(DETECTORS)})",
    )
    parser.add_argument(
        "--max-samples-per-file",
        type=int,
        default=25,
        help="Max stored sample rows per entity type per file (true counts are "
        "always complete; this only caps findings.csv detail rows). Default 25.",
    )
    args = parser.parse_args()

    evidence_root = validate_evidence_root(args.evidence_root)
    raw_root = resolve_raw_root(evidence_root, args.raw_root)
    raw_dir = raw_root / "pii-scan"
    if args.targets:
        targets = [Path(t).expanduser().resolve() for t in args.targets]
    else:
        targets = default_targets(raw_root, paths.resolve_from_args(args))
        if not targets:
            parser.error(
                "no default targets found (no chat-history export under the raw "
                "root and no native chat locations detected); pass --target DIR"
            )
    entities = [e.strip().upper() for e in args.entities.split(",") if e.strip()]
    unknown = [e for e in entities if e not in DETECTORS]
    if unknown:
        parser.error(f"unknown entities: {unknown}; supported: {list(DETECTORS)}")

    envelope, hits = collect(
        targets, entities, raw_dir,
        max_samples_per_file=max(1, args.max_samples_per_file),
    )

    finish_collector(envelope, evidence_root, dry_run=args.dry_run)

    if not args.dry_run:
        print(
            f"PII scan: {envelope['summary'].get('files_scanned', 0)} files scanned, "
            f"{envelope['summary'].get('hits', 0)} hits. "
            f"Details: {raw_dir / 'summary.md'}"
        )


if __name__ == "__main__":
    main()
