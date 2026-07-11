"""
PII scanner collector (Microsoft Presidio).

Scans one or more target directory trees for personally identifiable information
using presidio-analyzer (regex + spaCy NER + context words) plus the secret
patterns from common. Designed for the personal chat-history use case but works
on any text corpus.

Usage:
    python pii-scan.py --evidence-root ./out
    python pii-scan.py --evidence-root ./out --target "C:\\Users\\me\\cursor-projects\\chat_history"
    python pii-scan.py --evidence-root ./out --target ./corpus --min-score 0.6 --entities EMAIL_ADDRESS,PHONE_NUMBER
    python pii-scan.py --evidence-root ./out --target ./dir1 --target ./dir2

With no --target, scans the chat-history export (<raw-root>/chat-history, if a
chat-history run left one) plus the native chat-history locations resolved via
paths.py (Claude projects, Codex sessions, Cursor projects, Grok sessions).

Outputs:
    <evidence-root>/evidence/pii-scan.json  (envelope, severity findings only)
    <evidence-root>/raw/pii-scan/findings.csv  (one row per hit, redacted)
    <evidence-root>/raw/pii-scan/summary.md  (human-readable rollup)

Requires:
    pip install presidio-analyzer presidio-anonymizer spacy
    python -m spacy download en_core_web_lg   (or en_core_web_sm for faster/smaller)
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

import paths
from common import (
    add_base_args,
    compute_scope_hash,
    finish_collector,
    looks_like_secret,
    make_envelope,
    make_finding,
    redact_sample,
    resolve_raw_root,
    secret_types_in,
    validate_evidence_root,
)

__version__ = "1.0.0"

COLLECTOR = "pii-scan"

TEXT_EXTENSIONS = {
    ".md", ".markdown", ".txt", ".json", ".jsonl", ".ndjson",
    ".csv", ".tsv", ".log", ".yaml", ".yml", ".html", ".htm",
}

DEFAULT_ENTITIES = [
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "US_SSN",
    "US_PASSPORT",
    "US_DRIVER_LICENSE",
    "US_BANK_NUMBER",
    "US_ITIN",
    "IBAN_CODE",
    "IP_ADDRESS",
    "PERSON",
    "LOCATION",
    "DATE_TIME",
    "URL",
    "MEDICAL_LICENSE",
    "CRYPTO",
]

SEVERITY_BY_ENTITY = {
    "CREDIT_CARD": "critical",
    "US_SSN": "critical",
    "US_PASSPORT": "critical",
    "US_BANK_NUMBER": "critical",
    "US_ITIN": "critical",
    "IBAN_CODE": "critical",
    "CRYPTO": "critical",
    "MEDICAL_LICENSE": "high",
    "US_DRIVER_LICENSE": "high",
    "EMAIL_ADDRESS": "medium",
    "PHONE_NUMBER": "medium",
    "IP_ADDRESS": "medium",
    "PERSON": "low",
    "LOCATION": "low",
    "DATE_TIME": "low",
    "URL": "low",
}

MAX_FILE_BYTES = 5 * 1024 * 1024
CHUNK_CHARS = 20_000


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


def chunk_text(text: str, size: int = CHUNK_CHARS) -> Iterable[tuple[int, str]]:
    for offset in range(0, len(text), size):
        yield offset, text[offset : offset + size]


def severity_for(entity: str) -> str:
    return SEVERITY_BY_ENTITY.get(entity, "medium")


def build_analyzer(entities: list[str]):
    try:
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider
    except ImportError as exc:
        raise RuntimeError(
            "presidio-analyzer is not installed. Run: pip install -r requirements.txt "
            "and python -m spacy download en_core_web_lg"
        ) from exc

    model = _resolve_spacy_model()
    provider = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": model}],
        }
    )
    nlp_engine = provider.create_engine()
    return AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])


def _resolve_spacy_model() -> str:
    import importlib.util

    for candidate in ("en_core_web_lg", "en_core_web_md", "en_core_web_sm"):
        if importlib.util.find_spec(candidate) is not None:
            return candidate
    raise RuntimeError(
        "No spaCy English model installed. Run: python -m spacy download en_core_web_lg"
    )


def scan_file(analyzer, path: Path, entities: list[str], min_score: float) -> list[dict]:
    text = read_text(path)
    if not text:
        return []

    hits: list[dict] = []
    for offset, chunk in chunk_text(text):
        try:
            results = analyzer.analyze(text=chunk, entities=entities, language="en")
        except Exception as exc:
            hits.append(
                {
                    "file": str(path),
                    "entity": "ANALYZER_ERROR",
                    "score": 0.0,
                    "start": 0,
                    "end": 0,
                    "sample": str(exc)[:120],
                }
            )
            continue

        for result in results:
            if result.score < min_score:
                continue
            sample = chunk[result.start : result.end]
            hits.append(
                {
                    "file": str(path),
                    "entity": result.entity_type,
                    "score": round(float(result.score), 3),
                    "start": offset + result.start,
                    "end": offset + result.end,
                    "sample": sample,
                }
            )

        for secret_type in secret_types_in(chunk):
            hits.append(
                {
                    "file": str(path),
                    "entity": f"SECRET_{secret_type.upper()}",
                    "score": 1.0,
                    "start": offset,
                    "end": offset,
                    "sample": secret_type,
                }
            )

    return hits


def write_raw_outputs(raw_dir: Path, hits: list[dict], entity_counts: Counter, file_counts: Counter) -> None:
    raw_dir.mkdir(parents=True, exist_ok=True)
    csv_path = raw_dir / "findings.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["file", "entity", "score", "start", "end", "sample_redacted"])
        for hit in hits:
            writer.writerow(
                [
                    hit["file"],
                    hit["entity"],
                    hit["score"],
                    hit["start"],
                    hit["end"],
                    redact_sample(hit["sample"], hit["entity"]),
                ]
            )

    summary_path = raw_dir / "summary.md"
    lines = ["# PII scan summary", ""]
    lines.append(f"- Total hits: {len(hits)}")
    lines.append(f"- Files with hits: {len(file_counts)}")
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


def collect(targets: list[Path], entities: list[str], min_score: float, raw_dir: Path) -> tuple[dict, list[dict]]:
    # Check Presidio availability first — emit tool_unavailable and exit cleanly if missing.
    try:
        from presidio_analyzer import AnalyzerEngine  # noqa: F401
    except ImportError:
        scope_hash = compute_scope_hash(str(t) for t in targets)
        envelope = make_envelope(COLLECTOR, __version__, scope_hash, platform_detected=bool(targets))
        envelope["findings"] = [
            make_finding(
                "pii-scan.tool_unavailable",
                "medium",
                "PII Exposure",
                "presidio-analyzer is not installed; PII scan skipped. "
                "Run: pip install presidio-analyzer presidio-anonymizer spacy && "
                "python -m spacy download en_core_web_lg",
                tags=["env_read"],
            )
        ]
        envelope["summary"] = {"scanner": "none", "hits": 0, "targets": len(targets)}
        return envelope, []

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

    print(
        f"pii-scan: loading NLP model ({_resolve_spacy_model()})...",
        file=sys.stderr, flush=True,
    )
    analyzer = build_analyzer(entities)

    all_hits: list[dict] = []
    files_scanned = 0
    entity_counts: Counter[str] = Counter()
    file_counts: Counter[str] = Counter()
    per_entity_files: dict[str, set[str]] = defaultdict(set)

    # Progress goes to stderr: aiscan.ps1 suppresses collector stdout but
    # passes stderr through, and a Presidio pass over a real chat corpus
    # runs for minutes with nothing else to show for it.
    for target in existing_targets:
        target_files = list(iter_text_files(target))
        print(
            f"pii-scan: scanning {len(target_files)} file(s) in target "
            f"{existing_targets.index(target) + 1}/{len(existing_targets)}",
            file=sys.stderr, flush=True,
        )
        for file_path in target_files:
            files_scanned += 1
            if files_scanned % 25 == 0:
                print(
                    f"pii-scan: {files_scanned} files scanned, {len(all_hits)} hits so far",
                    file=sys.stderr, flush=True,
                )
            hits = scan_file(analyzer, file_path, entities, min_score)
            if not hits:
                continue
            all_hits.extend(hits)
            file_counts[str(file_path)] += len(hits)
            for hit in hits:
                entity_counts[hit["entity"]] += 1
                per_entity_files[hit["entity"]].add(str(file_path))
    print(
        f"pii-scan: done. {files_scanned} files scanned, {len(all_hits)} hits.",
        file=sys.stderr, flush=True,
    )

    write_raw_outputs(raw_dir, all_hits, entity_counts, file_counts)

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
        "hits": len(all_hits),
        "min_score": min_score,
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
    parser = argparse.ArgumentParser(description="Presidio PII scan collector")
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
        help="Comma-separated Presidio entity types",
    )
    parser.add_argument(
        "--min-score",
        type=float,
        default=0.5,
        help="Minimum analyzer confidence (0.0-1.0)",
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
    entities = [e.strip() for e in args.entities.split(",") if e.strip()]

    try:
        envelope, hits = collect(targets, entities, args.min_score, raw_dir)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)

    finish_collector(envelope, evidence_root, dry_run=args.dry_run)

    if not args.dry_run:
        print(
            f"PII scan: {envelope['summary'].get('files_scanned', 0)} files scanned, "
            f"{envelope['summary'].get('hits', 0)} hits. "
            f"Details: {raw_dir / 'summary.md'}"
        )


if __name__ == "__main__":
    main()
