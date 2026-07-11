"""
Shared helpers for aiscan collectors.

Sanitization, envelope construction, atomic evidence writes, and CLI utilities.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

USERPROFILE = Path(os.environ.get("USERPROFILE", Path.home()))
APPDATA = Path(os.environ.get("APPDATA", USERPROFILE / "AppData" / "Roaming"))

# Common developer code roots checked by git-posture and secrets-scan when no
# --repo-roots is given. Directory names only; each is used iff it exists.
DEFAULT_REPO_ROOT_NAMES = (
    "repos", "code", "src", "projects", "source", "dev", "git", "work",
    "workspace", "cursor-projects",
)
DEFAULT_REPO_ROOT_EXTRA = (
    ("Documents", "GitHub"),
    ("Documents", "repos"),
)


def default_repo_roots() -> list[Path]:
    """Return the default repo roots that exist under the user profile."""
    roots = [USERPROFILE / name for name in DEFAULT_REPO_ROOT_NAMES]
    roots += [USERPROFILE.joinpath(*parts) for parts in DEFAULT_REPO_ROOT_EXTRA]
    return [r for r in roots if r.exists()]

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_pat", re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    (
        "generic_secret",
        re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{32,}(?![A-Za-z0-9+/=])"),
    ),
    ("hex_secret", re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32,}(?![A-Fa-f0-9])")),
]

EXPOSURE_CATEGORIES = {
    "bash": "Shell Execution",
    "powershell": "Shell Execution",
    "mcp_tool": "MCP Tooling",
    "web_fetch": "Network Egress",
    "edit": "Data Access",
    "approval_event": "Shell Execution",
    "other": "General Tooling",
}


def sha256_short(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def sha256_full(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def redact_scope_label(name: str, scope: str) -> str:
    label = name or "unknown"
    if redaction_disabled():
        # Local aiscan output may show a readable project/user label, but keep it
        # to the final path segment so full filesystem paths still stay out of
        # report tables.
        safe_label = label.rstrip("\\/")
        safe_label = re.split(r"[\\/]", safe_label)[-1] or "unknown"
        if scope == "user" and safe_label in {"global", "session", "session_snapshot"}:
            return f"user:{safe_label}"
        return f"{scope}:{safe_label}"
    return f"{scope}#{sha256_short(label)}"


def _is_plausible_secret(secret_type: str, value: str) -> bool:
    """Reject false positives from the length-only matchers.

    The generic/hex matchers fire on any 32+ char run, which also catches long
    camelCase identifiers (e.g. "skipDangerousModePermissionPrompt=") where the
    char class swallowed a trailing assignment '='. A real base64/hex key or
    token of that length always carries a digit; a word does not. The structured
    matchers (aws/github/slack) are specific enough to trust as-is.
    """
    if secret_type in ("generic_secret", "hex_secret"):
        return any(c.isdigit() for c in value)
    return True


def _mask_match(secret_type: str, match: re.Match[str]) -> str:
    value = match.group(0)
    if _is_plausible_secret(secret_type, value):
        return f"****REDACTED:{secret_type}****"
    return value


def mask_secrets(text: str) -> str:
    if not text:
        return text
    masked = text
    for secret_type, pattern in SECRET_PATTERNS:
        masked = pattern.sub(
            lambda m, st=secret_type: _mask_match(st, m), masked
        )
    return masked


def looks_like_secret(text: str) -> bool:
    if not text:
        return False
    return any(
        _is_plausible_secret(name, m.group(0))
        for name, pattern in SECRET_PATTERNS
        for m in pattern.finditer(text)
    )


def secret_types_in(text: str) -> list[str]:
    return [
        name
        for name, pattern in SECRET_PATTERNS
        if any(_is_plausible_secret(name, m.group(0)) for m in pattern.finditer(text))
    ]


# Generic absolute-path matcher. Segments deliberately exclude whitespace so the
# match does not run past a path into surrounding prose. The running operator's
# own profile (which may contain spaces, e.g. "Test User") is handled by
# the literal pass in redact_paths() before this regex runs.
_GENERIC_PATH_RE = re.compile(
    r"""(?ix)
    (?:
        [A-Za-z]:[\\/](?:[^\\/:*?"<>|\r\n\s]+[\\/]?)+   # Windows  C:\a\b
      | /mnt/[a-z]/(?:[^/\0"'\r\n\s]+/?)+                # WSL      /mnt/c/a/b
      | /(?:home|Users)/(?:[^/\0"'\r\n\s]+/?)+           # POSIX    /home/x  /Users/x
    )
    """
)


def _hash_path(raw: str) -> str:
    norm = raw.rstrip("\\/").replace("\\", "/").lower()
    return f"<path#{sha256_short(norm)}>"


def redact_paths(text: str) -> str:
    """Replace identifying filesystem paths with stable hashed tokens.

    Two passes:
      1. Literal removal of the running user's profile dir and bare username
         across Windows, WSL, mac, and POSIX forms. This catches usernames that
         contain spaces, which the generic regex cannot.
      2. Generic absolute paths (other users, no-space segments) -> <path#hash>.

    Deterministic: the same path always maps to the same token, so evidence
    stays correlatable without exposing the value. Applied centrally by
    make_rule() and make_finding(); collectors do not call it directly.
    """
    if not text:
        return text

    out = text
    user = USERPROFILE.name
    profile = str(USERPROFILE)
    drive = profile[0].lower() if profile[1:2] == ":" else "c"
    variants = {
        profile,
        profile.replace("\\", "/"),
        f"/mnt/{drive}/Users/{user}",
        f"/home/{user}",
        f"/Users/{user}",
    }
    for variant in sorted((v for v in variants if v), key=len, reverse=True):
        out = re.sub(re.escape(variant), "<userprofile>", out, flags=re.IGNORECASE)

    if user:
        out = re.sub(re.escape(user), "<user>", out, flags=re.IGNORECASE)

    out = _GENERIC_PATH_RE.sub(lambda m: _hash_path(m.group(0)), out)
    return out


def redaction_disabled() -> bool:
    """True when AISCAN_NO_REDACT is set to a truthy value.

    Local aiscan runs on the operator's own machine, where masking real rules and
    paths only hides the thing being inspected. aiscan.ps1 sets this by default
    (pass -Redact to mask). Leave it unset for output you intend to share.
    """
    return os.environ.get("AISCAN_NO_REDACT", "").strip().lower() in ("1", "true", "yes")


def sanitize_text(text: str) -> str:
    """Defense-in-depth: redact identifying paths, then mask secret values."""
    if redaction_disabled():
        return text
    return mask_secrets(redact_paths(text))


def hostname_short() -> str:
    return socket.gethostname().split(".")[0]


def compute_scope_hash(paths: Iterable[str | Path]) -> str:
    normalized = sorted({str(Path(p).resolve()) for p in paths if p})
    payload = "\n".join(normalized)
    return sha256_full(payload)


def make_envelope(
    collector: str,
    version: str,
    scope_hash: str,
    *,
    platform_detected: bool = True,
    host: str | None = None,
) -> dict[str, Any]:
    return {
        "collector": collector,
        "version": version,
        "ran_at": datetime.now().astimezone().isoformat(),
        "host": host or hostname_short(),
        "platform_detected": platform_detected,
        "scope_hash": scope_hash,
        "summary": {},
        "findings": [],
        "rules": [],
        "raw_pointers": [],
    }


def write_evidence(envelope: dict[str, Any], evidence_root: str | Path) -> Path:
    root = Path(evidence_root)
    out_dir = root / "evidence"
    out_dir.mkdir(parents=True, exist_ok=True)
    collector = envelope["collector"]
    dest = out_dir / f"{collector}.json"
    fd, tmp_name = tempfile.mkstemp(suffix=".json", dir=out_dir)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(envelope, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        tmp_path.replace(dest)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
    return dest


def add_base_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--evidence-root",
        required=True,
        help="Parent directory; writes to <root>/evidence/<collector>.json",
    )
    parser.add_argument(
        "--raw-root",
        default=None,
        help="Override raw artifact root (default: <evidence-root>/raw/)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Scan and print summary; write nothing",
    )
    parser.add_argument(
        "--scope",
        choices=["user", "workspace", "all"],
        default="all",
        help="Scope filter for workspace vs user settings",
    )


def validate_evidence_root(path: str | Path) -> Path:
    root = Path(path)
    if not root.exists():
        print(f"Error: --evidence-root does not exist: {root}", file=sys.stderr)
        sys.exit(1)
    return root


def resolve_raw_root(evidence_root: str | Path, raw_root: str | Path | None) -> Path:
    if raw_root:
        return Path(raw_root)
    return Path(evidence_root) / "raw"


def parse_iso(value: Any) -> str:
    if not value:
        return ""
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).isoformat()
    except ValueError:
        return str(value)


def classify_rule(rule: str) -> tuple[str, str, str]:
    if rule.startswith("Bash(") and rule.endswith(")"):
        inner = rule[5:-1]
        command = inner.split(None, 1)[0] if inner.strip() else "Bash"
        return "bash", command, inner
    if rule.startswith("PowerShell(") and rule.endswith(")"):
        inner = rule[11:-1]
        command = inner.split(None, 1)[0] if inner.strip() else "PowerShell"
        return "powershell", command, inner
    if rule.startswith("mcp__"):
        parts = rule.split("__")
        server = parts[1] if len(parts) > 1 else ""
        tool = parts[2] if len(parts) > 2 else rule
        return "mcp_tool", server, tool
    if rule.startswith("WebFetch("):
        return "web_fetch", "WebFetch", rule
    if rule.startswith("Edit("):
        return "edit", "Edit", rule
    return "other", rule.split("(", 1)[0], rule


def rule_risk(rule: str) -> str:
    low = rule.lower()
    critical_bits = [
        "bypasspermissions",
        "dangerously-skip-permissions",
        "skipdangerousmodepermissionprompt=true",
    ]
    high_bits = [
        "curl *",
        "curl:*",
        "wget *",
        "wget:*",
        "docker run *",
        "docker compose *",
        "pip install",
        "npm install",
        "powershell",
        "setx ",
        "rm ",
        "del ",
        "remove-item",
    ]
    if any(bit in low for bit in critical_bits):
        return "critical"
    if any(bit in low for bit in high_bits):
        return "high"
    if "*" in rule or low.startswith("mcp__"):
        return "medium"
    return "low"


def exposure_for_rule_type(rule_type: str) -> str:
    return EXPOSURE_CATEGORIES.get(rule_type, "General Tooling")


def make_finding(
    finding_id: str,
    severity: str,
    category: str,
    title: str,
    *,
    evidence_count: int = 1,
    first_seen: str = "",
    last_seen: str = "",
    sample_redacted: str = "",
    secret_redacted: bool = False,
    tags: list[str] | None = None,
    raw_evidence_ref: str | None = None,
) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "id": finding_id,
        "severity": severity,
        "category": category,
        "title": title,
        "evidence_count": evidence_count,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "sample_redacted": sanitize_text(sample_redacted),
        "secret_redacted": secret_redacted,
        "tags": tags or [],
    }
    if raw_evidence_ref:
        finding["raw_evidence_ref"] = raw_evidence_ref
    return finding


def make_rule(
    platform: str,
    scope: str,
    scope_label: str,
    rule_type: str,
    rule: str,
    decision: str,
    *,
    command_or_tool: str = "",
    risk: str | None = None,
    exposure_category: str | None = None,
    source_kind: str | None = None,
    settings_source: str | None = None,
    confidence: str | None = None,
) -> dict[str, Any]:
    resolved_risk = risk or rule_risk(rule)
    rule_obj: dict[str, Any] = {
        "platform": platform,
        "scope": scope,
        "scope_label_redacted": redact_scope_label(scope_label, scope),
        "rule_type": rule_type,
        "rule": sanitize_text(rule),
        "decision": decision,
        "command_or_tool_redacted": sanitize_text(command_or_tool or rule),
        "risk": resolved_risk,
        "exposure_category": exposure_category or exposure_for_rule_type(rule_type),
    }
    # Optional source metadata (SCHEMA.md). source_kind: user_config | project_config
    # | session_prefix | session_event. confidence: high | medium | observed_event.
    if source_kind is not None:
        rule_obj["source_kind"] = source_kind
    if settings_source is not None:
        rule_obj["settings_source"] = settings_source
    if confidence is not None:
        rule_obj["confidence"] = confidence
    return rule_obj


def load_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def iter_jsonl(path: Path):
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_no, raw in enumerate(handle, 1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    yield line_no, json.loads(raw)
                except json.JSONDecodeError:
                    continue
    except OSError:
        return


def nested_text(value: Any) -> str:
    chunks: list[str] = []

    def walk(item: Any) -> None:
        if isinstance(item, str):
            chunks.append(item)
        elif isinstance(item, dict):
            for child in item.values():
                walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)

    walk(value)
    return "\n".join(chunks)


def redact_sample(secret: str, secret_type: str = "generic") -> str:
    secret = secret.strip()
    if len(secret) <= 8:
        return f"****REDACTED:{secret_type}****"
    return f"{secret[:4]}...{secret[-4:]} ({secret_type})"


def finish_collector(
    envelope: dict[str, Any],
    evidence_root: Path,
    *,
    dry_run: bool = False,
) -> None:
    if dry_run:
        print(json.dumps(envelope, indent=2, ensure_ascii=False))
        return
    path = write_evidence(envelope, evidence_root)
    print(f"Wrote {path}")
