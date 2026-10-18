"""
GitHub Copilot settings collector.

Usage:
    python copilot.py --evidence-root ./audit-run [--dry-run]

Reads VS Code and JetBrains Copilot configuration for enable state, exclusions,
telemetry, and public-code suggestion policy.
"""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from common import (
    APPDATA,
    add_base_args,
    compute_scope_hash,
    finish_collector,
    make_envelope,
    make_finding,
    make_rule,
    read_json_object,
    validate_evidence_root,
)

__version__ = "1.1.0"

COLLECTOR = "copilot"
VSCODE_SETTINGS = APPDATA / "Code" / "User" / "settings.json"
COPILOT_STORAGE = APPDATA / "Code" / "User" / "globalStorage" / "github.copilot"
JETBRAINS_ROOT = APPDATA / "JetBrains"

# Fixed labels only. organizationLogin and any other free-text field stay out
# of the summary; an unrecognized sku/plan is ignored rather than copied.
_SKU_ALIASES = {
    "free": "free",
    "individual": "individual",
    "pro": "individual",
    "pro_plus": "individual",
    "individual_or_business": "individual_or_business",
    "business": "business",
    "team": "business",
    "enterprise": "enterprise",
    "signed_in": "signed_in",
    "unknown": "unknown",
}


def _sku_alias(value: object) -> str:
    if not isinstance(value, str):
        return ""
    token = value.strip().lower().replace("-", "_").replace(" ", "_")
    return _SKU_ALIASES.get(token, "")


def _sku_from_object(data: dict) -> str:
    mapped = _sku_alias(data.get("sku")) or _sku_alias(data.get("plan"))
    if mapped:
        return mapped
    if data.get("enterprise"):
        return "enterprise"
    # Presence of an org login means Business. The login string itself is not a sku.
    if data.get("organizationLogin"):
        return "business"
    return ""


def detect_sku() -> str:
    if not COPILOT_STORAGE.exists():
        return "unknown"
    for name in ("copilot-token", "copilot-chat-token"):
        if (COPILOT_STORAGE / name).exists():
            return "individual_or_business"
    try:
        storage_files = list(COPILOT_STORAGE.rglob("*.json"))
    except OSError:
        storage_files = []
    for path in storage_files:
        data, err = read_json_object(path)
        if err or not data:
            continue
        mapped = _sku_from_object(data)
        if mapped:
            return mapped
    signed_in = COPILOT_STORAGE / "copilot-user"
    if signed_in.exists():
        return "signed_in"
    return "unknown"


def _as_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    return None


def parse_vscode_settings(data: dict) -> tuple[list[dict], list[dict], dict]:
    rules: list[dict] = []
    findings: list[dict] = []
    summary: dict = {}

    enabled = data.get("github.copilot.enable")
    lang_map: dict[str, bool] = {}
    # VS Code stores this as {"*": true, "markdown": false}, not a bool.
    # bool({"*": false}) is True, which used to report a disabled install as on.
    if isinstance(enabled, dict):
        for key, value in enabled.items():
            if not isinstance(key, str):
                continue
            parsed = _as_bool(value)
            if parsed is not None:
                lang_map[key] = parsed
        summary["vscode_copilot_enabled"] = lang_map["*"] if "*" in lang_map else "unset"
    elif isinstance(enabled, bool):
        summary["vscode_copilot_enabled"] = enabled
    else:
        summary["vscode_copilot_enabled"] = "unset"

    for key, value in data.items():
        if not isinstance(key, str) or not key.startswith("github.copilot.enable."):
            continue
        lang = key.split(".")[-1]
        parsed = _as_bool(value)
        if parsed is None:
            continue
        lang_map[lang] = parsed

    for lang, value in lang_map.items():
        rules.append(
            make_rule(
                "copilot",
                "user",
                "vscode",
                "other",
                f"github.copilot.enable.{lang}",
                "allow" if value else "deny",
                command_or_tool=lang,
                risk="low",
                exposure_category="General Tooling",
            )
        )
    summary["language_overrides"] = len(lang_map)

    excludes = data.get("github.copilot.advanced.exclude", [])
    if isinstance(excludes, list):
        summary["exclude_patterns"] = len(excludes)
        for pattern in excludes:
            if isinstance(pattern, str):
                rules.append(
                    make_rule(
                        "copilot",
                        "user",
                        "vscode",
                        "other",
                        f"exclude:{pattern}",
                        "deny",
                        command_or_tool=pattern,
                        risk="low",
                        exposure_category="Data Access",
                    )
                )
        if not excludes:
            findings.append(
                make_finding(
                    "copilot.exclude.none_configured",
                    "medium",
                    "Source Code Egress",
                    "Copilot has no file exclusion patterns configured",
                    tags=["chat_plaintext"],
                )
            )

    public_code = data.get("github.copilot.advanced.publicCodeSuggestions")
    if public_code is None:
        public_code = data.get("github.copilot.advanced.publicCodeSuggestions.enabled")
    summary["public_code_suggestions"] = str(public_code) if public_code is not None else "unset"
    if public_code is True or str(public_code).lower() == "enabled":
        findings.append(
            make_finding(
                "copilot.public_code.enabled",
                "medium",
                "Source Code Egress",
                "Copilot public code suggestions are allowed",
                tags=["chat_plaintext"],
            )
        )

    telemetry = data.get("telemetry.telemetryLevel") or data.get("telemetry.enableTelemetry")
    summary["telemetry"] = str(telemetry) if telemetry is not None else "unset"
    sku = detect_sku()
    if telemetry and str(telemetry).lower() not in ("off", "false", "none"):
        if sku in ("business", "enterprise", "signed_in"):
            findings.append(
                make_finding(
                    "copilot.telemetry.enabled",
                    "low",
                    "Telemetry Configuration",
                    "Copilot telemetry enabled on Business or Enterprise SKU",
                    tags=["chat_plaintext"],
                )
            )

    return rules, findings, summary


def parse_jetbrains_xml(path: Path) -> tuple[list[dict], dict]:
    rules: list[dict] = []
    summary: dict = {"jetbrains_config": str(path.name)}
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except (OSError, ET.ParseError, UnicodeDecodeError):
        return rules, summary

    for elem in root.iter():
        tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
        value = elem.text or elem.get("value", "")
        if tag.lower() in ("enabled", "enable") or "copilot" in tag.lower():
            rules.append(
                make_rule(
                    "copilot",
                    "user",
                    "jetbrains",
                    "other",
                    f"{tag}={value}",
                    "allow" if str(value).lower() in ("true", "1", "yes") else "other",
                    command_or_tool=tag,
                    risk="low",
                )
            )
    return rules, summary


def collect() -> dict:
    scanned: list[str] = []
    if VSCODE_SETTINGS.exists():
        scanned.append(str(VSCODE_SETTINGS))
    if JETBRAINS_ROOT.exists():
        scanned.extend(str(p) for p in JETBRAINS_ROOT.glob("*/options/github-copilot.xml"))
    scope_hash = compute_scope_hash(scanned or [str(APPDATA / "Code")])

    vscode_exists = VSCODE_SETTINGS.exists()
    jetbrains_configs = list(JETBRAINS_ROOT.glob("*/options/github-copilot.xml")) if JETBRAINS_ROOT.exists() else []
    platform_detected = vscode_exists or bool(jetbrains_configs)

    envelope = make_envelope(
        COLLECTOR,
        __version__,
        scope_hash,
        platform_detected=platform_detected,
    )

    if not platform_detected:
        envelope["summary"] = {"platforms_found": 0}
        return envelope

    all_rules: list[dict] = []
    all_findings: list[dict] = []
    summary: dict = {"platforms_found": 0, "sku": detect_sku()}

    if vscode_exists:
        summary["platforms_found"] += 1
        data, err = read_json_object(VSCODE_SETTINGS)
        if err or data is None:
            all_findings.append(
                make_finding(
                    "copilot.config.parse_error",
                    "low",
                    "General Tooling",
                    "VS Code settings.json is present but could not be parsed",
                    sample_redacted=err or "unreadable",
                    tags=["config_parse_error"],
                )
            )
        else:
            rules, findings, vs_summary = parse_vscode_settings(data)
            all_rules.extend(rules)
            all_findings.extend(findings)
            summary.update(vs_summary)

    for jb_path in jetbrains_configs:
        summary["platforms_found"] += 1
        rules, jb_summary = parse_jetbrains_xml(jb_path)
        all_rules.extend(rules)
        summary.setdefault("jetbrains_products", []).append(jb_path.parent.parent.name)

    envelope["rules"] = all_rules
    envelope["findings"] = all_findings
    envelope["summary"] = summary
    envelope["summary"]["rules"] = len(all_rules)
    envelope["summary"]["findings"] = len(all_findings)
    return envelope


def main() -> None:
    parser = argparse.ArgumentParser(description="GitHub Copilot settings collector")
    add_base_args(parser)
    args = parser.parse_args()
    evidence_root = validate_evidence_root(args.evidence_root)

    envelope = collect()
    if not envelope["platform_detected"]:
        finish_collector(envelope, evidence_root, dry_run=args.dry_run)
        sys.exit(2)

    finish_collector(envelope, evidence_root, dry_run=args.dry_run)
    sys.exit(0)


if __name__ == "__main__":
    main()
