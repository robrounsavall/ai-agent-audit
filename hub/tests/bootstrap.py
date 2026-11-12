"""Path bootstrap and shared builders for hub tests."""
from __future__ import annotations

import sys
from pathlib import Path

HUB_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = HUB_DIR.parent
if str(HUB_DIR) not in sys.path:
    sys.path.insert(0, str(HUB_DIR))

import hub_paths  # noqa: E402,F401  (adds core/ to sys.path)


def finding(fid: str, severity: str = "high", title: str = "", **extra) -> dict:
    data = {
        "id": fid, "severity": severity, "category": "Shell Execution",
        "title": title or f"Title for {fid}", "evidence_count": 1,
        "first_seen": "", "last_seen": "", "sample_redacted": "", "secret_redacted": False, "tags": [],
    }
    data.update(extra)
    return data


def envelope(collector: str, ran_at: str, findings=(), rules=(), host: str = "TEST-HOST", **extra) -> dict:
    data = {
        "collector": collector, "version": "1.0.0", "ran_at": ran_at, "host": host,
        "platform_detected": True, "scope_hash": "abcd", "summary": {},
        "findings": list(findings), "rules": list(rules), "raw_pointers": [],
    }
    data.update(extra)
    return data


def raw_bundle(ran_at: str, collectors: dict, host: str = "TEST-HOST") -> dict:
    """An unnormalized bundle. ``collectors`` maps name -> findings list or envelope."""
    return {
        "bundle_version": 1,
        "host": host,
        "collectors": {
            name: value if isinstance(value, dict) else envelope(name, ran_at, value, host=host)
            for name, value in collectors.items()
        },
    }


def allow_rule(rule: str, risk: str = "high", rule_type: str = "bash") -> dict:
    return {
        "platform": "claude", "scope": "user", "scope_label_redacted": "user:global",
        "rule_type": rule_type, "rule": rule, "decision": "allow",
        "command_or_tool_redacted": rule, "risk": risk, "exposure_category": "Shell Execution",
    }
