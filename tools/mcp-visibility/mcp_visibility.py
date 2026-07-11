#!/usr/bin/env python3
"""
Local-first MCP visibility tool.

This is intentionally outside the Phase 1 evidence pipeline. It inventories MCP
server registrations for local lab/testing use, prints real local paths by
default, and only masks obvious credential values.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
import tomllib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

VERSION = "0.1.0"

AUTH_KEY_RE = re.compile(r"(token|secret|key|password|bearer|auth)", re.I)
BEARER_RE = re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/\-=]{8,})")
AUTH_HEADER_RE = re.compile(r"(?i)(Authorization\s*:\s*)([^,\s]+(?:\s+[^,\s]+)?)")
URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.I)
ENV_REF_RE = re.compile(r"(\$\{[^}]+\}|%[A-Za-z_][A-Za-z0-9_]*%)")
TOKENISH_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{32,}(?![A-Za-z0-9+/=])")


def now_iso() -> str:
    return datetime.now().astimezone().isoformat()


def sha256_short(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def normalized_path(path: Path | str) -> str:
    return str(path).replace("\\", "/").lower()


def redact_path(path: str) -> str:
    userprofile = str(Path.home())
    out = path
    if userprofile:
        out = re.sub(re.escape(userprofile), "<userprofile>", out, flags=re.I)
    return out


def maybe_redact_path(path: Path | str, redact: bool) -> str:
    value = str(path)
    return redact_path(value) if redact else value


def mask_secret_text(value: Any) -> Any:
    """Mask obvious bearer/header/token values while preserving shape."""
    if not isinstance(value, str):
        return value
    out = BEARER_RE.sub("Bearer <redacted>", value)
    out = AUTH_HEADER_RE.sub(r"\1<redacted>", out)
    out = TOKENISH_RE.sub("<redacted>", out)
    return out


def sanitize_args(args: Any) -> list[str]:
    if not isinstance(args, list):
        return []
    return [str(mask_secret_text(item)) for item in args]


def load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        return None, str(exc)
    except json.JSONDecodeError as exc:
        return None, f"json parse error: {exc}"
    if not isinstance(data, dict):
        return None, "json root is not an object"
    return data, None


def load_toml(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except OSError as exc:
        return None, str(exc)
    except tomllib.TOMLDecodeError as exc:
        return None, f"toml parse error: {exc}"
    if not isinstance(data, dict):
        return None, "toml root is not an object"
    return data, None


def infer_transport(config: dict[str, Any] | None) -> str:
    if not isinstance(config, dict):
        return "reference"
    explicit = config.get("transport") or config.get("transportType") or config.get("type")
    if explicit:
        return str(explicit)
    if config.get("url"):
        return "http"
    if config.get("command"):
        return "stdio"
    return "unknown"


def extract_url(config: dict[str, Any] | None) -> str | None:
    if not isinstance(config, dict):
        return None
    direct = config.get("url") or config.get("serverUrl") or config.get("endpoint")
    if isinstance(direct, str) and direct:
        return mask_secret_text(direct)
    for item in config.get("args") or []:
        if not isinstance(item, str):
            continue
        match = URL_RE.search(item)
        if match:
            return mask_secret_text(match.group(0))
    return None


def endpoint_locality(url: str | None) -> str:
    if not url:
        return "command_only"
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return "unknown"
    low = host.lower()
    if low in {"localhost", "::1"}:
        return "localhost"
    try:
        ip = ipaddress.ip_address(low)
    except ValueError:
        if low.endswith(".local"):
            return "local_name"
        return "public_dns"
    if ip.is_loopback:
        return "localhost"
    if ip.is_private:
        return "private_ip"
    if ip.is_link_local:
        return "link_local"
    return "public_ip"


def endpoint_class(config: dict[str, Any] | None) -> str:
    url = extract_url(config)
    if url:
        return "url"
    if isinstance(config, dict) and config.get("command"):
        return "command_only"
    return "reference_only"


def classify_auth(config: dict[str, Any] | None) -> tuple[str, list[str], list[str], bool]:
    evidence: list[str] = []
    env_keys: list[str] = []
    secret_redacted = False
    if not isinstance(config, dict):
        return "none", evidence, env_keys, secret_redacted

    url = extract_url(config)
    locality = endpoint_locality(url)

    headers = config.get("headers")
    if isinstance(headers, dict) and headers:
        evidence.append("headers_object")
        for key, value in headers.items():
            key_text = str(key)
            if AUTH_KEY_RE.search(key_text):
                evidence.append(f"header_key:{key_text}")
            if isinstance(value, str) and (BEARER_RE.search(value) or TOKENISH_RE.search(value)):
                secret_redacted = True

    args = config.get("args") or []
    if isinstance(args, list):
        joined = " ".join(str(item) for item in args)
        if "--header" in joined.lower():
            evidence.append("args_header")
        if re.search(r"(?i)authorization|bearer", joined):
            evidence.append("args_header_authorization")
            secret_redacted = True

    env = config.get("env")
    env_has_secret_key = False
    env_has_reference = False
    if isinstance(env, dict):
        for key, value in env.items():
            env_keys.append(str(key))
            value_text = str(value)
            if AUTH_KEY_RE.search(str(key)):
                env_has_secret_key = True
                evidence.append(f"env_auth_key:{key}")
                if ENV_REF_RE.search(value_text):
                    env_has_reference = True
                elif value_text:
                    secret_redacted = True
            elif ENV_REF_RE.search(value_text):
                env_has_reference = True
                evidence.append(f"env_reference:{key}")
            elif TOKENISH_RE.search(value_text):
                env_has_secret_key = True
                secret_redacted = True
                evidence.append(f"env_secret_value:{key}")

    if url and locality in {"localhost", "private_ip", "link_local"}:
        evidence.append(f"url_{locality}")

    if "args_header_authorization" in evidence and locality == "localhost":
        return "localhost_with_bearer", evidence, sorted(env_keys), secret_redacted
    if any(item.startswith("header") or item.startswith("args_header") for item in evidence):
        return "header_configured", evidence, sorted(env_keys), secret_redacted
    if env_has_secret_key:
        return "env_configured", evidence, sorted(env_keys), secret_redacted
    if env_has_reference:
        return "env_var_reference", evidence, sorted(env_keys), secret_redacted
    if url and urlparse(url).scheme in {"http", "https"}:
        return "oauth_likely", evidence, sorted(env_keys), secret_redacted
    return "none", evidence, sorted(env_keys), secret_redacted


def config_fingerprint(config: dict[str, Any] | None) -> str:
    if not isinstance(config, dict):
        return sha256_short("reference")
    safe = {
        "command": config.get("command"),
        "args": sanitize_args(config.get("args")),
        "url": extract_url(config),
        "transport": infer_transport(config),
        "env_keys": sorted((config.get("env") or {}).keys()) if isinstance(config.get("env"), dict) else [],
        "headers_keys": sorted((config.get("headers") or {}).keys()) if isinstance(config.get("headers"), dict) else [],
    }
    return sha256_short(json.dumps(safe, sort_keys=True, ensure_ascii=False))


@dataclass
class SourceRecord:
    path: Path
    platform: str
    source_kind: str
    scope: str
    exists: bool
    parse_ok: bool = False
    error: str | None = None
    servers_found: int = 0

    def as_dict(self, redact: bool = False) -> dict[str, Any]:
        return {
            "path": maybe_redact_path(self.path, redact),
            "path_id": sha256_short(normalized_path(self.path)),
            "platform": self.platform,
            "source_kind": self.source_kind,
            "scope": self.scope,
            "exists": self.exists,
            "parse_ok": self.parse_ok,
            "error": self.error,
            "servers_found": self.servers_found,
        }


@dataclass
class ServerRecord:
    server_name: str
    platform: str
    scope: str
    source_file: Path
    source_kind: str
    config: dict[str, Any] | None = None
    scope_label: str = ""
    registered: bool = True
    reference_type: str | None = None
    effective_status: str = "unknown"
    status_basis: str = ""
    config_disabled_flag: bool | None = None
    explicit_enable: bool | None = None
    explicit_disable: bool | None = None
    duplicate_group: str = ""
    duplicate_of: list[str] = field(default_factory=list)
    definition_conflict: bool = False

    def finalize(self) -> None:
        if self.config_disabled_flag is None and isinstance(self.config, dict):
            disabled = self.config.get("disabled")
            if isinstance(disabled, bool):
                self.config_disabled_flag = disabled
            enabled = self.config.get("enabled")
            if isinstance(enabled, bool):
                self.explicit_enable = enabled
                self.explicit_disable = not enabled

    def as_dict(self, redact: bool = False) -> dict[str, Any]:
        self.finalize()
        command = self.config.get("command") if isinstance(self.config, dict) else None
        args = sanitize_args(self.config.get("args")) if isinstance(self.config, dict) else []
        url = extract_url(self.config)
        auth_status, auth_evidence, env_keys, secret_redacted = classify_auth(self.config)
        return {
            "server_name": self.server_name,
            "platform": self.platform,
            "scope": self.scope,
            "scope_label": self.scope_label,
            "source_file": maybe_redact_path(self.source_file, redact),
            "source_kind": self.source_kind,
            "source_path_id": sha256_short(normalized_path(self.source_file)),
            "registered": self.registered,
            "reference_type": self.reference_type,
            "transport": infer_transport(self.config),
            "endpoint_class": endpoint_class(self.config),
            "endpoint_locality": endpoint_locality(url),
            "command": mask_secret_text(command) if command else None,
            "args": args,
            "url": url,
            "config_disabled_flag": self.config_disabled_flag,
            "explicit_enable": self.explicit_enable,
            "explicit_disable": self.explicit_disable,
            "effective_status": self.effective_status,
            "status_basis": self.status_basis,
            "auth_status": auth_status,
            "auth_evidence": auth_evidence,
            "env_keys": env_keys,
            "secret_redacted": secret_redacted,
            "config_fingerprint": config_fingerprint(self.config),
            "duplicate_group": self.duplicate_group,
            "duplicate_of": self.duplicate_of,
            "definition_conflict": self.definition_conflict,
        }


def derive_cursor_status(config: dict[str, Any]) -> tuple[str, str, bool | None, bool | None, bool | None]:
    disabled_flag = config.get("disabled") if isinstance(config.get("disabled"), bool) else None
    enabled_flag = config.get("enabled") if isinstance(config.get("enabled"), bool) else None
    if disabled_flag is True:
        return "disabled", "cursor server block disabled=true", disabled_flag, enabled_flag, True
    if enabled_flag is False:
        return "disabled", "cursor server block enabled=false", disabled_flag, enabled_flag, True
    if enabled_flag is True:
        return "enabled", "cursor server block enabled=true", disabled_flag, enabled_flag, False
    return "enabled_implicit", "registered in Cursor MCP file", disabled_flag, enabled_flag, False


def derive_codex_status(config: dict[str, Any]) -> tuple[str, str, bool | None, bool | None, bool | None]:
    enabled_flag = config.get("enabled") if isinstance(config.get("enabled"), bool) else None
    if enabled_flag is False:
        return "disabled", "config.toml enabled=false", None, False, True
    if enabled_flag is True:
        return "enabled", "config.toml enabled=true", None, True, False
    return "enabled_unspecified", "registered in config.toml with no enabled key", None, None, False


def derive_claude_status(
    name: str,
    config: dict[str, Any] | None,
    overlays: dict[str, set[str]] | None = None,
    *,
    registered: bool = True,
    reference_type: str | None = None,
) -> tuple[str, str, bool | None, bool | None, bool | None]:
    overlays = overlays or {}
    disabled = overlays.get("disabledMcpServers", set()) | overlays.get("disabledMcpjsonServers", set())
    enabled = overlays.get("enabledMcpjsonServers", set())
    config_disabled = None
    if isinstance(config, dict) and isinstance(config.get("disabled"), bool):
        config_disabled = config.get("disabled")
    if not registered and reference_type == "enabled":
        return "enabled_reference_only", "name appears in enabledMcpjsonServers but no matching definition was found in this scope", None, True, False
    if not registered and reference_type == "disabled":
        return "disabled_reference_only", "name appears in disabled MCP list but no matching definition was found in this scope", None, None, True
    if name in disabled:
        return "disabled", "name appears in Claude disabled MCP list", config_disabled, None, True
    if config_disabled is True:
        return "disabled_config_flag", "server block has disabled=true", config_disabled, None, True
    if enabled and name not in enabled:
        return "disabled_by_allowlist", "Claude enabledMcpjsonServers is non-empty and omits this server", config_disabled, None, True
    if enabled and name in enabled:
        return "enabled", "name appears in Claude enabledMcpjsonServers", config_disabled, True, False
    if registered:
        return "enabled_by_default", "registered in Claude MCP config with no disable overlay", config_disabled, None, False
    return "reference_only", "MCP name reference without server definition", None, None, None


def derive_shared_status() -> tuple[str, str, bool | None, bool | None, bool | None]:
    return "registered_unattributed", "registered in shared ~/.mcp.json; platform activation depends on client", None, None, None


def mcp_servers_from_json(data: dict[str, Any]) -> dict[str, Any]:
    servers = data.get("mcpServers")
    if isinstance(servers, dict):
        return servers
    return {}


def make_record(
    *,
    name: str,
    platform: str,
    scope: str,
    scope_label: str,
    source_file: Path,
    source_kind: str,
    config: dict[str, Any] | None,
    registered: bool = True,
    reference_type: str | None = None,
    overlays: dict[str, set[str]] | None = None,
) -> ServerRecord:
    rec = ServerRecord(
        server_name=name,
        platform=platform,
        scope=scope,
        scope_label=scope_label,
        source_file=source_file,
        source_kind=source_kind,
        config=config if isinstance(config, dict) else {},
        registered=registered,
        reference_type=reference_type,
    )
    if platform == "cursor":
        status = derive_cursor_status(rec.config or {})
    elif platform in ("codex", "grok"):
        status = derive_codex_status(rec.config or {})
    elif platform == "claude":
        status = derive_claude_status(name, rec.config, overlays, registered=registered, reference_type=reference_type)
    elif platform == "shared":
        status = derive_shared_status()
    else:
        status = ("unknown", "unknown platform", None, None, None)
    (
        rec.effective_status,
        rec.status_basis,
        rec.config_disabled_flag,
        rec.explicit_enable,
        rec.explicit_disable,
    ) = status
    return rec


def parse_mcp_json_source(
    path: Path,
    *,
    platform: str,
    source_kind: str,
    scope: str,
    scope_label: str,
) -> tuple[SourceRecord, list[ServerRecord]]:
    src = SourceRecord(path, platform, source_kind, scope, exists=path.exists())
    if not path.exists():
        return src, []
    data, err = load_json(path)
    if err:
        src.error = err
        return src, []
    src.parse_ok = True
    records = []
    for name, cfg in mcp_servers_from_json(data or {}).items():
        records.append(
            make_record(
                name=str(name),
                platform=platform,
                scope=scope,
                scope_label=scope_label,
                source_file=path,
                source_kind=source_kind,
                config=cfg if isinstance(cfg, dict) else {},
            )
        )
    src.servers_found = len(records)
    return src, records


def _overlay_set(data: dict[str, Any], key: str) -> set[str]:
    value = data.get(key)
    if isinstance(value, list):
        return {str(item) for item in value if isinstance(item, str)}
    return set()


def _project_overlays(project_data: dict[str, Any]) -> dict[str, set[str]]:
    return {
        "enabledMcpjsonServers": _overlay_set(project_data, "enabledMcpjsonServers"),
        "disabledMcpjsonServers": _overlay_set(project_data, "disabledMcpjsonServers"),
        "disabledMcpServers": _overlay_set(project_data, "disabledMcpServers"),
    }


def _reference_records(
    *,
    names: set[str],
    reference_type: str,
    already_defined: set[str],
    path: Path,
    source_kind: str,
    scope: str,
    scope_label: str,
    overlays: dict[str, set[str]],
) -> list[ServerRecord]:
    records = []
    for name in sorted(names - already_defined):
        records.append(
            make_record(
                name=name,
                platform="claude",
                scope=scope,
                scope_label=scope_label,
                source_file=path,
                source_kind=source_kind,
                config={},
                registered=False,
                reference_type=reference_type,
                overlays=overlays,
            )
        )
    return records


def parse_claude_json(path: Path) -> tuple[SourceRecord, list[ServerRecord]]:
    src = SourceRecord(path, "claude", "claude_json", "user", exists=path.exists())
    if not path.exists():
        return src, []
    data, err = load_json(path)
    if err:
        src.error = err
        return src, []
    src.parse_ok = True
    data = data or {}
    records: list[ServerRecord] = []
    top_overlays = _project_overlays(data)
    defined = set()
    for name, cfg in mcp_servers_from_json(data).items():
        defined.add(str(name))
        records.append(
            make_record(
                name=str(name),
                platform="claude",
                scope="user",
                scope_label="global",
                source_file=path,
                source_kind="claude_json",
                config=cfg if isinstance(cfg, dict) else {},
                overlays=top_overlays,
            )
        )
    records.extend(
        _reference_records(
            names=top_overlays["enabledMcpjsonServers"],
            reference_type="enabled",
            already_defined=defined,
            path=path,
            source_kind="claude_json",
            scope="user",
            scope_label="global",
            overlays=top_overlays,
        )
    )
    records.extend(
        _reference_records(
            names=top_overlays["disabledMcpjsonServers"] | top_overlays["disabledMcpServers"],
            reference_type="disabled",
            already_defined=defined,
            path=path,
            source_kind="claude_json",
            scope="user",
            scope_label="global",
            overlays=top_overlays,
        )
    )

    projects = data.get("projects")
    if isinstance(projects, dict):
        for project_path, project_data in projects.items():
            if not isinstance(project_data, dict):
                continue
            overlays = _project_overlays(project_data)
            project_defined = set()
            for name, cfg in mcp_servers_from_json(project_data).items():
                project_defined.add(str(name))
                records.append(
                    make_record(
                        name=str(name),
                        platform="claude",
                        scope="project",
                        scope_label=str(project_path),
                        source_file=path,
                        source_kind="claude_json",
                        config=cfg if isinstance(cfg, dict) else {},
                        overlays=overlays,
                    )
                )
            records.extend(
                _reference_records(
                    names=overlays["enabledMcpjsonServers"],
                    reference_type="enabled",
                    already_defined=project_defined,
                    path=path,
                    source_kind="claude_json",
                    scope="project",
                    scope_label=str(project_path),
                    overlays=overlays,
                )
            )
            records.extend(
                _reference_records(
                    names=overlays["disabledMcpjsonServers"] | overlays["disabledMcpServers"],
                    reference_type="disabled",
                    already_defined=project_defined,
                    path=path,
                    source_kind="claude_json",
                    scope="project",
                    scope_label=str(project_path),
                    overlays=overlays,
                )
            )

    src.servers_found = len(records)
    return src, records


def parse_claude_settings(path: Path) -> tuple[SourceRecord, list[ServerRecord]]:
    src = SourceRecord(path, "claude", "settings_json", "user", exists=path.exists())
    if not path.exists():
        return src, []
    data, err = load_json(path)
    if err:
        src.error = err
        return src, []
    src.parse_ok = True
    data = data or {}
    overlays = _project_overlays(data)
    records: list[ServerRecord] = []
    for name, cfg in mcp_servers_from_json(data).items():
        records.append(
            make_record(
                name=str(name),
                platform="claude",
                scope="user",
                scope_label="global",
                source_file=path,
                source_kind="settings_json",
                config=cfg if isinstance(cfg, dict) else {},
                overlays=overlays,
            )
        )
    defined = {r.server_name for r in records}
    records.extend(
        _reference_records(
            names=overlays["enabledMcpjsonServers"],
            reference_type="enabled",
            already_defined=defined,
            path=path,
            source_kind="settings_json",
            scope="user",
            scope_label="global",
            overlays=overlays,
        )
    )
    records.extend(
        _reference_records(
            names=overlays["disabledMcpjsonServers"] | overlays["disabledMcpServers"],
            reference_type="disabled",
            already_defined=defined,
            path=path,
            source_kind="settings_json",
            scope="user",
            scope_label="global",
            overlays=overlays,
        )
    )
    src.servers_found = len(records)
    return src, records


def parse_codex_toml_source(
    path: Path,
    *,
    scope: str,
    scope_label: str,
    platform: str = "codex",
) -> tuple[SourceRecord, list[ServerRecord]]:
    """Parse a `[mcp_servers.<name>]` TOML config file.

    Codex and Grok Build share the same TOML shape, so `platform` is
    parameterized (default "codex" preserves existing call sites).
    """
    src = SourceRecord(path, platform, "config_toml", scope, exists=path.exists())
    if not path.exists():
        return src, []
    data, err = load_toml(path)
    if err:
        src.error = err
        return src, []
    src.parse_ok = True
    records = []
    servers = (data or {}).get("mcp_servers")
    if isinstance(servers, dict):
        for name, cfg in servers.items():
            records.append(
                make_record(
                    name=str(name),
                    platform=platform,
                    scope=scope,
                    scope_label=scope_label,
                    source_file=path,
                    source_kind="config_toml",
                    config=cfg if isinstance(cfg, dict) else {},
                )
            )
    src.servers_found = len(records)
    return src, records


def default_repo_roots(home: Path) -> list[Path]:
    return [home / name for name in ("repos", "code", "src", "projects", "source") if (home / name).exists()]


def parse_repo_roots(raw: str | None, home: Path) -> list[Path]:
    if raw:
        return [Path(item.strip()).expanduser() for item in raw.split(",") if item.strip()]
    return default_repo_roots(home)


def fixed_sources(home: Path, appdata: Path) -> list[tuple[Path, str, str, str, str]]:
    return [
        (home / ".mcp.json", "shared", "global_mcp_json", "global", "global"),
        (home / ".cursor" / "mcp.json", "cursor", "cursor_mcp_json", "user", "global"),
        (appdata / "Cursor" / "mcp.json", "cursor", "cursor_mcp_json", "user", "appdata"),
        (home / ".claude.json", "claude", "claude_json", "user", "global"),
        (home / ".claude" / "settings.json", "claude", "settings_json", "user", "global"),
        (home / ".claude" / "settings.local.json", "claude", "settings_json", "user", "global"),
        (home / ".codex" / "config.toml", "codex", "config_toml", "user", "global"),
        (home / ".grok" / "config.toml", "grok", "config_toml", "user", "global"),
        (appdata / "Cursor" / "User" / "settings.json", "cursor", "settings_json", "user", "appdata"),
    ]


def scan_fixed_paths(home: Path, appdata: Path) -> tuple[list[SourceRecord], list[ServerRecord]]:
    sources: list[SourceRecord] = []
    records: list[ServerRecord] = []
    for path, platform, kind, scope, label in fixed_sources(home, appdata):
        if platform == "claude" and kind == "claude_json":
            src, recs = parse_claude_json(path)
        elif platform == "claude" and kind == "settings_json":
            src, recs = parse_claude_settings(path)
        elif platform == "codex":
            src, recs = parse_codex_toml_source(path, scope=scope, scope_label=label)
        elif platform == "grok":
            src, recs = parse_codex_toml_source(path, scope=scope, scope_label=label, platform="grok")
        elif kind.endswith("mcp_json") or kind == "global_mcp_json":
            src, recs = parse_mcp_json_source(
                path,
                platform=platform,
                source_kind=kind,
                scope=scope,
                scope_label=label,
            )
        else:
            src = SourceRecord(path, platform, kind, scope, exists=path.exists())
            if path.exists():
                _, err = load_json(path)
                src.parse_ok = err is None
                src.error = err
            recs = []
        sources.append(src)
        records.extend(recs)
    return sources, records


def scan_repo_roots(roots: list[Path]) -> tuple[list[SourceRecord], list[ServerRecord]]:
    sources: list[SourceRecord] = []
    records: list[ServerRecord] = []
    seen_paths: set[str] = set()
    for root in roots:
        if not root.exists():
            continue
        candidates: list[tuple[Path, str, str]] = []
        candidates.extend((p, "cursor", "cursor_mcp_json") for p in root.rglob(".cursor/mcp.json"))
        candidates.extend((p, "claude", "project_mcp_json") for p in root.rglob(".mcp.json"))
        candidates.extend((p, "codex", "config_toml") for p in root.rglob(".codex/config.toml"))
        candidates.extend((p, "grok", "config_toml") for p in root.rglob(".grok/config.toml"))
        for path, platform, kind in candidates:
            key = normalized_path(path)
            if key in seen_paths:
                continue
            seen_paths.add(key)
            try:
                scope_label = str(path.parent.parent if kind in {"cursor_mcp_json", "config_toml"} else path.parent)
            except OSError:
                scope_label = str(path)
            if platform == "codex":
                src, recs = parse_codex_toml_source(path, scope="project", scope_label=scope_label)
            elif platform == "grok":
                src, recs = parse_codex_toml_source(path, scope="project", scope_label=scope_label, platform="grok")
            else:
                src, recs = parse_mcp_json_source(
                    path,
                    platform=platform,
                    source_kind=kind,
                    scope="project",
                    scope_label=scope_label,
                )
            sources.append(src)
            records.extend(recs)
    return sources, records


def add_duplicate_metadata(records: list[ServerRecord]) -> None:
    by_name: dict[str, list[ServerRecord]] = {}
    for rec in records:
        by_name.setdefault(rec.server_name.lower(), []).append(rec)

    for name_key, group in by_name.items():
        if len(group) <= 1:
            group[0].duplicate_group = ""
            continue
        fingerprints = {config_fingerprint(rec.config) for rec in group if rec.registered}
        group_id = sha256_short(name_key)
        conflict = len(fingerprints) > 1
        refs = [
            f"{rec.platform}:{rec.scope}:{sha256_short(rec.scope_label)}:{sha256_short(normalized_path(rec.source_file))}"
            for rec in group
        ]
        for rec in group:
            own = f"{rec.platform}:{rec.scope}:{sha256_short(rec.scope_label)}:{sha256_short(normalized_path(rec.source_file))}"
            rec.duplicate_group = group_id
            rec.duplicate_of = [item for item in refs if item != own]
            rec.definition_conflict = conflict


def summarize(records: list[ServerRecord], sources: list[SourceRecord]) -> dict[str, Any]:
    rows = [rec.as_dict(False) for rec in records]
    by_status: dict[str, int] = {}
    by_auth: dict[str, int] = {}
    by_platform: dict[str, int] = {}
    by_name: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_status[row["effective_status"]] = by_status.get(row["effective_status"], 0) + 1
        by_auth[row["auth_status"]] = by_auth.get(row["auth_status"], 0) + 1
        by_platform[row["platform"]] = by_platform.get(row["platform"], 0) + 1
        by_name.setdefault(row["server_name"].lower(), []).append(row)
    duplicate_names = [
        group[0]["server_name"] for group in by_name.values() if len(group) > 1
    ]
    conflict_names = [
        group[0]["server_name"]
        for group in by_name.values()
        if any(row["definition_conflict"] for row in group)
    ]
    return {
        "sources_found": sum(1 for src in sources if src.exists),
        "sources_parse_errors": sum(1 for src in sources if src.exists and not src.parse_ok),
        "servers_total": len(records),
        "registered_servers": sum(1 for rec in records if rec.registered),
        "reference_only": sum(1 for rec in records if not rec.registered),
        "unique_server_names": len({rec.server_name.lower() for rec in records}),
        "duplicate_server_names": len(duplicate_names),
        "conflicting_server_names": len(conflict_names),
        "by_platform": dict(sorted(by_platform.items())),
        "by_effective_status": dict(sorted(by_status.items())),
        "by_auth_status": dict(sorted(by_auth.items())),
        "external_or_nonlocal": sum(
            1
            for row in rows
            if row["endpoint_locality"] in {"public_dns", "public_ip", "private_ip", "link_local"}
        ),
        "definition_conflicts": sum(1 for rec in records if rec.definition_conflict),
        "secrets_in_config": sum(1 for row in rows if row["secret_redacted"]),
    }


def collect_inventory(
    *,
    home: Path | None = None,
    appdata: Path | None = None,
    repo_roots: list[Path] | None = None,
    include_repo_roots: bool = True,
    redact: bool = False,
) -> dict[str, Any]:
    home = home or Path.home()
    appdata = appdata or Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))

    sources, records = scan_fixed_paths(home, appdata)
    if include_repo_roots:
        root_sources, root_records = scan_repo_roots(repo_roots if repo_roots is not None else default_repo_roots(home))
        sources.extend(root_sources)
        records.extend(root_records)

    add_duplicate_metadata(records)
    rows = [rec.as_dict(redact) for rec in records]
    rows.sort(key=lambda r: (r["server_name"].lower(), r["platform"], r["scope"], r["source_file"]))

    return {
        "tool": "mcp-visibility",
        "version": VERSION,
        "ran_at": now_iso(),
        "host": socket.gethostname().split(".")[0],
        "mode": "local-first",
        "redact_paths": redact,
        "sources_scanned": [src.as_dict(redact) for src in sources],
        "servers": rows,
        "summary": summarize(records, sources),
    }


def render_table(inventory: dict[str, Any]) -> str:
    rows = inventory.get("servers") or []
    if not rows:
        return "No MCP servers or references found."
    headers = ["server", "platform", "scope", "scope_label", "status", "auth", "locality", "source"]
    table_rows = []
    for row in rows:
        table_rows.append(
            [
                str(row.get("server_name") or ""),
                str(row.get("platform") or ""),
                str(row.get("scope") or ""),
                str(row.get("scope_label") or ""),
                str(row.get("effective_status") or ""),
                str(row.get("auth_status") or ""),
                str(row.get("endpoint_locality") or ""),
                str(row.get("source_file") or ""),
            ]
        )
    widths = [
        max(len(headers[idx]), *(len(row[idx]) for row in table_rows))
        for idx in range(len(headers))
    ]
    lines = ["  ".join(headers[idx].ljust(widths[idx]) for idx in range(len(headers)))]
    lines.append("  ".join("-" * width for width in widths))
    for row in table_rows:
        lines.append("  ".join(row[idx].ljust(widths[idx]) for idx in range(len(headers))))
    return "\n".join(lines)


def _count_map_text(values: dict[str, Any]) -> str:
    if not values:
        return "none"
    return ", ".join(f"{key}={value}" for key, value in sorted(values.items()))


def _source_ref(row: dict[str, Any]) -> str:
    scope = str(row.get("scope") or "")
    platform = str(row.get("platform") or "")
    status = str(row.get("effective_status") or "")
    label = str(row.get("scope_label") or "")
    if label and label != "global":
        label = Path(label.replace("\\", "/")).name
        return f"{platform}:{scope}:{label}:{status}"
    return f"{platform}:{scope}:{status}"


def _status_bucket(status: str) -> str:
    if status.startswith("enabled"):
        return "enabled"
    if status.startswith("disabled"):
        return "disabled"
    if status == "registered_unattributed":
        return "registered"
    return status or "unknown"


def _server_groups(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_name: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_name.setdefault(str(row.get("server_name") or "").lower(), []).append(row)
    groups = []
    for key, items in by_name.items():
        display_name = str(items[0].get("server_name") or key)
        registered = [row for row in items if row.get("registered")]
        refs = [row for row in items if not row.get("registered")]
        auth = sorted({str(row.get("auth_status") or "none") for row in items})
        statuses = sorted({_status_bucket(str(row.get("effective_status") or "")) for row in items})
        platforms = sorted({str(row.get("platform") or "") for row in items})
        groups.append(
            {
                "server": display_name,
                "rows": len(items),
                "registered": len(registered),
                "references": len(refs),
                "platforms": ", ".join(platforms),
                "statuses": ", ".join(statuses),
                "auth": ", ".join(auth),
                "conflict": any(bool(row.get("definition_conflict")) for row in items),
                "nonlocal": any(
                    row.get("endpoint_locality")
                    in {"public_dns", "public_ip", "private_ip", "link_local"}
                    for row in items
                ),
                "secret": any(bool(row.get("secret_redacted")) for row in items),
                "sources": sorted({_source_ref(row) for row in items}),
            }
        )
    groups.sort(key=lambda item: (not item["conflict"], item["server"].lower()))
    return groups


def _render_group_table(groups: list[dict[str, Any]]) -> str:
    if not groups:
        return "No MCP servers or references found."
    headers = ["server", "rows", "defs", "refs", "platforms", "status", "auth", "flags"]
    table_rows = []
    for group in groups:
        flags = []
        if group["conflict"]:
            flags.append("definition-drift")
        if group["nonlocal"]:
            flags.append("non-local")
        if group["secret"]:
            flags.append("secret-config")
        table_rows.append(
            [
                str(group["server"]),
                str(group["rows"]),
                str(group["registered"]),
                str(group["references"]),
                str(group["platforms"]),
                str(group["statuses"]),
                str(group["auth"]),
                ", ".join(flags) if flags else "-",
            ]
        )
    widths = [
        max(len(headers[idx]), *(len(row[idx]) for row in table_rows))
        for idx in range(len(headers))
    ]
    lines = ["  ".join(headers[idx].ljust(widths[idx]) for idx in range(len(headers)))]
    lines.append("  ".join("-" * width for width in widths))
    for row in table_rows:
        lines.append("  ".join(row[idx].ljust(widths[idx]) for idx in range(len(headers))))
    return "\n".join(lines)


def render_summary_report(inventory: dict[str, Any]) -> str:
    summary = inventory.get("summary") or {}
    rows = inventory.get("servers") or []
    groups = _server_groups(rows)
    conflicts = [group for group in groups if group["conflict"]]
    secret_groups = [group for group in groups if group["secret"]]
    nonlocal_groups = [group for group in groups if group["nonlocal"]]
    reference_only_groups = [
        group for group in groups if group["registered"] == 0 and group["references"] > 0
    ]

    lines = [
        "MCP Visibility Summary",
        "======================",
        "",
        f"Ran: {inventory.get('ran_at', 'unknown')} on {inventory.get('host', 'unknown')}",
        f"Sources: {summary.get('sources_found', 0)} found, {summary.get('sources_parse_errors', 0)} parse errors",
        (
            "Inventory: "
            f"{summary.get('servers_total', 0)} rows, "
            f"{summary.get('registered_servers', 0)} concrete definitions, "
            f"{summary.get('reference_only', 0)} reference-only entries, "
            f"{summary.get('unique_server_names', 0)} unique server names"
        ),
        f"Platforms: {_count_map_text(summary.get('by_platform') or {})}",
        f"Status: {_count_map_text(summary.get('by_effective_status') or {})}",
        f"Auth: {_count_map_text(summary.get('by_auth_status') or {})}",
        "",
        "Watch Items",
        "-----------",
    ]

    if conflicts:
        lines.append(
            "Definition drift: "
            + ", ".join(group["server"] for group in conflicts)
            + " (same server name, different command/args/url/env/header-key fingerprint)"
        )
    else:
        lines.append("Definition drift: none")

    if secret_groups:
        lines.append(
            "Secret/auth config: "
            + ", ".join(group["server"] for group in secret_groups)
            + " (credential-like value or auth header was detected and masked)"
        )
    else:
        lines.append("Secret/auth config: none")

    if nonlocal_groups:
        lines.append(
            "Non-local endpoints: "
            + ", ".join(group["server"] for group in nonlocal_groups)
        )
    else:
        lines.append("Non-local endpoints: none")

    if reference_only_groups:
        lines.append(
            "Reference-only names: "
            + ", ".join(group["server"] for group in reference_only_groups)
            + " (enable/disable overlay exists, but no definition in that scope)"
        )
    else:
        lines.append("Reference-only names: none")

    lines.extend(
        [
            "",
            "Server Groups",
            "-------------",
            _render_group_table(groups),
            "",
            "Duplicate Fields Explained",
            "--------------------------",
            (
                "A duplicate is not automatically bad. It means the same MCP server "
                "name appears in more than one place: for example shared ~/.mcp.json, "
                "Codex config, Claude project state, and Cursor project config."
            ),
            (
                "definition-drift is the useful warning: it means those same-name "
                "entries do not point to the exact same command/args/url/env/header-key "
                "shape. That can be intentional, but it is worth reviewing."
            ),
            (
                "reference-only means Claude recorded an enabled/disabled overlay for "
                "a name without a server definition in that same scope."
            ),
        ]
    )

    if conflicts:
        lines.extend(["", "Drift Detail", "------------"])
        for group in conflicts:
            lines.append(f"{group['server']}:")
            for source in group["sources"]:
                lines.append(f"  - {source}")

    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local MCP server visibility inventory")
    parser.add_argument("--output", default=None, help="Write JSON to this path instead of stdout")
    parser.add_argument("--format", choices=["json", "table", "summary"], default="json")
    parser.add_argument(
        "--repo-roots",
        default=None,
        help="Comma-separated repo roots to scan for .cursor/mcp.json, .mcp.json, .codex/config.toml",
    )
    parser.add_argument("--no-repo-roots", action="store_true", help="Only scan user/global MCP config paths")
    parser.add_argument("--redact", action="store_true", help="Redact local path prefixes; secrets are always masked")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    home = Path.home()
    roots = parse_repo_roots(args.repo_roots, home)
    inventory = collect_inventory(
        home=home,
        repo_roots=roots,
        include_repo_roots=not args.no_repo_roots,
        redact=args.redact,
    )
    if args.format == "table":
        output = render_table(inventory) + "\n"
    elif args.format == "summary":
        output = render_summary_report(inventory) + "\n"
    else:
        output = json.dumps(inventory, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
