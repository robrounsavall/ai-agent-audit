"""
Unified, override-aware tool-path resolution for aiscan collectors.

Single source of truth for where each AI coding tool keeps its data on the
current Windows user profile. Models tool *homes* and the data paths derived
from them so every collector (claude, cursor, codex, chat-history) and the
discovery command agree on the same locations.

Precedence per override unit (highest wins):
    CLI flag  >  config file entry  >  tool env var  >  default

Override units (homes; subpaths derive):
    claude          -> claude_home          (env: CLAUDE_CONFIG_DIR)
    codex           -> codex_home           (env: CODEX_HOME)
    cursor_projects -> cursor_projects      (no env var)
    cursor_db       -> cursor_db            (no env var)
    grok            -> grok_home            (env: GROK_HOME)

Safe source labels (never expose the resolved value):
    default | cli | config | env:CLAUDE_CONFIG_DIR | env:CODEX_HOME | env:GROK_HOME

Project-scoped Grok config (`<git-root>/.grok/config.toml`) has no env var or CLI
override; it is resolved on demand from the current working directory via
`find_repo_root()` / `resolve_grok_project_config()`.

Evidence boundary (SCHEMA.md): full resolved paths are LOCAL-only. Stored
evidence uses safe_path_meta() — detected/count/newest/source label + a hashed
path identity, never the raw path.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from common import APPDATA, USERPROFILE, sha256_short

# Override units and their config keys / env vars.
OVERRIDE_KEYS = ("claude_home", "codex_home", "cursor_projects", "cursor_db", "grok_home")
ENV_VARS = {
    "claude_home": "CLAUDE_CONFIG_DIR",
    "codex_home": "CODEX_HOME",
    "grok_home": "GROK_HOME",
}
# Source label per override unit, set during resolution.
_SOURCE_UNITS = ("claude", "codex", "cursor_projects", "cursor_db", "grok")

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "paths.json"


@dataclass
class ToolPaths:
    # Claude
    claude_home: Path
    claude_projects: Path
    # Codex
    codex_home: Path
    codex_sessions: Path
    codex_config: Path
    codex_auth: Path
    # Cursor
    cursor_projects: Path
    cursor_db: Path
    # Cursor / shared MCP registries (derived defaults; not CLI override units)
    cursor_user_mcp: Path
    cursor_appdata_mcp: Path
    shared_mcp: Path
    # Grok Build (xAI)
    grok_home: Path
    grok_sessions: Path
    grok_config: Path
    grok_logs: Path
    grok_auth: Path
    # Project-scoped Grok config (<git-root>/.grok/config.toml); None if no repo
    # root was found or the file does not exist. No CLI/env override (SCHEMA
    # boundary: derived from cwd, never persisted).
    grok_project_config: Path | None
    # Safe source label per override unit (claude|codex|cursor_projects|cursor_db|grok)
    sources: dict[str, str] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Config loading
# --------------------------------------------------------------------------- #
def _load_config(config_path: Path | str | None) -> tuple[dict, Path | None]:
    """Load the paths config. Malformed config is fatal (fail closed).

    Returns (config_dict, used_path). If no config is requested and the default
    does not exist, returns ({}, None).
    """
    if config_path is not None:
        path = Path(config_path)
        if not path.exists():
            print(f"Error: --paths-config not found: {path}", file=sys.stderr)
            raise SystemExit(2)
    else:
        path = DEFAULT_CONFIG_PATH
        if not path.exists():
            return {}, None

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Error: malformed paths config {path}: {exc}", file=sys.stderr)
        raise SystemExit(2)

    if not isinstance(data, dict):
        print(f"Error: paths config {path} must be a JSON object", file=sys.stderr)
        raise SystemExit(2)

    unknown = set(data) - set(OVERRIDE_KEYS)
    if unknown:
        print(
            f"Error: paths config {path} has unknown keys: {sorted(unknown)}; "
            f"allowed: {list(OVERRIDE_KEYS)}",
            file=sys.stderr,
        )
        raise SystemExit(2)

    return data, path


def _pick(unit: str, cli: dict, config: dict, env_value: str | None) -> tuple[Path, str]:
    """Resolve one override unit, returning (path, safe_source_label)."""
    cli_val = cli.get(unit)
    if cli_val:
        return Path(cli_val), "cli"
    cfg_val = config.get(unit)
    if cfg_val:
        return Path(cfg_val), "config"
    if env_value:
        return Path(env_value), f"env:{ENV_VARS[unit]}"
    return _default_for(unit), "default"


def _default_for(unit: str) -> Path:
    if unit == "claude_home":
        return USERPROFILE / ".claude"
    if unit == "codex_home":
        return USERPROFILE / ".codex"
    if unit == "cursor_projects":
        return USERPROFILE / ".cursor" / "projects"
    if unit == "cursor_db":
        return APPDATA / "Cursor" / "User" / "globalStorage" / "state.vscdb"
    if unit == "grok_home":
        return USERPROFILE / ".grok"
    raise ValueError(unit)


def find_repo_root(start: Path | None = None) -> Path | None:
    """Walk up from `start` (default: cwd) looking for a `.git` directory.

    Returns None if no repo root is found. Used only to derive project-scoped
    config locations (e.g. Grok's `<repo>/.grok/config.toml|`); never persisted.
    """
    cur = (start or Path.cwd()).resolve()
    for candidate in (cur, *cur.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def resolve_grok_project_config(start: Path | None = None) -> Path | None:
    """Resolve `<git-root>/.grok/config.toml` for the current repo, if any.

    Returns None when no repo root is found. Does not check existence of the
    file itself; callers check `.exists()` same as other config paths.
    """
    root = find_repo_root(start)
    if root is None:
        return None
    return root / ".grok" / "config.toml"


def resolve_tool_paths(
    cli_overrides: dict | None = None,
    config_path: Path | str | None = None,
) -> ToolPaths:
    """Resolve all tool paths with CLI > config > env > default precedence."""
    cli = {k: v for k, v in (cli_overrides or {}).items() if v}
    config, _ = _load_config(config_path)

    import os

    claude_home, claude_src = _pick(
        "claude_home", cli, config, os.environ.get("CLAUDE_CONFIG_DIR")
    )
    codex_home, codex_src = _pick(
        "codex_home", cli, config, os.environ.get("CODEX_HOME")
    )
    cursor_projects, cursor_proj_src = _pick("cursor_projects", cli, config, None)
    cursor_db, cursor_db_src = _pick("cursor_db", cli, config, None)
    grok_home, grok_src = _pick("grok_home", cli, config, os.environ.get("GROK_HOME"))

    paths = ToolPaths(
        claude_home=claude_home,
        claude_projects=claude_home / "projects",
        codex_home=codex_home,
        codex_sessions=codex_home / "sessions",
        codex_config=codex_home / "config.toml",
        codex_auth=codex_home / "auth.json",
        cursor_projects=cursor_projects,
        cursor_db=cursor_db,
        cursor_user_mcp=USERPROFILE / ".cursor" / "mcp.json",
        cursor_appdata_mcp=APPDATA / "Cursor" / "mcp.json",
        shared_mcp=USERPROFILE / ".mcp.json",
        grok_home=grok_home,
        grok_sessions=grok_home / "sessions",
        grok_config=grok_home / "config.toml",
        grok_logs=grok_home / "logs",
        grok_auth=grok_home / "auth.json",
        grok_project_config=resolve_grok_project_config(),
        sources={
            "claude": claude_src,
            "codex": codex_src,
            "cursor_projects": cursor_proj_src,
            "cursor_db": cursor_db_src,
            "grok": grok_src,
        },
    )
    _warn_missing_explicit_overrides(paths, cli, config)
    return paths


def _warn_missing_explicit_overrides(paths: ToolPaths, cli: dict, config: dict) -> None:
    """Warn (stderr, console-only) when an explicit override points nowhere.

    Default paths are allowed to be absent (the tool may simply not be installed);
    an explicit CLI/config override that does not exist is likely an operator
    error worth surfacing, but is non-fatal so the audit still records 'not found'.
    """
    explicit = set(cli) | set(config)
    unit_to_attr = {
        "claude_home": paths.claude_home,
        "codex_home": paths.codex_home,
        "cursor_projects": paths.cursor_projects,
        "cursor_db": paths.cursor_db,
        "grok_home": paths.grok_home,
    }
    for unit in explicit:
        target = unit_to_attr.get(unit)
        if target is not None and not target.exists():
            print(
                f"Warning: explicit override {unit} -> {target} does not exist; "
                f"continuing (will report as not detected).",
                file=sys.stderr,
            )


# --------------------------------------------------------------------------- #
# Detection / metadata
# --------------------------------------------------------------------------- #
def _scan_dir(path: Path, pattern: str = "*.jsonl") -> tuple[bool, int, str | None]:
    if not path.exists():
        return False, 0, None
    if path.is_file():
        ts = datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d")
        return True, 1, ts
    files = list(path.rglob(pattern))
    if not files:
        return True, 0, None
    newest = max(f.stat().st_mtime for f in files)
    return True, len(files), datetime.fromtimestamp(newest).strftime("%Y-%m-%d")


# Logical data paths reported by detection, keyed by name -> (attr, source_unit, pattern).
_DATA_PATHS = {
    "claude_projects": ("claude_projects", "claude", "*.jsonl"),
    "codex_sessions": ("codex_sessions", "codex", "*.jsonl"),
    "cursor_projects": ("cursor_projects", "cursor_projects", "*.jsonl"),
    "cursor_db": ("cursor_db", "cursor_db", "*.vscdb"),
    "cursor_user_mcp": ("cursor_user_mcp", "cursor_projects", "mcp.json"),
    "cursor_appdata_mcp": ("cursor_appdata_mcp", "cursor_db", "mcp.json"),
    "shared_mcp": ("shared_mcp", "cursor_projects", "mcp.json"),
    "grok_sessions": ("grok_sessions", "grok", "summary.json"),
}


def detected(paths: ToolPaths) -> dict[str, dict]:
    """Per data-path detection: {detected, file_count, newest, source}."""
    out: dict[str, dict] = {}
    for name, (attr, unit, pattern) in _DATA_PATHS.items():
        target: Path = getattr(paths, attr)
        ok, count, newest = _scan_dir(target, pattern)
        out[name] = {
            "detected": ok,
            "file_count": count,
            "newest": newest,
            "source": paths.sources.get(unit, "default"),
        }
    return out


def safe_path_meta(paths: ToolPaths) -> dict:
    """Evidence-safe metadata: NO raw paths. Hashed identity + safe fields only."""
    det = detected(paths)
    meta: dict[str, dict] = {}
    for name, (attr, _unit, _pattern) in _DATA_PATHS.items():
        target: Path = getattr(paths, attr)
        info = det[name]
        meta[name] = {
            "detected": info["detected"],
            "file_count": info["file_count"],
            "newest": info["newest"],
            "source": info["source"],
            "path_id": sha256_short(str(target).replace("\\", "/").lower()),
        }
    return meta


# --------------------------------------------------------------------------- #
# CLI integration
# --------------------------------------------------------------------------- #
def add_path_args(parser: argparse.ArgumentParser) -> None:
    """Add the shared path-override flags to a collector's arg parser."""
    group = parser.add_argument_group("path overrides")
    group.add_argument("--claude-home", default=None, help="Claude home dir (default ~/.claude)")
    group.add_argument("--codex-home", default=None, help="Codex home dir (default ~/.codex)")
    group.add_argument(
        "--cursor-projects", default=None, help="Cursor projects dir (default ~/.cursor/projects)"
    )
    group.add_argument(
        "--cursor-db", default=None, help="Cursor state.vscdb (default %%APPDATA%%/Cursor/...)"
    )
    group.add_argument("--grok-home", default=None, help="Grok Build home dir (default ~/.grok)")
    group.add_argument(
        "--paths-config", default=None, help="JSON file overriding any of the five roots"
    )


def overrides_from_args(args: argparse.Namespace) -> dict:
    """Extract CLI override dict from parsed args (None values dropped)."""
    return {
        "claude_home": getattr(args, "claude_home", None),
        "codex_home": getattr(args, "codex_home", None),
        "cursor_projects": getattr(args, "cursor_projects", None),
        "cursor_db": getattr(args, "cursor_db", None),
        "grok_home": getattr(args, "grok_home", None),
    }


def resolve_from_args(args: argparse.Namespace) -> ToolPaths:
    """Convenience: resolve ToolPaths directly from a parsed Namespace."""
    return resolve_tool_paths(
        cli_overrides=overrides_from_args(args),
        config_path=getattr(args, "paths_config", None),
    )


def paths_to_cli_args(paths: ToolPaths) -> list[str]:
    """Re-emit resolved homes/paths as flags for orchestrator pass-through.

    Full paths only — caller MUST treat the result as local/transient (process
    args), never persisted to evidence or logs.
    """
    return [
        "--claude-home", str(paths.claude_home),
        "--codex-home", str(paths.codex_home),
        "--cursor-projects", str(paths.cursor_projects),
        "--cursor-db", str(paths.cursor_db),
        "--grok-home", str(paths.grok_home),
    ]
