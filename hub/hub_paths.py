"""Import path setup and default locations for the hub.

Importing this module puts ``core/`` and ``hub/`` on ``sys.path``, the same
no-install pattern the collectors use through ``PYTHONPATH``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

HUB_DIR = Path(__file__).resolve().parent
REPO_ROOT = HUB_DIR.parent
CORE_DIR = REPO_ROOT / "core"
STATIC_DIR = HUB_DIR / "static"

for _path in (str(CORE_DIR), str(HUB_DIR)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

ENV_DB = "AISCAN_HUB_DB"
ENV_TOKEN = "AISCAN_HUB_TOKEN"
DB_FILENAME = "hub.db"
UI_TOKEN_FILENAME = "ui-token"


def default_data_dir() -> Path:
    """Per-user data folder. ``%LOCALAPPDATA%\\aiscan\\hub`` on Windows."""
    local = os.environ.get("LOCALAPPDATA", "").strip()
    if local:
        return Path(local) / "aiscan" / "hub"
    xdg = os.environ.get("XDG_DATA_HOME", "").strip()
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "aiscan" / "hub"


def resolve_db_path(explicit: str | os.PathLike[str] | None = None) -> Path:
    """Database file: ``--db``, then ``AISCAN_HUB_DB``, then the default."""
    if explicit:
        return Path(explicit)
    env = os.environ.get(ENV_DB, "").strip()
    if env:
        return Path(env)
    return default_data_dir() / DB_FILENAME
