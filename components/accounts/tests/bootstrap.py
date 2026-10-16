"""Path bootstrap for component unit tests. Import before collector modules."""
from __future__ import annotations

import sys
from pathlib import Path

# tests/ -> component/ -> components/ -> repo
COMPONENT_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = COMPONENT_DIR.parent.parent
CORE_DIR = REPO_ROOT / "core"

for p in (CORE_DIR, COMPONENT_DIR):
    s = str(p)
    if s not in sys.path:
        sys.path.insert(0, s)
