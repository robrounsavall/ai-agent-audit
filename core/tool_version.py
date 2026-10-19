"""aiscan tool version for the console banner and evidence envelopes.

A git checkout uses ``git describe --tags --dirty --always`` so a commit that
is not the release tag cannot print a bare release number. A release zip has
no ``.git`` and uses the ``VERSION`` file the release workflow checks. If
neither is available the version is ``dev``.

``aiscan.ps1`` runs this file to choose the banner, then sets
``AISCAN_VERSION`` so every collector stamps that same string. The CLI
ignores ``AISCAN_VERSION`` so a stale value in the environment cannot stick.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def git_describe(root: Path) -> str | None:
    """Return a stripped ``git describe`` string, or None when git cannot.

    A leading ``v`` is removed only when the next character is a digit
    (``v0.2.0`` becomes ``0.2.0``). A bare commit hash is left as-is.
    """
    if not (root / ".git").exists():
        return None
    env = os.environ.copy()
    env.pop("GIT_DIR", None)
    env.pop("GIT_WORK_TREE", None)
    try:
        proc = subprocess.run(
            ["git", "-C", os.fspath(root), "describe", "--tags", "--dirty", "--always"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    lines = [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]
    if not lines:
        return None
    text = lines[-1]
    if len(text) >= 2 and text[0] == "v" and text[1].isdigit():
        text = text[1:]
    return text or None


def read_version_file(root: Path) -> str | None:
    path = root / "VERSION"
    if not path.is_file():
        return None
    try:
        # utf-8-sig drops a Windows editor BOM so it cannot leak into envelopes.
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except OSError:
        return None
    if not lines:
        return None
    text = lines[0].strip()
    return text or None


# Default-repo lookups only. Callers that pass a root (tests, other trees)
# are not cached, because that tree can change during the process.
_resolved_cache: dict[str, str] = {}


def tool_version(root: Path | None = None, *, use_env: bool = True) -> str:
    """Version string for this tree.

    ``AISCAN_VERSION`` wins when ``use_env`` is set, so envelopes match the
    banner ``aiscan.ps1`` already printed. Otherwise git describe wins over
    the VERSION file, including when describe is only a commit hash: a hash
    is not a release tag, and falling back to VERSION would hide that.
    """
    if use_env:
        env = os.environ.get("AISCAN_VERSION", "").strip()
        if env:
            return env
    root_path = Path(root) if root is not None else repo_root()
    cacheable = root is None
    cache_key = os.fspath(root_path.resolve()) if cacheable else ""
    if cacheable and cache_key in _resolved_cache:
        return _resolved_cache[cache_key]
    described = git_describe(root_path)
    if described:
        resolved = described
    else:
        resolved = read_version_file(root_path) or "dev"
    if cacheable:
        _resolved_cache[cache_key] = resolved
    return resolved


def main() -> int:
    print(tool_version(use_env=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
