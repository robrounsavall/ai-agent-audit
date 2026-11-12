from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import datetime
from pathlib import Path

ENV_SCANS_ROOT = "AISCAN_SCANS_ROOT"
LATEST_FILENAME = "latest.txt"
# A junction or folder with this name is a pointer, not a scan.
LATEST_DIR_NAME = "latest"
LEGACY_RESULTS_DIRNAME = "aiscan-results"

# Default stamp, then seconds, then a numeric suffix if that second is taken.
_STAMP_MINUTE = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{4}$")
_STAMP_SECOND = re.compile(r"^(\d{4}-\d{2}-\d{2}_\d{6})(?:-(\d+))?$")
# Earlier aiscan / RUN-AISCAN folders: yyyyMMdd-HHmmss
_STAMP_LEGACY = re.compile(r"^\d{8}-\d{6}$")


def default_scans_root() -> Path:
    """Folder that holds dated scan directories.

    ``AISCAN_SCANS_ROOT`` wins when it is set and non-empty. Otherwise this
    is ``%USERPROFILE%\\aiscan\\scans`` on Windows, or ``~/aiscan/scans``.
    The path is not created and does not have to exist.
    """
    env = os.environ.get(ENV_SCANS_ROOT, "").strip()
    if env:
        return Path(env)
    home = os.environ.get("USERPROFILE", "").strip()
    base = Path(home) if home else Path.home()
    return base / "aiscan" / "scans"


def legacy_results_root() -> Path | None:
    """``%LOCALAPPDATA%\\aiscan-results``, or None when that env is unset."""
    local = os.environ.get("LOCALAPPDATA", "").strip()
    if not local:
        return None
    return Path(local) / LEGACY_RESULTS_DIRNAME


def parse_folder_stamp(name: str) -> datetime | None:
    """Local-time stamp from a scan folder name, or None if it is not one."""
    if _STAMP_MINUTE.fullmatch(name):
        try:
            return datetime.strptime(name, "%Y-%m-%d_%H%M")
        except ValueError:
            return None
    match = _STAMP_SECOND.fullmatch(name)
    if match:
        try:
            return datetime.strptime(match.group(1), "%Y-%m-%d_%H%M%S")
        except ValueError:
            return None
    if _STAMP_LEGACY.fullmatch(name):
        try:
            return datetime.strptime(name, "%Y%m%d-%H%M%S")
        except ValueError:
            return None
    return None


def folder_sort_key(path: Path) -> tuple[float, str]:
    """Sort key for a scan folder: stamp (or mtime), then the folder name."""
    stamp = parse_folder_stamp(path.name)
    if stamp is not None:
        return (stamp.timestamp(), path.name)
    try:
        return (path.stat().st_mtime, path.name)
    except OSError:
        return (0.0, path.name)


def is_pointer_name(name: str) -> bool:
    return name.casefold() == LATEST_DIR_NAME


def iter_scan_children(root: Path) -> list[Path]:
    """Child directories that look like scan folders, excluding ``latest``."""
    if not root.is_dir():
        return []
    found: list[Path] = []
    try:
        children = list(root.iterdir())
    except OSError:
        return []
    for child in children:
        try:
            if not child.is_dir():
                continue
            if is_pointer_name(child.name):
                continue
            if not (child / "evidence").is_dir():
                continue
        except OSError:
            continue
        found.append(child)
    return found


def has_scan_children(root: Path) -> bool:
    return bool(iter_scan_children(root))


def legacy_scan_roots() -> list[Path]:
    """Older default locations that still hold scan folders, if any.

    These are never created, moved, or deleted here. The caller may hint
    that they can be imported into the hub.
    """
    root = legacy_results_root()
    if root is not None and has_scan_children(root):
        return [root]
    return []


def read_latest(root: Path | None = None) -> Path | None:
    """The scan folder named in ``latest.txt``, if that folder still exists."""
    base = Path(root) if root is not None else default_scans_root()
    path = base / LATEST_FILENAME
    try:
        text = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    if not text:
        return None
    name = text[0].strip()
    if not name or is_pointer_name(name) or "/" in name or "\\" in name:
        return None
    if parse_folder_stamp(name) is None and name in {".", ".."}:
        return None
    candidate = base / name
    try:
        if candidate.is_dir() and (candidate / "evidence").is_dir():
            return candidate
    except OSError:
        return None
    if candidate.is_dir():
        return candidate
    return None


def write_latest(root: Path, scan_dir: Path) -> None:
    """Write ``latest.txt`` with the child folder name. Best-effort."""
    name = Path(scan_dir).name
    if not name or is_pointer_name(name) or "/" in name or "\\" in name:
        return
    target = Path(root) / LATEST_FILENAME
    try:
        target.write_text(name + "\n", encoding="utf-8", newline="\n")
    except OSError:
        print("Could not write the latest-scan pointer.", file=sys.stderr)


def allocate_scan_dir(
    root: Path | None = None,
    when: datetime | None = None,
) -> Path:
    """Create a new dated folder under the scans root and point ``latest.txt`` at it.

    Names are ``yyyy-MM-dd_HHmm``. If that minute is taken, seconds are
    added (``yyyy-MM-dd_HHmmss``). If that second is taken too, a numeric
    suffix is added. Creation uses an exclusive mkdir so two runs cannot
    share a folder.
    """
    base = Path(root) if root is not None else default_scans_root()
    try:
        base.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RuntimeError("Could not create the default scan folder.") from exc
    stamp = when or datetime.now()
    minute = stamp.strftime("%Y-%m-%d_%H%M")
    second = stamp.strftime("%Y-%m-%d_%H%M%S")
    names = [minute, second]
    names.extend(f"{second}-{n}" for n in range(2, 1000))
    last_error: OSError | None = None
    for name in names:
        path = base / name
        try:
            path.mkdir()
        except FileExistsError:
            continue
        except OSError as exc:
            last_error = exc
            continue
        write_latest(base, path)
        return path
    if last_error is not None:
        raise RuntimeError("Could not create the default scan folder.") from last_error
    raise RuntimeError("Could not create the default scan folder.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Default aiscan scan-folder locations.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--alloc",
        action="store_true",
        help="Create a new dated folder under the default root and print its path.",
    )
    group.add_argument(
        "--print-root",
        action="store_true",
        help="Print the default scans root (AISCAN_SCANS_ROOT or %%USERPROFILE%%\\aiscan\\scans).",
    )
    group.add_argument(
        "--print-latest",
        action="store_true",
        help="Print the folder named in latest.txt, if it exists.",
    )
    parser.add_argument(
        "--root",
        default=None,
        help="Override the scans root for --alloc and --print-latest. Default is the same as --print-root.",
    )
    args = parser.parse_args(argv)
    try:
        if args.print_root:
            print(default_scans_root())
            return 0
        root = Path(args.root) if args.root else default_scans_root()
        if args.print_latest:
            latest = read_latest(root)
            if latest is None:
                print("No latest scan pointer.", file=sys.stderr)
                return 1
            print(latest)
            return 0
        path = allocate_scan_dir(root)
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 1
    print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
