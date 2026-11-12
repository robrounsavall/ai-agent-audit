"""
WSL discovery: find Claude Code homes inside running WSL distros.

Only distros that are already running are touched. Opening
\\\\wsl.localhost\\<distro> for a stopped distro boots it, so the distro list
comes from `wsl.exe --list --running --quiet`, which does not start anything.
Only /home/<user> is searched; /root is not readable from Windows.

Set AISCAN_WSL=0 (or off/false/no) to skip WSL entirely.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

UNC_ROOTS = (Path("\\\\wsl.localhost"), Path("\\\\wsl$"))
_DISTRO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_MAX_USERS = 32


@dataclass(frozen=True)
class WslHome:
    distro: str
    home: Path  # <unc>\<distro>\home\<user>

    @property
    def claude_home(self) -> Path:
        return self.home / ".claude"

    @property
    def label(self) -> str:
        """Safe display label. The Linux username is never part of it."""
        return f"wsl:{self.distro}"


def wsl_disabled() -> bool:
    return os.environ.get("AISCAN_WSL", "").strip().lower() in {"0", "off", "false", "no"}


def _decode(raw: bytes) -> str:
    # wsl.exe writes UTF-16LE to a pipe on most builds and UTF-8 on some
    # (WSL_UTF8=1). NUL bytes between ASCII letters mean UTF-16.
    if raw.count(b"\x00") > len(raw) // 4:
        return raw.decode("utf-16-le", errors="ignore")
    return raw.decode("utf-8", errors="ignore")


def parse_distro_list(raw: bytes) -> list[str]:
    names: list[str] = []
    for line in _decode(raw).replace("﻿", "").splitlines():
        name = line.strip().strip("\x00").strip()
        if name and _DISTRO_RE.match(name) and name not in names:
            names.append(name)
    return names


def running_distros(timeout: float = 5.0) -> list[str]:
    """Names of running WSL distros, or [] when WSL is absent or disabled."""
    if sys.platform != "win32" or wsl_disabled():
        return []
    try:
        proc = subprocess.run(
            ["wsl.exe", "--list", "--running", "--quiet"],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if proc.returncode != 0:
        return []
    return parse_distro_list(proc.stdout)


def _unc_base(distro: str, unc_roots: tuple[Path, ...]) -> Path | None:
    for root in unc_roots:
        base = root / distro
        try:
            if (base / "home").is_dir():
                return base
        except OSError:
            continue
    return None


def claude_homes(
    distros: list[str] | None = None,
    unc_roots: tuple[Path, ...] = UNC_ROOTS,
) -> list[WslHome]:
    """WSL user homes that contain a ~/.claude directory.

    `distros` defaults to the running distros. Tests pass both arguments.
    """
    if distros is None:
        distros = running_distros()
    found: list[WslHome] = []
    for distro in distros:
        if not _DISTRO_RE.match(distro):
            continue
        base = _unc_base(distro, unc_roots)
        if base is None:
            continue
        try:
            users = sorted(p for p in (base / "home").iterdir() if p.is_dir())[:_MAX_USERS]
        except OSError:
            continue
        for home in users:
            try:
                if (home / ".claude").is_dir():
                    found.append(WslHome(distro, home))
            except OSError:
                continue
    return found
