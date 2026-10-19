"""Read zstd-compressed JSONL without adding a dependency.

Codex stores older session rollouts as ``*.jsonl.zst``. Support is a try-import
of the standard-library module ``compression.zstd``, and only when
``sys.version_info >= (3, 14)``. That is a feature check plus a version tuple
guard so an older Python cannot pick up some other module of the same name.
``sys.version`` is not parsed. The third-party ``zstandard`` package is not
used, even if it happens to be installed.

A ``.zst`` that is missing a backend raises ``ZstdUnavailable`` before the
file is opened. Corrupt data, a decompressed size past the cap, or a read
that exceeds the time budget raises; callers turn that into a coverage note.
"""
from __future__ import annotations

import importlib
import io
import json
import os
import shutil
import sys
import time
from contextlib import contextmanager
from pathlib import Path

ZST_SUFFIX = ".zst"

# One file must not expand without bound or run forever. 64 MiB is enough
# for a session log and small enough that a bomb cannot exhaust memory.
# The time budget is checked between chunks, so a stuck frame cannot hang
# the collector.
MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024
MAX_DECOMPRESS_SECONDS = 30
_READ_CHUNK = 1024 * 1024

# libzstd window for one frame. 2**27 bytes is the library's historical
# default ceiling; a frame that asks for more fails as unreadable.
_WINDOW_LOG_MAX = 27


class ZstdUnavailable(RuntimeError):
    """A .zst file was found but stdlib compression.zstd is not importable."""


class TooLarge(ValueError):
    """Decompressed content exceeded the byte limit."""


class DecompressTimeout(Exception):
    """Decompression exceeded the per-file time budget."""


def is_compressed(path: Path | str) -> bool:
    return Path(path).suffix.lower() == ZST_SUFFIX


def zstd_backend() -> str | None:
    """``compression.zstd`` when this interpreter can import it, else None.

    The import is attempted only on Python 3.14 or newer (``sys.version_info``).
    Nothing is installed.
    """
    if sys.version_info < (3, 14):
        return None
    try:
        importlib.import_module("compression.zstd")
    except ImportError:
        return None
    return "compression.zstd"


def _module():
    if zstd_backend() is None:
        return None
    return importlib.import_module("compression.zstd")


def compress(data: bytes) -> bytes:
    """Compress bytes with stdlib compression.zstd. Tests use this for fixtures."""
    module = _module()
    if module is None:
        raise ZstdUnavailable("compression.zstd is not available")
    return module.compress(data)


def _decompression_options(module) -> dict | None:
    param = getattr(module, "DecompressionParameter", None)
    window = getattr(param, "window_log_max", None) if param is not None else None
    if window is None:
        return None
    return {window: _WINDOW_LOG_MAX}


class _BudgetReader(io.RawIOBase):
    """Stop a decompressor that grows past the byte cap or the time budget."""

    def __init__(self, inner, limit: int, deadline: float) -> None:
        super().__init__()
        self._inner = inner
        self._left = limit
        self._deadline = deadline

    def readable(self) -> bool:
        return True

    def _check_time(self) -> None:
        if time.monotonic() > self._deadline:
            raise DecompressTimeout("decompression time budget exceeded")

    def readinto(self, buffer) -> int:
        self._check_time()
        if self._left <= 0:
            extra = self._inner.read(1)
            self._check_time()
            if extra:
                raise TooLarge("decompressed content exceeds byte limit")
            return 0
        want = min(len(buffer), self._left, _READ_CHUNK)
        chunk = self._inner.read(want)
        self._check_time()
        if not chunk:
            return 0
        self._left -= len(chunk)
        buffer[: len(chunk)] = chunk
        return len(chunk)


@contextmanager
def _open_binary(path: Path, max_bytes: int | None = None):
    """Binary stream of file content. Compressed input is size- and time-capped.

    Corrupt zstd becomes ``OSError``. ``ZstdUnavailable`` is raised before the
    file is opened. ``TooLarge`` and ``DecompressTimeout`` propagate.
    """
    path = Path(path)
    limit = MAX_DECOMPRESSED_BYTES if max_bytes is None else max_bytes
    if not is_compressed(path):
        with path.open("rb") as stream:
            yield stream
        return
    module = _module()
    if module is None:
        raise ZstdUnavailable(f"reading {path.name} needs Python 3.14+ compression.zstd")
    zstd_error = getattr(module, "ZstdError", OSError)
    deadline = time.monotonic() + MAX_DECOMPRESS_SECONDS
    options = _decompression_options(module)
    try:
        with path.open("rb") as fh:
            reader = module.ZstdFile(fh, "rb", options=options)
            try:
                with reader:
                    buffered = io.BufferedReader(_BudgetReader(reader, limit, deadline))
                    try:
                        yield buffered
                    finally:
                        buffered.detach()
            except (zstd_error, EOFError) as exc:
                raise OSError(f"invalid zstd data in {path.name}") from exc
    except (zstd_error, EOFError) as exc:
        raise OSError(f"invalid zstd data in {path.name}") from exc


@contextmanager
def open_text(path: Path, errors: str = "strict", max_bytes: int | None = None):
    """UTF-8 text stream for a .jsonl or .jsonl.zst file."""
    with _open_binary(path, max_bytes=max_bytes) as stream:
        text = io.TextIOWrapper(stream, encoding="utf-8", errors=errors)
        try:
            yield text
        finally:
            text.detach()


def read_text(path: Path, errors: str = "strict", max_bytes: int | None = None) -> str:
    """Whole text. Raises TooLarge, DecompressTimeout, ZstdUnavailable, or OSError."""
    with _open_binary(path, max_bytes=max_bytes) as stream:
        data = stream.read()
    return data.decode("utf-8", errors=errors)


def iter_jsonl(path: Path):
    """Yield ``(line_no, obj)`` for a .jsonl or .jsonl.zst file.

    Blank and invalid JSON lines are skipped. A plain file that cannot be
    opened stops the iterator, matching ``common.iter_jsonl``. A compressed
    file that is corrupt, too large, or over the time budget raises so the
    caller can record a coverage note. ``ZstdUnavailable`` always propagates
    and is raised before the file is opened.
    """
    try:
        with open_text(path) as stream:
            for line_no, raw in enumerate(stream, 1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    yield line_no, json.loads(raw)
                except json.JSONDecodeError:
                    continue
    except (OSError, UnicodeError, TooLarge, DecompressTimeout):
        if is_compressed(path):
            raise
        return


def plain_twin(path: Path) -> Path:
    """``a.jsonl.zst`` -> ``a.jsonl``."""
    return Path(path).with_suffix("")


def jsonl_files(root: Path, pattern: str = "*.jsonl") -> list[Path]:
    """Files matching ``pattern`` or ``pattern + '.zst'`` under root, sorted.

    When both ``X.jsonl`` and ``X.jsonl.zst`` exist only the plain file is
    kept, so a rollout is never counted twice. One directory walk.
    """
    root = Path(root)
    if not root.is_dir():
        return []
    plain: set[Path] = set()
    packed: set[Path] = set()
    try:
        matches = root.rglob(pattern + "*")
    except OSError:
        return []
    for path in matches:
        if path.match(pattern):
            target = plain
        elif path.match(pattern + ZST_SUFFIX):
            target = packed
        else:
            continue
        try:
            if path.is_file():
                target.add(path)
        except OSError:
            continue
    packed = {path for path in packed if plain_twin(path) not in plain}
    return sorted(plain | packed)


def decompress_to(src: Path, dest: Path, max_bytes: int | None = None) -> None:
    """Stream-decompress ``src`` into ``dest``. On failure ``dest`` is removed."""
    if max_bytes is None:
        max_bytes = MAX_DECOMPRESSED_BYTES
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        with _open_binary(src, max_bytes=max_bytes) as stream, dest.open("wb") as out:
            while True:
                chunk = stream.read(_READ_CHUNK)
                if not chunk:
                    break
                out.write(chunk)
    except BaseException:
        try:
            dest.unlink()
        except OSError:
            pass
        raise


def stage_compressed(
    targets: list[Path], staging_root: Path
) -> tuple[list[Path], dict[str, str], int]:
    """Decompress every ``*.jsonl.zst`` under ``targets`` into a fresh staging tree.

    Returns ``(staging_dirs_to_scan, staged_path -> original_path, unreadable)``.
    With no stdlib backend the compressed files are counted and not opened.
    Corrupt, oversized, and timed-out files count as unreadable. Short staged
    names (``<target>/<n>.jsonl``) stay under Windows MAX_PATH. The caller
    deletes ``staging_root``.
    """
    staging_root = Path(staging_root)
    shutil.rmtree(staging_root, ignore_errors=True)
    try:
        staging_resolved = staging_root.resolve()
    except OSError:
        staging_resolved = staging_root
    backend = zstd_backend()
    extra: list[Path] = []
    path_map: dict[str, str] = {}
    unreadable = 0
    seen: set[Path] = set()
    for index, target in enumerate(targets):
        stage = staging_root / str(index)
        staged_here = 0
        for src in jsonl_files(target):
            if not is_compressed(src):
                continue
            try:
                resolved = src.resolve()
            except OSError:
                unreadable += 1
                continue
            try:
                under_staging = resolved.is_relative_to(staging_resolved)
            except (OSError, ValueError):
                under_staging = False
            if resolved in seen or under_staging:
                continue
            seen.add(resolved)
            if backend is None:
                unreadable += 1
                continue
            dest = stage / f"{staged_here}.jsonl"
            try:
                decompress_to(src, dest)
            except (ZstdUnavailable, OSError, TooLarge, DecompressTimeout):
                unreadable += 1
                continue
            path_map[_key(dest)] = str(src)
            staged_here += 1
        if staged_here:
            extra.append(stage)
    return extra, path_map, unreadable


def is_under(path: Path | str, root: Path) -> bool:
    """True when ``path`` is inside ``root``."""
    if not path:
        return False
    try:
        return Path(_key(path)).is_relative_to(Path(_key(root)))
    except (OSError, ValueError):
        return False


def _key(path: Path | str) -> str:
    return os.path.normcase(str(Path(path).resolve()))


def map_back(path: str, path_map: dict[str, str], target: Path | None = None) -> str:
    """Map a scanner-reported staged path back to the original .zst path."""
    if not path or not path_map:
        return path
    candidates = [Path(path)]
    if target is not None and not Path(path).is_absolute():
        candidates.insert(0, Path(target) / path)
    for candidate in candidates:
        try:
            original = path_map.get(_key(candidate))
        except OSError:
            continue
        if original:
            return original
    return path
