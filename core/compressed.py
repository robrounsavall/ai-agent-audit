"""Transparent reading of zstd-compressed JSONL files (stdlib only, no installs).

Codex compresses session rollouts older than seven days in place
(``rollout-*.jsonl`` -> ``rollout-*.jsonl.zst``, mtimes preserved). Collectors
use this module so a compressed rollout is read exactly like a plain one.

Backends, in order: stdlib ``compression.zstd`` (Python 3.14+), then the
third-party ``zstandard`` module only if it is already importable. Nothing is
ever installed. With no backend, opening a ``.zst`` raises ``ZstdUnavailable``
so callers can count the file and report the coverage gap instead of silently
reporting zero.

Tests force "no backend" with ``patch.object(compressed, "zstd_backend",
return_value=None)``; every reader looks the backend up through that function.
"""
from __future__ import annotations

import importlib
import io
import json
import os
import shutil
from contextlib import contextmanager
from pathlib import Path

ZST_SUFFIX = ".zst"

# Decompression-bomb guard for compressed inputs. Plain files keep their
# existing behaviour; a .zst that inflates past this is treated as unreadable.
MAX_DECOMPRESSED_BYTES = 1024 * 1024 * 1024

UNAVAILABLE_HINT = "Python 3.14+ (stdlib compression.zstd) or an already-installed zstandard package"

_BACKENDS = ("compression.zstd", "zstandard")


class ZstdUnavailable(RuntimeError):
    """A .zst file was found but no zstd backend is importable."""


class TooLarge(ValueError):
    """Decompressed content exceeded the caller's byte limit."""


def is_compressed(path: Path | str) -> bool:
    return Path(path).suffix.lower() == ZST_SUFFIX


def zstd_backend() -> str | None:
    """Name of the first importable backend, or None. Never installs anything."""
    for name in _BACKENDS:
        try:
            importlib.import_module(name)
            return name
        except ImportError:
            continue
    return None


def compress(data: bytes) -> bytes:
    """Compress bytes with the available backend (used by tests to build fixtures)."""
    backend = zstd_backend()
    if backend is None:
        raise ZstdUnavailable(f"zstd compression needs {UNAVAILABLE_HINT}")
    module = importlib.import_module(backend)
    if backend == "zstandard":
        return module.ZstdCompressor().compress(data)
    return module.compress(data)


class _LimitedReader(io.RawIOBase):
    """Read-only wrapper that raises TooLarge once more than limit bytes are read."""

    def __init__(self, inner, limit: int) -> None:
        super().__init__()
        self._inner = inner
        self._left = limit

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        chunk = self._inner.read(len(buffer))
        if not chunk:
            return 0
        self._left -= len(chunk)
        if self._left < 0:
            raise TooLarge("decompressed content exceeds byte limit")
        buffer[: len(chunk)] = chunk
        return len(chunk)


@contextmanager
def _open_binary(path: Path):
    """Binary stream over the (decompressed) file content.

    Corrupt/truncated zstd data surfaces as OSError so callers treat it like
    an unreadable file.
    """
    path = Path(path)
    if not is_compressed(path):
        with path.open("rb") as stream:
            yield stream
        return
    backend = zstd_backend()
    if backend is None:
        raise ZstdUnavailable(f"reading {path.name} needs {UNAVAILABLE_HINT}")
    module = importlib.import_module(backend)
    errors: tuple[type[BaseException], ...] = (getattr(module, "ZstdError", OSError), EOFError)
    with path.open("rb") as fh:
        if backend == "zstandard":
            reader = module.ZstdDecompressor().stream_reader(fh, read_across_frames=True)
        else:
            reader = module.ZstdFile(fh, "rb")
        try:
            with reader:
                yield io.BufferedReader(_LimitedReader(reader, MAX_DECOMPRESSED_BYTES))
        except errors as exc:
            raise OSError(f"invalid zstd data in {path.name}") from exc


@contextmanager
def open_text(path: Path, errors: str = "strict"):
    """UTF-8 text stream for a .jsonl or .jsonl.zst file."""
    with _open_binary(path) as stream:
        text = io.TextIOWrapper(stream, encoding="utf-8", errors=errors)
        try:
            yield text
        finally:
            text.detach()


def read_text(path: Path, errors: str = "strict", max_bytes: int | None = None) -> str:
    """Whole (decompressed) text. Raises TooLarge past max_bytes, ZstdUnavailable, OSError."""
    with _open_binary(path) as stream:
        data = stream.read() if max_bytes is None else stream.read(max_bytes + 1)
    if max_bytes is not None and len(data) > max_bytes:
        raise TooLarge("content exceeds byte limit")
    return data.decode("utf-8", errors=errors)


def iter_jsonl(path: Path):
    """Yield (line_no, obj) like common.iter_jsonl, transparently for .zst.

    Blank/invalid lines are skipped; OSError, corrupt zstd data and oversized
    content stop iteration (a truncated file may yield its readable prefix;
    the zstandard backend can return a partial frame without raising). ZstdUnavailable propagates so the caller can count
    the file as unreadable.
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
    except (OSError, UnicodeError, TooLarge):
        return


def plain_twin(path: Path) -> Path:
    """a.jsonl.zst -> a.jsonl"""
    return Path(path).with_suffix("")


def jsonl_files(root: Path, pattern: str = "*.jsonl") -> list[Path]:
    """Files matching pattern or pattern + '.zst' under root, one walk, sorted.

    When both X.jsonl and X.jsonl.zst exist only the uncompressed file is kept,
    so a rollout is never counted twice.
    """
    root = Path(root)
    if not root.is_dir():
        return []
    plain: set[Path] = set()
    packed: set[Path] = set()
    for path in root.rglob(pattern + "*"):
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
    packed = {p for p in packed if plain_twin(p) not in plain}
    return sorted(plain | packed)


def decompress_to(src: Path, dest: Path, max_bytes: int | None = None) -> None:
    """Stream-decompress src into dest. On any failure dest is removed and the error re-raised."""
    if max_bytes is None:
        max_bytes = MAX_DECOMPRESSED_BYTES
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        with _open_binary(src) as stream, dest.open("wb") as out:
            written = 0
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    raise TooLarge("decompressed content exceeds byte limit")
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
    """Decompress every *.jsonl.zst under targets into a fresh staging tree.

    Returns (staging_dirs_to_scan, staged_path -> original_path, unreadable).
    unreadable counts files that could not be staged (no backend, corrupt,
    too large, disk/path errors). Short staged names (<target>/<n>.jsonl)
    keep paths under Windows MAX_PATH. Files under staging_root itself are
    ignored. The CALLER must delete staging_root (try/finally).
    """
    staging_root = Path(staging_root)
    shutil.rmtree(staging_root, ignore_errors=True)
    staging_resolved = staging_root.resolve()
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
            resolved = src.resolve()
            if resolved in seen or resolved.is_relative_to(staging_resolved):
                continue
            seen.add(resolved)
            dest = stage / f"{staged_here}.jsonl"
            try:
                decompress_to(src, dest)
            except (ZstdUnavailable, OSError, TooLarge):
                unreadable += 1
                continue
            path_map[_key(dest)] = str(src)
            staged_here += 1
        if staged_here:
            extra.append(stage)
    return extra, path_map, unreadable


def is_under(path: Path | str, root: Path) -> bool:
    """True if path lies inside root (case-insensitive on Windows)."""
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
