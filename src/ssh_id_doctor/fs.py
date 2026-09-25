"""Safe filesystem access (sdd-spec §10 SEC-001, SEC-003, §13.4).

The only module that reads files. Discovery never opens anything: it lists
directory entries and resolves symlinks, and an entry whose real location is
outside the scan root is reported as ``outside_root`` and not descended into.
Nothing here changes permissions or timestamps.

:func:`read_public_text` is the single reading function. It refuses, by name
and before any ``open``, every path that is not a ``.pub`` file (including a
``.pub`` symlink whose target is not one), and it refuses a ``.pub`` file that
holds a private-key header on any line — not just the first — since a private
key can be renamed to look public with an unrelated line prepended.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from ssh_id_doctor.domain import Resolution

PUBLIC_SUFFIX = ".pub"
MAX_PUBLIC_BYTES = 64 * 1024
"""A public key is a single short line; anything larger is not one."""

_PRIVATE_MARKERS: tuple[bytes, ...] = (
    b"openssh-key-v1",
    b"b3BlbnNzaC1rZXktdjE",  # base64 of "openssh-key-v1"
)


class PrivateKeyAccessDenied(PermissionError):
    """Raised instead of reading something that is or may be a private key."""


class EntryKind(StrEnum):
    FILE = "file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class WalkEntry:
    """One discovered entry. ``path`` is its location under the root, not its target."""

    path: Path
    kind: EntryKind
    resolution: Resolution


def _normalize(path: str | os.PathLike[str]) -> Path:
    return Path(os.path.normpath(os.path.abspath(os.fspath(path))))


def _is_within(candidate: str, root: str) -> bool:
    return candidate == root or candidate.startswith(root.rstrip(os.sep) + os.sep)


def resolve_within(
    root: str | os.PathLike[str], path: str | os.PathLike[str]
) -> tuple[Path, Resolution]:
    """Resolve ``path`` (relative paths are taken from ``root``) against ``root``.

    Returns the real path and ``resolved`` when it stays inside the real root,
    the normalized path and ``outside_root`` when it (or a symlink on the way)
    leaves it, and ``missing`` when it does not exist. Nothing is opened.
    """
    real_root = os.path.realpath(_normalize(root))
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = Path(real_root) / candidate
    normalized = _normalize(candidate)
    real = os.path.realpath(normalized)
    if not _is_within(real, real_root):
        return normalized, Resolution.OUTSIDE_ROOT
    if not os.path.lexists(real):
        return Path(real), Resolution.MISSING
    return Path(real), Resolution.RESOLVED


def safe_walk(root: str | os.PathLike[str]) -> Iterator[WalkEntry]:
    """List everything under ``root`` without leaving it and without reading files.

    Symlinks are never descended into; one that points outside the root is
    reported as ``outside_root``. Order is deterministic (sorted per directory).
    """
    real_root = os.path.realpath(_normalize(root))
    pending = [real_root]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            yield WalkEntry(Path(directory), EntryKind.DIRECTORY, Resolution.UNREADABLE)
            continue
        subdirs: list[str] = []
        for entry in entries:
            path = Path(entry.path)
            if entry.is_symlink():
                _, resolution = resolve_within(real_root, path)
                yield WalkEntry(path, EntryKind.SYMLINK, resolution)
            elif entry.is_dir(follow_symlinks=False):
                yield WalkEntry(path, EntryKind.DIRECTORY, Resolution.RESOLVED)
                subdirs.append(entry.path)
            elif entry.is_file(follow_symlinks=False):
                yield WalkEntry(path, EntryKind.FILE, Resolution.RESOLVED)
            else:
                yield WalkEntry(path, EntryKind.OTHER, Resolution.RESOLVED)
        pending.extend(reversed(subdirs))


def looks_like_private_key(data: bytes) -> bool:
    """True if any line of ``data`` carries a private-key header or marker."""
    return any(_is_private_key_line(line) for line in data.split(b"\n"))


def _is_private_key_line(line: bytes) -> bool:
    stripped = line.strip()
    if stripped.startswith(b"-----BEGIN") and b"PRIVATE KEY" in stripped:
        return True
    return any(stripped.startswith(marker) for marker in _PRIVATE_MARKERS)


def read_public_text(path: str | os.PathLike[str], *, max_bytes: int = MAX_PUBLIC_BYTES) -> str:
    """Read a public-key file. The only function in the package that opens a file.

    Refuses with :class:`PrivateKeyAccessDenied` — before opening — any path
    whose name, or whose symlink target's name, lacks the ``.pub`` suffix; and,
    after reading the content, a ``.pub`` file holding a private-key header on
    any line (not just the first). The message names the file only by its base
    name and never quotes file content.
    """
    normalized = _normalize(path)
    real = Path(os.path.realpath(normalized))
    if normalized.suffix != PUBLIC_SUFFIX or real.suffix != PUBLIC_SUFFIX:
        raise PrivateKeyAccessDenied(f"refusing to read non-.pub file {normalized.name!r}")
    with open(real, "rb") as handle:
        data = handle.read(max_bytes + 1)
    if looks_like_private_key(data):
        raise PrivateKeyAccessDenied(f"{normalized.name!r} holds private-key material")
    if len(data) > max_bytes:
        raise ValueError(f"{normalized.name!r} exceeds {max_bytes} bytes; not a public key")
    return data.decode("utf-8", errors="replace")
