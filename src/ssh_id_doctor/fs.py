"""Safe filesystem access (sdd-spec §10 SEC-001, SEC-003, §13.4).

The only module that reads files. Discovery never opens anything: it lists
directory entries and resolves symlinks, and an entry whose real location is
outside the scan root is reported as ``outside_root`` and not descended into.
Nothing here changes permissions or timestamps.

:func:`read_public_text` is the single reading function for public keys. It
refuses, by name and before any ``open``, every path that is not a ``.pub``
file (including a ``.pub`` symlink whose target is not one), and it refuses a
``.pub`` file that holds a private-key header on any line — not just the
first — since a private key can be renamed to look public with an unrelated
line prepended.

:func:`read_config_text` is the analogous single reading function for one
ssh_config(5) file (FR-004a, §10 SEC-001/SEC-003): it refuses — before any
``open`` — a target that is not a regular file (a config path is usually
literally named ``config``, so unlike public keys there is no name check),
refuses content over a size limit, and refuses (after reading) content
holding a private-key header on any line.

:func:`read_known_hosts_text` is the third and last reading function, for one
known_hosts(5) file (task #1794, §10 SEC-001/SEC-003). Like public keys it
refuses by name before any ``open`` (the name must be ``known_hosts``, both
as given and after resolving symlinks), and like discovery it refuses a
target whose real location leaves ``ssh_dir`` via :func:`resolve_within`.
Otherwise it follows :func:`read_config_text`: regular-file check before
`open`, then a size limit and a private-key header check after reading.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from ssh_id_doctor.domain import Resolution

PUBLIC_SUFFIX = ".pub"
MAX_PUBLIC_BYTES = 64 * 1024
"""A public key is a single short line; anything larger is not one."""

MAX_CONFIG_BYTES = 1024 * 1024
"""An ssh_config(5) file is plain text with a modest line count; larger is refused (AC-4)."""

KNOWN_HOSTS_NAME = "known_hosts"

MAX_KNOWN_HOSTS_BYTES = 10 * 1024 * 1024
"""known_hosts can carry many thousands of host keys; still bounded against a wild read."""

_PRIVATE_MARKERS: tuple[bytes, ...] = (
    b"openssh-key-v1",
    b"b3BlbnNzaC1rZXktdjE",  # base64 of "openssh-key-v1"
)


class PrivateKeyAccessDenied(PermissionError):
    """Raised instead of reading something that is or may be a private key."""


class NotAPublicKeyFile(ValueError):
    """A ``.pub`` path that cannot hold a public key: not a regular file, or too large.

    Callers record such a path as unresolved instead of aborting a scan.
    """


class NotAConfigFile(ValueError):
    """A config path that cannot hold an ssh_config(5) file: not a regular file, or too large.

    Callers record such a path as unresolved instead of aborting a scan (AC-4).
    """


class NotAKnownHostsFile(ValueError):
    """A known_hosts path that cannot hold the source: wrong name, outside the ssh
    directory, not a regular file, or too large.

    Callers record such a path as unavailable instead of aborting a scan (AC-4).
    """


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
    any line (not just the first). A target that is not a regular file (FIFO,
    socket, device) is refused with :class:`NotAPublicKeyFile` before any
    ``open``, as is content over ``max_bytes``. The message names the file only by its base
    name and never quotes file content.
    """
    normalized = _normalize(path)
    real = Path(os.path.realpath(normalized))
    if normalized.suffix != PUBLIC_SUFFIX or real.suffix != PUBLIC_SUFFIX:
        raise PrivateKeyAccessDenied(f"refusing to read non-.pub file {normalized.name!r}")
    if not stat.S_ISREG(os.stat(real).st_mode):
        raise NotAPublicKeyFile(f"{normalized.name!r} is not a regular file")
    # O_NONBLOCK: should the path be swapped for a FIFO after the check above,
    # the open still returns at once and the fstat below refuses it.
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    with os.fdopen(os.open(real, flags), "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise NotAPublicKeyFile(f"{normalized.name!r} is not a regular file")
        data = handle.read(max_bytes + 1)
    if looks_like_private_key(data):
        raise PrivateKeyAccessDenied(f"{normalized.name!r} holds private-key material")
    if len(data) > max_bytes:
        raise NotAPublicKeyFile(f"{normalized.name!r} exceeds {max_bytes} bytes; not a public key")
    return data.decode("utf-8", errors="replace")


def read_config_text(path: str | os.PathLike[str], *, max_bytes: int = MAX_CONFIG_BYTES) -> str:
    """Read one ssh_config(5) file. One of two functions in the package that opens a file.

    Unlike :func:`read_public_text` there is no filename check (a config file
    is usually literally named ``config``, not suffixed). A target that is
    not a regular file (FIFO, socket, device — including one reached through
    a symlink, per review lessons on SID-3) is refused with
    :class:`NotAConfigFile` before any ``open``, as is content over
    ``max_bytes``. Content holding a private-key header on any line is
    refused with :class:`PrivateKeyAccessDenied` after reading, same as a
    public key (SEC-001: a config can name a real key path but must never
    carry one inline). The message names the file only by its base name and
    never quotes file content.
    """
    normalized = _normalize(path)
    real = Path(os.path.realpath(normalized))
    if not stat.S_ISREG(os.stat(real).st_mode):
        raise NotAConfigFile(f"{normalized.name!r} is not a regular file")
    # O_NONBLOCK: should the path be swapped for a FIFO after the check above,
    # the open still returns at once and the fstat below refuses it.
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    with os.fdopen(os.open(real, flags), "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise NotAConfigFile(f"{normalized.name!r} is not a regular file")
        data = handle.read(max_bytes + 1)
    if looks_like_private_key(data):
        raise PrivateKeyAccessDenied(f"{normalized.name!r} holds private-key material")
    if len(data) > max_bytes:
        raise NotAConfigFile(f"{normalized.name!r} exceeds {max_bytes} bytes; not a config file")
    return data.decode("utf-8", errors="replace")


def read_known_hosts_text(
    path: str | os.PathLike[str],
    *,
    ssh_dir: str | os.PathLike[str],
    max_bytes: int = MAX_KNOWN_HOSTS_BYTES,
) -> str:
    """Read one known_hosts(5) file (AC-1). The third of three functions that open a file.

    Refuses — before any ``open`` — a path whose name is not ``known_hosts``;
    one whose real location, per :func:`resolve_within`, leaves ``ssh_dir``
    (covers a symlinked ancestor directory as well as the file itself) or
    whose real name is not ``known_hosts`` either (a same-named symlink
    pointing at a differently named file); and one that is not a regular file
    (FIFO, socket, device). After reading, refuses content holding a
    private-key header on any line, or over ``max_bytes``, just like
    :func:`read_config_text`. The message names the file only by its base
    name and never quotes file content — including an ``OSError`` raised by
    the ``stat``/``open`` syscalls themselves (e.g. :class:`PermissionError`),
    which the stdlib would otherwise format with the full path; those are
    re-raised with the same exception type but a sanitized message. A
    missing file raises ``FileNotFoundError``, distinct from a refusal.
    """
    normalized = _normalize(path)
    if normalized.name != KNOWN_HOSTS_NAME:
        raise NotAKnownHostsFile(f"refusing to read non-known_hosts file {normalized.name!r}")
    real, resolution = resolve_within(ssh_dir, normalized)
    if resolution is Resolution.MISSING:
        raise FileNotFoundError(f"{normalized.name!r} not found")
    if resolution is not Resolution.RESOLVED or real.name != KNOWN_HOSTS_NAME:
        raise NotAKnownHostsFile(f"{normalized.name!r} is outside the ssh directory")
    try:
        file_mode = os.stat(real).st_mode
    except OSError as exc:
        raise type(exc)(f"{normalized.name!r}: {exc.strerror or type(exc).__name__}") from exc
    if not stat.S_ISREG(file_mode):
        raise NotAKnownHostsFile(f"{normalized.name!r} is not a regular file")
    # O_NONBLOCK: should the path be swapped for a FIFO after the check above,
    # the open still returns at once and the fstat below refuses it.
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(real, flags)
    except OSError as exc:
        raise type(exc)(f"{normalized.name!r}: {exc.strerror or type(exc).__name__}") from exc
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise NotAKnownHostsFile(f"{normalized.name!r} is not a regular file")
        data = handle.read(max_bytes + 1)
    if looks_like_private_key(data):
        raise PrivateKeyAccessDenied(f"{normalized.name!r} holds private-key material")
    if len(data) > max_bytes:
        raise NotAKnownHostsFile(f"{normalized.name!r} exceeds {max_bytes} bytes")
    return data.decode("utf-8", errors="replace")
