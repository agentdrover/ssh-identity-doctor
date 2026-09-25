"""FR-001 (sdd-spec §7.3, §10 SEC-001/SEC-003): enumerate .pub files under an SSH directory.

Discovery is built entirely on :func:`ssh_id_doctor.fs.safe_walk` (to traverse
without leaving the root or following an out-of-root symlink) and
:func:`ssh_id_doctor.fs.read_public_text` (the only function allowed to open a
file). A ``.pub`` symlink whose target lies outside the scan root is reported
as ``outside_root`` and its target is never passed to ``read_public_text``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from ssh_id_doctor import fs
from ssh_id_doctor.domain import Resolution
from ssh_id_doctor.fs import EntryKind, PrivateKeyAccessDenied

PUBLIC_SUFFIX = ".pub"


@dataclass(frozen=True, slots=True)
class PublicKeyObservation:
    """One ``.pub`` path found under the scan root (§7.3, ``LocalReference`` kind=public_key).

    ``key_line`` is the first non-empty line of the key file and is only set
    when ``resolution`` is ``resolved``.
    """

    path: str
    resolution: Resolution
    key_line: str | None = None


def _first_nonempty_line(text: str) -> str | None:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return None


def discover_public_keys(ssh_dir: str | os.PathLike[str]) -> list[PublicKeyObservation]:
    """List every ``.pub`` file under ``ssh_dir``, sorted by canonical path.

    Directories, sockets, FIFOs and other non-regular entries are skipped
    without a record. A ``.pub`` file that is unreadable, holds private-key
    material on any line, or is a symlink escaping the root is still recorded,
    with ``resolution`` set to ``unreadable``, ``private_only`` or
    ``outside_root`` respectively and ``key_line`` left ``None``.
    """
    observations: list[PublicKeyObservation] = []
    for entry in fs.safe_walk(ssh_dir):
        if entry.kind not in (EntryKind.FILE, EntryKind.SYMLINK):
            continue
        if entry.path.suffix != PUBLIC_SUFFIX:
            continue
        path = str(entry.path)
        if entry.kind is EntryKind.SYMLINK and entry.resolution is Resolution.OUTSIDE_ROOT:
            observations.append(PublicKeyObservation(path, Resolution.OUTSIDE_ROOT))
            continue
        try:
            text = fs.read_public_text(entry.path)
        except PrivateKeyAccessDenied:
            observations.append(PublicKeyObservation(path, Resolution.PRIVATE_ONLY))
            continue
        except OSError:
            observations.append(PublicKeyObservation(path, Resolution.UNREADABLE))
            continue
        observations.append(
            PublicKeyObservation(path, Resolution.RESOLVED, _first_nonempty_line(text))
        )
    observations.sort(key=lambda observation: observation.path)
    return observations
