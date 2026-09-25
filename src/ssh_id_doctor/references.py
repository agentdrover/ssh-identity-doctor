"""FR-002 (sdd-spec §7.3, §10 SEC-001/SEC-003): resolve IdentityFile references.

For each ``IdentityFile`` directive found in a parsed ssh_config document,
constructs a :class:`LocalReference` (kind=``config_identity``) classified into
one of five resolution states (plus ``unresolved`` for unexpandable tokens):

- ``resolved``: a matching ``.pub`` file exists and was safely read through
  :func:`ssh_id_doctor.fs.read_public_text`.
- ``private_only``: only the private-key path exists (or the ``.pub`` file
  contained private-key material); the private file is never opened (SEC-001),
  checked only via ``os.stat``.
- ``missing``: neither ``.pub`` nor the identity file exists.
- ``unreadable``: the ``.pub`` file could not be read (permission denied, FIFO,
  socket, directory, oversized), or the identity path is a directory.
- ``outside_root``: the identity path or its ``.pub`` escapes the user's HOME
  scan root; it is not opened or stat-ed.
- ``unresolved``: the path contains unexpanded tokens (``%h``, ``%r``, ``%d``,
  ``%u``, ``${VAR}``); it is not resolved or stat-ed.

Scan root rule (FR-002 risk mitigation):
The scan root for ``IdentityFile`` references is the user's HOME directory, NOT
``--ssh-dir``. Keys stored in legitimate locations under HOME (e.g.
``~/keys/id_work``) must not be reported as ``outside_root``. Only paths leaving
HOME are flagged as ``outside_root``.
"""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import cast

from ssh_id_doctor import fs, ssh_config
from ssh_id_doctor.domain import (
    LocalReference as BaseLocalReference,
)
from ssh_id_doctor.domain import (
    LocalReferenceKind,
    Resolution,
)
from ssh_id_doctor.fs import NotAPublicKeyFile, PrivateKeyAccessDenied
from ssh_id_doctor.ssh_config import (
    ConfigDocument,
    IdentityFileEntry,
    ResolvedIdentityFile,
    UnresolvedConfigItem,
)

_TOKEN_RE = re.compile(r"%[hrdu]|\$\{[^}]*\}")


class IdentityResolution(StrEnum):
    """Resolution states for identity references, extending domain.Resolution with unresolved."""

    RESOLVED = "resolved"
    MISSING = "missing"
    UNREADABLE = "unreadable"
    OUTSIDE_ROOT = "outside_root"
    PRIVATE_ONLY = "private_only"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True, slots=True)
class LocalReference(BaseLocalReference):
    """§7.3 LocalReference for an IdentityFile directive from ssh_config(5).

    Carries ``public_key_text`` (and its alias ``key_line``) when the reference
    resolves to a valid ``.pub`` file.
    """

    public_key_text: str | None = None
    key_line: str | None = None

    @property
    def public_text(self) -> str | None:
        return self.public_key_text


ConfigIdentityReference = LocalReference
IdentityReference = LocalReference


def _first_nonempty_line(text: str) -> str | None:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return None


def _has_unresolved_token(
    entry: IdentityFileEntry | ResolvedIdentityFile,
    unresolved_items: Sequence[UnresolvedConfigItem],
) -> bool:
    if _TOKEN_RE.search(entry.path):
        return True
    for item in unresolved_items:
        if (
            item.reason == "unresolved_token"
            and item.source_file == entry.source.file
            and item.source_line == entry.source.line
        ):
            return True
    return False


def resolve_identity_references(
    config_tree: ConfigDocument | str | os.PathLike[str],
    home: str | os.PathLike[str] | None = None,
    ssh_dir: str | os.PathLike[str] | None = None,
) -> list[LocalReference]:
    """Resolve IdentityFile references from a parsed ssh_config document (FR-002).

    Parameters:
        config_tree: A parsed :class:`ConfigDocument` or path to an ssh_config file.
        home: The user's home directory (scan root for references). Defaults to ``$HOME``.
        ssh_dir: The directory used to resolve relative IdentityFile arguments.
                 Defaults to ``home / .ssh``.
    """
    if isinstance(config_tree, (str, os.PathLike)):
        doc = ssh_config.parse_file(config_tree)
    else:
        doc = config_tree

    home_str = os.fspath(home) if home is not None else os.environ.get("HOME")
    home_path = Path(os.path.realpath(home_str)) if home_str else None

    if ssh_dir is not None:
        ssh_dir_path = Path(os.path.realpath(os.fspath(ssh_dir)))
    elif home_path is not None:
        ssh_dir_path = home_path / ".ssh"
    else:
        ssh_dir_path = None

    entries: list[IdentityFileEntry | ResolvedIdentityFile] = []
    if hasattr(doc, "global_block") and hasattr(doc, "host_blocks"):
        if doc.global_block is not None:
            entries.extend(doc.global_block.identity_files)
        for block in doc.host_blocks:
            entries.extend(block.identity_files)
    elif hasattr(doc, "identity_files"):
        entries.extend(doc.identity_files)

    unresolved_items: Sequence[UnresolvedConfigItem] = getattr(doc, "unresolved", ())

    references: list[LocalReference] = []

    for entry in entries:
        raw = entry.path.strip()
        if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
            raw = raw[1:-1]

        # 1. Unresolved token check (%h, %r, %d, %u, ${VAR})
        if _has_unresolved_token(entry, unresolved_items):
            references.append(
                LocalReference(
                    kind=LocalReferenceKind.CONFIG_IDENTITY,
                    path=entry.path,
                    source_file=entry.source.file,
                    source_line=entry.source.line,
                    resolution=cast(Resolution, IdentityResolution.UNRESOLVED),
                )
            )
            continue

        # 2. ~ without HOME
        if raw.startswith("~") and home_path is None:
            references.append(
                LocalReference(
                    kind=LocalReferenceKind.CONFIG_IDENTITY,
                    path=entry.path,
                    source_file=entry.source.file,
                    source_line=entry.source.line,
                    resolution=Resolution.UNREADABLE,
                )
            )
            continue

        # 3. Path expansion
        if raw == "~" and home_path is not None:
            candidate = home_path
        elif raw.startswith("~/") and home_path is not None:
            candidate = home_path / raw[2:]
        elif raw.startswith("~") and home_path is not None:
            candidate = Path(os.path.expanduser(raw))
        elif os.path.isabs(raw):
            candidate = Path(raw)
        else:
            base_dir = (
                ssh_dir_path
                if ssh_dir_path is not None
                else (home_path / ".ssh" if home_path is not None else Path.cwd())
            )
            candidate = base_dir / raw

        normalized_path = Path(os.path.normpath(candidate))

        # 4. Check if path is outside root (HOME)
        if home_path is None:
            references.append(
                LocalReference(
                    kind=LocalReferenceKind.CONFIG_IDENTITY,
                    path=str(normalized_path),
                    source_file=entry.source.file,
                    source_line=entry.source.line,
                    resolution=Resolution.OUTSIDE_ROOT,
                )
            )
            continue

        _, within_status = fs.resolve_within(home_path, normalized_path)
        if within_status is Resolution.OUTSIDE_ROOT:
            references.append(
                LocalReference(
                    kind=LocalReferenceKind.CONFIG_IDENTITY,
                    path=str(normalized_path),
                    source_file=entry.source.file,
                    source_line=entry.source.line,
                    resolution=Resolution.OUTSIDE_ROOT,
                )
            )
            continue

        # 5. Check for <ref>.pub
        if normalized_path.name.endswith(".pub"):
            pub_candidate = normalized_path
        else:
            pub_candidate = normalized_path.with_name(normalized_path.name + ".pub")

        resolved_pub, pub_resolution = fs.resolve_within(home_path, pub_candidate)
        if pub_resolution is Resolution.OUTSIDE_ROOT:
            references.append(
                LocalReference(
                    kind=LocalReferenceKind.CONFIG_IDENTITY,
                    path=str(normalized_path),
                    source_file=entry.source.file,
                    source_line=entry.source.line,
                    resolution=Resolution.OUTSIDE_ROOT,
                )
            )
            continue

        if pub_resolution is Resolution.RESOLVED:
            try:
                pub_text = fs.read_public_text(resolved_pub)
                key_line = _first_nonempty_line(pub_text)
                references.append(
                    LocalReference(
                        kind=LocalReferenceKind.CONFIG_IDENTITY,
                        path=str(normalized_path),
                        source_file=entry.source.file,
                        source_line=entry.source.line,
                        resolution=Resolution.RESOLVED,
                        public_key_text=key_line,
                        key_line=key_line,
                    )
                )
                continue
            except PrivateKeyAccessDenied:
                references.append(
                    LocalReference(
                        kind=LocalReferenceKind.CONFIG_IDENTITY,
                        path=str(normalized_path),
                        source_file=entry.source.file,
                        source_line=entry.source.line,
                        resolution=Resolution.PRIVATE_ONLY,
                    )
                )
                continue
            except (OSError, NotAPublicKeyFile):
                references.append(
                    LocalReference(
                        kind=LocalReferenceKind.CONFIG_IDENTITY,
                        path=str(normalized_path),
                        source_file=entry.source.file,
                        source_line=entry.source.line,
                        resolution=Resolution.UNREADABLE,
                    )
                )
                continue

        # 6. No .pub file exists; check <ref> itself without opening (SEC-001).
        resolved_ref, ref_resolution = fs.resolve_within(home_path, normalized_path)
        if ref_resolution is Resolution.MISSING:
            resolution = Resolution.MISSING
        else:
            try:
                st = os.stat(resolved_ref)
                if stat.S_ISDIR(st.st_mode):
                    resolution = Resolution.UNREADABLE
                elif stat.S_ISREG(st.st_mode):
                    resolution = Resolution.PRIVATE_ONLY
                else:
                    resolution = Resolution.UNREADABLE
            except FileNotFoundError:
                resolution = Resolution.MISSING
            except PermissionError:
                resolution = Resolution.UNREADABLE
            except OSError:
                resolution = Resolution.UNREADABLE

        references.append(
            LocalReference(
                kind=LocalReferenceKind.CONFIG_IDENTITY,
                path=str(normalized_path),
                source_file=entry.source.file,
                source_line=entry.source.line,
                resolution=resolution,
            )
        )

    return references


__all__ = [
    "ConfigIdentityReference",
    "IdentityReference",
    "IdentityResolution",
    "LocalReference",
    "resolve_identity_references",
]
