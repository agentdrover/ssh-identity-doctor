"""FR-002 (sdd-spec §7.3, §10 SEC-001/SEC-003): resolve IdentityFile references.

For each ``IdentityFile`` directive found in a parsed ssh_config document,
:func:`resolve_identity_references` returns an :class:`IdentityReferences`
result with two parts:

``references`` — one :class:`LocalReference` (kind=``config_identity``) per
concrete path, classified into exactly one ``domain.Resolution`` (§7.3):

- ``resolved``: ``<ref>.pub`` exists inside the scan root and was safely read
  through :func:`ssh_id_doctor.fs.read_public_text`. The ``.pub`` decides on
  its own: where the private ``<ref>`` points (even a symlink leaving HOME) is
  irrelevant, and the private file is never opened.
- ``private_only``: no ``.pub``, only the private path exists (or the ``.pub``
  contained private-key material); the private file is never opened (SEC-001),
  checked only via ``os.stat``.
- ``missing``: neither ``.pub`` nor the identity file exists.
- ``unreadable``: the ``.pub`` file could not be read (permission denied, FIFO,
  socket, directory, oversized), or the identity path is a directory.
- ``outside_root``: the ``.pub`` itself escapes the scan root, or there is no
  ``.pub`` and the private path escapes it; nothing outside is opened or stat-ed.

``unresolved`` — an :class:`~ssh_id_doctor.ssh_config.UnresolvedConfigItem`
(reason ``unresolved_token``, detail = the raw value, with its source file and
line) for every ``IdentityFile`` whose path carries an unexpanded token
(``%h``, ``%r``, ``%d``, ``%u``, ``${VAR}``). Such a value is not a
LocalReference at all (§12: unresolved inputs are reported as unresolved, not
approximated); it is not resolved or stat-ed.

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
from pathlib import Path

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
_UNRESOLVED_REASON = "unresolved_token"


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


@dataclass(frozen=True, slots=True)
class IdentityReferences:
    """Result of :func:`resolve_identity_references`.

    ``references`` holds concrete paths, each with a ``domain.Resolution``;
    ``unresolved`` holds token-bearing ``IdentityFile`` values as
    ``unresolved_token`` items with their provenance (never LocalReferences).
    """

    references: tuple[LocalReference, ...]
    unresolved: tuple[UnresolvedConfigItem, ...]


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
            item.reason == _UNRESOLVED_REASON
            and item.source_file == entry.source.file
            and item.source_line == entry.source.line
        ):
            return True
    return False


def _collect_entries(doc: ConfigDocument) -> list[IdentityFileEntry | ResolvedIdentityFile]:
    entries: list[IdentityFileEntry | ResolvedIdentityFile] = []
    if hasattr(doc, "global_block") and hasattr(doc, "host_blocks"):
        if doc.global_block is not None:
            entries.extend(doc.global_block.identity_files)
        for block in doc.host_blocks:
            entries.extend(block.identity_files)
    elif hasattr(doc, "identity_files"):
        entries.extend(doc.identity_files)
    return entries


def _expand(raw: str, home_path: Path | None, ssh_dir_path: Path | None) -> Path:
    if raw == "~" and home_path is not None:
        candidate = home_path
    elif raw.startswith("~/") and home_path is not None:
        candidate = home_path / raw[2:]
    elif raw.startswith("~"):
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
    return Path(os.path.normpath(candidate))


def _classify_pub(resolved_pub: Path) -> tuple[Resolution, str | None]:
    """Read ``<ref>.pub`` (inside the root) through the safe reader only."""
    try:
        key_line = _first_nonempty_line(fs.read_public_text(resolved_pub))
    except PrivateKeyAccessDenied:
        return Resolution.PRIVATE_ONLY, None
    except (OSError, NotAPublicKeyFile):
        return Resolution.UNREADABLE, None
    return Resolution.RESOLVED, key_line


def _classify_private(home_path: Path, private_path: Path) -> Resolution:
    """No ``.pub``: classify ``<ref>`` itself by stat only, never open (SEC-001)."""
    resolved_ref, ref_resolution = fs.resolve_within(home_path, private_path)
    if ref_resolution is not Resolution.RESOLVED:
        return ref_resolution  # outside_root or missing
    try:
        st = os.stat(resolved_ref)
    except FileNotFoundError:
        return Resolution.MISSING
    except OSError:
        return Resolution.UNREADABLE
    if stat.S_ISREG(st.st_mode):
        return Resolution.PRIVATE_ONLY
    return Resolution.UNREADABLE


def _classify(home_path: Path, normalized_path: Path) -> tuple[Resolution, str | None]:
    """FR-002: ``<ref>.pub`` decides first; the private path only matters without it."""
    if normalized_path.name.endswith(".pub"):
        pub_candidate = normalized_path
    else:
        pub_candidate = normalized_path.with_name(normalized_path.name + ".pub")

    resolved_pub, pub_resolution = fs.resolve_within(home_path, pub_candidate)
    if pub_resolution is Resolution.OUTSIDE_ROOT:
        return Resolution.OUTSIDE_ROOT, None
    if pub_resolution is Resolution.RESOLVED:
        return _classify_pub(resolved_pub)
    return _classify_private(home_path, normalized_path), None


def resolve_identity_references(
    config_tree: ConfigDocument | str | os.PathLike[str],
    home: str | os.PathLike[str] | None = None,
    ssh_dir: str | os.PathLike[str] | None = None,
) -> IdentityReferences:
    """Resolve IdentityFile references from a parsed ssh_config document (FR-002).

    Parameters:
        config_tree: A parsed :class:`ConfigDocument` or path to an ssh_config file.
        home: The user's home directory (scan root for references). Defaults to ``$HOME``.
        ssh_dir: The directory used to resolve relative IdentityFile arguments.
                 Defaults to ``home / .ssh``.

    Returns an :class:`IdentityReferences`: concrete ``references`` (each with
    a ``domain.Resolution``) and token-bearing values as ``unresolved`` items.
    """
    if isinstance(config_tree, (str, os.PathLike)):
        doc = ssh_config.parse_file(config_tree)
    else:
        doc = config_tree

    home_str = os.fspath(home) if home is not None else os.environ.get("HOME")
    home_path = Path(os.path.realpath(home_str)) if home_str else None

    if ssh_dir is not None:
        ssh_dir_path: Path | None = Path(os.path.realpath(os.fspath(ssh_dir)))
    elif home_path is not None:
        ssh_dir_path = home_path / ".ssh"
    else:
        ssh_dir_path = None

    unresolved_items: Sequence[UnresolvedConfigItem] = getattr(doc, "unresolved", ())

    references: list[LocalReference] = []
    unresolved: list[UnresolvedConfigItem] = []

    for entry in _collect_entries(doc):
        raw = entry.path.strip()
        if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
            raw = raw[1:-1]

        # 1. Unexpanded token (%h, %r, %d, %u, ${VAR}): an unresolved item, not a reference.
        if _has_unresolved_token(entry, unresolved_items):
            unresolved.append(
                UnresolvedConfigItem(
                    reason=_UNRESOLVED_REASON,
                    detail=entry.path,
                    source_file=entry.source.file,
                    source_line=entry.source.line,
                )
            )
            continue

        public_key_text: str | None = None
        if raw.startswith("~") and home_path is None:
            # 2. ~ without HOME cannot be expanded.
            path_str, resolution = entry.path, Resolution.UNREADABLE
        else:
            normalized_path = _expand(raw, home_path, ssh_dir_path)
            path_str = str(normalized_path)
            if home_path is None:
                # 3. No scan root at all: nothing can be shown to lie inside it.
                resolution = Resolution.OUTSIDE_ROOT
            else:
                resolution, public_key_text = _classify(home_path, normalized_path)

        references.append(
            LocalReference(
                kind=LocalReferenceKind.CONFIG_IDENTITY,
                path=path_str,
                source_file=entry.source.file,
                source_line=entry.source.line,
                resolution=resolution,
                public_key_text=public_key_text,
                key_line=public_key_text,
            )
        )

    return IdentityReferences(references=tuple(references), unresolved=tuple(unresolved))


__all__ = [
    "ConfigIdentityReference",
    "IdentityReference",
    "IdentityReferences",
    "LocalReference",
    "resolve_identity_references",
]
