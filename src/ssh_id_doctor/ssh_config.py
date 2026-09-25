"""FR-004a (sdd-spec §7.4, §10 SEC-001/SEC-003): parse one ssh_config(5) file.

:func:`parse_file` lexes and parses a single config file into a
:class:`ConfigDocument`: the options declared before the first ``Host`` line
(the *global* block, which OpenSSH applies unconditionally) plus one
:class:`HostBlock` per ``Host`` directive, each carrying the file and line
number every option came from. :meth:`ConfigDocument.evaluate` then resolves
one alias against the document the way ``ssh`` does: parameters are applied
top to bottom, the global block first, and for a scalar option (``User``,
``HostName``, ``IdentitiesOnly``) the *first* value seen among the blocks
that match the alias wins (man ssh_config: "for each parameter, the first
obtained value will be used"); ``IdentityFile`` is multi-valued and
accumulates, in file order, from every matching block instead.

Unsupported options are ignored without breaking the parse; a line with no
keyword before its separator becomes an :class:`UnresolvedConfigItem` naming
its line, and parsing continues with the rest of the file. ``Include``,
``Match`` and the ``%h``/``%d``/``${VAR}`` tokens are out of scope (SID-6);
a ``Match`` line is currently just an unsupported keyword.

The file itself is read only through :func:`ssh_id_doctor.fs.read_config_text`
(SEC-001/SEC-003): a target that is not a regular file, is over the size
limit, or holds a private-key header on any line never reaches the lexer —
it becomes a single :class:`UnresolvedConfigItem` on the returned document
instead of raising, so a scan does not abort on one unreadable config.
"""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from ssh_id_doctor import fs
from ssh_id_doctor.fs import NotAConfigFile, PrivateKeyAccessDenied

_SUPPORTED_KEYS: frozenset[str] = frozenset(
    {"host", "identityfile", "identitiesonly", "user", "hostname"}
)


@dataclass(frozen=True, slots=True)
class IdentityFileEntry:
    """One ``IdentityFile`` value, in the block that declared it."""

    path: str
    source_line: int


@dataclass(frozen=True, slots=True)
class HostBlock:
    """One parsed stanza: the implicit global block, or one ``Host`` directive.

    ``patterns`` is empty for the global block and the raw tokens (each
    optionally prefixed with ``!`` for negation) for a ``Host`` line;
    ``header_line`` is ``None`` for the global block and the line of the
    ``Host`` directive otherwise. Scalar fields keep only the first value
    declared inside this block (OpenSSH first-value-wins applies within a
    block too); ``identity_files`` accumulates every value in order.
    """

    patterns: tuple[str, ...]
    header_line: int | None
    hostname: str | None = None
    hostname_line: int | None = None
    user: str | None = None
    user_line: int | None = None
    identities_only: bool | None = None
    identities_only_line: int | None = None
    identity_files: tuple[IdentityFileEntry, ...] = ()


@dataclass(frozen=True, slots=True)
class UnresolvedConfigItem:
    """One config line, or the whole file, that could not be resolved.

    ``reason`` is a short stable code (e.g. ``malformed_line``); ``detail``
    is free text for diagnostics and never carries key material.
    """

    reason: str
    detail: str
    source_file: str
    source_line: int | None


@dataclass(frozen=True, slots=True)
class ResolvedIdentityFile:
    """One ``IdentityFile`` value contributed to a resolved alias, with its provenance."""

    path: str
    source_file: str
    source_line: int


@dataclass(frozen=True, slots=True)
class ResolvedHost:
    """The result of :meth:`ConfigDocument.evaluate` for one alias (§7.4).

    ``patterns`` is the pattern list of the first ``Host`` block (in file
    order) that matched the alias — empty when only the global block
    applied. Each scalar field is paired with the line that produced it
    (``None`` when nothing set it); ``identity_files`` lists every
    contributing value in the order it was declared across the file.
    """

    alias: str
    source_file: str
    patterns: tuple[str, ...]
    hostname: str | None
    hostname_source_line: int | None
    user: str | None
    user_source_line: int | None
    identities_only: bool | None
    identities_only_source_line: int | None
    identity_files: tuple[ResolvedIdentityFile, ...]


@dataclass(frozen=True, slots=True)
class ConfigDocument:
    """One parsed ssh_config(5) file (§7.4)."""

    path: str
    global_block: HostBlock
    host_blocks: tuple[HostBlock, ...]
    unresolved: tuple[UnresolvedConfigItem, ...]

    def evaluate(self, alias: str) -> ResolvedHost:
        """Resolve ``alias`` against this document; see module docstring for the semantics."""
        return evaluate(self, alias)


class _MalformedLine(Exception):
    """Raised internally for a line with no keyword before its separator."""


@dataclass(slots=True)
class _MutableBlock:
    patterns: tuple[str, ...]
    header_line: int | None
    hostname: str | None = None
    hostname_line: int | None = None
    user: str | None = None
    user_line: int | None = None
    identities_only: bool | None = None
    identities_only_line: int | None = None
    identity_files: list[IdentityFileEntry] = field(default_factory=list)

    def freeze(self) -> HostBlock:
        return HostBlock(
            patterns=self.patterns,
            header_line=self.header_line,
            hostname=self.hostname,
            hostname_line=self.hostname_line,
            user=self.user,
            user_line=self.user_line,
            identities_only=self.identities_only,
            identities_only_line=self.identities_only_line,
            identity_files=tuple(self.identity_files),
        )


def parse_file(path: str | os.PathLike[str]) -> ConfigDocument:
    """Parse one ssh_config(5) file, safely, into a :class:`ConfigDocument`.

    A file that cannot be read at all (not a regular file, over the size
    limit, or holding private-key material — AC-4) yields a document with no
    blocks and a single :class:`UnresolvedConfigItem` naming the reason,
    instead of raising: the caller's scan continues.
    """
    path_str = os.fspath(path)
    try:
        text = fs.read_config_text(path)
    except PrivateKeyAccessDenied as exc:
        return _refused_document(path_str, "private_key_material", str(exc))
    except NotAConfigFile as exc:
        return _refused_document(path_str, "not_a_config_file", str(exc))
    except OSError as exc:
        return _refused_document(path_str, "unreadable_config", str(exc))

    global_block = _MutableBlock(patterns=(), header_line=None)
    blocks: list[_MutableBlock] = []
    current = global_block
    unresolved: list[UnresolvedConfigItem] = []

    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        try:
            parsed = _parse_line(raw_line)
        except _MalformedLine as exc:
            unresolved.append(UnresolvedConfigItem("malformed_line", str(exc), path_str, lineno))
            continue
        if parsed is None:
            continue
        keyword, tokens = parsed
        key = keyword.lower()
        if key == "host":
            current = _MutableBlock(patterns=tuple(tokens), header_line=lineno)
            blocks.append(current)
            continue
        if key not in _SUPPORTED_KEYS:
            continue
        if not tokens:
            unresolved.append(UnresolvedConfigItem("missing_value", keyword, path_str, lineno))
            continue
        _apply_option(current, key, tokens[0], lineno, unresolved, path_str)

    return ConfigDocument(
        path=path_str,
        global_block=global_block.freeze(),
        host_blocks=tuple(block.freeze() for block in blocks),
        unresolved=tuple(unresolved),
    )


def _refused_document(path_str: str, reason: str, detail: str) -> ConfigDocument:
    return ConfigDocument(
        path=path_str,
        global_block=HostBlock(patterns=(), header_line=None),
        host_blocks=(),
        unresolved=(UnresolvedConfigItem(reason, detail, path_str, None),),
    )


def _apply_option(
    block: _MutableBlock,
    key: str,
    value: str,
    lineno: int,
    unresolved: list[UnresolvedConfigItem],
    path_str: str,
) -> None:
    if key == "identityfile":
        block.identity_files.append(IdentityFileEntry(value, lineno))
    elif key == "user":
        if block.user is None:
            block.user, block.user_line = value, lineno
    elif key == "hostname":
        if block.hostname is None:
            block.hostname, block.hostname_line = value, lineno
    elif key == "identitiesonly":
        parsed_bool = _parse_bool(value)
        if parsed_bool is None:
            unresolved.append(
                UnresolvedConfigItem("invalid_identities_only", value, path_str, lineno)
            )
        elif block.identities_only is None:
            block.identities_only, block.identities_only_line = parsed_bool, lineno


def _parse_bool(token: str) -> bool | None:
    lowered = token.lower()
    if lowered == "yes":
        return True
    if lowered == "no":
        return False
    return None


def _parse_line(raw_line: str) -> tuple[str, list[str]] | None:
    """One line's ``(keyword, value_tokens)``, or ``None`` for blank/comment.

    Raises :class:`_MalformedLine` for a line with no keyword before its
    separator (e.g. ``"=== "``).
    """
    stripped = raw_line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    split = _split_keyword(stripped)
    if split is None:
        raise _MalformedLine(stripped)
    keyword, rest = split
    return keyword, _tokenize_value(rest)


def _split_keyword(stripped: str) -> tuple[str, str] | None:
    """Split ``"Keyword rest"`` / ``"Keyword=rest"`` / ``"Keyword = rest"``."""
    i = 0
    n = len(stripped)
    while i < n and stripped[i] not in " \t=":
        i += 1
    if i == 0:
        return None
    keyword = stripped[:i]
    rest = stripped[i:]
    j = 0
    m = len(rest)
    while j < m and rest[j] in " \t":
        j += 1
    if j < m and rest[j] == "=":
        j += 1
        while j < m and rest[j] in " \t":
            j += 1
    return keyword, rest[j:]


def _tokenize_value(text: str) -> list[str]:
    """Whitespace-separated tokens, honoring double quotes and a trailing ``#`` comment."""
    tokens: list[str] = []
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i] in " \t":
            i += 1
        if i >= n or text[i] == "#":
            break
        if text[i] == '"':
            end = text.find('"', i + 1)
            if end == -1:
                tokens.append(text[i + 1 :])
                i = n
            else:
                tokens.append(text[i + 1 : end])
                i = end + 1
        else:
            j = i
            while j < n and text[j] not in " \t":
                j += 1
            tokens.append(text[i:j])
            i = j
    return tokens


def evaluate(document: ConfigDocument, alias: str) -> ResolvedHost:
    """Resolve ``alias`` against ``document``; see module docstring for the semantics."""
    hostname: str | None = None
    hostname_line: int | None = None
    user: str | None = None
    user_line: int | None = None
    identities_only: bool | None = None
    identities_only_line: int | None = None
    identity_files: list[ResolvedIdentityFile] = []
    primary_patterns: tuple[str, ...] = ()

    for block in (document.global_block, *document.host_blocks):
        is_global = block is document.global_block
        if not is_global and not _host_line_matches(block.patterns, alias):
            continue
        if not is_global and not primary_patterns:
            primary_patterns = block.patterns
        if user is None and block.user is not None:
            user, user_line = block.user, block.user_line
        if hostname is None and block.hostname is not None:
            hostname, hostname_line = block.hostname, block.hostname_line
        if identities_only is None and block.identities_only is not None:
            identities_only = block.identities_only
            identities_only_line = block.identities_only_line
        for entry in block.identity_files:
            identity_files.append(
                ResolvedIdentityFile(entry.path, document.path, entry.source_line)
            )

    return ResolvedHost(
        alias=alias,
        source_file=document.path,
        patterns=primary_patterns,
        hostname=hostname,
        hostname_source_line=hostname_line,
        user=user,
        user_source_line=user_line,
        identities_only=identities_only,
        identities_only_source_line=identities_only_line,
        identity_files=tuple(identity_files),
    )


def _host_line_matches(patterns: Sequence[str], alias: str) -> bool:
    """OpenSSH Host-list semantics: any matching negated pattern excludes the whole line."""
    matched = False
    for raw in patterns:
        negate = raw.startswith("!")
        pattern = raw[1:] if negate else raw
        if _wildcard_match(pattern, alias):
            if negate:
                return False
            matched = True
    return matched


def _wildcard_match(pattern: str, value: str) -> bool:
    return re.fullmatch(_wildcard_to_regex(pattern), value) is not None


def _wildcard_to_regex(pattern: str) -> str:
    """Translate ssh_config's ``*``/``?`` globbing (only) to a regex."""
    parts: list[str] = []
    for char in pattern:
        if char == "*":
            parts.append(".*")
        elif char == "?":
            parts.append(".")
        else:
            parts.append(re.escape(char))
    return "".join(parts)


__all__ = [
    "ConfigDocument",
    "HostBlock",
    "IdentityFileEntry",
    "ResolvedHost",
    "ResolvedIdentityFile",
    "UnresolvedConfigItem",
    "evaluate",
    "parse_file",
]
