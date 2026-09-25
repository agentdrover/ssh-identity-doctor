"""FR-004 (sdd-spec §7.4, §10 SEC-001/SEC-002/SEC-003): parse ssh_config(5), with Include.

:func:`parse_file` lexes and parses one ssh_config(5) file — following any
``Include`` directives it finds — into a :class:`ConfigDocument`: the
options declared before the first ``Host``/``Match`` line (the *global*
block, which OpenSSH applies unconditionally) plus one :class:`HostBlock` per
``Host`` directive, each carrying the real file and line number every option
came from (an included file's blocks point at *that* file, not the one that
included it). :meth:`ConfigDocument.evaluate` then resolves one alias
against the document the way ``ssh`` does: parameters are applied top to
bottom, the global block first, and for a scalar option (``User``,
``HostName``, ``IdentitiesOnly``) the *first* value seen among the blocks
that match the alias wins (man ssh_config: "for each parameter, the first
obtained value will be used"); ``IdentityFile`` is multi-valued and
accumulates, in file order, from every matching block instead.

``Include`` is followed with OpenSSH's own rules: quoted and unquoted
arguments, ``~`` expanded to ``$HOME``, a relative argument resolved against
the directory of the top-level file being parsed (as OpenSSH resolves a
relative Include in a user config against ``~/.ssh``), and the result
glob-expanded in sorted order (an empty match is not an error). An Include
inside a ``Host``/``Match`` block continues in that block's context, exactly
as OpenSSH splices the included text in place — including a ``Host`` line
inside the included file, which still opens a new stanza. Recursion is
bounded by both a cycle guard (the *ancestor* chain of real paths currently
being read) and a hard depth limit, so a self-including file terminates
deterministically (NFR-002) instead of recursing forever; an explicit,
non-glob include that resolves to nothing becomes an :class:`UnresolvedConfigItem`
(``include_missing``) instead of aborting the parse.

Unsupported options are ignored without breaking the parse; a line with no
keyword before its separator becomes an :class:`UnresolvedConfigItem` naming
its line. ``Match`` is not evaluated (SEC-002: its ``exec`` clause is never
run) — a ``Match`` line opens its own stanza, reported as
:class:`UnresolvedConfigItem` (``match_not_evaluated``), whose options apply
to no alias. A value containing an unexpandable token (``%h``, ``%r``,
``%d``, ``%u`` or ``${VAR}``) is kept as its literal text — never expanded —
and paired with an :class:`UnresolvedConfigItem` (``unresolved_token``)
naming the line, since it cannot be checked against anything concrete.

Every file this module reads — the top-level path and every ``Include``
target — goes exclusively through :func:`ssh_id_doctor.fs.read_config_text`
(SEC-001/SEC-003): a target that is not a regular file, is over the size
limit, or holds a private-key header on any line never reaches the lexer —
it becomes a single :class:`UnresolvedConfigItem` on the document instead of
raising, so one bad file does not abort the rest of the tree.
"""

from __future__ import annotations

import glob as glob_module
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from ssh_id_doctor import fs
from ssh_id_doctor.fs import NotAConfigFile, PrivateKeyAccessDenied

_SUPPORTED_KEYS: frozenset[str] = frozenset(
    {"host", "identityfile", "identitiesonly", "user", "hostname"}
)
_TOKEN_RE = re.compile(r"%[hrdu]|\$\{[^}]*\}")
_MAX_INCLUDE_DEPTH = 16
"""Recursion limit for Include chains (scope_in), on top of the cycle guard."""


@dataclass(frozen=True, slots=True)
class SourceLoc:
    """Where one option or block header came from: a real file path and its line."""

    file: str
    line: int


@dataclass(frozen=True, slots=True)
class IdentityFileEntry:
    """One ``IdentityFile`` value, where it was declared."""

    path: str
    source: SourceLoc


@dataclass(frozen=True, slots=True)
class HostBlock:
    """One parsed stanza: the implicit global block, or one ``Host``/``Match`` directive.

    ``patterns`` is empty for the global block and for a ``Match`` stanza
    (so it never matches any alias — see module docstring), and the raw
    ``Host`` tokens (each optionally prefixed with ``!`` for negation)
    otherwise; ``header`` is ``None`` for the global block and the location
    of the ``Host``/``Match`` line otherwise. Scalar fields keep only the
    first value declared inside this block (OpenSSH first-value-wins applies
    within a block too); ``identity_files`` accumulates every value in
    order. An Include spliced into this block contributes its own options
    here too, each with its own file's :class:`SourceLoc`.
    """

    patterns: tuple[str, ...]
    header: SourceLoc | None
    hostname: str | None = None
    hostname_source: SourceLoc | None = None
    user: str | None = None
    user_source: SourceLoc | None = None
    identities_only: bool | None = None
    identities_only_source: SourceLoc | None = None
    identity_files: tuple[IdentityFileEntry, ...] = ()


@dataclass(frozen=True, slots=True)
class UnresolvedConfigItem:
    """One config line, or one whole file, that could not be resolved.

    ``reason`` is a short stable code (e.g. ``malformed_line``,
    ``include_cycle``, ``include_missing``, ``match_not_evaluated``,
    ``unresolved_token``); ``detail`` is free text for diagnostics and never
    carries key material. ``source_line`` is ``None`` for a whole-file
    problem (the file itself could not be read at all).
    """

    reason: str
    detail: str
    source_file: str
    source_line: int | None


@dataclass(frozen=True, slots=True)
class ResolvedIdentityFile:
    """One ``IdentityFile`` value contributed to a resolved alias, with its provenance."""

    path: str
    source: SourceLoc


@dataclass(frozen=True, slots=True)
class ResolvedHost:
    """The result of :meth:`ConfigDocument.evaluate` for one alias (§7.4).

    ``patterns`` is the pattern list of the first ``Host`` block (in file
    order) that matched the alias — empty when only the global block
    applied. Each scalar field is paired with the location that produced it
    (``None`` when nothing set it); ``identity_files`` lists every
    contributing value in the order it was declared, each with the file it
    actually came from (which may differ from any other field's file, when
    an Include spliced a different file into this alias's blocks).
    """

    alias: str
    patterns: tuple[str, ...]
    hostname: str | None
    hostname_source: SourceLoc | None
    user: str | None
    user_source: SourceLoc | None
    identities_only: bool | None
    identities_only_source: SourceLoc | None
    identity_files: tuple[ResolvedIdentityFile, ...]


@dataclass(frozen=True, slots=True)
class ConfigDocument:
    """One parsed ssh_config(5) file, with every ``Include`` it reached (§7.4)."""

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
    header: SourceLoc | None
    hostname: str | None = None
    hostname_source: SourceLoc | None = None
    user: str | None = None
    user_source: SourceLoc | None = None
    identities_only: bool | None = None
    identities_only_source: SourceLoc | None = None
    identity_files: list[IdentityFileEntry] = field(default_factory=list)

    def freeze(self) -> HostBlock:
        return HostBlock(
            patterns=self.patterns,
            header=self.header,
            hostname=self.hostname,
            hostname_source=self.hostname_source,
            user=self.user,
            user_source=self.user_source,
            identities_only=self.identities_only,
            identities_only_source=self.identities_only_source,
            identity_files=tuple(self.identity_files),
        )


@dataclass(slots=True)
class _ParseState:
    """Accumulated across one top-level file and every Include it pulls in."""

    root_dir: str
    blocks: list[_MutableBlock] = field(default_factory=list)
    unresolved: list[UnresolvedConfigItem] = field(default_factory=list)


def parse_file(path: str | os.PathLike[str]) -> ConfigDocument:
    """Parse one ssh_config(5) file, safely, following ``Include`` (§7.4, SEC-001/003).

    A file that cannot be read at all (not a regular file, over the size
    limit, or holding private-key material) contributes no blocks and a
    single :class:`UnresolvedConfigItem` naming the reason, instead of
    raising — the same is true of any ``Include`` target that fails the
    same way; either way the rest of the tree is still parsed.
    """
    root_real = os.path.realpath(os.fspath(path))
    root_dir = os.path.dirname(root_real) or os.sep
    state = _ParseState(root_dir=root_dir)
    global_block = _MutableBlock(patterns=(), header=None)
    _parse_into(root_real, state, global_block, frozenset({root_real}), depth=0)

    return ConfigDocument(
        path=root_real,
        global_block=global_block.freeze(),
        host_blocks=tuple(block.freeze() for block in state.blocks),
        unresolved=tuple(state.unresolved),
    )


def _parse_into(
    path: str | os.PathLike[str],
    state: _ParseState,
    current: _MutableBlock,
    ancestors: frozenset[str],
    depth: int,
) -> _MutableBlock:
    """Parse one file's lines into ``state``, continuing from ``current``.

    Returns the block active at end of file, so a caller that reached this
    file through ``Include`` knows which block to keep appending to.
    """
    path_str = os.path.realpath(os.fspath(path))
    try:
        text = fs.read_config_text(path)
    except PrivateKeyAccessDenied as exc:
        _refuse_file(state, path_str, "private_key_material", exc)
        return current
    except NotAConfigFile as exc:
        _refuse_file(state, path_str, "not_a_config_file", exc)
        return current
    except OSError as exc:
        _refuse_file(state, path_str, "unreadable_config", exc)
        return current

    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        try:
            parsed = _parse_line(raw_line)
        except _MalformedLine as exc:
            state.unresolved.append(
                UnresolvedConfigItem("malformed_line", str(exc), path_str, lineno)
            )
            continue
        if parsed is None:
            continue
        keyword, tokens = parsed
        key = keyword.lower()
        source = SourceLoc(path_str, lineno)
        if key == "host":
            current = _MutableBlock(patterns=tuple(tokens), header=source)
            state.blocks.append(current)
        elif key == "match":
            # Match is never evaluated (SEC-002): its stanza is unresolved and
            # detached — its options land in a block no alias will ever see.
            state.unresolved.append(
                UnresolvedConfigItem("match_not_evaluated", raw_line.strip(), path_str, lineno)
            )
            current = _MutableBlock(patterns=(), header=source)
        elif key == "include":
            current = _handle_include(tokens, state, current, ancestors, depth, source)
        elif key in _SUPPORTED_KEYS:
            if not tokens:
                state.unresolved.append(
                    UnresolvedConfigItem("missing_value", keyword, path_str, lineno)
                )
            else:
                _apply_option(current, key, tokens[0], source, state.unresolved)
        # else: unsupported option, ignored without breaking the parse.

    return current


def _refuse_file(state: _ParseState, path_str: str, reason: str, exc: Exception) -> None:
    state.unresolved.append(UnresolvedConfigItem(reason, str(exc), path_str, None))


def _handle_include(
    tokens: Sequence[str],
    state: _ParseState,
    current: _MutableBlock,
    ancestors: frozenset[str],
    depth: int,
    source: SourceLoc,
) -> _MutableBlock:
    if depth >= _MAX_INCLUDE_DEPTH:
        state.unresolved.append(
            UnresolvedConfigItem("include_depth_exceeded", source.file, source.file, source.line)
        )
        return current
    for argument in tokens:
        pattern = _resolve_include_argument(argument, state.root_dir)
        has_wildcard = any(char in pattern for char in "*?[")
        matches = sorted(glob_module.glob(pattern))
        if not matches and not has_wildcard:
            state.unresolved.append(
                UnresolvedConfigItem("include_missing", pattern, source.file, source.line)
            )
            continue
        for match in matches:
            real = os.path.realpath(match)
            if real in ancestors:
                state.unresolved.append(
                    UnresolvedConfigItem("include_cycle", match, source.file, source.line)
                )
                continue
            current = _parse_into(real, state, current, ancestors | {real}, depth + 1)
    return current


def _resolve_include_argument(argument: str, root_dir: str) -> str:
    """OpenSSH Include argument rules: ``~`` to ``$HOME``, else relative to ``root_dir``."""
    if argument == "~" or argument.startswith("~/"):
        expanded = os.path.expanduser(argument)
    elif os.path.isabs(argument):
        expanded = argument
    else:
        expanded = os.path.join(root_dir, argument)
    return os.path.normpath(expanded)


def _apply_option(
    block: _MutableBlock,
    key: str,
    value: str,
    source: SourceLoc,
    unresolved: list[UnresolvedConfigItem],
) -> None:
    if _TOKEN_RE.search(value):
        unresolved.append(UnresolvedConfigItem("unresolved_token", value, source.file, source.line))
    if key == "identityfile":
        block.identity_files.append(IdentityFileEntry(value, source))
    elif key == "user":
        if block.user is None:
            block.user, block.user_source = value, source
    elif key == "hostname":
        if block.hostname is None:
            block.hostname, block.hostname_source = value, source
    elif key == "identitiesonly":
        parsed_bool = _parse_bool(value)
        if parsed_bool is None:
            unresolved.append(
                UnresolvedConfigItem("invalid_identities_only", value, source.file, source.line)
            )
        elif block.identities_only is None:
            block.identities_only, block.identities_only_source = parsed_bool, source


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
    hostname_source: SourceLoc | None = None
    user: str | None = None
    user_source: SourceLoc | None = None
    identities_only: bool | None = None
    identities_only_source: SourceLoc | None = None
    identity_files: list[ResolvedIdentityFile] = []
    primary_patterns: tuple[str, ...] = ()

    for block in (document.global_block, *document.host_blocks):
        is_global = block is document.global_block
        if not is_global and not _host_line_matches(block.patterns, alias):
            continue
        if not is_global and not primary_patterns:
            primary_patterns = block.patterns
        if user is None and block.user is not None:
            user, user_source = block.user, block.user_source
        if hostname is None and block.hostname is not None:
            hostname, hostname_source = block.hostname, block.hostname_source
        if identities_only is None and block.identities_only is not None:
            identities_only = block.identities_only
            identities_only_source = block.identities_only_source
        for entry in block.identity_files:
            identity_files.append(ResolvedIdentityFile(entry.path, entry.source))

    return ResolvedHost(
        alias=alias,
        patterns=primary_patterns,
        hostname=hostname,
        hostname_source=hostname_source,
        user=user,
        user_source=user_source,
        identities_only=identities_only,
        identities_only_source=identities_only_source,
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
    "SourceLoc",
    "UnresolvedConfigItem",
    "evaluate",
    "parse_file",
]
