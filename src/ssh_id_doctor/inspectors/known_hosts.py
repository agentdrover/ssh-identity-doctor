"""known_hosts(5) grammar parser (task #1794, sdd-spec §7, §10 SEC-002/SEC-003).

Pure text parsing: no I/O, no ``subprocess``/``ssh_id_doctor.process`` import.
The caller hands this module text already produced by
:func:`ssh_id_doctor.fs.read_known_hosts_text`; it never touches a path
itself. A line that does not fit the grammar becomes a
:class:`ssh_id_doctor.domain.UnresolvedItem` whose ``detail`` is always empty
and whose ``kind`` is a stable short code — the broken line's content is
never quoted anywhere.

Grammar (known_hosts(5)):

- blank lines and ``#`` comments are skipped;
- an optional marker, ``@revoked`` or ``@cert-authority`` — any other
  ``@...`` token is broken;
- a comma-separated hosts field: each item is a name, ``[name]:port``, a
  ``*``/``?`` pattern (optionally negated with a leading ``!``), or a
  hashed ``|1|<base64 salt>|<base64 hash>`` token whose salt and hash must
  each be strictly valid base64 decoding to exactly 20 bytes (the HMAC-SHA1
  digest size OpenSSH uses for ``HashKnownHosts``);
- a key type and a base64 blob: the base64 must decode under
  ``binascii.a2b_base64(strict_mode=True)``; the blob's first SSH wire
  string must equal the key type; the remaining bytes must parse completely,
  with no leftover, into the fields that type defines (ed25519: one 32-byte
  string; rsa: two mpints; dss: four mpints; ecdsa: a curve-name string
  matching the type plus a point string; the two ``sk-*@openssh.com`` types:
  the base algorithm's fields plus an application string). An unrecognized
  type is still recorded, with its ``key_type`` kept as-is, as long as the
  blob is a clean sequence of SSH wire strings with nothing left over;
- anything after the blob is a comment and is discarded, never stored.

The fingerprint is ``'SHA256:' + base64(sha256(blob))`` with the trailing
``=`` padding stripped — the same value ``ssh-keygen -l`` prints.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass

from ssh_id_doctor.domain import KnownHostEntry, UnresolvedItem

_MARKERS: dict[str, str] = {"@revoked": "revoked", "@cert-authority": "cert-authority"}

_HASH_TOKEN_LENGTH = 20
"""Bytes. OpenSSH's HashKnownHosts salt and HMAC-SHA1 digest are both this size."""

_ECDSA_CURVES: dict[str, bytes] = {
    "ecdsa-sha2-nistp256": b"nistp256",
    "ecdsa-sha2-nistp384": b"nistp384",
    "ecdsa-sha2-nistp521": b"nistp521",
}
_SK_ECDSA_CURVES: dict[str, bytes] = {
    "sk-ecdsa-sha2-nistp256@openssh.com": b"nistp256",
}
_SK_ED25519_TYPE = "sk-ssh-ed25519@openssh.com"
_ED25519_POINT_LENGTH = 32


@dataclass(frozen=True, slots=True)
class ParseResult:
    """Parsed known_hosts(5) text: valid entries and broken lines, in line order."""

    entries: tuple[KnownHostEntry, ...]
    unresolved: tuple[UnresolvedItem, ...]


class _BlobReader:
    """Sequential reader of SSH wire-format strings/mpints (RFC 4251 §5)."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def read_string(self) -> bytes | None:
        if self._pos + 4 > len(self._data):
            return None
        length = int.from_bytes(self._data[self._pos : self._pos + 4], "big")
        self._pos += 4
        if length < 0 or self._pos + length > len(self._data):
            return None
        value = self._data[self._pos : self._pos + length]
        self._pos += length
        return value

    def has_remaining(self) -> bool:
        return self._pos < len(self._data)

    def at_end(self) -> bool:
        return self._pos == len(self._data)


def _bad(source_file: str, line: int, reason: str) -> UnresolvedItem:
    return UnresolvedItem(kind=reason, detail="", source_file=source_file, source_line=line)


def _strict_b64_decode(text: str) -> bytes | None:
    try:
        return binascii.a2b_base64(text.encode("ascii"), strict_mode=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return None


def _valid_hashed_token(token: str) -> bool:
    parts = token.split("|")
    if len(parts) != 4 or parts[0] != "" or parts[1] != "1":
        return False
    salt = _strict_b64_decode(parts[2])
    digest = _strict_b64_decode(parts[3])
    if salt is None or digest is None:
        return False
    return len(salt) == _HASH_TOKEN_LENGTH and len(digest) == _HASH_TOKEN_LENGTH


def _parse_hosts_field(field: str) -> tuple[str, ...] | None:
    items = field.split(",")
    parsed: list[str] = []
    for item in items:
        candidate = item[1:] if item.startswith("!") else item
        if not candidate:
            return None
        if candidate.startswith("|1|") and not _valid_hashed_token(candidate):
            return None
        parsed.append(item)
    return tuple(parsed)


def _validate_blob(key_type: str, blob: bytes) -> bool:
    reader = _BlobReader(blob)
    type_field = reader.read_string()
    try:
        if type_field != key_type.encode("ascii"):
            return False
    except UnicodeEncodeError:
        return False

    if key_type == "ssh-ed25519":
        point = reader.read_string()
        return point is not None and len(point) == _ED25519_POINT_LENGTH and reader.at_end()

    if key_type == "ssh-rsa":
        e = reader.read_string()
        n = reader.read_string()
        return e is not None and n is not None and reader.at_end()

    if key_type == "ssh-dss":
        fields = [reader.read_string() for _ in range(4)]
        return all(f is not None for f in fields) and reader.at_end()

    if key_type in _ECDSA_CURVES:
        curve = reader.read_string()
        point = reader.read_string()
        return curve == _ECDSA_CURVES[key_type] and point is not None and reader.at_end()

    if key_type == _SK_ED25519_TYPE:
        point = reader.read_string()
        application = reader.read_string()
        return (
            point is not None
            and len(point) == _ED25519_POINT_LENGTH
            and application is not None
            and reader.at_end()
        )

    if key_type in _SK_ECDSA_CURVES:
        curve = reader.read_string()
        point = reader.read_string()
        application = reader.read_string()
        return (
            curve == _SK_ECDSA_CURVES[key_type]
            and point is not None
            and application is not None
            and reader.at_end()
        )

    # Unknown type: accept only a clean sequence of further SSH wire strings.
    while reader.has_remaining():
        if reader.read_string() is None:
            return False
    return True


def _fingerprint(blob: bytes) -> str:
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _parse_line(line: str, lineno: int, source_file: str) -> KnownHostEntry | UnresolvedItem:
    marker: str | None = None
    rest = line
    if rest.startswith("@"):
        token, _, remainder = rest.partition(" ")
        if token not in _MARKERS:
            return _bad(source_file, lineno, "unknown_marker")
        marker = _MARKERS[token]
        rest = remainder.strip()
        if not rest:
            return _bad(source_file, lineno, "missing_hosts_field")

    parts = rest.split(None, 3)
    if len(parts) < 3:
        return _bad(source_file, lineno, "incomplete_line")
    hosts_field, key_type, base64_field = parts[0], parts[1], parts[2]

    hosts = _parse_hosts_field(hosts_field)
    if hosts is None:
        return _bad(source_file, lineno, "invalid_hosts_field")

    blob = _strict_b64_decode(base64_field)
    if blob is None:
        return _bad(source_file, lineno, "invalid_base64")

    if not _validate_blob(key_type, blob):
        return _bad(source_file, lineno, "invalid_key_blob")

    hashed = any((h[1:] if h.startswith("!") else h).startswith("|1|") for h in hosts)
    return KnownHostEntry(
        source_file=source_file,
        line=lineno,
        marker=marker,
        hosts=hosts,
        hashed=hashed,
        key_type=key_type,
        fingerprint=_fingerprint(blob),
    )


def parse_known_hosts(text: str, source_file: str) -> ParseResult:
    """Parse the text of one known_hosts(5) file into entries and broken lines."""
    entries: list[KnownHostEntry] = []
    unresolved: list[UnresolvedItem] = []
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        result = _parse_line(line, lineno, source_file)
        if isinstance(result, KnownHostEntry):
            entries.append(result)
        else:
            unresolved.append(result)
    return ParseResult(entries=tuple(entries), unresolved=tuple(unresolved))


__all__ = ["ParseResult", "parse_known_hosts"]
