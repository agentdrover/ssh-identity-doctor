"""FR-003 (sdd-spec §7.2, §10 SEC-001/SEC-002, §12): canonical SHA-256 fingerprint.

:class:`PublicKeyInspector` turns one public key line into its canonical
``SHA256:<base64>`` identity id by calling the system ``ssh-keygen`` through
the one audited runner, :mod:`ssh_id_doctor.process`. ``ssh-keygen`` never
sees anything but the public line the caller supplies (SEC-001: ``-y`` is
never passed, and this module never opens or reads ``~/.ssh`` itself); the
scanner is responsible for handing it only text that already passed
:func:`ssh_id_doctor.fs.read_public_text`.

``ssh-keygen`` has no way to read a key from stdin (``-f -`` reads a
*private* key candidate from stdin, not a public one), so the line is placed
in a private scratch file (mode 0600, under the OS temp directory, removed
in a ``finally`` on every path) and ``-f <path>`` names it instead.
"""

from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass

from ssh_id_doctor import process
from ssh_id_doctor.inspectors import RequiredSourceError, Unresolved
from ssh_id_doctor.process import ProcessStatus

DEFAULT_TIMEOUT = 5.0
"""Seconds. ssh-keygen -l on a single key is near-instant; this only bounds a hang."""

MAX_OUTPUT = 8192
"""Bytes. One fingerprint line is at most a few hundred bytes."""

_TMP_PREFIX = "ssh-id-doctor-fp-"
_TMP_SUFFIX = ".pub"

# "<bits> SHA256:<fp> <comment> (<ALGO>)" — comment may be empty (extra
# whitespace, no trailing text) but the fingerprint and the trailing
# parenthesised algorithm name are required. `.*?` is lazy so a comment that
# happens to contain "(" still resolves to the *last* parenthesised group.
_OUTPUT_RE = re.compile(r"^\d+\s+(SHA256:\S+)\s+(.*?)\s*\(([^()]+)\)\s*$")
_FINGERPRINT_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]+=*$")


@dataclass(frozen=True, slots=True)
class KeyInfo:
    """One resolved identity's key attributes (FR-003)."""

    fingerprint: str
    algorithm: str
    bits_or_curve: str
    comment: str


class PublicKeyInspector:
    """Fingerprints one public key line via the system ``ssh-keygen``."""

    def fingerprint(
        self,
        public_line: str,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        max_output: int = MAX_OUTPUT,
    ) -> KeyInfo | Unresolved:
        algorithm = _leading_algorithm(public_line)
        if algorithm is None:
            return Unresolved(reason="invalid_public_key", detail="not one public-key line")

        path = _write_scratch_pub(public_line)
        try:
            result = process.run(
                ["ssh-keygen", "-l", "-E", "sha256", "-f", path],
                timeout=timeout,
                max_output=max_output,
            )
        finally:
            _remove_scratch(path)

        if result.status is ProcessStatus.NOT_FOUND:
            raise RequiredSourceError("ssh-keygen is not installed or not on PATH")
        if result.status is ProcessStatus.NOT_EXECUTABLE:
            raise RequiredSourceError("ssh-keygen on PATH is not executable")
        if result.status is ProcessStatus.TIMEOUT:
            return Unresolved(reason="ssh_keygen_timeout", detail="ssh-keygen did not return")
        if result.status is not ProcessStatus.OK:
            return Unresolved(reason="invalid_public_key", detail="ssh-keygen rejected the key")

        return _parse_output(result.stdout, algorithm)


def _leading_algorithm(public_line: str) -> str | None:
    """The wire-format algorithm name (first field), or None if not one clean line."""
    if "\n" in public_line.rstrip("\n") or "\r" in public_line:
        return None
    stripped = public_line.strip()
    if not stripped:
        return None
    parts = stripped.split(None, 1)
    if len(parts) < 2:
        return None
    algorithm, rest = parts
    if not rest.strip():
        return None
    return algorithm


def _write_scratch_pub(public_line: str) -> str:
    text = public_line if public_line.endswith("\n") else public_line + "\n"
    fd, path = tempfile.mkstemp(prefix=_TMP_PREFIX, suffix=_TMP_SUFFIX)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
    except BaseException:
        _remove_scratch(path)
        raise
    return path


def _remove_scratch(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def _parse_output(stdout: bytes, algorithm: str) -> KeyInfo | Unresolved:
    line = stdout.decode("utf-8", errors="replace").strip()
    if not line:
        return Unresolved(reason="empty_ssh_keygen_output", detail="ssh-keygen printed nothing")
    match = _OUTPUT_RE.match(line)
    if match is None:
        return Unresolved(reason="unparseable_ssh_keygen_output", detail="unexpected -l format")
    fingerprint, comment, bits_or_curve = match.groups()
    if not _FINGERPRINT_RE.match(fingerprint):
        return Unresolved(reason="unparseable_ssh_keygen_output", detail="fingerprint not base64")
    return KeyInfo(
        fingerprint=fingerprint,
        algorithm=algorithm,
        bits_or_curve=bits_or_curve,
        comment=comment,
    )


__all__ = ["KeyInfo", "PublicKeyInspector"]
