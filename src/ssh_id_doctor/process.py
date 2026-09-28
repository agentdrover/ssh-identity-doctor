"""The one subprocess runner (sdd-spec §10 SEC-002, §12).

Every external program (ssh-keygen, ssh-add, gh) is started through
:func:`run` and nowhere else; a test forbids ``subprocess`` in other modules.

Guarantees, by construction rather than by caller discipline:

- ``argv`` is a list or tuple of strings. A string is refused with
  ``TypeError`` before anything starts, so no command line is ever parsed by
  a shell; ``shell=False`` is hard-coded.
- The timeout is a required keyword. On expiry the whole process group is
  killed and the result says ``timeout`` (§12: terminate, report, continue).
- Captured output is bounded by ``max_output`` bytes per stream; the rest is
  drained and discarded so a chatty child can neither block nor exhaust memory.
- The child environment is reduced to a whitelist (``ENV_WHITELIST``).
- A missing executable is a result (``not_found``), not an exception.
- An executable that exists but cannot be run (no +x bit, or the name on
  ``PATH`` is a directory) is a result (``not_executable``), not a raised
  ``PermissionError`` (sdd-spec §12, SID-2 review finding).
"""

from __future__ import annotations

import math
import os
import signal
import subprocess
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import IO

ENV_WHITELIST: tuple[str, ...] = ("PATH", "LANG", "SSH_AUTH_SOCK", "HOME")
"""The only environment variables a child process inherits."""

_CHUNK = 65536
_REAP_SECONDS = 2.0


class ProcessStatus(StrEnum):
    OK = "ok"
    NONZERO = "nonzero"
    TIMEOUT = "timeout"
    NOT_FOUND = "not_found"
    NOT_EXECUTABLE = "not_executable"


@dataclass(frozen=True, slots=True)
class ProcessResult:
    """Outcome of one call. ``returncode`` is None for timeout and not_found."""

    status: ProcessStatus
    returncode: int | None
    stdout: bytes
    stderr: bytes
    truncated: bool


def minimal_env() -> dict[str, str]:
    """The whitelisted part of the current environment."""
    return {name: os.environ[name] for name in ENV_WHITELIST if name in os.environ}


def _validate(argv: object, timeout: float, max_output: int) -> list[str]:
    if isinstance(argv, str | bytes) or not isinstance(argv, list | tuple):
        raise TypeError("argv must be a list or tuple of strings, never a command string")
    if not argv:
        raise ValueError("argv must name an executable")
    if not all(isinstance(arg, str) for arg in argv):
        raise TypeError("every argv element must be a str")
    if not (math.isfinite(timeout) and timeout > 0):
        raise ValueError("timeout must be positive")
    if max_output < 0:
        raise ValueError("max_output must not be negative")
    return list(argv)


class _BoundedReader(threading.Thread):
    """Reads a pipe to EOF, keeping at most ``limit`` bytes."""

    def __init__(self, stream: IO[bytes], limit: int) -> None:
        super().__init__(daemon=True)
        self._stream = stream
        self._limit = limit
        self._chunks: list[bytes] = []
        self._kept = 0
        self.overflowed = False

    def run(self) -> None:
        while chunk := self._stream.read1(_CHUNK):  # type: ignore[attr-defined]
            room = self._limit - self._kept
            if len(chunk) > room:
                self.overflowed = True
                chunk = chunk[:room]
            if chunk:
                self._chunks.append(chunk)
                self._kept += len(chunk)
        self._stream.close()

    def data(self) -> bytes:
        return b"".join(self._chunks)


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        proc.kill()


def run(argv: Sequence[str], *, timeout: float, max_output: int) -> ProcessResult:
    """Run ``argv`` without a shell, bounded in time and captured output."""
    args = _validate(argv, timeout, max_output)
    try:
        proc = subprocess.Popen(  # noqa: S603 - argv array, shell=False, validated above
            args,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=minimal_env(),
            close_fds=True,
            start_new_session=True,
        )
    except FileNotFoundError:
        return ProcessResult(ProcessStatus.NOT_FOUND, None, b"", b"", False)
    except PermissionError:
        # argv[0] resolved to something on PATH that exec() refuses: a file
        # without the execute bit, or a directory sharing the executable's
        # name. Both surface as EACCES/PermissionError, never a traceback.
        return ProcessResult(ProcessStatus.NOT_EXECUTABLE, None, b"", b"", False)
    assert proc.stdout is not None and proc.stderr is not None  # noqa: S101 - PIPE requested
    readers = (_BoundedReader(proc.stdout, max_output), _BoundedReader(proc.stderr, max_output))
    for reader in readers:
        reader.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_group(proc)
        proc.wait(timeout=_REAP_SECONDS)
    for reader in readers:
        reader.join(timeout=_REAP_SECONDS)
    out, err = readers[0].data(), readers[1].data()
    truncated = any(reader.overflowed for reader in readers)
    if timed_out:
        return ProcessResult(ProcessStatus.TIMEOUT, None, out, err, truncated)
    status = ProcessStatus.OK if proc.returncode == 0 else ProcessStatus.NONZERO
    return ProcessResult(status, proc.returncode, out, err, truncated)
