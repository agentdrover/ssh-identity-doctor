"""Shared fixtures: every test runs against a synthetic HOME, never the real ~/.ssh.

Three layers, all built on the one HOME redirection below (SID-1):

- ``_isolated_home`` (autouse): HOME points at a temporary directory and
  SSH_AUTH_SOCK is unset for every test.
- ``_private_open_guard`` (autouse, sdd-spec SEC-001): wraps ``builtins.open``,
  ``io.open``, ``os.open``, ``Path.read_bytes`` and ``Path.read_text``. A READ
  of any path inside the synthetic HOME that is not a ``.pub`` or config file
  raises and fails the test — even if the code under test swallows the error,
  because every attempt is recorded and checked at teardown. Paths outside the
  synthetic HOME (pytest, uv, imports, tmp_path) pass straight through.
- ``fake_home``: populates HOME/.ssh with a public key, a config and the
  private-key trap ``id_canary`` whose bytes contain ``CANARY``.
"""

from __future__ import annotations

import builtins
import io
import os
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

CANARY = "CANARY-PRIVATE-7f3a"
"""Bytes that must never be read by the product, nor appear in any output."""

CANARY_PRIVATE_KEY = (
    f"-----BEGIN OPENSSH PRIVATE KEY-----\n{CANARY}\n-----END OPENSSH PRIVATE KEY-----\n"
)
CANARY_PUBLIC_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHf1xYl0lq7mJ0Ra0cWm9vQn2c9c5b3nq1F0mX4bY0Zs canary@test\n"
)

ALLOWED_SUFFIXES = (".pub", ".conf")
ALLOWED_NAMES = frozenset({"config", "known_hosts"})


class PrivateReadAttempt(AssertionError):
    """Raised by the guard when a test's code tries to read a protected file."""


@dataclass
class OpenGuard:
    home: str
    violations: list[str] = field(default_factory=list)

    def is_protected(self, file: object) -> bool:
        if isinstance(file, int) or not isinstance(file, str | bytes | os.PathLike):
            return False
        raw = os.fsdecode(os.fspath(file))
        real = os.path.realpath(raw)
        inside = real == self.home or real.startswith(self.home + os.sep)
        if not inside:
            return False
        name = os.path.basename(real)
        return not (name.endswith(ALLOWED_SUFFIXES) or name in ALLOWED_NAMES)

    def check(self, file: object, reading: bool) -> None:
        if reading and self.is_protected(file):
            message = f"read of protected file {os.fsdecode(os.fspath(file))!r}"  # type: ignore[arg-type]
            self.violations.append(message)
            raise PrivateReadAttempt(message)


def _mode_reads(mode: str) -> bool:
    return "r" in mode or "+" in mode


def _flags_read(flags: int) -> bool:
    return flags & (os.O_WRONLY | os.O_RDWR) != os.O_WRONLY


@pytest.fixture(autouse=True)
def _isolated_home(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> Path:
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    return home


@pytest.fixture(autouse=True)
def _private_open_guard(
    _isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[OpenGuard]:
    guard = OpenGuard(home=os.path.realpath(_isolated_home))
    real_open = builtins.open
    real_os_open = os.open
    real_read_bytes = Path.read_bytes
    real_read_text = Path.read_text

    def guarded_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        guard.check(file, _mode_reads(mode))
        return real_open(file, mode, *args, **kwargs)

    def guarded_os_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        guard.check(path, _flags_read(flags))
        return real_os_open(path, flags, *args, **kwargs)

    def guarded_path(real: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(self: Path, *args: Any, **kwargs: Any) -> Any:
            guard.check(self, True)
            return real(self, *args, **kwargs)

        return wrapper

    monkeypatch.setattr(builtins, "open", guarded_open)
    monkeypatch.setattr(io, "open", guarded_open)
    monkeypatch.setattr(os, "open", guarded_os_open)
    monkeypatch.setattr(Path, "read_bytes", guarded_path(real_read_bytes))
    monkeypatch.setattr(Path, "read_text", guarded_path(real_read_text))
    yield guard
    if guard.violations:
        pytest.fail(f"private-file read attempts: {guard.violations}", pytrace=False)


@pytest.fixture
def open_guard(_private_open_guard: OpenGuard) -> OpenGuard:
    """The active guard, for tests that assert on (or deliberately clear) violations."""
    return _private_open_guard


@pytest.fixture
def fake_home(_isolated_home: Path) -> Path:
    """Synthetic HOME with .ssh/{id_canary, id_canary.pub, config}. Returns HOME."""
    ssh = _isolated_home / ".ssh"
    ssh.mkdir(mode=0o700)
    (ssh / "id_canary").write_text(CANARY_PRIVATE_KEY)
    (ssh / "id_canary").chmod(0o600)
    (ssh / "id_canary.pub").write_text(CANARY_PUBLIC_KEY)
    (ssh / "config").write_text("Host example\n  IdentityFile ~/.ssh/id_canary\n")
    return _isolated_home
