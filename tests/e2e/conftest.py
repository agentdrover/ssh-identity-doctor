"""Shared fixtures and setup for e2e tests."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "home_basic"
CANARY = "CANARY-PRIVATE-7f3a"
CANARY_PRIVATE_KEY = (
    f"-----BEGIN OPENSSH PRIVATE KEY-----\n{CANARY}\n-----END OPENSSH PRIVATE KEY-----\n"
)
CANARY_PUBLIC_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHf1xYl0lq7mJ0Ra0cWm9vQn2c9c5b3nq1F0mX4bY0Zs canary@test\n"
)
ALLOWED_SUFFIXES = (".pub", ".conf")
ALLOWED_NAMES = frozenset({"config", "known_hosts"})


class PrivateReadAttempt(AssertionError):
    pass


@dataclass
class OpenGuard:
    home: str
    violations: list[str] = field(default_factory=list)
    allowed: set[str] = field(default_factory=set)
    extra_roots: list[str] = field(default_factory=list)

    def guard_root(self, *roots: str | os.PathLike[str]) -> None:
        for root in roots:
            self.extra_roots.append(os.path.realpath(os.fsdecode(os.fspath(root))))

    def allow(self, *paths: str | os.PathLike[str]) -> None:
        for path in paths:
            self.allowed.add(os.path.realpath(os.fsdecode(os.fspath(path))))

    def is_protected(self, file: object) -> bool:
        if isinstance(file, int) or not isinstance(file, str | bytes | os.PathLike):
            return False
        raw = os.fsdecode(os.fspath(file))
        real = os.path.realpath(raw)
        inside = any(
            real == root or real.startswith(root + os.sep)
            for root in (self.home, *self.extra_roots)
        )
        if not inside:
            return False
        if real in self.allowed:
            return False
        name = os.path.basename(real)
        return not (name.endswith(ALLOWED_SUFFIXES) or name in ALLOWED_NAMES)

    def check(self, file: object, reading: bool) -> None:
        if reading and self.is_protected(file):
            message = f"read of protected file {os.fsdecode(os.fspath(file))!r}"  # type: ignore[arg-type]
            self.violations.append(message)
            raise PrivateReadAttempt(message)


def _setup_home_basic(fake_home: Path) -> Path:
    ssh = fake_home / ".ssh"
    ssh.mkdir(mode=0o700, parents=True, exist_ok=True)
    for p in FIXTURES_DIR.glob("*.pub"):
        (ssh / p.name).write_text(p.read_text())
    (ssh / "config").write_text((FIXTURES_DIR / "config").read_text())
    config_d = ssh / "config.d"
    config_d.mkdir(exist_ok=True)
    for p in (FIXTURES_DIR / "config.d").glob("*.conf"):
        text = p.read_text()
        if "Include cycle.conf" in text:
            text = text.replace("Include cycle.conf", "Include config.d/cycle.conf")
        if "Include included.conf" in text:
            text = text.replace("Include included.conf", "Include config.d/included.conf")
        (config_d / p.name).write_text(text)

    (ssh / "id_canary.pub").unlink(missing_ok=True)
    (ssh / "id_canary").write_text(CANARY_PRIVATE_KEY)
    (ssh / "id_canary").chmod(0o600)
    return fake_home


@pytest.fixture
def home_basic(fake_home: Path) -> Path:
    """Fixture providing populated home_basic."""
    return _setup_home_basic(fake_home)


@pytest.fixture
def open_guard(_private_open_guard: Any) -> OpenGuard:
    return _private_open_guard  # type: ignore[no-any-return]
