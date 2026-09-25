"""FR-001 (sdd-spec §7.3, §10 SEC-001/SEC-003): discovering .pub files (AC-1..AC-5)."""

from __future__ import annotations

import builtins
import io
import logging
import os
import socket
import threading
from pathlib import Path
from typing import Any

import pytest

from conftest import CANARY, CANARY_PRIVATE_KEY, OpenGuard
from ssh_id_doctor import fs, scanner
from ssh_id_doctor.domain import Resolution


@pytest.fixture
def scan_root(_isolated_home: Path) -> Path:
    """A bare ``.ssh`` under the guarded synthetic HOME, without the shared fixture's extras.

    Built directly on ``_isolated_home`` (not a directory of our own) so the
    private-open guard still protects every path here (AGENTS.md).
    """
    ssh = _isolated_home / ".ssh"
    ssh.mkdir(mode=0o700)
    return ssh


@pytest.fixture
def read_spy(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every real path passed into ``fs.read_public_text`` while the test runs."""
    calls: list[str] = []
    original = fs.read_public_text

    def spy(path: object, *args: object, **kwargs: object) -> str:
        calls.append(os.path.realpath(os.fspath(path)))  # type: ignore[arg-type]
        return original(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(fs, "read_public_text", spy)
    return calls


@pytest.fixture
def opened_paths(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Real path of every open (any route, any mode), layered over the private-open guard."""
    calls: list[str] = []
    inner_open = builtins.open
    inner_os_open = os.open

    def recording_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(file, str | bytes | os.PathLike):
            calls.append(os.path.realpath(os.fsdecode(os.fspath(file))))
        return inner_open(file, *args, **kwargs)

    def recording_os_open(path: Any, *args: Any, **kwargs: Any) -> int:
        calls.append(os.path.realpath(os.fsdecode(os.fspath(path))))
        return inner_os_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", recording_open)
    monkeypatch.setattr(io, "open", recording_open)
    monkeypatch.setattr(os, "open", recording_os_open)
    return calls


def test_lists_only_regular_pub_files_sorted(scan_root: Path, open_guard: OpenGuard) -> None:
    (scan_root / "id_ed25519.pub").write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA id\n")
    (scan_root / "id_canary").write_text(CANARY_PRIVATE_KEY)
    (scan_root / "id_canary").chmod(0o600)
    (scan_root / "sockets").mkdir()
    work = scan_root / "work"
    work.mkdir()
    (work / "id_rsa.pub").write_text("ssh-rsa AAAAB3NzaC1yc2EAAAA work\n")

    observations = scanner.discover_public_keys(scan_root)

    assert [Path(o.path).name for o in observations] == ["id_ed25519.pub", "id_rsa.pub"]
    assert [o.path for o in observations] == sorted(o.path for o in observations)
    assert observations[0].path == str((scan_root / "id_ed25519.pub").resolve())
    assert observations[1].path == str((work / "id_rsa.pub").resolve())
    assert all(o.resolution is Resolution.RESOLVED for o in observations)
    assert observations[0].key_line == "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA id"
    assert observations[1].key_line == "ssh-rsa AAAAB3NzaC1yc2EAAAA work"
    assert open_guard.violations == []


def test_ignores_sockets_fifos_and_directories(fake_home: Path, open_guard: OpenGuard) -> None:
    ssh = fake_home / ".ssh"
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind(str(ssh / "agent.sock"))
        os.mkfifo(ssh / "pipe.pub")

        observations = scanner.discover_public_keys(ssh)
    finally:
        sock.close()

    names = {Path(o.path).name for o in observations}
    assert "agent.sock" not in names
    assert "pipe.pub" not in names
    assert open_guard.violations == []


def test_unreadable_and_outside_root_are_unresolved(
    fake_home: Path,
    tmp_path: Path,
    read_spy: list[str],
    open_guard: OpenGuard,
) -> None:
    ssh = fake_home / ".ssh"
    outside = tmp_path / "outside"
    outside.mkdir()
    external = outside / "external.pub"
    external.write_text("ssh-ed25519 AAAAEXTERNAL outside\n")

    locked = ssh / "locked.pub"
    locked.write_text("ssh-ed25519 AAAALOCKED locked\n")
    locked.chmod(0o000)
    (ssh / "escape.pub").symlink_to(external)

    try:
        observations = scanner.discover_public_keys(ssh)
    finally:
        locked.chmod(0o600)

    by_name = {Path(o.path).name: o for o in observations}
    assert by_name["locked.pub"].resolution is Resolution.UNREADABLE
    assert by_name["locked.pub"].key_line is None
    assert by_name["escape.pub"].resolution is Resolution.OUTSIDE_ROOT
    assert by_name["escape.pub"].key_line is None
    assert str(os.path.realpath(external)) not in read_spy
    assert open_guard.violations == []


def test_pub_with_private_block_is_refused_and_canary_never_leaks(
    fake_home: Path,
    open_guard: OpenGuard,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    ssh = fake_home / ".ssh"
    mixed = ssh / "mixed.pub"
    mixed.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA mixed@test\n" + CANARY_PRIVATE_KEY)

    observations = scanner.discover_public_keys(ssh)

    by_name = {Path(o.path).name: o for o in observations}
    mixed_observation = by_name["mixed.pub"]
    assert mixed_observation.resolution is Resolution.PRIVATE_ONLY
    assert mixed_observation.key_line is None

    out, err = capsys.readouterr()
    assert CANARY not in out + err
    assert CANARY not in caplog.text
    assert all(CANARY not in repr(o) for o in observations)
    assert open_guard.violations == []


def test_pub_symlink_outside_root_is_never_read(
    fake_home: Path,
    tmp_path: Path,
    read_spy: list[str],
    open_guard: OpenGuard,
) -> None:
    ssh = fake_home / ".ssh"
    outside = tmp_path / "outside"
    outside.mkdir()
    leaked = outside / "leaked.pub"
    leaked_text = "ssh-ed25519 AAAALEAKED leaked-outside\n"
    leaked.write_text(leaked_text)
    (ssh / "leak.pub").symlink_to(leaked)

    observations = scanner.discover_public_keys(ssh)

    by_name = {Path(o.path).name: o for o in observations}
    assert by_name["leak.pub"].resolution is Resolution.OUTSIDE_ROOT
    assert by_name["leak.pub"].key_line is None
    assert str(os.path.realpath(leaked)) not in read_spy
    assert not any(o.key_line == leaked_text.strip() for o in observations)
    assert open_guard.violations == []


def test_pub_symlink_to_fifo_inside_root_is_unreadable_without_open(
    fake_home: Path, opened_paths: list[str], open_guard: OpenGuard
) -> None:
    """Review #562 finding 466094cf: alias.pub -> pipe.pub (FIFO, inside root) must not hang."""
    ssh = fake_home / ".ssh"
    fifo = ssh / "pipe.pub"
    os.mkfifo(fifo)
    (ssh / "alias.pub").symlink_to(fifo)

    result: list[list[scanner.PublicKeyObservation]] = []
    errors: list[BaseException] = []

    def run() -> None:
        try:
            result.append(scanner.discover_public_keys(ssh))
        except BaseException as exc:  # surfaced in the main thread below
            errors.append(exc)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout=5)
    if worker.is_alive():
        # Release the blocked reader so the thread (and CI) does not hang.
        writer = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        os.close(writer)
        worker.join(timeout=5)
        pytest.fail("discover_public_keys blocked opening a FIFO behind a .pub symlink")
    assert errors == []

    by_name = {Path(o.path).name: o for o in result[0]}
    assert by_name["alias.pub"].resolution is Resolution.UNREADABLE
    assert by_name["alias.pub"].key_line is None
    assert "pipe.pub" not in by_name
    assert by_name["id_canary.pub"].resolution is Resolution.RESOLVED
    assert os.path.realpath(fifo) not in opened_paths
    assert open_guard.violations == []


def test_oversized_pub_is_unreadable_and_scan_continues(
    fake_home: Path, open_guard: OpenGuard
) -> None:
    """Review #562 finding dbb72cc2: a .pub over MAX_PUBLIC_BYTES is unresolved, not a crash."""
    ssh = fake_home / ".ssh"
    huge = ssh / "huge.pub"
    huge.write_text("ssh-ed25519 " + "A" * (fs.MAX_PUBLIC_BYTES + 1024) + " huge\n")
    (ssh / "id_ed25519.pub").write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA id\n")

    observations = scanner.discover_public_keys(ssh)

    by_name = {Path(o.path).name: o for o in observations}
    assert by_name["huge.pub"].resolution is Resolution.UNREADABLE
    assert by_name["huge.pub"].key_line is None
    assert by_name["id_ed25519.pub"].resolution is Resolution.RESOLVED
    assert by_name["id_ed25519.pub"].key_line == "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA id"
    assert by_name["id_canary.pub"].resolution is Resolution.RESOLVED
    assert open_guard.violations == []
