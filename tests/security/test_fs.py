"""SEC-003 / §13.4: discovery stays inside its root and never reads (AC-3).

Also covers :func:`ssh_id_doctor.fs.read_config_text` (FR-004a AC-4): the
same regular-file-before-open and size-limit safety as :func:`read_public_text`,
applied to one ssh_config(5) file.
"""

from __future__ import annotations

import builtins
import io
import os
import stat
import traceback
from pathlib import Path
from typing import Any

import pytest

from conftest import CANARY, CANARY_PRIVATE_KEY, DenyOpen, OpenGuard
from ssh_id_doctor import fs
from ssh_id_doctor.domain import Resolution
from ssh_id_doctor.fs import NotAConfigFile, NotAKnownHostsFile, PrivateKeyAccessDenied


@pytest.fixture
def opened_paths(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every path opened (for any mode) while the test runs."""
    seen: list[str] = []
    inner_open = builtins.open
    inner_os_open = os.open

    def recording_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        if not isinstance(file, int):
            seen.append(os.path.realpath(os.fspath(file)))
        return inner_open(file, *args, **kwargs)

    def recording_os_open(path: Any, *args: Any, **kwargs: Any) -> int:
        seen.append(os.path.realpath(os.fspath(path)))
        return inner_os_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", recording_open)
    monkeypatch.setattr(io, "open", recording_open)
    monkeypatch.setattr(os, "open", recording_os_open)
    return seen


def _snapshot(root: Path) -> dict[str, tuple[int, int]]:
    return {str(p): (p.lstat().st_mode, p.lstat().st_mtime_ns) for p in sorted(root.rglob("*"))}


@pytest.fixture
def guarded_ssh_dir(tmp_path: Path, open_guard: OpenGuard) -> Path:
    """A fresh ssh_dir under tmp_path, registered via ``open_guard.guard_root``.

    AGENTS.md: a fixture built outside fake_home must guard_root() explicitly. Shared
    by the two traceback tests below and by test_traceback_fixture_is_guarded, so that
    proof test actually exercises the same registration those two tests rely on (#1836)
    instead of only proving the mechanism works on a directory of its own.
    """
    ssh_dir = tmp_path / "ssh"
    ssh_dir.mkdir()
    open_guard.guard_root(ssh_dir)
    return ssh_dir


def test_safe_walk_does_not_follow_symlink_outside_root(
    fake_home: Path, tmp_path: Path, opened_paths: list[str]
) -> None:
    ssh = fake_home / ".ssh"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "stolen_key").write_text("outside-root-secret\n")
    (ssh / "evil.pub").symlink_to("/etc/hosts")
    (ssh / "sub").symlink_to(outside, target_is_directory=True)
    (ssh / "inner").mkdir()
    (ssh / "inner" / "work.pub").write_text("ssh-ed25519 AAAA work\n")
    before = _snapshot(ssh)
    opened_paths.clear()

    entries = {entry.path.name: entry for entry in fs.safe_walk(ssh)}

    assert entries["evil.pub"].resolution is Resolution.OUTSIDE_ROOT
    assert entries["sub"].resolution is Resolution.OUTSIDE_ROOT
    assert "stolen_key" not in entries
    real_outside = os.path.realpath(outside)
    assert not any(str(e.path).startswith(real_outside) for e in entries.values())
    assert entries["work.pub"].resolution is Resolution.RESOLVED
    assert entries["id_canary"].resolution is Resolution.RESOLVED
    assert opened_paths == [], "discovery must not open any file"
    assert _snapshot(ssh) == before, "permissions and timestamps must not change"

    assert fs.resolve_within(ssh, "evil.pub")[1] is Resolution.OUTSIDE_ROOT
    assert fs.resolve_within(ssh, "../../etc/passwd")[1] is Resolution.OUTSIDE_ROOT
    assert fs.resolve_within(ssh, "inner/../id_canary.pub")[1] is Resolution.RESOLVED
    assert fs.resolve_within(ssh, "absent.pub")[1] is Resolution.MISSING


def test_read_config_text_refuses_fifo_before_opening(
    tmp_path: Path, opened_paths: list[str]
) -> None:
    """A config path that is (or resolves through a symlink to) a FIFO is refused by its
    ``S_ISREG`` check before any ``open`` — the read can never block on it."""
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    alias = tmp_path / "config"
    alias.symlink_to(fifo)

    with pytest.raises(NotAConfigFile):
        fs.read_config_text(alias)

    assert os.path.realpath(fifo) not in opened_paths


def test_read_config_text_refuses_oversize_and_private_material(tmp_path: Path) -> None:
    """Content over ``max_bytes`` and content holding a private-key header are both refused,
    the latter without the header (or the canary payload after it) ever appearing in the
    exception message."""
    huge = tmp_path / "config"
    huge.write_text("HostName " + "A" * (fs.MAX_CONFIG_BYTES + 1024) + "\n")
    with pytest.raises(NotAConfigFile) as too_big:
        fs.read_config_text(huge)
    assert "A" * 100 not in str(too_big.value)

    private = tmp_path / "private_config"
    private.write_text("Host x\n" + CANARY_PRIVATE_KEY)
    with pytest.raises(PrivateKeyAccessDenied) as leaked:
        fs.read_config_text(private)
    assert CANARY not in str(leaked.value)


def test_read_known_hosts_text_refusals(
    tmp_path: Path, opened_paths: list[str], open_guard: OpenGuard
) -> None:
    """AC-1: every unsafe known_hosts path is refused before any open (name not
    known_hosts; a known_hosts symlink to a differently named file; a known_hosts
    symlink to a known_hosts file outside ssh_dir; ssh_dir/sub a symlink to an
    outside directory; a FIFO); a private-key header on a later line and content
    over max_bytes are refused only after reading. Every message names the base
    name only."""
    ssh_dir = tmp_path / "ssh"
    ssh_dir.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    # AGENTS.md: fixtures built outside fake_home must guard_root() explicitly,
    # so a private-key read here still fails the test via open_guard's teardown.
    open_guard.guard_root(ssh_dir, outside)
    valid_line = "example.com ssh-ed25519 AAAA\n"

    # 1. name is not known_hosts.
    (ssh_dir / "known_hosts2").write_text(valid_line)
    opened_paths.clear()
    with pytest.raises(NotAKnownHostsFile) as wrong_name:
        fs.read_known_hosts_text(ssh_dir / "known_hosts2", ssh_dir=ssh_dir)
    assert opened_paths == []
    assert "known_hosts2" in str(wrong_name.value)
    assert str(ssh_dir) not in str(wrong_name.value)

    # 2. known_hosts symlink -> a file with a different name, inside ssh_dir.
    (ssh_dir / "other_name").write_text(valid_line)
    (ssh_dir / "known_hosts").symlink_to(ssh_dir / "other_name")
    opened_paths.clear()
    with pytest.raises(NotAKnownHostsFile):
        fs.read_known_hosts_text(ssh_dir / "known_hosts", ssh_dir=ssh_dir)
    assert opened_paths == []
    (ssh_dir / "known_hosts").unlink()
    (ssh_dir / "other_name").unlink()

    # 3. known_hosts symlink -> a known_hosts file outside ssh_dir.
    (outside / "known_hosts").write_text(valid_line)
    (ssh_dir / "known_hosts").symlink_to(outside / "known_hosts")
    opened_paths.clear()
    with pytest.raises(NotAKnownHostsFile):
        fs.read_known_hosts_text(ssh_dir / "known_hosts", ssh_dir=ssh_dir)
    assert opened_paths == []
    (ssh_dir / "known_hosts").unlink()

    # 4. ssh_dir/sub is a symlink to an outside directory holding known_hosts.
    (ssh_dir / "sub").symlink_to(outside, target_is_directory=True)
    opened_paths.clear()
    with pytest.raises(NotAKnownHostsFile):
        fs.read_known_hosts_text(ssh_dir / "sub" / "known_hosts", ssh_dir=ssh_dir)
    assert opened_paths == []
    (ssh_dir / "sub").unlink()
    (outside / "known_hosts").unlink()

    # 5. FIFO named known_hosts, inside ssh_dir: refused before open (S_ISREG check).
    fifo = ssh_dir / "known_hosts"
    os.mkfifo(fifo)
    opened_paths.clear()
    with pytest.raises(NotAKnownHostsFile):
        fs.read_known_hosts_text(fifo, ssh_dir=ssh_dir)
    assert opened_paths == []
    fifo.unlink()

    # 6. A private-key header on the second line is refused only after reading.
    (ssh_dir / "known_hosts").write_text(valid_line + CANARY_PRIVATE_KEY)
    opened_paths.clear()
    with pytest.raises(PrivateKeyAccessDenied) as leaked:
        fs.read_known_hosts_text(ssh_dir / "known_hosts", ssh_dir=ssh_dir)
    assert CANARY not in str(leaked.value)
    assert str(ssh_dir / "known_hosts") in opened_paths
    opened_paths.clear()
    (ssh_dir / "known_hosts").unlink()

    # 7. Content over max_bytes is refused only after reading.
    (ssh_dir / "known_hosts").write_text("example.com ssh-ed25519 " + "A" * 100 + "\n")
    opened_paths.clear()
    with pytest.raises(NotAKnownHostsFile) as too_big:
        fs.read_known_hosts_text(ssh_dir / "known_hosts", ssh_dir=ssh_dir, max_bytes=16)
    assert "A" * 50 not in str(too_big.value)
    assert opened_paths != []
    (ssh_dir / "known_hosts").unlink()

    # Missing file is a distinct FileNotFoundError, not a refusal.
    with pytest.raises(FileNotFoundError):
        fs.read_known_hosts_text(ssh_dir / "known_hosts", ssh_dir=ssh_dir)


def test_read_known_hosts_text_open_uses_nofollow_nonblock_cloexec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, open_guard: OpenGuard
) -> None:
    """Review finding #1794 gen1 (medium, test gap): a regression test that would
    catch dropping O_NOFOLLOW/O_NONBLOCK/O_CLOEXEC from the real ``os.open`` call
    in :func:`read_known_hosts_text` (AC-1's existing refusal tests only exercise
    the *earlier*, pure-Python checks and never look at the flags passed to the
    syscall itself)."""
    ssh_dir = tmp_path / "ssh"
    ssh_dir.mkdir()
    # AGENTS.md: a fixture built outside fake_home must guard_root() explicitly.
    open_guard.guard_root(ssh_dir)
    target = ssh_dir / "known_hosts"
    target.write_text("example.com ssh-ed25519 AAAA\n")

    captured_flags: list[int] = []
    real_open = os.open

    def recording_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        captured_flags.append(flags)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", recording_open)

    fs.read_known_hosts_text(target, ssh_dir=ssh_dir)

    assert captured_flags, "read_known_hosts_text must call os.open"
    flags = captured_flags[-1]
    assert flags & os.O_NOFOLLOW
    assert flags & os.O_NONBLOCK
    assert flags & os.O_CLOEXEC


def test_read_known_hosts_text_fstat_refuses_fifo_even_if_the_prior_stat_lied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, open_guard: OpenGuard
) -> None:
    """Review finding #1794 gen1 (medium, test gap): a regression test for the
    ``fstat``-after-``open`` check, which today's AC-1 FIFO case never reaches
    (that FIFO is already named ``known_hosts`` and so is refused by the earlier,
    pre-open ``os.stat`` check). Here the pre-open ``stat`` is made to report a
    regular file for a target that is actually a FIFO — simulating it being
    swapped out between the two checks — so only the ``fstat`` on the opened fd
    can catch it; removing that check would make this read succeed instead of
    raising."""
    ssh_dir = tmp_path / "ssh"
    ssh_dir.mkdir()
    # AGENTS.md: a fixture built outside fake_home must guard_root() explicitly.
    open_guard.guard_root(ssh_dir)
    target = ssh_dir / "known_hosts"
    os.mkfifo(target)
    real_target = os.path.realpath(target)
    real_stat = os.stat

    class _RegularFileStat:
        def __init__(self, real_result: os.stat_result) -> None:
            self._real = real_result

        def __getattr__(self, name: str) -> Any:
            return getattr(self._real, name)

        @property
        def st_mode(self) -> int:
            return stat.S_IFREG | 0o644

    def lying_stat(path: Any, *args: Any, **kwargs: Any) -> Any:
        result = real_stat(path, *args, **kwargs)
        if os.fspath(path) == real_target:
            return _RegularFileStat(result)
        return result

    monkeypatch.setattr(os, "stat", lying_stat)

    with pytest.raises(NotAKnownHostsFile):
        fs.read_known_hosts_text(target, ssh_dir=ssh_dir)


def test_read_known_hosts_text_permission_error_names_only_the_base_name(
    tmp_path: Path, open_guard: OpenGuard, deny_open: DenyOpen
) -> None:
    """Review finding #1794 gen1 (low, fs.py:266): an ``OSError`` raised by the
    ``stat``/``open`` syscalls themselves (unlike the function's own explicit
    refusals) must not leak the full path either — the stdlib formats
    ``PermissionError`` with the complete path by default."""
    ssh_dir = tmp_path / "ssh"
    ssh_dir.mkdir()
    # AGENTS.md: a fixture built outside fake_home must guard_root() explicitly.
    open_guard.guard_root(ssh_dir)
    target = ssh_dir / "known_hosts"
    target.write_text("example.com ssh-ed25519 AAAA\n")
    with deny_open(target), pytest.raises(PermissionError) as exc_info:
        fs.read_known_hosts_text(target, ssh_dir=ssh_dir)
    assert str(ssh_dir) not in str(exc_info.value)
    assert "known_hosts" in str(exc_info.value)


def test_read_known_hosts_text_permission_error_does_not_leak_path_via_traceback(
    guarded_ssh_dir: Path,
    deny_open: DenyOpen,
) -> None:
    """Review finding (low, fs.py:272/281): the stat/open ``OSError`` was re-raised
    with ``from exc``, so the original, path-carrying exception stayed reachable as
    ``__cause__`` and would still appear — full path and all — in a printed
    traceback, even though the new exception's own message is sanitized.

    ``deny_open`` denies ``os.open`` only, not ``os.stat`` (chmod(0o000) would
    do the same on a non-root process, but not under root — SID #1860), so
    this exercises the *second* ``except OSError`` branch (around
    ``os.open``); the ``os.stat`` branch has its own regression test below."""
    ssh_dir = guarded_ssh_dir
    target = ssh_dir / "known_hosts"
    target.write_text("example.com ssh-ed25519 AAAA\n")
    with deny_open(target), pytest.raises(PermissionError) as exc_info:
        fs.read_known_hosts_text(target, ssh_dir=ssh_dir)
    assert exc_info.value.__cause__ is None
    rendered = "".join(
        traceback.format_exception(
            type(exc_info.value), exc_info.value, exc_info.value.__traceback__
        )
    )
    assert str(ssh_dir) not in rendered
    assert str(target) not in rendered


def test_stat_error_traceback_has_no_full_path(
    guarded_ssh_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-1 (#1833): the test above only reaches the ``except OSError`` branch
    around ``os.open`` — ``deny_open`` denies ``open`` but not ``stat``. The
    branch around the earlier ``os.stat(real).st_mode`` call (fs.py) has its
    own ``from None`` rollback that no existing test exercised; this
    monkeypatches ``os.stat`` itself to raise, forcing that first branch.
    Dropping its ``from None`` would keep the original, path-carrying OSError
    reachable as ``__cause__`` and visible in a rendered traceback."""
    ssh_dir = guarded_ssh_dir
    target = ssh_dir / "known_hosts"
    target.write_text("example.com ssh-ed25519 AAAA\n")
    real_target = os.path.realpath(target)
    real_stat = os.stat

    def failing_stat(path: Any, *args: Any, **kwargs: Any) -> Any:
        if os.fspath(path) == real_target:
            raise PermissionError(13, "Permission denied", str(path))
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", failing_stat)

    with pytest.raises(PermissionError) as exc_info:
        fs.read_known_hosts_text(target, ssh_dir=ssh_dir)
    assert exc_info.value.__cause__ is None
    rendered = "".join(
        traceback.format_exception(
            type(exc_info.value), exc_info.value, exc_info.value.__traceback__
        )
    )
    assert str(ssh_dir) not in rendered
    assert str(target) not in rendered


def test_traceback_fixture_is_guarded(guarded_ssh_dir: Path, open_guard: OpenGuard) -> None:
    """AC-3 (#1833), AC-2 (#1836): the two tests above build their SSH directory via
    the shared ``guarded_ssh_dir`` fixture, which is acceptable under AGENTS.md only
    because that fixture registers it with ``open_guard.guard_root``, supposed to
    extend the very same private-file protection ``fake_home`` gets. Prove the
    registration actually works on the exact fixture those two tests depend on: a
    deliberate read of a private-key file inside it must be caught by the guard —
    a guard that silently no-ops here would let this violation through, and would
    equally let it through for the two traceback tests above."""
    private = guarded_ssh_dir / "id_canary"
    private.write_text(CANARY_PRIVATE_KEY)

    # AssertionError, not the more specific PrivateReadAttempt: a second,
    # same-named conftest.py (tests/e2e/conftest.py) defines its own
    # PrivateReadAttempt subclass, and pytest's rootdir-relative "conftest"
    # import can resolve to either one — matching on the shared base class
    # is the same idiom tests/security/test_no_private_read.py uses.
    with pytest.raises(AssertionError):
        private.read_text()

    assert len(open_guard.violations) == 1
    open_guard.violations.clear()  # deliberate violation; do not fail teardown
