"""SEC-003 / §13.4: discovery stays inside its root and never reads (AC-3).

Also covers :func:`ssh_id_doctor.fs.read_config_text` (FR-004a AC-4): the
same regular-file-before-open and size-limit safety as :func:`read_public_text`,
applied to one ssh_config(5) file.
"""

from __future__ import annotations

import builtins
import io
import os
from pathlib import Path
from typing import Any

import pytest

from conftest import CANARY, CANARY_PRIVATE_KEY
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


def test_read_known_hosts_text_refusals(tmp_path: Path, opened_paths: list[str]) -> None:
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
