"""FR-002 (sdd-spec §7.3, §10 SEC-001/SEC-003): resolve IdentityFile references.

Covers AC-1..AC-3 of SID-7 plus security edge cases:
- AC-1: test_reference_with_pub_is_resolved
- AC-2: test_private_only_and_missing_without_opening_private_key
- AC-3: test_outside_root_and_token_references
- Resolution contract (§7.3): test_every_resolution_is_a_domain_resolution
- .pub inside HOME wins over private symlink outside HOME:
  test_private_symlink_outside_home_does_not_hide_pub_inside_home
"""

from __future__ import annotations

import builtins
import io
import os
from pathlib import Path
from typing import Any

import pytest

from conftest import CANARY, CANARY_PRIVATE_KEY, OpenGuard
from ssh_id_doctor.domain import LocalReferenceKind, Resolution
from ssh_id_doctor.references import (
    IdentityReferences,
    LocalReference,
    resolve_identity_references,
)
from ssh_id_doctor.ssh_config import UnresolvedConfigItem, parse_file


def test_reference_with_pub_is_resolved(fake_home: Path, open_guard: OpenGuard) -> None:
    """AC-1: IdentityFile with existing .pub resolves to Resolution.RESOLVED."""
    ssh = fake_home / ".ssh"
    (ssh / "id_work").write_text("dummy-private-key-material\n")
    expected_pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIWorkKeySignature work@company"
    (ssh / "id_work.pub").write_text(f"{expected_pub}\n")

    config_content = "Host work\n  HostName work.example.com\n  IdentityFile ~/.ssh/id_work\n"
    (ssh / "config").write_text(config_content)

    refs = resolve_identity_references(ssh / "config", home=fake_home, ssh_dir=ssh).references

    assert len(refs) == 1
    ref = refs[0]
    assert isinstance(ref, LocalReference)
    assert ref.kind is LocalReferenceKind.CONFIG_IDENTITY
    assert ref.path == str((ssh / "id_work").resolve())
    assert ref.resolution is Resolution.RESOLVED
    assert ref.source_line == 3
    assert ref.source_file == str((ssh / "config").resolve())
    assert ref.public_key_text == expected_pub
    assert ref.key_line == expected_pub
    assert ref.public_text == expected_pub
    assert open_guard.violations == []


def test_private_only_and_missing_without_opening_private_key(
    fake_home: Path, open_guard: OpenGuard
) -> None:
    """AC-2: private-only reference checked via stat without opening; missing reference marked."""
    ssh = fake_home / ".ssh"
    # fake_home creates id_canary and id_canary.pub; remove .pub to make it private-only
    (ssh / "id_canary.pub").unlink()

    config_content = (
        "Host example\n"
        "  User alice\n"
        "  HostName example.com\n"
        "  # comment\n"
        "  IdentityFile ~/.ssh/id_canary\n"
        "  IdentityFile ~/.ssh/gone\n"
    )
    (ssh / "config").write_text(config_content)

    refs = resolve_identity_references(ssh / "config", home=fake_home, ssh_dir=ssh).references

    assert len(refs) == 2
    canary_ref, gone_ref = refs

    assert canary_ref.kind is LocalReferenceKind.CONFIG_IDENTITY
    assert canary_ref.resolution is Resolution.PRIVATE_ONLY
    assert canary_ref.source_line == 5
    assert canary_ref.source_file == str((ssh / "config").resolve())
    assert canary_ref.path == str((ssh / "id_canary").resolve())
    assert canary_ref.public_key_text is None
    assert canary_ref.key_line is None

    assert gone_ref.kind is LocalReferenceKind.CONFIG_IDENTITY
    assert gone_ref.resolution is Resolution.MISSING
    assert gone_ref.source_line == 6
    assert gone_ref.source_file == str((ssh / "config").resolve())
    assert gone_ref.path == str((ssh / "gone").resolve())
    assert gone_ref.public_key_text is None
    assert gone_ref.key_line is None

    assert open_guard.violations == [], "no private file was opened"
    assert CANARY not in str(refs)
    assert CANARY not in repr(refs)


def test_outside_root_and_token_references(
    fake_home: Path, open_guard: OpenGuard, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-3: path outside HOME is outside_root without stat; token path is an unresolved item.

    A token reference is not a LocalReference at all (sdd-spec §7.3 allows only
    five resolutions): it becomes an ``unresolved_token`` item with provenance.
    """
    ssh = fake_home / ".ssh"
    config_content = (
        "Host example\n  IdentityFile /etc/ssh/ssh_host_ed25519_key\n  IdentityFile ~/.ssh/%h_key\n"
    )
    (ssh / "config").write_text(config_content)

    stat_calls: list[str] = []
    real_stat = os.stat

    def recording_stat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        stat_calls.append(os.fsdecode(os.fspath(path)))
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", recording_stat)

    result = resolve_identity_references(ssh / "config", ssh_dir=ssh)

    assert isinstance(result, IdentityReferences)
    assert len(result.references) == 1
    outside_ref = result.references[0]
    assert outside_ref.kind is LocalReferenceKind.CONFIG_IDENTITY
    assert outside_ref.resolution is Resolution.OUTSIDE_ROOT
    assert outside_ref.path == "/etc/ssh/ssh_host_ed25519_key"
    assert outside_ref.source_line == 2
    assert outside_ref.public_key_text is None

    assert result.unresolved == (
        UnresolvedConfigItem(
            reason="unresolved_token",
            detail="~/.ssh/%h_key",
            source_file=str((ssh / "config").resolve()),
            source_line=3,
        ),
    )
    assert not any("%h" in ref.path for ref in result.references)

    assert not any("ssh_host_ed25519_key" in call for call in stat_calls)
    assert not any("%h" in call for call in stat_calls)
    assert open_guard.violations == []


def test_every_resolution_is_a_domain_resolution(fake_home: Path, open_guard: OpenGuard) -> None:
    """Every LocalReference.resolution is a member of domain.Resolution (sdd-spec §7.3)."""
    ssh = fake_home / ".ssh"
    (ssh / "id_work").write_text("priv\n")
    (ssh / "id_work.pub").write_text("ssh-ed25519 AAAAC3work work@test\n")
    (ssh / "dir_key").mkdir()
    (ssh / "config").write_text(
        "Host all\n"
        "  IdentityFile ~/.ssh/id_work\n"
        "  IdentityFile ~/.ssh/id_canary\n"
        "  IdentityFile ~/.ssh/gone\n"
        "  IdentityFile ~/.ssh/dir_key\n"
        "  IdentityFile /etc/ssh/ssh_host_ed25519_key\n"
        "  IdentityFile ~/.ssh/%r_key\n"
        "  IdentityFile ~/.ssh/${KEYNAME}\n"
        "  IdentityFile ~/.ssh/%d/%u\n"
    )

    result = resolve_identity_references(ssh / "config", home=fake_home, ssh_dir=ssh)

    assert len(result.references) == 5
    for ref in result.references:
        assert type(ref.resolution) is Resolution
        assert ref.resolution in set(Resolution)
    assert [item.reason for item in result.unresolved] == ["unresolved_token"] * 3
    assert [item.source_line for item in result.unresolved] == [7, 8, 9]
    assert open_guard.violations == []


def test_private_symlink_outside_home_does_not_hide_pub_inside_home(
    fake_home: Path,
    tmp_path_factory: pytest.TempPathFactory,
    open_guard: OpenGuard,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """FR-002: <ref>.pub inside HOME wins over a private <ref> symlinked outside HOME.

    The private symlink target lies outside the synthetic HOME, where the
    autouse guard does not look, so this test guards it explicitly.
    """
    outside = tmp_path_factory.mktemp("outside_private")
    outside_key = outside / "id_work_real"
    outside_key.write_text(CANARY_PRIVATE_KEY)
    outside_real = os.path.realpath(outside_key)

    ssh = fake_home / ".ssh"
    (ssh / "id_work").symlink_to(outside_key)
    expected_pub = "ssh-ed25519 AAAAC3symlinked work@test"
    (ssh / "id_work.pub").write_text(f"{expected_pub}\n")
    (ssh / "config").write_text("Host work\n  IdentityFile ~/.ssh/id_work\n")

    outside_opens: list[str] = []

    def touches_outside(file: Any) -> bool:
        if isinstance(file, int) or not isinstance(file, str | bytes | os.PathLike):
            return False
        return os.path.realpath(os.fsdecode(os.fspath(file))) == outside_real

    def wrap(real: Any) -> Any:
        def wrapper(file: Any, *args: Any, **kwargs: Any) -> Any:
            if touches_outside(file):
                outside_opens.append(os.fsdecode(os.fspath(file)))
            return real(file, *args, **kwargs)

        return wrapper

    monkeypatch.setattr(builtins, "open", wrap(builtins.open))
    monkeypatch.setattr(io, "open", wrap(io.open))
    monkeypatch.setattr(os, "open", wrap(os.open))
    monkeypatch.setattr(Path, "read_text", wrap(Path.read_text))
    monkeypatch.setattr(Path, "read_bytes", wrap(Path.read_bytes))

    refs = resolve_identity_references(ssh / "config", home=fake_home, ssh_dir=ssh).references

    assert len(refs) == 1
    ref = refs[0]
    assert ref.resolution is Resolution.RESOLVED
    assert ref.public_key_text == expected_pub
    assert ref.source_line == 2
    assert outside_opens == [], "private symlink target outside HOME was opened"
    assert CANARY not in repr(refs)
    assert open_guard.violations == []


def test_private_outside_home_without_pub_is_outside_root(
    fake_home: Path, tmp_path_factory: pytest.TempPathFactory, open_guard: OpenGuard
) -> None:
    """No <ref>.pub and a private <ref> symlinked outside HOME -> outside_root."""
    outside = tmp_path_factory.mktemp("outside_private_only")
    outside_key = outside / "id_lonely"
    outside_key.write_text(CANARY_PRIVATE_KEY)

    ssh = fake_home / ".ssh"
    (ssh / "id_lonely").symlink_to(outside_key)
    (ssh / "config").write_text("Host l\n  IdentityFile ~/.ssh/id_lonely\n")

    refs = resolve_identity_references(ssh / "config", home=fake_home, ssh_dir=ssh).references

    assert len(refs) == 1
    assert refs[0].resolution is Resolution.OUTSIDE_ROOT
    assert open_guard.violations == []


def test_same_reference_across_multiple_hosts_has_distinct_provenance(
    fake_home: Path, open_guard: OpenGuard
) -> None:
    """Multiple Host blocks with the same IdentityFile produce distinct LocalReference entries."""
    ssh = fake_home / ".ssh"
    (ssh / "shared").write_text("key\n")
    (ssh / "shared.pub").write_text("ssh-ed25519 AAAAC3shared shared\n")

    config_content = (
        "Host alpha\n  IdentityFile ~/.ssh/shared\nHost beta\n  IdentityFile ~/.ssh/shared\n"
    )
    (ssh / "config").write_text(config_content)

    refs = resolve_identity_references(ssh / "config", home=fake_home, ssh_dir=ssh).references

    assert len(refs) == 2
    assert refs[0].source_line == 2
    assert refs[1].source_line == 4
    assert refs[0].path == refs[1].path
    assert refs[0].resolution is Resolution.RESOLVED
    assert refs[1].resolution is Resolution.RESOLVED
    assert refs[0].public_key_text == "ssh-ed25519 AAAAC3shared shared"
    assert open_guard.violations == []


def test_include_splices_references_with_real_source_loc(
    fake_home: Path, open_guard: OpenGuard
) -> None:
    """Include directives splice IdentityFile entries with their true source_file and line."""
    ssh = fake_home / ".ssh"
    extra_dir = ssh / "config.d"
    extra_dir.mkdir()
    included_file = extra_dir / "work.conf"
    included_file.write_text("IdentityFile ~/.ssh/included_key\n")

    (ssh / "included_key").write_text("priv\n")
    (ssh / "included_key.pub").write_text("ssh-ed25519 AAAAC3inc inc@test\n")

    open_guard.allow(included_file)

    (ssh / "config").write_text("Include config.d/*.conf\n")

    doc = parse_file(ssh / "config")
    refs = resolve_identity_references(doc, home=fake_home, ssh_dir=ssh).references

    assert len(refs) == 1
    ref = refs[0]
    assert ref.source_file == str(included_file.resolve())
    assert ref.source_line == 1
    assert ref.resolution is Resolution.RESOLVED
    assert ref.public_key_text == "ssh-ed25519 AAAAC3inc inc@test"
    assert open_guard.violations == []


def test_pub_file_with_private_key_material_marked_private_only(
    fake_home: Path, open_guard: OpenGuard
) -> None:
    """A .pub file containing private keys raises PrivateKeyAccessDenied -> private_only."""
    ssh = fake_home / ".ssh"
    (ssh / "bad_pub").write_text("dummy\n")
    (ssh / "bad_pub.pub").write_text(CANARY_PRIVATE_KEY)

    (ssh / "config").write_text("Host bad\n  IdentityFile ~/.ssh/bad_pub\n")

    refs = resolve_identity_references(ssh / "config", home=fake_home, ssh_dir=ssh).references

    assert len(refs) == 1
    ref = refs[0]
    assert ref.resolution is Resolution.PRIVATE_ONLY
    assert ref.public_key_text is None
    assert CANARY not in str(refs)
    assert open_guard.violations == []


def test_pub_file_symlink_outside_root_marked_outside_root(
    fake_home: Path, tmp_path_factory: pytest.TempPathFactory, open_guard: OpenGuard
) -> None:
    """A .pub symlink that points outside HOME is marked outside_root and not opened."""
    ssh = fake_home / ".ssh"
    outside = tmp_path_factory.mktemp("outside")
    outside_pub = outside / "secret.pub"
    outside_pub.write_text("ssh-ed25519 AAAAC3outside outside\n")

    (ssh / "target_key").write_text("target\n")
    (ssh / "target_key.pub").symlink_to(outside_pub)

    (ssh / "config").write_text("Host ext\n  IdentityFile ~/.ssh/target_key\n")

    refs = resolve_identity_references(ssh / "config", home=fake_home, ssh_dir=ssh).references

    assert len(refs) == 1
    assert refs[0].resolution is Resolution.OUTSIDE_ROOT
    assert refs[0].public_key_text is None
    assert open_guard.violations == []


def test_pub_fifo_or_unreadable_marked_unreadable(fake_home: Path, open_guard: OpenGuard) -> None:
    """A .pub FIFO or unreadable file maps to Resolution.UNREADABLE."""
    ssh = fake_home / ".ssh"
    (ssh / "pipe_key").write_text("key\n")
    os.mkfifo(ssh / "pipe_key.pub")

    (ssh / "config").write_text("Host pipe\n  IdentityFile ~/.ssh/pipe_key\n")

    refs = resolve_identity_references(ssh / "config", home=fake_home, ssh_dir=ssh).references

    assert len(refs) == 1
    assert refs[0].resolution is Resolution.UNREADABLE
    assert refs[0].public_key_text is None
    assert open_guard.violations == []


def test_directory_as_identity_file_marked_unreadable(
    fake_home: Path, open_guard: OpenGuard
) -> None:
    """An IdentityFile pointing to a directory is marked Resolution.UNREADABLE."""
    ssh = fake_home / ".ssh"
    (ssh / "dir_key").mkdir()

    (ssh / "config").write_text("Host d\n  IdentityFile ~/.ssh/dir_key\n")

    refs = resolve_identity_references(ssh / "config", home=fake_home, ssh_dir=ssh).references

    assert len(refs) == 1
    assert refs[0].resolution is Resolution.UNREADABLE
    assert refs[0].public_key_text is None
    assert open_guard.violations == []


def test_relative_identity_file_resolved_against_ssh_dir(
    fake_home: Path, open_guard: OpenGuard
) -> None:
    """A relative IdentityFile path is resolved relative to ssh_dir."""
    ssh = fake_home / ".ssh"
    (ssh / "rel_key").write_text("rel\n")
    (ssh / "rel_key.pub").write_text("ssh-ed25519 AAAAC3rel rel@host\n")

    (ssh / "config").write_text("Host r\n  IdentityFile rel_key\n")

    refs = resolve_identity_references(ssh / "config", home=fake_home, ssh_dir=ssh).references

    assert len(refs) == 1
    ref = refs[0]
    assert ref.path == str((ssh / "rel_key").resolve())
    assert ref.resolution is Resolution.RESOLVED
    assert ref.public_key_text == "ssh-ed25519 AAAAC3rel rel@host"
    assert open_guard.violations == []


def test_quoted_path_with_spaces(fake_home: Path, open_guard: OpenGuard) -> None:
    """IdentityFile in double quotes with spaces is parsed and resolved properly."""
    ssh = fake_home / ".ssh"
    (ssh / "my key").write_text("spaces\n")
    (ssh / "my key.pub").write_text("ssh-ed25519 AAAAC3spaces spaces@test\n")

    (ssh / "config").write_text('Host sp\n  IdentityFile "~/.ssh/my key"\n')

    refs = resolve_identity_references(ssh / "config", home=fake_home, ssh_dir=ssh).references

    assert len(refs) == 1
    ref = refs[0]
    assert ref.path == str((ssh / "my key").resolve())
    assert ref.resolution is Resolution.RESOLVED
    assert ref.public_key_text == "ssh-ed25519 AAAAC3spaces spaces@test"
    assert open_guard.violations == []


def test_tilde_without_home_is_unreadable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """IdentityFile with ~ when HOME is absent produces Resolution.UNREADABLE."""
    monkeypatch.delenv("HOME", raising=False)
    config_file = tmp_path / "config"
    config_file.write_text("Host nohome\n  IdentityFile ~/key\n")

    refs = resolve_identity_references(config_file, home=None).references

    assert len(refs) == 1
    assert refs[0].resolution is Resolution.UNREADABLE


def test_identity_outside_ssh_dir_but_inside_home_is_resolved(
    fake_home: Path, open_guard: OpenGuard
) -> None:
    """Risk mitigation: IdentityFile outside ~/.ssh but inside HOME is resolved."""
    custom_dir = fake_home / "custom_keys"
    custom_dir.mkdir()
    (custom_dir / "id_deploy").write_text("deploy-priv\n")
    (custom_dir / "id_deploy.pub").write_text("ssh-ed25519 AAAAC3deploy deploy@ci\n")

    ssh = fake_home / ".ssh"
    (ssh / "config").write_text("Host deploy\n  IdentityFile ~/custom_keys/id_deploy\n")

    refs = resolve_identity_references(ssh / "config", home=fake_home, ssh_dir=ssh).references

    assert len(refs) == 1
    ref = refs[0]
    assert ref.resolution is Resolution.RESOLVED
    assert ref.path == str((custom_dir / "id_deploy").resolve())
    assert ref.public_key_text == "ssh-ed25519 AAAAC3deploy deploy@ci"
    assert open_guard.violations == []
