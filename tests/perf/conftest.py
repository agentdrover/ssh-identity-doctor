"""Shared fixtures for performance budget tests (NFR-001).

Generates a synthetic HOME in tmp_path with:
- Exactly 100 .pub files
- ~/.ssh/config with exactly 500 Host blocks (some via Include config.d/*.conf)
- References to existing and missing keys
- No private keys created
- Real ~/.ssh is never read (§13.3)
"""

from __future__ import annotations

import base64
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from ssh_id_doctor.inspectors.agent import AgentResult, AgentState
from ssh_id_doctor.inspectors.keygen import KeyInfo


def _make_pub_key(index: int) -> tuple[str, str]:
    """Return (pub_line, fingerprint) for key index 0..99.

    Uses a deterministic valid ed25519 public key line format.
    Wire format: 32 bytes public key.
    """
    raw_pub = index.to_bytes(32, byteorder="big")
    b64_pub = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + raw_pub).decode()
    comment = f"user{index:03d}@perf-test"
    line = f"ssh-ed25519 {b64_pub} {comment}\n"

    # Deterministic 32-byte sha256 fingerprint representation
    raw_fp = (index + 1000).to_bytes(32, byteorder="big")
    b64_fp = base64.b64encode(raw_fp).decode()
    fp = f"SHA256:{b64_fp}"
    return line, fp


# Precompute 100 keys and fingerprints
_PRECOMPUTED_KEYS: list[tuple[str, str]] = [_make_pub_key(i) for i in range(100)]
KEY_MAP: dict[str, str] = {line.strip(): fp for line, fp in _PRECOMPUTED_KEYS}


class DeterministicKeygen:
    """Fake PublicKeyInspector that returns precomputed fingerprints deterministically."""

    def fingerprint(self, public_line: str, *, timeout: float = 5.0) -> KeyInfo:
        stripped = public_line.strip()
        parts = stripped.split(None, 2)
        algo = parts[0] if parts else "ssh-ed25519"
        comment = parts[2] if len(parts) >= 3 else ""

        fp = KEY_MAP.get(stripped)
        if fp is None:
            # Fallback deterministic fingerprint
            raw_hash = base64.b64encode(stripped.encode()[:32].ljust(32, b"0")).decode()
            fp = f"SHA256:{raw_hash}"

        return KeyInfo(
            fingerprint=fp,
            algorithm=algo,
            bits_or_curve="256",
            comment=comment,
        )


class FakeAgent:
    """Fake SSHAgentAdapter that returns empty identities without running external tools."""

    def list_identities(self, timeout: float = 5.0) -> AgentResult:
        return AgentResult(
            state=AgentState.AVAILABLE_EMPTY,
            identities=(),
            unresolved=(),
            detail="agent has no identities",
        )


@dataclass(frozen=True)
class PerfHomeFixture:
    home: Path
    num_pub_files: int
    num_host_blocks: int


@pytest.fixture
def perf_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[PerfHomeFixture]:
    """Generate synthetic HOME in tmp_path with 100 .pub files and 500 config Host blocks."""
    home = tmp_path / "perf_home"
    home.mkdir()
    ssh_dir = home / ".ssh"
    ssh_dir.mkdir(mode=0o700)
    config_d = ssh_dir / "config.d"
    config_d.mkdir()

    # 1. Exactly 100 .pub files
    # 80 in ~/.ssh, 20 in ~/.ssh/keys
    keys_dir = ssh_dir / "keys"
    keys_dir.mkdir()

    for i in range(80):
        key_file = ssh_dir / f"id_test_{i:03d}.pub"
        key_file.write_text(_PRECOMPUTED_KEYS[i][0])

    for i in range(80, 100):
        key_file = keys_dir / f"id_extra_{i:03d}.pub"
        key_file.write_text(_PRECOMPUTED_KEYS[i][0])

    # 2. Exactly 500 Host blocks:
    # 250 in ~/.ssh/config, 250 in ~/.ssh/config.d/included.conf via Include
    main_config_lines: list[str] = [
        "Include config.d/*.conf",
        "",
    ]

    for i in range(250):
        host_alias = f"host_main_{i:04d}"
        target_host = f"srv-{i:04d}.example.com"
        user = f"user_{i % 50}"
        if i % 5 == 0:
            # missing key
            id_file = f"~/.ssh/nonexistent_key_{i:04d}"
        elif i < 100:
            # existing key
            id_file = f"~/.ssh/id_test_{i:03d}"
        else:
            # existing key in keys/
            id_file = f"~/.ssh/keys/id_extra_{80 + (i % 20):03d}"

        main_config_lines.append(f"Host {host_alias}")
        main_config_lines.append(f"    HostName {target_host}")
        main_config_lines.append(f"    User {user}")
        main_config_lines.append(f"    IdentityFile {id_file}")
        main_config_lines.append("")

    (ssh_dir / "config").write_text("\n".join(main_config_lines))

    included_config_lines: list[str] = []
    for i in range(250):
        host_alias = f"host_inc_{i:04d}"
        target_host = f"inc-{i:04d}.example.com"
        user = f"inc_user_{i % 50}"
        if i % 7 == 0:
            id_file = f"~/.ssh/missing_inc_key_{i:04d}"
        else:
            id_file = f"~/.ssh/id_test_{i % 80:03d}"

        included_config_lines.append(f"Host {host_alias}")
        included_config_lines.append(f"    HostName {target_host}")
        included_config_lines.append(f"    User {user}")
        included_config_lines.append(f"    IdentityFile {id_file}")
        included_config_lines.append("")

    (config_d / "included.conf").write_text("\n".join(included_config_lines))

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)

    yield PerfHomeFixture(
        home=home,
        num_pub_files=100,
        num_host_blocks=500,
    )
