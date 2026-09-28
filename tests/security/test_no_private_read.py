"""SEC-001: the private-key trap (AC-4) and the guard that springs it."""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

import pytest

from conftest import CANARY, CANARY_PRIVATE_KEY, CANARY_PUBLIC_KEY, OpenGuard
from ssh_id_doctor import fs
from ssh_id_doctor.cli import main
from ssh_id_doctor.fs import PrivateKeyAccessDenied

SRC = Path(__file__).resolve().parents[2] / "src" / "ssh_id_doctor"
AUDITED = {"process.py", "fs.py", "output.py"}


def test_read_public_text_refuses_private_key_without_opening(
    fake_home: Path,
    open_guard: OpenGuard,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    ssh = fake_home / ".ssh"

    with pytest.raises(PrivateKeyAccessDenied) as refused:
        fs.read_public_text(ssh / "id_canary")

    assert open_guard.violations == [], "refusal must come before any open"
    assert CANARY not in str(refused.value)
    assert fs.read_public_text(ssh / "id_canary.pub") == CANARY_PUBLIC_KEY
    out, err = capsys.readouterr()
    assert CANARY not in out + err
    assert CANARY not in caplog.text


def test_read_public_text_refuses_disguised_private_key(
    fake_home: Path, open_guard: OpenGuard
) -> None:
    ssh = fake_home / ".ssh"
    (ssh / "renamed.pub").write_text(CANARY_PRIVATE_KEY)
    (ssh / "alias.pub").symlink_to(ssh / "id_canary")

    with pytest.raises(PrivateKeyAccessDenied) as renamed:
        fs.read_public_text(ssh / "renamed.pub")
    with pytest.raises(PrivateKeyAccessDenied):
        fs.read_public_text(ssh / "alias.pub")

    assert CANARY not in str(renamed.value)
    assert open_guard.violations == []


def test_open_guard_catches_every_read_route(fake_home: Path, open_guard: OpenGuard) -> None:
    canary = fake_home / ".ssh" / "id_canary"

    with pytest.raises(AssertionError):
        open(canary)
    with pytest.raises(AssertionError):
        os.open(canary, os.O_RDONLY)
    with pytest.raises(AssertionError):
        canary.read_bytes()
    with pytest.raises(AssertionError):
        canary.read_text()
    with pytest.raises(AssertionError):
        canary.open("rb")

    assert len(open_guard.violations) == 5
    open_guard.violations.clear()  # deliberate violations; do not fail teardown


def test_src_has_no_direct_subprocess_or_open() -> None:
    forbidden = re.compile(
        r"^\s*(?:import|from)\s+subprocess\b|\bsubprocess\.|(?<![\w.])open\("
        r"|\.read_(?:bytes|text)\(|\bos\.open\(|\.open\("
    )
    offenders = [
        f"{path.name}:{number}"
        for path in sorted(SRC.rglob("*.py"))
        if path.name not in AUDITED
        for number, line in enumerate(path.read_text().splitlines(), start=1)
        if forbidden.search(line)
    ]
    assert offenders == [], "use ssh_id_doctor.process.run / ssh_id_doctor.fs only"


def test_full_scan_never_opens_private_key(
    fake_home: Path,
    open_guard: OpenGuard,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC-5: Given fake_home with id_canary and config referencing id_canary via IdentityFile;

    open/io.open/Path.read_* intercepted by open_guard.
    When full `ssh-id-doctor scan --format json --no-agent --ssh-dir ... --config ...` runs,
    Then open_guard is never triggered, id_canary is present only as path (stat),
    marker string CANARY is not present in output; exit 0.
    """
    ssh_dir = str(fake_home / ".ssh")
    config = str(fake_home / ".ssh" / "config")

    # Run scan across all formats
    for fmt in ["json", "terminal", "md"]:
        rc = main(
            [
                "scan",
                "--format",
                fmt,
                "--no-agent",
                "--ssh-dir",
                ssh_dir,
                "--config",
                config,
            ]
        )
        assert rc == 0
        captured = capsys.readouterr()
        assert CANARY not in captured.out
        assert CANARY not in captured.err

    assert open_guard.violations == [], "SEC-001: canary private key was never opened"
