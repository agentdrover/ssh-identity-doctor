"""SEC-001: the private-key trap (AC-4) and the guard that springs it."""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

import pytest

from conftest import CANARY, CANARY_PRIVATE_KEY, CANARY_PUBLIC_KEY, OpenGuard, PrivateReadAttempt
from ssh_id_doctor import fs
from ssh_id_doctor.fs import PrivateKeyAccessDenied

SRC = Path(__file__).resolve().parents[2] / "src" / "ssh_id_doctor"
AUDITED = {"process.py", "fs.py"}


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

    with pytest.raises(PrivateReadAttempt):
        open(canary)
    with pytest.raises(PrivateReadAttempt):
        os.open(canary, os.O_RDONLY)
    with pytest.raises(PrivateReadAttempt):
        canary.read_bytes()
    with pytest.raises(PrivateReadAttempt):
        canary.read_text()
    with pytest.raises(PrivateReadAttempt):
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
