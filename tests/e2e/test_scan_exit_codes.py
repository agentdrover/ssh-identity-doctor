"""E2E exit code tests (AC-2)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ssh_id_doctor.cli import main
from ssh_id_doctor.exit_codes import ExitCode


def test_scan_exit_codes_match_spec_5_3(
    home_basic: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC-2: Given home_basic with error-finding CFG001.

    When runs:
    (a) scan --strict
    (b) scan --format xml
    (c) scan --timeout 0
    (d) scan with PATH without ssh-keygen
    (e) scan with agent in state unavailable without --strict
    Then exit codes: 3, 1, 1, 2, 0; in (d) stderr mentions ssh-keygen and remediation.
    """
    ssh_dir = str(home_basic / ".ssh")
    config = str(home_basic / ".ssh" / "config")

    # (a) scan --strict -> exit 3 (CFG001 is an error-severity finding)
    rc_a = main(
        [
            "scan",
            "--strict",
            "--no-agent",
            "--ssh-dir",
            ssh_dir,
            "--config",
            config,
        ]
    )
    assert rc_a == ExitCode.STRICT_FINDINGS

    # (b) scan --format xml -> exit 1 (invalid argument)
    with pytest.raises(SystemExit) as exc_b:
        main(["scan", "--format", "xml"])
    assert exc_b.value.code == ExitCode.INVALID_ARGS

    # (c) scan --timeout 0 -> exit 1 (invalid argument)
    rc_c = main(
        [
            "scan",
            "--timeout",
            "0",
            "--no-agent",
            "--ssh-dir",
            ssh_dir,
            "--config",
            config,
        ]
    )
    assert rc_c == ExitCode.INVALID_ARGS

    # (d) scan with PATH without ssh-keygen -> exit 2
    # Simulate missing ssh-keygen on PATH
    monkeypatch.setenv("PATH", "")
    rc_d = main(
        [
            "scan",
            "--no-agent",
            "--ssh-dir",
            ssh_dir,
            "--config",
            config,
        ]
    )
    captured_d = capsys.readouterr()
    assert rc_d == ExitCode.REQUIRED_SCAN_FAILED
    assert "ssh-keygen" in captured_d.err.lower()
    assert "remediation" in captured_d.err.lower() or "install" in captured_d.err.lower()
    monkeypatch.undo()

    # (e) scan with agent in state unavailable without --strict -> exit 0
    # HOME fixture unsets SSH_AUTH_SOCK so agent is unavailable
    rc_e = main(
        [
            "scan",
            "--ssh-dir",
            ssh_dir,
            "--config",
            config,
        ]
    )
    assert rc_e == ExitCode.OK
