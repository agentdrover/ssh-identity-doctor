"""AC-2: exit codes match sdd-spec §5.3; an unknown subcommand exits 1."""

from __future__ import annotations

import pytest

from ssh_id_doctor.cli import main
from ssh_id_doctor.exit_codes import ExitCode


def _run(argv: list[str]) -> int:
    try:
        return main(argv)
    except SystemExit as exc:  # argparse may exit instead of returning
        return int(exc.code) if isinstance(exc.code, int) else 1


def test_exit_codes_match_spec_5_3(capsys: pytest.CaptureFixture[str]) -> None:
    assert {member.name: member.value for member in ExitCode} == {
        "OK": 0,
        "INVALID_ARGS": 1,
        "REQUIRED_SCAN_FAILED": 2,
        "STRICT_FINDINGS": 3,
        "REPORT_WRITE_FAILED": 4,
    }

    assert _run(["bogus"]) == ExitCode.INVALID_ARGS == 1
    assert "bogus" in capsys.readouterr().err
