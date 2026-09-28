"""E2E exit code tests (AC-2)."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from ssh_id_doctor import process
from ssh_id_doctor.cli import main
from ssh_id_doctor.exit_codes import ExitCode
from ssh_id_doctor.process import ProcessResult, ProcessStatus


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

    # (f) scan with nonexistent --ssh-dir -> exit 1
    rc_f = main(
        [
            "scan",
            "--ssh-dir",
            "/nonexistent/directory/path/never/exists",
        ]
    )
    assert rc_f == ExitCode.INVALID_ARGS


# --- Review #701 (task #1392): explicit paths are taken as given --------------

_FIXTURE_PUB = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICy6m9y8JQXK/rnkedDzK3YZbu5pH10XpE6+eVYTfnB1"
    " stray@example\n"
)


def test_missing_ssh_dir_named_dotssh_is_not_remapped_to_parent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """§5.3: an explicit --ssh-dir that is not a directory is exit 1, even when
    it is spelled '<parent>/.ssh' and the parent exists. Nothing in the parent
    may be scanned instead."""
    parent = tmp_path / "parent"
    parent.mkdir()
    (parent / "stray.pub").write_text(_FIXTURE_PUB)
    missing = parent / ".ssh"
    assert not missing.exists()

    rc = main(["scan", "--format", "json", "--no-agent", "--ssh-dir", str(missing)])
    captured = capsys.readouterr()

    assert rc == ExitCode.INVALID_ARGS
    assert "is not a directory" in captured.err
    assert "stray" not in captured.out
    assert "stray" not in captured.err


def test_missing_config_under_dotssh_is_not_remapped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An explicit --config is used exactly as given: '<home>/.ssh/config' that
    does not exist must not silently become '<home>/config'."""
    home = tmp_path / "otherhome"
    home.mkdir()
    (home / "config").write_text("Host leaked-from-home-config\n  HostName leaked.example\n")
    keys = tmp_path / "keys"
    keys.mkdir()
    missing_config = home / ".ssh" / "config"
    assert not missing_config.exists()

    rc = main(
        [
            "scan",
            "--format",
            "json",
            "--no-agent",
            "--ssh-dir",
            str(keys),
            "--config",
            str(missing_config),
        ]
    )
    captured = capsys.readouterr()

    assert rc == ExitCode.OK
    assert "leaked" not in captured.out
    report = json.loads(captured.out)
    config_sources = [s for s in report["sources"] if s["source"] == "config"]
    assert [s["state"] for s in config_sources] == ["empty"]


# --- Review #701 (task #1392): --timeout reaches every external tool ----------


def _record_process_runs(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, float]]:
    """Patch process.run: ssh-keygen runs for real, ssh-add and gh are recorded
    fakes that hand back one public key each (so the nested fingerprint calls
    of the agent and GitHub adapters are exercised too)."""
    calls: list[tuple[str, float]] = []
    real_run = process.run
    github_keys = json.dumps([{"id": 7, "key": _FIXTURE_PUB.strip(), "title": "laptop"}])

    def fake_run(argv: Sequence[str], *, timeout: float, max_output: int) -> ProcessResult:
        tool = argv[0]
        calls.append((tool, timeout))
        if tool == "ssh-keygen":
            return real_run(argv, timeout=timeout, max_output=max_output)
        if tool == "ssh-add":
            return ProcessResult(ProcessStatus.OK, 0, _FIXTURE_PUB.encode(), b"", False)
        if tool == "gh" and list(argv[1:3]) == ["auth", "status"]:
            return ProcessResult(ProcessStatus.OK, 0, b"", b"", False)
        if tool == "gh":
            return ProcessResult(ProcessStatus.OK, 0, github_keys.encode(), b"", False)
        raise AssertionError(f"unexpected external tool {tool!r}")

    monkeypatch.setattr(process, "run", fake_run)
    return calls


def _scan_all_sources(home_basic: Path, *extra: str) -> int:
    return main(
        [
            "scan",
            "--format",
            "json",
            "--github",
            "--ssh-dir",
            str(home_basic / ".ssh"),
            "--config",
            str(home_basic / ".ssh" / "config"),
            *extra,
        ]
    )


def test_positive_timeout_reaches_every_external_tool(
    home_basic: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--timeout 1.5 is what ssh-keygen, ssh-add and gh are run with."""
    calls = _record_process_runs(monkeypatch)

    rc = _scan_all_sources(home_basic, "--timeout", "1.5")
    capsys.readouterr()

    assert rc == ExitCode.OK
    assert {tool for tool, _ in calls} == {"ssh-keygen", "ssh-add", "gh"}
    assert [t for _, t in calls] == [1.5] * len(calls)


def test_default_timeout_is_ten_seconds(
    home_basic: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Without --timeout every external tool gets the §5.2 default of 10 s."""
    calls = _record_process_runs(monkeypatch)

    rc = _scan_all_sources(home_basic)
    capsys.readouterr()

    assert rc == ExitCode.OK
    assert {tool for tool, _ in calls} == {"ssh-keygen", "ssh-add", "gh"}
    assert [t for _, t in calls] == [10.0] * len(calls)
