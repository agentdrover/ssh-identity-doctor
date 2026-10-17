"""E2E output writing tests (AC-4)."""

from __future__ import annotations

import json
import stat
from pathlib import Path
from unittest.mock import patch

import jsonschema
import pytest

from ssh_id_doctor.cli import main
from ssh_id_doctor.exit_codes import ExitCode

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "src" / "ssh_id_doctor" / "reporting" / "schema" / "scan-1.0.json"


def test_output_atomic_0600_and_exit_4_keeps_old_report(
    home_basic: Path,
    tmp_path: Path,
) -> None:
    """AC-4: Given existing report.json with 'OLD' and dir out/ without write permissions.

    When:
    (a) scan --output report.json
    (b) scan --output out/report.json
    Then:
    (a) exit 0, file atomically replaced, mode 0600;
    (b) exit 4, no leftover temp files;
    upon simulated os.replace error, old report retains 'OLD'.
    """
    ssh_dir = str(home_basic / ".ssh")
    config = str(home_basic / ".ssh" / "config")

    report_file = tmp_path / "report.json"
    report_file.write_text("OLD")

    # (a) scan --output report.json
    rc_a = main(
        [
            "scan",
            "--format",
            "json",
            "--no-agent",
            "--ssh-dir",
            ssh_dir,
            "--config",
            config,
            "--output",
            str(report_file),
        ]
    )
    assert rc_a == ExitCode.OK
    content_a = report_file.read_text()
    assert content_a != "OLD"
    assert '"schema_version": "1.0"' in content_a
    # Check permissions 0600
    file_stat = report_file.stat()
    assert stat.S_IMODE(file_stat.st_mode) == 0o600

    # (b) scan --output out/report.json where out/ has no write permissions
    unwritable_dir = tmp_path / "unwritable_dir"
    unwritable_dir.mkdir(mode=0o555)
    unwritable_target = unwritable_dir / "report.json"

    rc_b = main(
        [
            "scan",
            "--format",
            "json",
            "--no-agent",
            "--ssh-dir",
            ssh_dir,
            "--config",
            config,
            "--output",
            str(unwritable_target),
        ]
    )
    assert rc_b == ExitCode.REPORT_WRITE_FAILED
    # Verify no temp files left in unwritable_dir
    leftovers = list(unwritable_dir.iterdir())
    assert leftovers == []

    # Check that simulated os.replace error keeps 'OLD' and exits 4
    report_file.write_text("OLD")
    with patch("ssh_id_doctor.output.os.replace", side_effect=OSError("disk failure")):
        rc_err = main(
            [
                "scan",
                "--format",
                "json",
                "--no-agent",
                "--ssh-dir",
                ssh_dir,
                "--config",
                config,
                "--output",
                str(report_file),
            ]
        )
        assert rc_err == ExitCode.REPORT_WRITE_FAILED
        assert report_file.read_text() == "OLD"


def test_known_hosts_json_schema(
    home_basic: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC-5: with a known_hosts file present, `scan --format json` still validates
    against schema 1.0, carries no `known_hosts` key, and reports an available
    known_hosts source."""
    ssh_dir = home_basic / ".ssh"
    config = ssh_dir / "config"
    (ssh_dir / "known_hosts").write_text(
        "example.com ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIMwKQfiW86Yu6eXH3bYIk94OnoidaKLausFeWb3nT/iL\n"
    )

    exit_code = main(
        [
            "scan",
            "--format",
            "json",
            "--no-agent",
            "--ssh-dir",
            str(ssh_dir),
            "--config",
            str(config),
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == ExitCode.OK

    data = json.loads(captured.out)
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(data)

    assert "known_hosts" not in data
    source_map = {s["source"]: s for s in data["sources"]}
    assert source_map["known_hosts"]["state"] == "available"
