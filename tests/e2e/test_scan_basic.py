"""E2E basic scan tests (AC-1, AC-6)."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from conftest import CANARY, OpenGuard
from ssh_id_doctor.cli import main

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "src" / "ssh_id_doctor" / "reporting" / "schema" / "scan-1.0.json"
REPORT_GOLDEN_PATH = REPO_ROOT / "docs" / "examples" / "report.json"


def test_scan_json_reports_identities_and_cfg001(
    home_basic: Path,
    open_guard: OpenGuard,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC-1: Given home_basic, HOME points at fixture.

    When `ssh-id-doctor scan --format json --no-agent ...`
    Then exit 0; JSON valid against schema 1.0, contains all fixture identities and CFG001;
    sources.agent = skipped; open guard had no violations; CANARY not in stdout/stderr.
    """
    ssh_dir = str(home_basic / ".ssh")
    config = str(home_basic / ".ssh" / "config")

    exit_code = main(
        [
            "scan",
            "--format",
            "json",
            "--no-agent",
            "--ssh-dir",
            ssh_dir,
            "--config",
            config,
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert CANARY not in captured.out
    assert CANARY not in captured.err

    # Validate JSON schema
    data = json.loads(captured.out)
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    validator.validate(data)

    # sources.agent = skipped
    source_map = {s["source"]: s for s in data["sources"]}
    assert source_map["agent"]["state"] == "skipped"

    # All fixture identities present
    fps = {ident["fingerprint"] for ident in data["identities"]}
    assert "SHA256:+92RsVKGXDDG2XlZkoQSG2sRjqnoPwysscnoHoCIdMk" in fps
    assert "SHA256:Kskz06nJKSQVXxudvVa4i2SSMi4R2H2KjSMgpNUyyFE" in fps

    # Contains CFG001 with file and line
    cfg001_findings = [f for f in data["findings"] if f["rule_id"] == "CFG001"]
    assert len(cfg001_findings) > 0
    f = cfg001_findings[0]
    assert f["severity"] == "error"
    assert f["evidence"][0]["source"].endswith("config")
    assert f["evidence"][0]["line"] == 15

    # open guard clean
    assert open_guard.violations == []


def test_cli_scan_matches_golden_identities_and_findings(
    home_basic: Path,
    open_guard: OpenGuard,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC-6: Given home_basic and docs/examples/report.json.

    When `ssh-id-doctor scan --format json --no-agent --ssh-dir ... --config ...`
    Then identities and findings match golden report up to HOME root normalization;
    findings include CFG001, CFG002, ID001.
    """
    ssh_dir = str(home_basic / ".ssh")
    config = str(home_basic / ".ssh" / "config")

    exit_code = main(
        [
            "scan",
            "--format",
            "json",
            "--no-agent",
            "--ssh-dir",
            ssh_dir,
            "--config",
            config,
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0

    cli_data = json.loads(captured.out)
    golden_data = json.loads(REPORT_GOLDEN_PATH.read_text(encoding="utf-8"))

    # Normalize HOME in cli_data
    home_str = str(home_basic)
    cli_json_norm = json.dumps(cli_data).replace(home_str, "/home/user")
    norm_cli_data = json.loads(cli_json_norm)

    # Compare identities fingerprints, algorithm, comments, etc.
    golden_fps = {i["fingerprint"] for i in golden_data["identities"]}
    cli_fps = {i["fingerprint"] for i in norm_cli_data["identities"]}
    assert cli_fps == golden_fps

    # Compare findings: rule_ids, IDs, severities, evidence details
    golden_findings_by_id = {f["id"]: f for f in golden_data["findings"]}
    cli_findings_by_id = {f["id"]: f for f in norm_cli_data["findings"]}

    assert set(cli_findings_by_id.keys()) == set(golden_findings_by_id.keys())

    rule_ids = {f["rule_id"] for f in norm_cli_data["findings"]}
    assert {"CFG001", "CFG002", "ID001"} <= rule_ids

    for fid, golden_f in golden_findings_by_id.items():
        cli_f = cli_findings_by_id[fid]
        assert cli_f["rule_id"] == golden_f["rule_id"]
        assert cli_f["severity"] == golden_f["severity"]
        assert cli_f["confidence"] == golden_f["confidence"]
        assert cli_f["evidence"] == golden_f["evidence"]
        assert cli_f["affected_hosts"] == golden_f["affected_hosts"]
        assert cli_f["affected_fingerprints"] == golden_f["affected_fingerprints"]

    assert open_guard.violations == []
