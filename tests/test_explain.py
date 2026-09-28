"""Tests for explain command (SID-19).

Acceptance criteria AC-1 to AC-3.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import CANARY, OpenGuard
from ssh_id_doctor.cli import main
from ssh_id_doctor.exit_codes import ExitCode
from ssh_id_doctor.explain import RULE_DESCRIPTIONS

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "home_basic"
CANARY_PRIVATE_KEY = (
    f"-----BEGIN OPENSSH PRIVATE KEY-----\n{CANARY}\n-----END OPENSSH PRIVATE KEY-----\n"
)


def _setup_home_basic(fake_home: Path) -> Path:
    ssh = fake_home / ".ssh"
    ssh.mkdir(mode=0o700, parents=True, exist_ok=True)
    for p in FIXTURES_DIR.glob("*.pub"):
        (ssh / p.name).write_text(p.read_text())
    (ssh / "config").write_text((FIXTURES_DIR / "config").read_text())
    config_d = ssh / "config.d"
    config_d.mkdir(exist_ok=True)
    for p in (FIXTURES_DIR / "config.d").glob("*.conf"):
        text = p.read_text()
        if "Include cycle.conf" in text:
            text = text.replace("Include cycle.conf", "Include config.d/cycle.conf")
        if "Include included.conf" in text:
            text = text.replace("Include included.conf", "Include config.d/included.conf")
        (config_d / p.name).write_text(text)

    (ssh / "id_canary.pub").unlink(missing_ok=True)
    (ssh / "id_canary").write_text(CANARY_PRIVATE_KEY)
    (ssh / "id_canary").chmod(0o600)
    return fake_home


@pytest.fixture
def home_basic(fake_home: Path) -> Path:
    """Fixture providing populated home_basic."""
    return _setup_home_basic(fake_home)


def test_explain_known_finding_shows_evidence_and_remediation(
    home_basic: Path,
    open_guard: OpenGuard,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC-1: Given home_basic; scan --format json yields finding CFG001.

    When `ssh-id-doctor explain X --no-agent` with same --ssh-dir/--config.
    Then exit 0; output contains 'CFG001', 'error', 'certain', certain confidence explanation,
    'config:<N>' and at least one step manual remediation.
    """
    ssh_dir = str(home_basic / ".ssh")
    config = str(home_basic / ".ssh" / "config")

    # Step 1: Run scan --format json to find CFG001 id and line N
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
    assert exit_code == ExitCode.OK

    data = json.loads(captured.out)
    cfg001_findings = [f for f in data["findings"] if f["rule_id"] == "CFG001"]
    assert len(cfg001_findings) > 0, "Expected at least one CFG001 finding in home_basic"
    target = cfg001_findings[0]
    finding_id = target["id"]
    evidence = target["evidence"][0]
    expected_evidence_loc = f"config:{evidence['line']}"

    # Step 2: Run explain <finding-id>
    exit_code_explain = main(
        [
            "explain",
            finding_id,
            "--no-agent",
            "--ssh-dir",
            ssh_dir,
            "--config",
            config,
        ]
    )
    captured_explain = capsys.readouterr()
    assert exit_code_explain == ExitCode.OK

    out = captured_explain.out
    assert "CFG001" in out
    assert "error" in out
    assert "certain" in out
    assert "Fact established directly from local configuration or key data." in out or (
        "local" in out.lower() and "certain" in out.lower()
    )
    assert (
        expected_evidence_loc in out or f"{Path(evidence['source']).name}:{evidence['line']}" in out
    )
    assert any(step in out for step in target["manual_remediation"])
    assert CANARY not in out
    assert CANARY not in captured_explain.err


def test_explain_unknown_id_exits_1_and_suggests_ids(
    home_basic: Path,
    open_guard: OpenGuard,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC-2: Given home_basic.

    When `ssh-id-doctor explain CFG001-000000000000`.
    Then exit 1; stderr reports finding not found, advises running scan with same options,
    and lists actual ids of CFG001 findings.
    """
    ssh_dir = str(home_basic / ".ssh")
    config = str(home_basic / ".ssh" / "config")

    exit_code = main(
        [
            "explain",
            "CFG001-000000000000",
            "--no-agent",
            "--ssh-dir",
            ssh_dir,
            "--config",
            config,
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == ExitCode.INVALID_ARGS

    err = captured.err
    assert "CFG001-000000000000" in err
    assert "not found" in err.lower()
    assert "scan" in err.lower()
    assert "CFG001-" in err


def test_every_rule_has_description_without_unsafe_wording() -> None:
    """AC-3: Given set of 9 rule_id FR-008.

    When test iterates over rule description registry in explain.py.
    Then each of CFG001, CFG002, ID001, ID002, LAB001, AGT001, AGT002, ALG001, REG001
    has non-empty description; none contains 'unused' and 'safe to delete'.
    Also ALG001 does not misleadingly cite ECDSA-256 as an example since it is not flagged.
    """
    required_rules = [
        "CFG001",
        "CFG002",
        "ID001",
        "ID002",
        "LAB001",
        "AGT001",
        "AGT002",
        "ALG001",
        "REG001",
    ]
    for rule_id in required_rules:
        assert rule_id in RULE_DESCRIPTIONS, f"Missing description for rule {rule_id}"
        desc = RULE_DESCRIPTIONS[rule_id]
        assert isinstance(desc, str) and len(desc.strip()) > 0, (
            f"Empty description for rule {rule_id}"
        )
        assert "unused" not in desc.lower(), f"Rule {rule_id} description contains 'unused'"
        assert "safe to delete" not in desc.lower(), (
            f"Rule {rule_id} description contains 'safe to delete'"
        )

    # Review finding 5266a94545452130: ALG001 must not cite ECDSA-256
    assert "ecdsa" not in RULE_DESCRIPTIONS["ALG001"].lower(), (
        "ALG001 cites ECDSA even though the rule does not flag it"
    )


def test_explain_json_and_markdown_formats(
    home_basic: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Test explain command with --format json and --format md."""
    ssh_dir = str(home_basic / ".ssh")
    config = str(home_basic / ".ssh" / "config")

    # Step 1: Scan to get CFG001 finding id
    main(
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
    data = json.loads(captured.out)
    cfg001_findings = [f for f in data["findings"] if f["rule_id"] == "CFG001"]
    finding_id = cfg001_findings[0]["id"]

    # Step 2: JSON format
    rc_json = main(
        [
            "explain",
            finding_id,
            "--format",
            "json",
            "--no-agent",
            "--ssh-dir",
            ssh_dir,
            "--config",
            config,
        ]
    )
    captured_json = capsys.readouterr()
    assert rc_json == ExitCode.OK
    parsed = json.loads(captured_json.out)
    assert parsed["schema_version"] == "1.0"
    assert parsed["kind"] == "finding_explanation"
    assert parsed["finding"]["id"] == finding_id
    assert parsed["finding"]["rule_id"] == "CFG001"
    assert "rule_description" in parsed
    assert "confidence_explanation" in parsed

    # Step 3: Markdown format
    rc_md = main(
        [
            "explain",
            finding_id,
            "--format",
            "md",
            "--no-agent",
            "--ssh-dir",
            ssh_dir,
            "--config",
            config,
        ]
    )
    captured_md = capsys.readouterr()
    assert rc_md == ExitCode.OK
    md_out = captured_md.out
    assert "# Finding Explanation:" in md_out
    assert "## Overview" in md_out
    assert "## Rule description" in md_out
    assert "## Evidence" in md_out
    assert "## Manual remediation" in md_out


def test_explain_redaction_and_atomic_output(
    home_basic: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Test explain command with --redact and --output."""
    ssh_dir = str(home_basic / ".ssh")
    config = str(home_basic / ".ssh" / "config")

    main(
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
    data = json.loads(captured.out)
    cfg001_findings = [f for f in data["findings"] if f["rule_id"] == "CFG001"]
    finding_id = cfg001_findings[0]["id"]

    out_file = tmp_path / "explain_output.txt"
    rc = main(
        [
            "explain",
            finding_id,
            "--redact",
            "all",
            "--output",
            str(out_file),
            "--no-agent",
            "--ssh-dir",
            ssh_dir,
            "--config",
            config,
        ]
    )
    assert rc == ExitCode.OK
    content = out_file.read_text(encoding="utf-8")
    assert "Finding: CFG001-" in content
    # Host and paths should be redacted
    assert "host-1" in content or "missing-key" not in content
    assert "/home_basic" not in content
