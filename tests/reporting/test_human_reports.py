"""Tests for FR-010 human-readable terminal and Markdown reports (SID-16)."""

from __future__ import annotations

import dataclasses
import json
import re
from pathlib import Path

import jsonschema

from conftest import CANARY, CANARY_PRIVATE_KEY, OpenGuard
from ssh_id_doctor.adapters.github import RegistryResult, RegistryState
from ssh_id_doctor.domain import (
    Confidence,
    CoverageState,
    EvidenceReference,
    Finding,
    Platform,
    ScanSnapshot,
    Severity,
    SourceCoverage,
)
from ssh_id_doctor.inspectors.agent import AgentResult, AgentState
from ssh_id_doctor.orchestrator import OrchestratorOptions, ScanOrchestrator
from ssh_id_doctor.reporting.json_report import render_json
from ssh_id_doctor.reporting.markdown import render_markdown
from ssh_id_doctor.reporting.terminal import render_terminal

FIXTURES_HOME = Path(__file__).resolve().parents[1] / "fixtures" / "home_basic"


class FakeTimeoutAgent:
    """Agent adapter returning TIMEOUT state."""

    def list_identities(self) -> AgentResult:
        return AgentResult(
            state=AgentState.TIMEOUT,
            detail="ssh-add timed out",
        )


class FakeNotAuthenticatedGitHub:
    """GitHub registry adapter returning UNAVAILABLE (not authenticated)."""

    def list_keys(self) -> RegistryResult:
        return RegistryResult(
            state=RegistryState.NOT_AUTHENTICATED,
            detail="gh: not authenticated",
        )


def _setup_home_basic(fake_home: Path) -> Path:
    ssh = fake_home / ".ssh"
    (ssh / "id_ed25519.pub").write_text((FIXTURES_HOME / "id_ed25519.pub").read_text())
    (ssh / "id_ed25519_copy.pub").write_text((FIXTURES_HOME / "id_ed25519_copy.pub").read_text())
    (ssh / "id_rsa.pub").write_text((FIXTURES_HOME / "id_rsa.pub").read_text())
    (ssh / "config").write_text((FIXTURES_HOME / "config").read_text())

    config_d = ssh / "config.d"
    config_d.mkdir(exist_ok=True)
    inc_text = (FIXTURES_HOME / "config.d" / "included.conf").read_text()
    cyc_text = (FIXTURES_HOME / "config.d" / "cycle.conf").read_text()
    if "Include cycle.conf" in inc_text:
        inc_text = inc_text.replace("Include cycle.conf", "Include config.d/cycle.conf")
    if "Include included.conf" in cyc_text:
        cyc_text = cyc_text.replace("Include included.conf", "Include config.d/included.conf")
    (config_d / "included.conf").write_text(inc_text)
    (config_d / "cycle.conf").write_text(cyc_text)

    (ssh / "id_canary.pub").unlink()
    (ssh / "id_canary").write_text(CANARY_PRIVATE_KEY)
    (ssh / "id_canary").chmod(0o600)

    return fake_home


def _normalize_report(text: str, home_path: str) -> str:
    res = text.replace(home_path, "/home/user")
    res = re.sub(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "00000000-0000-0000-0000-000000000000",
        res,
    )
    res = re.sub(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})",
        "2026-09-24T16:00:00+00:00",
        res,
    )
    return res


def test_terminal_markdown_json_describe_same_snapshot(
    fake_home: Path, open_guard: OpenGuard
) -> None:
    """AC-1: Given snapshot home_basic.

    When terminal, Markdown and JSON are rendered,
    Then sets of all fingerprints and finding.ids extracted by regex from terminal and
    Markdown equal sets from JSON; finding.id order is identical across all three.
    """
    home = _setup_home_basic(fake_home)
    orchestrator = ScanOrchestrator(
        agent_adapter=FakeTimeoutAgent(),  # type: ignore[arg-type]
        github_adapter=FakeNotAuthenticatedGitHub(),
    )
    opts = OrchestratorOptions(
        home=home,
        ssh_dir=home / ".ssh",
        config_path=home / ".ssh" / "config",
        check_agent=True,
        check_github=True,
    )
    snapshot = orchestrator.run(opts)

    term_out = render_terminal(snapshot)
    md_out = render_markdown(snapshot)
    json_out = render_json(snapshot)

    fp_regex = re.compile(r"SHA256:[A-Za-z0-9+/=]+")
    id_regex = re.compile(r"\b[A-Z]{2,}\d+-[0-9a-f]{12}\b")

    term_fps = set(fp_regex.findall(term_out))
    md_fps = set(fp_regex.findall(md_out))
    json_fps = set(fp_regex.findall(json_out))

    assert term_fps == json_fps
    assert md_fps == json_fps
    assert len(term_fps) == 2

    term_ids = id_regex.findall(term_out)
    md_ids = id_regex.findall(md_out)
    json_ids = id_regex.findall(json_out)

    assert term_ids == json_ids
    assert md_ids == json_ids
    assert len(term_ids) == len(snapshot.findings)
    assert len(term_ids) > 0

    assert open_guard.violations == []


def test_markdown_sections_coverage_and_evidence() -> None:
    """AC-2: Given snapshot with finding CFG001 (config:6) and agent in timeout.

    When Markdown is rendered,
    Then headers '## Source coverage', '## Findings', '## Limitations' are present,
    agent line contains 'timeout', and finding CFG001 contains 'config:6' and
    manual remediation block.
    """
    finding_cfg001 = Finding(
        id="CFG001-0123456789ab",
        rule_id="CFG001",
        severity=Severity.ERROR,
        confidence=Confidence.CERTAIN,
        title="Unresolved IdentityFile: ~/.ssh/gone",
        summary="IdentityFile '~/.ssh/gone' referenced at config:6 cannot be resolved (missing).",
        evidence=(EvidenceReference(source="config", line=6, detail="~/.ssh/gone"),),
        affected_hosts=("prod",),
        manual_remediation=("ls -l ~/.ssh/gone", "ssh -G prod"),
    )
    agent_coverage = SourceCoverage(
        source="agent",
        state=CoverageState.TIMEOUT,
        required=False,
        detail="ssh-add timed out",
    )
    snapshot = ScanSnapshot(
        scan_id="00000000-0000-0000-0000-000000000000",
        started_at="2026-09-24T16:00:00+00:00",
        completed_at="2026-09-24T16:00:01+00:00",
        platform=Platform.LINUX,
        sources=(agent_coverage,),
        findings=(finding_cfg001,),
    )

    md = render_markdown(snapshot)

    assert "## Source coverage" in md
    assert "## Findings" in md
    assert "## Limitations" in md

    agent_lines = [line for line in md.splitlines() if "agent" in line.lower()]
    assert any("timeout" in line for line in agent_lines)

    assert "CFG001" in md
    assert "config:6" in md
    assert "manual remediation" in md.lower()
    assert "ls -l ~/.ssh/gone" in md


def test_terminal_plain_without_key_bodies_or_canary(
    fake_home: Path, open_guard: OpenGuard
) -> None:
    """AC-3: Given snapshot home_basic, stdout not TTY; fixture has canary and base64 bodies.

    When terminal is rendered,
    Then no ANSI escape sequences, no CANARY-PRIVATE-7f3a, no base64 key bodies from fixture,
    and first line is summary with count of identities.
    """
    home = _setup_home_basic(fake_home)
    orchestrator = ScanOrchestrator(
        agent_adapter=FakeTimeoutAgent(),  # type: ignore[arg-type]
        github_adapter=FakeNotAuthenticatedGitHub(),
    )
    opts = OrchestratorOptions(
        home=home,
        ssh_dir=home / ".ssh",
        config_path=home / ".ssh" / "config",
        check_agent=False,
        check_github=False,
    )
    snapshot = orchestrator.run(opts)

    term = render_terminal(snapshot)

    assert "\x1b[" not in term
    assert CANARY not in term

    ed25519_pub_body = "AAAAC3NzaC1lZDI1NTE5AAAAICy6m9y8JQXK/rnkedDzK3YZbu5pH10XpE6+eVYTfnB1"
    rsa_pub_body_prefix = "AAAAB3NzaC1yc2EAAAADAQABAAABgQDB04ht"
    assert ed25519_pub_body not in term
    assert rsa_pub_body_prefix not in term

    first_line = term.splitlines()[0]
    assert "identit" in first_line.lower()
    assert "2" in first_line

    assert open_guard.violations == []


def test_examples_match_a_fresh_real_scan_of_home_basic(
    fake_home: Path, open_guard: OpenGuard
) -> None:
    """AC-4: Given home_basic, real ScanOrchestrator with default rule registry and adapters.

    When rendered to Markdown and JSON,
    Then fresh render matches example files up to scan_id, timestamps and HOME root;
    Markdown contains CFG001, CFG002 and ID001 of real scan, and unresolved config items
    (Match, Include cycle) are visibly marked as unresolved (§14 п.6).
    """
    home = _setup_home_basic(fake_home)
    orchestrator = ScanOrchestrator(
        agent_adapter=FakeTimeoutAgent(),  # type: ignore[arg-type]
        github_adapter=FakeNotAuthenticatedGitHub(),
    )
    opts = OrchestratorOptions(
        home=home,
        ssh_dir=home / ".ssh",
        config_path=home / ".ssh" / "config",
        check_agent=True,
        check_github=True,
    )
    # The examples document a Linux scan; platform is a fact of the host, not of
    # home_basic, so it is pinned on the input instead of masked in the output.
    fresh_snapshot = dataclasses.replace(orchestrator.run(opts), platform=Platform.LINUX)

    fresh_md = render_markdown(fresh_snapshot)
    fresh_json = render_json(fresh_snapshot)

    repo_root = Path(__file__).resolve().parents[2]
    example_md_file = repo_root / "docs" / "examples" / "report.md"
    example_json_file = repo_root / "docs" / "examples" / "report.json"

    assert example_md_file.is_file()
    assert example_json_file.is_file()

    example_md = example_md_file.read_text(encoding="utf-8")
    example_json = example_json_file.read_text(encoding="utf-8")

    home_str = str(home)

    assert _normalize_report(fresh_md, home_str) == _normalize_report(example_md, "/home/user")
    assert _normalize_report(fresh_json, home_str) == _normalize_report(example_json, "/home/user")

    assert "CFG001" in fresh_md
    assert "CFG002" in fresh_md
    assert "ID001" in fresh_md

    assert "unsupported_match" in fresh_md
    assert "include_cycle" in fresh_md
    assert "unresolved" in fresh_md.lower()

    schema_path = repo_root / "src" / "ssh_id_doctor" / "reporting" / "schema" / "scan-1.0.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    validator.validate(json.loads(example_json))

    assert open_guard.violations == []
