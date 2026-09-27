"""Tests for FR-010 JSON report rendering, schema validation and sorting (SID-15)."""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from conftest import CANARY, CANARY_PRIVATE_KEY, OpenGuard
from ssh_id_doctor.adapters.github import RegistryResult, RegistryState
from ssh_id_doctor.domain import (
    Confidence,
    EvidenceReference,
    Finding,
    Platform,
    ScanSnapshot,
    Severity,
)
from ssh_id_doctor.inspectors.agent import AgentResult, AgentState
from ssh_id_doctor.orchestrator import OrchestratorOptions, ScanOrchestrator
from ssh_id_doctor.reporting.json_report import render_json
from ssh_id_doctor.reporting.ordering import sort_findings

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


@pytest.fixture
def home_basic_setup(fake_home: Path) -> Path:
    """Populate synthetic HOME with fixtures/home_basic contents."""
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


def _load_schema() -> dict[str, Any]:
    schema_path = resources.files("ssh_id_doctor.reporting.schema").joinpath("scan-1.0.json")
    with schema_path.open("r", encoding="utf-8") as f:
        return json.load(f)  # type: ignore[no-any-return]


def test_json_validates_against_schema_1_0(home_basic_setup: Path, open_guard: OpenGuard) -> None:
    """AC-1: Given snapshot home_basic from orchestrator (recorded adapters).

    When render_json is called and validated with jsonschema against scan-1.0.json,
    Then validation passes, schema_version == '1.0', and each identity.fingerprint starts
    with 'SHA256:'.
    """
    orchestrator = ScanOrchestrator(
        agent_adapter=FakeTimeoutAgent(),  # type: ignore[arg-type]
        github_adapter=FakeNotAuthenticatedGitHub(),
    )
    opts = OrchestratorOptions(
        home=home_basic_setup,
        ssh_dir=home_basic_setup / ".ssh",
        config_path=home_basic_setup / ".ssh" / "config",
        check_agent=True,
        check_github=True,
    )
    snapshot = orchestrator.run(opts)

    raw_json = render_json(snapshot)
    parsed = json.loads(raw_json)

    schema = _load_schema()
    validator = jsonschema.Draft202012Validator(schema)
    validator.validate(parsed)

    assert parsed["schema_version"] == "1.0"
    assert len(parsed["identities"]) > 0
    for ident in parsed["identities"]:
        assert ident["fingerprint"].startswith("SHA256:")

    assert open_guard.violations == []


def test_findings_sorted_by_severity_confidence_rule_location() -> None:
    """AC-2: Given snapshot with findings in shuffled order:

    LAB001/info, CFG001/error (config:9), CFG001/error (config:3),
    AGT001/warning, CFG002/info/unresolved.
    When render_json is called,
    Then findings order: CFG001(config:3), CFG001(config:9), AGT001, LAB001, CFG002.
    """
    f_lab001 = Finding(
        id="f-lab001",
        rule_id="LAB001",
        severity=Severity.INFO,
        confidence=Confidence.CERTAIN,
        title="Lab finding",
        summary="Lab summary",
        evidence=(EvidenceReference(source="config", line=1, detail="lab"),),
    )
    f_cfg001_9 = Finding(
        id="f-cfg001-9",
        rule_id="CFG001",
        severity=Severity.ERROR,
        confidence=Confidence.CERTAIN,
        title="Cfg 9 finding",
        summary="Cfg 9 summary",
        evidence=(EvidenceReference(source="config", line=9, detail="cfg9"),),
    )
    f_cfg001_3 = Finding(
        id="f-cfg001-3",
        rule_id="CFG001",
        severity=Severity.ERROR,
        confidence=Confidence.CERTAIN,
        title="Cfg 3 finding",
        summary="Cfg 3 summary",
        evidence=(EvidenceReference(source="config", line=3, detail="cfg3"),),
    )
    f_agt001 = Finding(
        id="f-agt001",
        rule_id="AGT001",
        severity=Severity.WARNING,
        confidence=Confidence.CERTAIN,
        title="Agt finding",
        summary="Agt summary",
        evidence=(EvidenceReference(source="config", line=5, detail="agt"),),
    )
    f_cfg002 = Finding(
        id="f-cfg002",
        rule_id="CFG002",
        severity=Severity.INFO,
        confidence=Confidence.UNRESOLVED,
        title="Cfg002 finding",
        summary="Cfg002 summary",
        evidence=(EvidenceReference(source="config", line=2, detail="cfg002"),),
    )

    shuffled = (f_lab001, f_cfg001_9, f_cfg001_3, f_agt001, f_cfg002)
    snapshot = ScanSnapshot(
        scan_id="00000000-0000-0000-0000-000000000000",
        started_at="2026-01-01T00:00:00+00:00",
        completed_at="2026-01-01T00:00:00+00:00",
        platform=Platform.LINUX,
        findings=shuffled,
    )

    raw_json = render_json(snapshot)
    parsed = json.loads(raw_json)

    finding_ids = [f["id"] for f in parsed["findings"]]
    expected_order = [
        "f-cfg001-3",
        "f-cfg001-9",
        "f-agt001",
        "f-lab001",
        "f-cfg002",
    ]
    assert finding_ids == expected_order


def test_json_is_deterministic_and_has_no_canary(
    home_basic_setup: Path, open_guard: OpenGuard
) -> None:
    """AC-3: Two home_basic snapshots differing only in scan_id and timestamps,

    with CANARY-PRIVATE-7f3a in fixture.
    When rendered to JSON:
    After removing scan_id/started_at/completed_at strings are equal, and canary is absent.
    """
    orchestrator = ScanOrchestrator(
        agent_adapter=FakeTimeoutAgent(),  # type: ignore[arg-type]
        github_adapter=FakeNotAuthenticatedGitHub(),
    )
    opts = OrchestratorOptions(
        home=home_basic_setup,
        ssh_dir=home_basic_setup / ".ssh",
        config_path=home_basic_setup / ".ssh" / "config",
        check_agent=False,
        check_github=False,
    )

    snap1 = orchestrator.run(opts)
    snap2 = orchestrator.run(opts)

    json1 = render_json(snap1)
    json2 = render_json(snap2)

    assert CANARY not in json1
    assert CANARY not in json2

    parsed1 = json.loads(json1)
    parsed2 = json.loads(json2)

    for field in ("scan_id", "started_at", "completed_at"):
        parsed1.pop(field)
        parsed2.pop(field)

    assert parsed1 == parsed2

    canon1 = json.dumps(parsed1, sort_keys=True, indent=2)
    canon2 = json.dumps(parsed2, sort_keys=True, indent=2)
    assert canon1 == canon2

    assert open_guard.violations == []


def test_real_scan_of_home_basic_renders_valid_json_with_all_rule_modules(
    home_basic_setup: Path, open_guard: OpenGuard
) -> None:
    """AC-4: Given home_basic, default rule registry (all four rule modules SID-11..14),

    recorded adapters, and scan-1.0.json forbidding unknown properties.
    When end-to-end run: orchestrator -> render_json -> schema validation,
    Then validation passes; JSON contains local_references and unresolved;
    findings contain at least CFG001, CFG002, and ID001; and order matches sort_findings.
    """
    orchestrator = ScanOrchestrator(
        agent_adapter=FakeTimeoutAgent(),  # type: ignore[arg-type]
        github_adapter=FakeNotAuthenticatedGitHub(),
    )
    opts = OrchestratorOptions(
        home=home_basic_setup,
        ssh_dir=home_basic_setup / ".ssh",
        config_path=home_basic_setup / ".ssh" / "config",
        check_agent=True,
        check_github=True,
    )
    snapshot = orchestrator.run(opts)

    raw_json = render_json(snapshot)
    parsed = json.loads(raw_json)

    schema = _load_schema()
    validator = jsonschema.Draft202012Validator(schema)
    validator.validate(parsed)

    assert "local_references" in parsed
    assert len(parsed["local_references"]) > 0
    assert "unresolved" in parsed
    assert len(parsed["unresolved"]) > 0

    finding_rule_ids = {f["rule_id"] for f in parsed["findings"]}
    assert "CFG001" in finding_rule_ids
    assert "CFG002" in finding_rule_ids
    assert "ID001" in finding_rule_ids

    expected_sorted = sort_findings(snapshot.findings)
    actual_finding_ids = [f["id"] for f in parsed["findings"]]
    expected_finding_ids = [f.id for f in expected_sorted]
    assert actual_finding_ids == expected_finding_ids

    assert open_guard.violations == []
