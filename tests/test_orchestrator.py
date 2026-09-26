"""Tests for ScanOrchestrator (AC-2, AC-3)."""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import CANARY_PRIVATE_KEY, OpenGuard
from ssh_id_doctor.adapters.github import RegistryResult, RegistryState
from ssh_id_doctor.domain import (
    Confidence,
    CoverageState,
    EvidenceReference,
    Finding,
    ScanSnapshot,
    Severity,
)
from ssh_id_doctor.inspectors.agent import AgentResult, AgentState
from ssh_id_doctor.orchestrator import OrchestratorOptions, ScanOrchestrator
from ssh_id_doctor.rules import finding_id

FIXTURES_HOME = Path(__file__).resolve().parent / "fixtures" / "home_basic"


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
    # Copy files from fixtures/home_basic to synthetic fake_home
    (ssh / "id_ed25519.pub").write_text((FIXTURES_HOME / "id_ed25519.pub").read_text())
    (ssh / "id_ed25519_copy.pub").write_text((FIXTURES_HOME / "id_ed25519_copy.pub").read_text())
    (ssh / "id_rsa.pub").write_text((FIXTURES_HOME / "id_rsa.pub").read_text())
    (ssh / "config").write_text((FIXTURES_HOME / "config").read_text())

    config_d = ssh / "config.d"
    config_d.mkdir(exist_ok=True)
    (config_d / "included.conf").write_text(
        (FIXTURES_HOME / "config.d" / "included.conf").read_text()
    )
    (config_d / "cycle.conf").write_text((FIXTURES_HOME / "config.d" / "cycle.conf").read_text())

    # §13.3: the canary is a private-only reference. fake_home also plants
    # id_canary.pub; drop it so Host canary-test names no fingerprint. The
    # private trap id_canary stays (0600) and the open guard stays armed.
    (ssh / "id_canary.pub").unlink()
    (ssh / "id_canary").write_text(CANARY_PRIVATE_KEY)
    (ssh / "id_canary").chmod(0o600)

    return fake_home


def test_optional_source_failures_keep_local_results(
    home_basic_setup: Path, open_guard: OpenGuard
) -> None:
    """AC-2: ScanOrchestrator on home_basic with agent returning timeout and gh returning

    not_authenticated produces a snapshot containing all local identities and HostBindings,
    sources contains agent=timeout and github=unavailable/not_authenticated, no exceptions,
    and the private-key trap guard is not sprung on the canary.
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

    # All local identities discovered (ed25519 and rsa)
    assert len(snapshot.identities) >= 2
    fps = {ident.fingerprint for ident in snapshot.identities}
    # ed25519 fingerprint
    assert "SHA256:+92RsVKGXDDG2XlZkoQSG2sRjqnoPwysscnoHoCIdMk" in fps
    # rsa fingerprint
    assert "SHA256:Kskz06nJKSQVXxudvVa4i2SSMi4R2H2KjSMgpNUyyFE" in fps

    # Check HostBindings exist
    assert len(snapshot.host_bindings) > 0
    patterns = {p for hb in snapshot.host_bindings for p in hb.patterns}
    assert "gh" in patterns
    assert "server" in patterns

    # Check sources
    source_map = {s.source: s for s in snapshot.sources}
    assert "filesystem" in source_map
    assert source_map["filesystem"].state is CoverageState.AVAILABLE

    assert "config" in source_map
    assert source_map["config"].state is CoverageState.AVAILABLE

    assert "agent" in source_map
    assert source_map["agent"].state is CoverageState.TIMEOUT

    assert "github" in source_map
    assert source_map["github"].state is CoverageState.UNAVAILABLE
    assert source_map["github"].detail == "gh: not authenticated"

    # Guard check: canary was not read
    assert open_guard.violations == [], "SEC-001: canary private key was not opened"


class DummyTestRule:
    """Stub rule for deterministic finding test."""

    rule_id = "TEST001"

    def evaluate(self, snapshot: ScanSnapshot) -> list[Finding]:
        findings: list[Finding] = []
        for ident in snapshot.identities:
            fid = finding_id(self.rule_id, fingerprints=[ident.fingerprint])
            findings.append(
                Finding(
                    id=fid,
                    rule_id=self.rule_id,
                    severity=Severity.INFO,
                    confidence=Confidence.CERTAIN,
                    title="Test finding",
                    summary="Deterministic finding for test",
                    evidence=(EvidenceReference(source="test", line=1, detail="detail"),),
                    affected_fingerprints=(ident.fingerprint,),
                    affected_hosts=(),
                    manual_remediation=(),
                )
            )
        return findings


def test_snapshot_and_finding_ids_are_deterministic(
    home_basic_setup: Path, open_guard: OpenGuard
) -> None:
    """AC-3: Two orchestrator runs on home_basic with a stub rule produce snapshots whose

    identities, host_bindings and finding.id match byte-for-byte (scan_id and timestamps differ);
    finding.id matches pattern '<RULE>-<12 hex>'.
    """
    rule = DummyTestRule()
    orchestrator = ScanOrchestrator()

    opts = OrchestratorOptions(
        home=home_basic_setup,
        ssh_dir=home_basic_setup / ".ssh",
        config_path=home_basic_setup / ".ssh" / "config",
        check_agent=False,
        check_github=False,
        rules=[rule],
    )

    snap1 = orchestrator.run(opts)
    snap2 = orchestrator.run(opts)

    # scan_id and timestamps may differ
    # But identities, host_bindings, findings must match exactly
    assert snap1.identities == snap2.identities
    assert snap1.host_bindings == snap2.host_bindings
    assert snap1.findings == snap2.findings

    # Check finding id format
    assert len(snap1.findings) > 0
    for finding in snap1.findings:
        assert finding.id.startswith(f"{rule.rule_id}-")
        hex_part = finding.id[len(rule.rule_id) + 1 :]
        assert len(hex_part) == 12
        int(hex_part, 16)  # must be valid hex

    assert open_guard.violations == []


def test_home_basic_has_two_identities_and_private_only_canary(
    home_basic_setup: Path, open_guard: OpenGuard
) -> None:
    """Finding aca0075f07b943fb: home_basic (§13.3) has exactly two identities.

    fake_home plants ~/.ssh/id_canary.pub; home_basic must not keep it, so the
    canary is a private-only reference: Host canary-test resolves to no fingerprint.
    The private-key trap stays planted and is never opened.
    """
    ssh = home_basic_setup / ".ssh"
    assert (ssh / "id_canary").is_file()
    assert not (ssh / "id_canary.pub").exists()

    snapshot = ScanOrchestrator().run(
        OrchestratorOptions(home=home_basic_setup, check_agent=False, check_github=False)
    )

    assert len(snapshot.identities) == 2
    canary = [hb for hb in snapshot.host_bindings if "canary-test" in hb.patterns]
    assert len(canary) == 1
    assert canary[0].resolved_fingerprints == ()
    assert open_guard.violations == []


def test_github_disabled_is_recorded_as_skipped(home_basic_setup: Path) -> None:
    """Finding b56d2bbc9f1d05b4: with check_github=False the github source is SKIPPED,

    like a disabled agent, so every source has a SourceCoverage.
    """
    snapshot = ScanOrchestrator().run(
        OrchestratorOptions(home=home_basic_setup, check_agent=False, check_github=False)
    )

    source_map = {s.source: s for s in snapshot.sources}
    assert source_map["agent"].state is CoverageState.SKIPPED
    assert "github" in source_map
    assert source_map["github"].state is CoverageState.SKIPPED
    assert source_map["github"].required is False
