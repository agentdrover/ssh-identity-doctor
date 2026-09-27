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
    LocalReferenceKind,
    Resolution,
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


def _populate_home_basic(home: Path) -> Path:
    """Lay fixtures/home_basic out as HOME/.ssh under any root. Returns HOME."""
    ssh = home / ".ssh"
    ssh.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Copy files from fixtures/home_basic to synthetic fake_home
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

    # §13.3: the canary is a private-only reference. fake_home also plants
    # id_canary.pub; drop it so Host canary-test names no fingerprint. The
    # private trap id_canary stays (0600) and the open guard stays armed.
    (ssh / "id_canary.pub").unlink(missing_ok=True)
    (ssh / "id_canary").write_text(CANARY_PRIVATE_KEY)
    (ssh / "id_canary").chmod(0o600)

    return home


@pytest.fixture
def home_basic_setup(fake_home: Path) -> Path:
    """Populate synthetic HOME with fixtures/home_basic contents."""
    return _populate_home_basic(fake_home)


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


def test_unbound_config_references_are_in_snapshot_and_distinguishable(
    home_basic_setup: Path, open_guard: OpenGuard
) -> None:
    """Finding 343c16827cf015fe: an IdentityFile with no fingerprint is not dropped.

    It lands in snapshot.local_references with its resolution and provenance, so
    missing-key (missing) and canary-test (private_only) do not look alike.
    """
    snapshot = ScanOrchestrator().run(
        OrchestratorOptions(home=home_basic_setup, check_agent=False, check_github=False)
    )

    ssh = home_basic_setup / ".ssh"
    config = str(ssh / "config")
    by_path = {Path(ref.path).name: ref for ref in snapshot.local_references}
    missing = by_path["nonexistent_key"]
    canary = by_path["id_canary"]
    assert missing.kind is LocalReferenceKind.CONFIG_IDENTITY
    assert missing.resolution is Resolution.MISSING
    assert (missing.source_file, missing.source_line) == (config, 15)
    assert canary.kind is LocalReferenceKind.CONFIG_IDENTITY
    assert canary.resolution is Resolution.PRIVATE_ONLY
    assert (canary.source_file, canary.source_line) == (config, 12)
    bound = {ref.path for ident in snapshot.identities for ref in ident.local_references}
    assert not bound & {missing.path, canary.path}
    assert list(snapshot.local_references) == sorted(
        snapshot.local_references,
        key=lambda r: (r.source_file or "", r.source_line or 0, r.path),
    )
    assert open_guard.violations == []


def test_config_rules_fire_on_home_basic_end_to_end(
    home_basic_setup: Path, open_guard: OpenGuard
) -> None:
    """AC-4: ScanOrchestrator.run with default rule registry on home_basic produces:

    - snapshot.unresolved containing include_cycle and unsupported_match with file and line
      (match_not_evaluated parser code mapped to unsupported_match);
    - snapshot.findings containing CFG001 for missing key and CFG002 for cycle and Match.
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

    # 1. snapshot.unresolved contains include_cycle and unsupported_match with file and line
    unresolved_kinds = {u.kind for u in snapshot.unresolved}
    assert "include_cycle" in unresolved_kinds
    assert "unsupported_match" in unresolved_kinds
    assert "match_not_evaluated" not in unresolved_kinds

    match_items = [u for u in snapshot.unresolved if u.kind == "unsupported_match"]
    assert len(match_items) >= 1
    assert match_items[0].source_file.endswith("config")
    assert match_items[0].source_line == 20

    cycle_items = [u for u in snapshot.unresolved if u.kind == "include_cycle"]
    assert len(cycle_items) >= 1
    for item in cycle_items:
        assert item.source_file.endswith(".conf")
        assert item.source_line is not None

    # 2. snapshot.findings contains CFG001 on missing key and CFG002 on cycle and Match
    rule_ids = {f.rule_id for f in snapshot.findings}
    assert "CFG001" in rule_ids
    assert "CFG002" in rule_ids

    cfg001_findings = [f for f in snapshot.findings if f.rule_id == "CFG001"]
    assert any("nonexistent_key" in f.evidence[0].detail for f in cfg001_findings)
    assert any(list(f.affected_hosts) == ["missing-key"] for f in cfg001_findings)
    for f in cfg001_findings:
        assert f.severity is Severity.ERROR
        assert f.confidence is Confidence.CERTAIN

    cfg002_findings = [f for f in snapshot.findings if f.rule_id == "CFG002"]
    assert any("cycle" in f.title.lower() or "cycle" in f.summary.lower() for f in cfg002_findings)
    assert any("match" in f.title.lower() or "match" in f.summary.lower() for f in cfg002_findings)
    for f in cfg002_findings:
        assert f.severity is Severity.INFO
        assert f.confidence is Confidence.UNRESOLVED

    assert open_guard.violations == []


def _scan_home_basic(home: Path) -> ScanSnapshot:
    orchestrator = ScanOrchestrator(
        agent_adapter=FakeTimeoutAgent(),  # type: ignore[arg-type]
        github_adapter=FakeNotAuthenticatedGitHub(),
    )
    return orchestrator.run(
        OrchestratorOptions(
            home=home,
            ssh_dir=home / ".ssh",
            config_path=home / ".ssh" / "config",
            check_agent=True,
            check_github=True,
        )
    )


def test_finding_ids_do_not_depend_on_the_scanned_home_root(
    home_basic_setup: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Finding 8425fb9af74bb35b: the same home_basic layout under two different
    HOME roots yields the same finding ids (paths under HOME hash as '~/...'),
    while the evidence in each Finding keeps that scan's real paths."""
    other_home = _populate_home_basic(tmp_path_factory.mktemp("another-root") / "someone")
    assert str(other_home) != str(home_basic_setup)

    first = _scan_home_basic(home_basic_setup)
    second = _scan_home_basic(other_home)

    first_ids = {f.id for f in first.findings}
    second_ids = {f.id for f in second.findings}
    assert first_ids
    assert {f.rule_id for f in first.findings} >= {"CFG001", "CFG002", "ID001"}
    assert first_ids == second_ids

    # Evidence is not rewritten: each scan shows its own absolute paths.
    first_cfg001 = next(f for f in first.findings if f.rule_id == "CFG001")
    second_cfg001 = next(f for f in second.findings if f.rule_id == "CFG001")
    assert first_cfg001.evidence[0].source.startswith(str(home_basic_setup))
    assert second_cfg001.evidence[0].source.startswith(str(other_home))
