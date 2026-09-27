"""Tests for agent rules AGT001 and AGT002 (sdd-spec FR-008)."""

from __future__ import annotations

import dataclasses
import re

from ssh_id_doctor.domain import (
    Confidence,
    CoverageState,
    HostBinding,
    Identity,
    LocalReference,
    LocalReferenceKind,
    Platform,
    RegistryBinding,
    Resolution,
    ScanSnapshot,
    Severity,
    SourceCoverage,
    UnresolvedItem,
)
from ssh_id_doctor.rules import get_default_rules
from ssh_id_doctor.rules.agent_rules import (
    AGENT_EXPOSURE_THRESHOLD,
    AGT001,
    AGT002,
    RULES,
    AGT001Rule,
    AGT002Rule,
)


def _make_snapshot(
    *,
    sources: tuple[SourceCoverage, ...] = (),
    local_references: tuple[LocalReference, ...] = (),
    identities: tuple[Identity, ...] = (),
    host_bindings: tuple[HostBinding, ...] = (),
    unresolved: tuple[UnresolvedItem, ...] = (),
) -> ScanSnapshot:
    return ScanSnapshot(
        scan_id="00000000-0000-0000-0000-000000000000",
        started_at="2026-01-01T00:00:00+00:00",
        completed_at="2026-01-01T00:00:00+00:00",
        platform=Platform.LINUX,
        sources=sources,
        local_references=local_references,
        identities=identities,
        host_bindings=host_bindings,
        unresolved=unresolved,
    )


_DESTRUCTIVE_REMEDIATION = re.compile(
    r"\brm\b|sed\s+-i|ssh-add\s+-[dD]\b|\bdelete\b|\bdeleted\b|safe to remove",
    re.IGNORECASE,
)


def _all_strings(obj: object) -> list[str]:
    """Every string reachable from a finding: all fields, nested evidence, tuples."""
    if isinstance(obj, str):
        return [obj]
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return [s for f in dataclasses.fields(obj) for s in _all_strings(getattr(obj, f.name))]
    if isinstance(obj, (tuple, list)):
        return [s for item in obj for s in _all_strings(item)]
    if obj is None or isinstance(obj, (int, bool)):
        return []
    return [str(obj)]


def _assert_never_says_insecure(finding: object) -> None:
    for text in _all_strings(finding):
        assert "insecure" not in text.lower(), f"'insecure' found in finding text: {text!r}"


def _assert_never_says_unused(finding: object) -> None:
    for text in _all_strings(finding):
        assert "unused" not in text.lower(), f"'unused' found in finding text: {text!r}"


def _assert_remediation_not_destructive(finding: object) -> None:
    for rem in getattr(finding, "manual_remediation", ()):
        assert not _DESTRUCTIVE_REMEDIATION.search(rem), f"destructive remediation: {rem!r}"


def test_agt001_agent_identity_without_known_relationship() -> None:
    """AC-1: Snapshot with agent available_with_identities, identity A (has local .pub) and X.

    Identity X has no local file, HostBinding, or RegistryBinding.
    When AGT001 runs: exactly one finding with affected_fingerprints=[X] (warning, heuristic).
    """
    fp_a = "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA"
    fp_x = "SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxX"

    ref_a = LocalReference(
        kind=LocalReferenceKind.PUBLIC_KEY,
        path="~/.ssh/id_a.pub",
        source_file=None,
        source_line=None,
        resolution=Resolution.RESOLVED,
    )
    ident_a = Identity(
        fingerprint=fp_a,
        algorithm="ed25519",
        bits_or_curve="256",
        comments=("key-a",),
        local_references=(ref_a,),
        agent_presence=True,
    )
    ident_x = Identity(
        fingerprint=fp_x,
        algorithm="ed25519",
        bits_or_curve="256",
        comments=("temp-key-x",),
        local_references=(),
        agent_presence=True,
        registry_bindings=(),
    )

    agent_cov = SourceCoverage(
        source="agent",
        state=CoverageState.AVAILABLE,
        required=False,
        detail="2 identities loaded",
    )
    snapshot = _make_snapshot(
        sources=(agent_cov,),
        identities=(ident_a, ident_x),
    )

    findings = AGT001.evaluate(snapshot)

    assert len(findings) == 1
    finding = findings[0]

    assert finding.rule_id == "AGT001"
    assert finding.severity is Severity.WARNING
    assert finding.confidence is Confidence.HEURISTIC
    assert list(finding.affected_fingerprints) == [fp_x]
    assert finding.affected_hosts == ()
    assert len(finding.evidence) == 1
    assert finding.evidence[0].source == "agent"

    summary_lower = finding.summary.lower()
    assert "may offer" in summary_lower
    assert "heuristic" in summary_lower

    _assert_never_says_insecure(finding)
    _assert_never_says_unused(finding)
    _assert_remediation_not_destructive(finding)


def test_agt002_threshold_and_identities_only() -> None:
    """AC-2: Agent with 5 identities; HostBinding 'Host *' (config:20, identities_only=None)

    and 'Host gh' (config:3, identities_only=True).
    When AGT002 runs: one finding for 'Host *' with evidence config:20; none for 'gh';
    with 4 identities in agent, no findings; summary does not contain 'insecure'.
    """
    identities_5 = tuple(
        Identity(
            fingerprint=f"SHA256:{i:043d}",
            algorithm="ed25519",
            bits_or_curve="256",
            agent_presence=True,
        )
        for i in range(5)
    )

    hb_star = HostBinding(
        patterns=("*",),
        hostname=None,
        user=None,
        identity_references=(),
        resolved_fingerprints=(),
        identities_only=None,
        source_file="config",
        source_line=20,
        confidence=Confidence.CERTAIN,
    )
    hb_gh = HostBinding(
        patterns=("gh",),
        hostname="github.com",
        user="git",
        identity_references=(),
        resolved_fingerprints=(),
        identities_only=True,
        source_file="config",
        source_line=3,
        confidence=Confidence.CERTAIN,
    )

    agent_cov = SourceCoverage(
        source="agent",
        state=CoverageState.AVAILABLE,
        required=False,
        detail="5 identities loaded",
    )

    snapshot_5 = _make_snapshot(
        sources=(agent_cov,),
        identities=identities_5,
        host_bindings=(hb_star, hb_gh),
    )

    findings_5 = AGT002.evaluate(snapshot_5)

    assert len(findings_5) == 1
    finding = findings_5[0]

    assert finding.rule_id == "AGT002"
    assert finding.severity is Severity.WARNING
    assert finding.confidence is Confidence.HEURISTIC
    assert list(finding.affected_hosts) == ["*"]
    assert len(finding.evidence) == 1
    assert finding.evidence[0].source == "config"
    assert finding.evidence[0].line == 20

    summary_lower = finding.summary.lower()
    assert "insecure" not in summary_lower
    assert "may offer" in summary_lower
    assert "heuristic" in summary_lower

    _assert_never_says_insecure(finding)
    _assert_never_says_unused(finding)
    _assert_remediation_not_destructive(finding)

    # With 4 identities in agent, no findings are produced
    snapshot_4 = _make_snapshot(
        sources=(agent_cov,),
        identities=identities_5[:4],
        host_bindings=(hb_star, hb_gh),
    )
    findings_4 = AGT002.evaluate(snapshot_4)
    assert findings_4 == []


def test_agent_rules_silent_without_agent_coverage() -> None:
    """AC-3: Same snapshot, but agent SourceCoverage is unavailable (or skipped with --no-agent).

    When AGT001 and AGT002 run: no findings.
    """
    fp_x = "SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxX"
    ident_x = Identity(
        fingerprint=fp_x,
        algorithm="ed25519",
        bits_or_curve="256",
        agent_presence=True,
    )
    identities_5 = tuple(
        Identity(
            fingerprint=f"SHA256:{i:043d}",
            algorithm="ed25519",
            bits_or_curve="256",
            agent_presence=True,
        )
        for i in range(5)
    )
    hb_star = HostBinding(
        patterns=("*",),
        hostname=None,
        user=None,
        identity_references=(),
        resolved_fingerprints=(),
        identities_only=None,
        source_file="config",
        source_line=20,
        confidence=Confidence.CERTAIN,
    )

    # 1. SourceCoverage state = unavailable
    cov_unavailable = SourceCoverage(
        source="agent",
        state=CoverageState.UNAVAILABLE,
        required=False,
        detail="agent socket not found",
    )
    snap_unavailable = _make_snapshot(
        sources=(cov_unavailable,),
        identities=(*identities_5, ident_x),
        host_bindings=(hb_star,),
    )
    assert AGT001.evaluate(snap_unavailable) == []
    assert AGT002.evaluate(snap_unavailable) == []

    # 2. SourceCoverage state = skipped (--no-agent)
    cov_skipped = SourceCoverage(
        source="agent",
        state=CoverageState.SKIPPED,
        required=False,
        detail="agent check skipped",
    )
    snap_skipped = _make_snapshot(
        sources=(cov_skipped,),
        identities=(*identities_5, ident_x),
        host_bindings=(hb_star,),
    )
    assert AGT001.evaluate(snap_skipped) == []
    assert AGT002.evaluate(snap_skipped) == []

    # 3. SourceCoverage state = empty
    cov_empty = SourceCoverage(
        source="agent",
        state=CoverageState.EMPTY,
        required=False,
        detail="agent has no identities",
    )
    snap_empty = _make_snapshot(
        sources=(cov_empty,),
        identities=(*identities_5, ident_x),
        host_bindings=(hb_star,),
    )
    assert AGT001.evaluate(snap_empty) == []
    assert AGT002.evaluate(snap_empty) == []

    # 4. No sources at all
    snap_no_sources = _make_snapshot(
        sources=(),
        identities=(*identities_5, ident_x),
        host_bindings=(hb_star,),
    )
    assert AGT001.evaluate(snap_no_sources) == []
    assert AGT002.evaluate(snap_no_sources) == []


def test_agt001_ignores_bound_identities() -> None:
    """AGT001 ignores agent identities bound via HostBinding or RegistryBinding."""
    fp_bound_host = "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbB"
    fp_bound_reg = "SHA256:ccccccccccccccccccccccccccccccccccccccccccC"
    fp_no_agent = "SHA256:ddddddddddddddddddddddddddddddddddddddddddD"

    ident_host = Identity(
        fingerprint=fp_bound_host,
        algorithm="ed25519",
        bits_or_curve="256",
        agent_presence=True,
    )
    ident_reg = Identity(
        fingerprint=fp_bound_reg,
        algorithm="ed25519",
        bits_or_curve="256",
        agent_presence=True,
        registry_bindings=(
            RegistryBinding(registry="github", fingerprint=fp_bound_reg, title="work"),
        ),
    )
    ident_no_agent = Identity(
        fingerprint=fp_no_agent,
        algorithm="ed25519",
        bits_or_curve="256",
        agent_presence=False,
    )

    hb = HostBinding(
        patterns=("server",),
        hostname="server.example.com",
        user=None,
        identity_references=(),
        resolved_fingerprints=(fp_bound_host,),
        identities_only=True,
        source_file="config",
        source_line=1,
        confidence=Confidence.CERTAIN,
    )

    agent_cov = SourceCoverage(
        source="agent",
        state=CoverageState.AVAILABLE,
        required=False,
    )

    snapshot = _make_snapshot(
        sources=(agent_cov,),
        identities=(ident_host, ident_reg, ident_no_agent),
        host_bindings=(hb,),
    )

    findings = AGT001.evaluate(snapshot)
    assert findings == []


def test_agt002_identities_only_false_produces_finding() -> None:
    """AGT002 fires when identities_only is explicitly False."""
    identities_5 = tuple(
        Identity(
            fingerprint=f"SHA256:{i:043d}",
            algorithm="ed25519",
            bits_or_curve="256",
            agent_presence=True,
        )
        for i in range(5)
    )

    hb_false = HostBinding(
        patterns=("lab",),
        hostname="lab.internal",
        user="dev",
        identity_references=(),
        resolved_fingerprints=(),
        identities_only=False,
        source_file="config",
        source_line=15,
        confidence=Confidence.CERTAIN,
    )

    agent_cov = SourceCoverage(
        source="agent",
        state=CoverageState.AVAILABLE,
        required=False,
    )

    snapshot = _make_snapshot(
        sources=(agent_cov,),
        identities=identities_5,
        host_bindings=(hb_false,),
    )

    findings = AGT002.evaluate(snapshot)
    assert len(findings) == 1
    assert findings[0].affected_hosts == ("lab",)
    assert findings[0].evidence[0].line == 15


def test_agent_rules_registration_and_constants() -> None:
    """AGT001 and AGT002 are registered in RULES and get_default_rules; threshold is 5."""
    assert AGENT_EXPOSURE_THRESHOLD == 5

    assert isinstance(AGT001, AGT001Rule)
    assert isinstance(AGT002, AGT002Rule)
    assert AGT001 in RULES
    assert AGT002 in RULES

    defaults = get_default_rules()
    rule_ids = {r.rule_id for r in defaults}
    assert "AGT001" in rule_ids
    assert "AGT002" in rule_ids


def test_remediation_standards_and_phrasing() -> None:
    """Remediation mentions IdentitiesOnly yes, IdentityFile, ssh -G; phrasing uses may offer."""
    fp_x = "SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxX"
    ident_x = Identity(
        fingerprint=fp_x,
        algorithm="ed25519",
        bits_or_curve="256",
        agent_presence=True,
    )
    ref_bound = LocalReference(
        kind=LocalReferenceKind.PUBLIC_KEY,
        path="~/.ssh/id_bound.pub",
        source_file=None,
        source_line=None,
        resolution=Resolution.RESOLVED,
    )
    identities_5 = tuple(
        Identity(
            fingerprint=f"SHA256:{i:043d}",
            algorithm="ed25519",
            bits_or_curve="256",
            local_references=(ref_bound,),
            agent_presence=True,
        )
        for i in range(5)
    )
    hb_star = HostBinding(
        patterns=("*",),
        hostname=None,
        user=None,
        identity_references=(),
        resolved_fingerprints=(),
        identities_only=None,
        source_file="config",
        source_line=20,
        confidence=Confidence.CERTAIN,
    )
    agent_cov = SourceCoverage(
        source="agent",
        state=CoverageState.AVAILABLE,
        required=False,
    )

    snap = _make_snapshot(
        sources=(agent_cov,),
        identities=(*identities_5, ident_x),
        host_bindings=(hb_star,),
    )

    findings_agt001 = AGT001.evaluate(snap)
    findings_agt002 = AGT002.evaluate(snap)

    assert len(findings_agt001) == 1
    assert len(findings_agt002) == 1

    for f in findings_agt001 + findings_agt002:
        _assert_never_says_insecure(f)
        _assert_never_says_unused(f)
        _assert_remediation_not_destructive(f)

        summary_lower = f.summary.lower()
        assert "may offer" in summary_lower
        assert "heuristic" in summary_lower

        rem_combined = " ".join(f.manual_remediation)
        assert "IdentitiesOnly yes" in rem_combined
        assert "IdentityFile" in rem_combined
        assert "ssh -G" in rem_combined
