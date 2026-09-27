"""Tests for configuration rules CFG001 and CFG002 (sdd-spec FR-008)."""

from __future__ import annotations

from ssh_id_doctor.domain import (
    Confidence,
    HostBinding,
    Identity,
    LocalReference,
    LocalReferenceKind,
    Platform,
    Resolution,
    ScanSnapshot,
    Severity,
    UnresolvedItem,
)
from ssh_id_doctor.rules.config_rules import CFG001, CFG002, CFG001Rule, CFG002Rule


def _make_snapshot(
    *,
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
        local_references=local_references,
        identities=identities,
        host_bindings=host_bindings,
        unresolved=unresolved,
    )


def test_cfg001_missing_identityfile_is_certain_error() -> None:
    """AC-1: LocalReference(config_identity, path=~/.ssh/gone, resolution=missing,

    source_file=config, source_line=6) in 'Host prod' block produces one finding:
    rule_id=CFG001, severity=error, confidence=certain, evidence contains config:6
    and path, affected_hosts=['prod'], manual_remediation is non-empty and has no 'rm '.
    """
    ref = LocalReference(
        kind=LocalReferenceKind.CONFIG_IDENTITY,
        path="~/.ssh/gone",
        source_file="config",
        source_line=6,
        resolution=Resolution.MISSING,
    )
    host_binding = HostBinding(
        patterns=("prod",),
        hostname=None,
        user=None,
        identity_references=("~/.ssh/gone",),
        resolved_fingerprints=(),
        identities_only=None,
        source_file="config",
        source_line=5,
        confidence=Confidence.UNRESOLVED,
    )
    snapshot = _make_snapshot(
        local_references=(ref,),
        host_bindings=(host_binding,),
    )

    findings = CFG001.evaluate(snapshot)
    assert len(findings) == 1
    finding = findings[0]

    assert finding.rule_id == "CFG001"
    assert finding.severity is Severity.ERROR
    assert finding.confidence is Confidence.CERTAIN
    assert list(finding.affected_hosts) == ["prod"]
    assert len(finding.evidence) == 1

    ev = finding.evidence[0]
    assert ev.source == "config"
    assert ev.line == 6
    assert ev.detail == "~/.ssh/gone"
    assert "config" in ev.source and ev.line == 6 and "~/.ssh/gone" in ev.detail

    assert len(finding.manual_remediation) > 0
    for step in finding.manual_remediation:
        assert "rm " not in step


def test_cfg001_ignores_resolved_and_private_only() -> None:
    """AC-2: A snapshot with resolution=resolved and resolution=private_only references

    produces no findings (negative case).
    """
    resolved_ref = LocalReference(
        kind=LocalReferenceKind.CONFIG_IDENTITY,
        path="~/.ssh/id_ed25519",
        source_file="config",
        source_line=4,
        resolution=Resolution.RESOLVED,
    )
    private_only_ref = LocalReference(
        kind=LocalReferenceKind.CONFIG_IDENTITY,
        path="~/.ssh/id_canary",
        source_file="config",
        source_line=12,
        resolution=Resolution.PRIVATE_ONLY,
    )
    snapshot = _make_snapshot(
        local_references=(resolved_ref, private_only_ref),
    )

    findings = CFG001.evaluate(snapshot)
    assert findings == []


def test_cfg001_unreadable_and_outside_root_and_global_host() -> None:
    """CFG001 also catches unreadable and outside_root; global refs have empty affected_hosts."""
    unreadable_ref = LocalReference(
        kind=LocalReferenceKind.CONFIG_IDENTITY,
        path="/etc/secret_key",
        source_file="config",
        source_line=2,
        resolution=Resolution.UNREADABLE,
    )
    outside_ref = LocalReference(
        kind=LocalReferenceKind.CONFIG_IDENTITY,
        path="/outside/key",
        source_file="config",
        source_line=10,
        resolution=Resolution.OUTSIDE_ROOT,
    )
    host_binding = HostBinding(
        patterns=("staging", "staging.internal"),
        hostname=None,
        user=None,
        identity_references=("/outside/key",),
        resolved_fingerprints=(),
        identities_only=None,
        source_file="config",
        source_line=8,
        confidence=Confidence.UNRESOLVED,
    )
    snapshot = _make_snapshot(
        local_references=(unreadable_ref, outside_ref),
        host_bindings=(host_binding,),
    )

    findings = CFG001.evaluate(snapshot)
    assert len(findings) == 2

    # First is line 2 (before any host block, global)
    assert findings[0].affected_hosts == ()
    assert findings[0].severity is Severity.ERROR

    # Second is line 10 (inside staging block)
    assert list(findings[1].affected_hosts) == ["staging", "staging.internal"]
    assert findings[1].severity is Severity.ERROR


def test_cfg002_reports_cycle_match_and_token_as_unresolved() -> None:
    """AC-3: A snapshot with UnresolvedItem include_cycle (loop.conf:1),

    unsupported_match (config:6), unresolved_token (config:10) produces 3 findings:
    rule_id=CFG002, severity=info, confidence=unresolved, each with its own file:line
    and distinct stable ids.
    """
    items = (
        UnresolvedItem(
            kind="include_cycle",
            detail="loop.conf",
            source_file="loop.conf",
            source_line=1,
        ),
        UnresolvedItem(
            kind="unsupported_match",
            detail="Match host *.corp",
            source_file="config",
            source_line=6,
        ),
        UnresolvedItem(
            kind="unresolved_token",
            detail="%h",
            source_file="config",
            source_line=10,
        ),
    )
    snapshot = _make_snapshot(unresolved=items)

    findings = CFG002.evaluate(snapshot)
    assert len(findings) == 3

    finding_ids = {f.id for f in findings}
    assert len(finding_ids) == 3, "Each finding must have a distinct stable id"

    evidence_locations = {(f.evidence[0].source, f.evidence[0].line) for f in findings}
    assert evidence_locations == {
        ("loop.conf", 1),
        ("config", 6),
        ("config", 10),
    }

    for f in findings:
        assert f.rule_id == "CFG002"
        assert f.severity is Severity.INFO
        assert f.confidence is Confidence.UNRESOLVED
        assert f.id.startswith("CFG002-")
        assert len(f.manual_remediation) > 0
        for step in f.manual_remediation:
            assert "rm " not in step


def test_cfg002_ignores_non_cfg002_kinds_and_handles_missing_include() -> None:
    """CFG002 handles include_missing, but ignores malformed_line or unknown kinds."""
    items = (
        UnresolvedItem(
            kind="include_missing",
            detail="missing.conf",
            source_file="config",
            source_line=4,
        ),
        UnresolvedItem(
            kind="malformed_line",
            detail="invalid syntax",
            source_file="config",
            source_line=2,
        ),
    )
    snapshot = _make_snapshot(unresolved=items)

    findings = CFG002.evaluate(snapshot)
    assert len(findings) == 1
    assert findings[0].rule_id == "CFG002"
    assert findings[0].evidence[0].source == "config"
    assert findings[0].evidence[0].line == 4
    assert findings[0].evidence[0].detail == "missing.conf"


def test_rules_list_contains_rule_instances() -> None:
    from ssh_id_doctor.rules.config_rules import RULES

    assert len(RULES) == 2
    rule_ids = {r.rule_id for r in RULES}
    assert rule_ids == {"CFG001", "CFG002"}
    assert any(isinstance(r, CFG001Rule) for r in RULES)
    assert any(isinstance(r, CFG002Rule) for r in RULES)
