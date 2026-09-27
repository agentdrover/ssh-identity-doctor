"""Tests for identity rules ID001, ID002, and LAB001 (sdd-spec FR-008)."""

from __future__ import annotations

import dataclasses
import re
from typing import TYPE_CHECKING

from ssh_id_doctor.domain import (
    Confidence,
    HostBinding,
    Identity,
    LocalReference,
    LocalReferenceKind,
    Platform,
    RegistryBinding,
    Resolution,
    ScanSnapshot,
    Severity,
    UnresolvedItem,
)
from ssh_id_doctor.rules import get_default_rules, run_rules
from ssh_id_doctor.rules.identity_rules import (
    ID001,
    ID002,
    LAB001,
    RULES,
    ID001Rule,
    ID002Rule,
    LAB001Rule,
)

if TYPE_CHECKING:
    from pathlib import Path


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


def _assert_never_says_unused(finding: object) -> None:
    for text in _all_strings(finding):
        assert "unused" not in text.lower(), f"'unused' found in finding text: {text!r}"


def _assert_remediation_not_destructive(finding: object) -> None:
    for rem in getattr(finding, "manual_remediation", ()):
        assert not _DESTRUCTIVE_REMEDIATION.search(rem), f"destructive remediation: {rem!r}"


def test_id001_same_fingerprint_multiple_paths() -> None:
    """AC-1: Identity F with public_key references ~/.ssh/id_a.pub and ~/.ssh/backup/a.pub

    produces one ID001 finding (info, certain) with both paths in evidence and
    affected_fingerprints=[F]; an identity with only one path produces no finding.
    """
    fp_f = "SHA256:ffffffffffffffffffffffffffffffffffffffffffF"
    fp_single = "SHA256:1111111111111111111111111111111111111111111"

    ref_a = LocalReference(
        kind=LocalReferenceKind.PUBLIC_KEY,
        path="~/.ssh/id_a.pub",
        source_file=None,
        source_line=None,
        resolution=Resolution.RESOLVED,
    )
    ref_backup = LocalReference(
        kind=LocalReferenceKind.PUBLIC_KEY,
        path="~/.ssh/backup/a.pub",
        source_file=None,
        source_line=None,
        resolution=Resolution.RESOLVED,
    )
    ident_f = Identity(
        fingerprint=fp_f,
        algorithm="ed25519",
        bits_or_curve="256",
        comments=("work",),
        local_references=(ref_a, ref_backup),
    )

    ref_single = LocalReference(
        kind=LocalReferenceKind.PUBLIC_KEY,
        path="~/.ssh/id_single.pub",
        source_file=None,
        source_line=None,
        resolution=Resolution.RESOLVED,
    )
    ident_single = Identity(
        fingerprint=fp_single,
        algorithm="ed25519",
        bits_or_curve="256",
        comments=("single",),
        local_references=(ref_single,),
    )

    snapshot = _make_snapshot(identities=(ident_f, ident_single))
    findings = ID001.evaluate(snapshot)

    assert len(findings) == 1
    finding = findings[0]

    assert finding.rule_id == "ID001"
    assert finding.severity is Severity.INFO
    assert finding.confidence is Confidence.CERTAIN
    assert list(finding.affected_fingerprints) == [fp_f]

    evidence_sources = {ev.source for ev in finding.evidence}
    evidence_details = {ev.detail for ev in finding.evidence}
    assert "~/.ssh/id_a.pub" in (evidence_sources | evidence_details)
    assert "~/.ssh/backup/a.pub" in (evidence_sources | evidence_details)
    assert len(finding.evidence) == 2

    _assert_never_says_unused(finding)
    _assert_remediation_not_destructive(finding)


def test_id002_no_known_binding_never_says_unused() -> None:
    """AC-2: Identity G with single public_key reference, without HostBinding and RegistryBinding;

    Identity H with HostBinding.
    Produces exactly one ID002 finding (warning, heuristic) for G; title and summary
    contain 'no known binding' and do not contain 'unused' (case-insensitive) in any field.
    """
    fp_g = "SHA256:ggggggggggggggggggggggggggggggggggggggggggG"
    fp_h = "SHA256:hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhH"

    ref_g = LocalReference(
        kind=LocalReferenceKind.PUBLIC_KEY,
        path="~/.ssh/id_g.pub",
        source_file=None,
        source_line=None,
        resolution=Resolution.RESOLVED,
    )
    ident_g = Identity(
        fingerprint=fp_g,
        algorithm="ed25519",
        bits_or_curve="256",
        comments=("key-g",),
        local_references=(ref_g,),
    )

    ref_h = LocalReference(
        kind=LocalReferenceKind.PUBLIC_KEY,
        path="~/.ssh/id_h.pub",
        source_file=None,
        source_line=None,
        resolution=Resolution.RESOLVED,
    )
    ident_h = Identity(
        fingerprint=fp_h,
        algorithm="ed25519",
        bits_or_curve="256",
        comments=("key-h",),
        local_references=(ref_h,),
    )

    host_binding = HostBinding(
        patterns=("server.example.com",),
        hostname="server.example.com",
        user="deploy",
        identity_references=("~/.ssh/id_h",),
        resolved_fingerprints=(fp_h,),
        identities_only=True,
        source_file="config",
        source_line=1,
        confidence=Confidence.CERTAIN,
    )

    snapshot = _make_snapshot(
        identities=(ident_g, ident_h),
        host_bindings=(host_binding,),
    )
    findings = ID002.evaluate(snapshot)

    assert len(findings) == 1
    finding = findings[0]

    assert finding.rule_id == "ID002"
    assert finding.severity is Severity.WARNING
    assert finding.confidence is Confidence.HEURISTIC
    assert list(finding.affected_fingerprints) == [fp_g]

    assert "no known binding" in finding.title.lower()
    assert "no known binding" in finding.summary.lower()

    # SEC-006 & FR-008: 'unused' must NOT appear in ANY field, nested ones included
    _assert_never_says_unused(finding)
    _assert_remediation_not_destructive(finding)


def test_lab001_empty_and_ambiguous_comments() -> None:
    """AC-3: Identity P with empty comment; Identity Q and R (different fingerprints)

    with comment 'me@laptop'; Identity S with unique comment.
    Produces LAB001 finding for P (empty) and one LAB001 finding for pair Q+R with
    affected_fingerprints=[Q, R]; S produces no findings; severity=info, confidence=heuristic.
    """
    fp_p = "SHA256:ppppppppppppppppppppppppppppppppppppppppppP"
    fp_q = "SHA256:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqQ"
    fp_r = "SHA256:rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrR"
    fp_s = "SHA256:ssssssssssssssssssssssssssssssssssssssssssS"

    ref_p = LocalReference(
        kind=LocalReferenceKind.PUBLIC_KEY,
        path="~/.ssh/id_p.pub",
        source_file=None,
        source_line=None,
        resolution=Resolution.RESOLVED,
    )
    ident_p = Identity(
        fingerprint=fp_p,
        algorithm="ed25519",
        bits_or_curve="256",
        comments=(),
        local_references=(ref_p,),
    )

    ref_q = LocalReference(
        kind=LocalReferenceKind.PUBLIC_KEY,
        path="~/.ssh/id_q.pub",
        source_file=None,
        source_line=None,
        resolution=Resolution.RESOLVED,
    )
    ident_q = Identity(
        fingerprint=fp_q,
        algorithm="ed25519",
        bits_or_curve="256",
        comments=("me@laptop",),
        local_references=(ref_q,),
    )

    ref_r = LocalReference(
        kind=LocalReferenceKind.PUBLIC_KEY,
        path="~/.ssh/id_r.pub",
        source_file=None,
        source_line=None,
        resolution=Resolution.RESOLVED,
    )
    ident_r = Identity(
        fingerprint=fp_r,
        algorithm="ed25519",
        bits_or_curve="256",
        comments=("me@laptop",),
        local_references=(ref_r,),
    )

    ref_s = LocalReference(
        kind=LocalReferenceKind.PUBLIC_KEY,
        path="~/.ssh/id_s.pub",
        source_file=None,
        source_line=None,
        resolution=Resolution.RESOLVED,
    )
    ident_s = Identity(
        fingerprint=fp_s,
        algorithm="ed25519",
        bits_or_curve="256",
        comments=("unique-s@work",),
        local_references=(ref_s,),
    )

    snapshot = _make_snapshot(identities=(ident_p, ident_q, ident_r, ident_s))
    findings = LAB001.evaluate(snapshot)

    assert len(findings) == 2

    p_findings = [f for f in findings if fp_p in f.affected_fingerprints]
    assert len(p_findings) == 1
    f_p = p_findings[0]
    assert f_p.rule_id == "LAB001"
    assert f_p.severity is Severity.INFO
    assert f_p.confidence is Confidence.HEURISTIC
    assert list(f_p.affected_fingerprints) == [fp_p]
    assert "empty" in f_p.title.lower() or "empty" in f_p.summary.lower()

    qr_findings = [f for f in findings if fp_q in f.affected_fingerprints]
    assert len(qr_findings) == 1
    f_qr = qr_findings[0]
    assert f_qr.rule_id == "LAB001"
    assert f_qr.severity is Severity.INFO
    assert f_qr.confidence is Confidence.HEURISTIC
    assert set(f_qr.affected_fingerprints) == {fp_q, fp_r}
    assert list(f_qr.affected_fingerprints) == sorted([fp_q, fp_r])
    assert "me@laptop" in f_qr.title or "me@laptop" in f_qr.summary

    # Identity S should have no findings
    s_findings = [f for f in findings if fp_s in f.affected_fingerprints]
    assert s_findings == []

    # None should say 'unused' in any field or suggest destructive remediation
    for f in findings:
        _assert_never_says_unused(f)
        _assert_remediation_not_destructive(f)


def test_id001_multiple_comments_single_path() -> None:
    """ID001 triggers when an identity has >= 2 distinct comments even with a single path."""
    fp = "SHA256:2222222222222222222222222222222222222222222"
    ref = LocalReference(
        kind=LocalReferenceKind.PUBLIC_KEY,
        path="~/.ssh/id_multi.pub",
        source_file=None,
        source_line=None,
        resolution=Resolution.RESOLVED,
    )
    ident = Identity(
        fingerprint=fp,
        algorithm="ed25519",
        bits_or_curve="256",
        comments=("label1", "label2"),
        local_references=(ref,),
    )
    snapshot = _make_snapshot(identities=(ident,))
    findings = ID001.evaluate(snapshot)

    assert len(findings) == 1
    assert findings[0].rule_id == "ID001"
    assert findings[0].affected_fingerprints == (fp,)
    assert len(findings[0].evidence) == 1
    assert "label1" in findings[0].summary
    assert "label2" in findings[0].summary


def test_id001_remediation_follows_the_cause() -> None:
    """ID001 remediation depends on the cause: labels-only has no duplicate files to consolidate."""

    def _ref(path: str) -> LocalReference:
        return LocalReference(
            kind=LocalReferenceKind.PUBLIC_KEY,
            path=path,
            source_file=None,
            source_line=None,
            resolution=Resolution.RESOLVED,
        )

    def _remediation(paths: tuple[str, ...], comments: tuple[str, ...]) -> str:
        ident = Identity(
            fingerprint="SHA256:labelslabelslabelslabelslabelslabelslabelsL",
            algorithm="ed25519",
            bits_or_curve="256",
            comments=comments,
            local_references=tuple(_ref(p) for p in paths),
        )
        (finding,) = ID001.evaluate(_make_snapshot(identities=(ident,)))
        _assert_remediation_not_destructive(finding)
        return " ".join(finding.manual_remediation).lower()

    labels_only = _remediation(("~/.ssh/id_one.pub",), ("label1", "label2"))
    assert "duplicate key files" not in labels_only
    assert "canonical path" not in labels_only
    assert "comment" in labels_only

    paths_only = _remediation(("~/.ssh/a.pub", "~/.ssh/b.pub"), ("same",))
    assert "duplicate key files" in paths_only
    assert "comment" not in paths_only

    both = _remediation(("~/.ssh/a.pub", "~/.ssh/b.pub"), ("label1", "label2"))
    assert "duplicate key files" in both
    assert "comment" in both


def test_id002_with_unresolved_config_notes_in_summary() -> None:
    """ID002 notes that binding may exist in unevaluated config when CFG002 items are present."""
    fp = "SHA256:3333333333333333333333333333333333333333333"
    ref = LocalReference(
        kind=LocalReferenceKind.PUBLIC_KEY,
        path="~/.ssh/id_test.pub",
        source_file=None,
        source_line=None,
        resolution=Resolution.RESOLVED,
    )
    ident = Identity(
        fingerprint=fp,
        algorithm="ed25519",
        bits_or_curve="256",
        comments=("test",),
        local_references=(ref,),
    )
    unresolved_item = UnresolvedItem(
        kind="unsupported_match",
        detail="Match host specific.example.com",
        source_file="~/.ssh/config",
        source_line=20,
    )
    snapshot = _make_snapshot(
        identities=(ident,),
        unresolved=(unresolved_item,),
    )
    findings = ID002.evaluate(snapshot)

    assert len(findings) == 1
    summary_lower = findings[0].summary.lower()
    assert "unevaluated configuration" in summary_lower or "match" in summary_lower
    assert "no known binding" in summary_lower
    assert "unused" not in summary_lower


def test_id002_ignores_identity_with_registry_binding() -> None:
    """Identity with a RegistryBinding produces no ID002 finding."""
    fp = "SHA256:4444444444444444444444444444444444444444444"
    ref = LocalReference(
        kind=LocalReferenceKind.PUBLIC_KEY,
        path="~/.ssh/id_reg.pub",
        source_file=None,
        source_line=None,
        resolution=Resolution.RESOLVED,
    )
    reg_binding = RegistryBinding(
        registry="github",
        fingerprint=fp,
        title="Personal GitHub key",
    )
    ident = Identity(
        fingerprint=fp,
        algorithm="ed25519",
        bits_or_curve="256",
        comments=("gh-key",),
        local_references=(ref,),
        registry_bindings=(reg_binding,),
    )
    snapshot = _make_snapshot(identities=(ident,))
    findings = ID002.evaluate(snapshot)

    assert findings == []


def test_id002_ignores_agent_only_identity() -> None:
    """Identity only present in agent (no local public_key reference) produces no ID002 finding."""
    fp = "SHA256:5555555555555555555555555555555555555555555"
    ident = Identity(
        fingerprint=fp,
        algorithm="ed25519",
        bits_or_curve="256",
        comments=("agent-only",),
        agent_presence=True,
        local_references=(),
    )
    snapshot = _make_snapshot(identities=(ident,))
    findings = ID002.evaluate(snapshot)

    assert findings == []


def test_id002_agent_presence_is_not_a_binding() -> None:
    """Being loaded in the agent is exposure, not a binding: ID002 still fires."""
    fp = "SHA256:8888888888888888888888888888888888888888888"
    ref = LocalReference(
        kind=LocalReferenceKind.PUBLIC_KEY,
        path="~/.ssh/id_agent_loaded.pub",
        source_file=None,
        source_line=None,
        resolution=Resolution.RESOLVED,
    )
    ident = Identity(
        fingerprint=fp,
        algorithm="ed25519",
        bits_or_curve="256",
        comments=("loaded",),
        local_references=(ref,),
        agent_presence=True,
    )
    findings = ID002.evaluate(_make_snapshot(identities=(ident,)))

    assert [f.affected_fingerprints for f in findings] == [(fp,)]
    assert "no known binding" in findings[0].title.lower()


def test_remediation_never_destructive_across_identity_rules() -> None:
    """SEC-006: no rule suggests rm, sed -i, ssh-add -d/-D or promises deletion is safe."""
    fp_dup = "SHA256:9999999999999999999999999999999999999999999"
    fp_other = "SHA256:0000000000000000000000000000000000000000000"
    refs = tuple(
        LocalReference(
            kind=LocalReferenceKind.PUBLIC_KEY,
            path=path,
            source_file=None,
            source_line=None,
            resolution=Resolution.RESOLVED,
        )
        for path in ("~/.ssh/a.pub", "~/.ssh/b.pub", "~/.ssh/c.pub")
    )
    ident_dup = Identity(
        fingerprint=fp_dup,
        algorithm="ed25519",
        bits_or_curve="256",
        comments=("",),
        local_references=refs[:2],
    )
    ident_a = Identity(
        fingerprint=fp_other,
        algorithm="ed25519",
        bits_or_curve="256",
        comments=("shared",),
        local_references=refs[2:],
    )
    ident_b = Identity(
        fingerprint="SHA256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeE",
        algorithm="ed25519",
        bits_or_curve="256",
        comments=("shared",),
        agent_presence=True,
    )
    snapshot = _make_snapshot(identities=(ident_dup, ident_a, ident_b))

    findings = [f for rule in RULES for f in rule.evaluate(snapshot)]
    assert {f.rule_id for f in findings} == {"ID001", "ID002", "LAB001"}
    assert len([f for f in findings if f.rule_id == "LAB001"]) == 2  # empty + shared
    for f in findings:
        assert f.manual_remediation, f"{f.rule_id} has no remediation"
        _assert_remediation_not_destructive(f)
        _assert_never_says_unused(f)


def test_lab001_whitespace_only_comment_treated_as_empty() -> None:
    """Identity with whitespace-only comment is treated as having an empty comment."""
    fp = "SHA256:6666666666666666666666666666666666666666666"
    ref = LocalReference(
        kind=LocalReferenceKind.PUBLIC_KEY,
        path="~/.ssh/id_blank.pub",
        source_file=None,
        source_line=None,
        resolution=Resolution.RESOLVED,
    )
    ident = Identity(
        fingerprint=fp,
        algorithm="ed25519",
        bits_or_curve="256",
        comments=("   ",),
        local_references=(ref,),
    )
    snapshot = _make_snapshot(identities=(ident,))
    findings = LAB001.evaluate(snapshot)

    assert len(findings) == 1
    assert findings[0].affected_fingerprints == (fp,)
    assert "empty" in findings[0].title.lower() or "empty" in findings[0].summary.lower()


def test_rules_registered_in_default_registry() -> None:
    """ID001, ID002, LAB001 are in RULES and returned by get_default_rules()."""

    assert isinstance(ID001, ID001Rule)
    assert isinstance(ID002, ID002Rule)
    assert isinstance(LAB001, LAB001Rule)
    assert ID001 in RULES
    assert ID002 in RULES
    assert LAB001 in RULES

    defaults = get_default_rules()
    rule_ids = {r.rule_id for r in defaults}
    assert "ID001" in rule_ids
    assert "ID002" in rule_ids
    assert "LAB001" in rule_ids


def test_run_rules_integration() -> None:
    """run_rules executes ID001, ID002, LAB001 alongside CFG rules and returns sorted findings."""
    fp_dup = "SHA256:7777777777777777777777777777777777777777777"
    ref1 = LocalReference(
        kind=LocalReferenceKind.PUBLIC_KEY,
        path="~/.ssh/key1.pub",
        source_file=None,
        source_line=None,
        resolution=Resolution.RESOLVED,
    )
    ref2 = LocalReference(
        kind=LocalReferenceKind.PUBLIC_KEY,
        path="~/.ssh/key2.pub",
        source_file=None,
        source_line=None,
        resolution=Resolution.RESOLVED,
    )
    ident = Identity(
        fingerprint=fp_dup,
        algorithm="ed25519",
        bits_or_curve="256",
        comments=(),
        local_references=(ref1, ref2),
    )
    snapshot = _make_snapshot(identities=(ident,))
    findings = run_rules(snapshot)

    # Should have ID001 (duplicate paths), ID002 (no binding), and LAB001 (empty comment)
    rule_ids = {f.rule_id for f in findings}
    assert "ID001" in rule_ids
    assert "ID002" in rule_ids
    assert "LAB001" in rule_ids

    # Sorted by (severity, rule_id, id)
    # severity order: error, warning, info
    severities = [f.severity for f in findings]
    assert severities == sorted(severities)

    # Check 0 occurrences of 'unused' across all findings
    for f in findings:
        for field_name in ("id", "rule_id", "severity", "confidence", "title", "summary"):
            val = str(getattr(f, field_name)).lower()
            assert "unused" not in val, f"{field_name} in finding {f.id} contains 'unused'"
        for ev in f.evidence:
            assert "unused" not in ev.source.lower()
            assert "unused" not in ev.detail.lower()
        for rem in f.manual_remediation:
            assert "unused" not in rem.lower()


def test_home_basic_produces_id001_and_no_unused(fake_home: Path) -> None:
    """Outcome metric: home_basic gives ID001 on duplicate, 0 occurrences of 'unused'."""
    from pathlib import Path

    from ssh_id_doctor.adapters.github import RegistryResult, RegistryState
    from ssh_id_doctor.inspectors.agent import AgentResult, AgentState
    from ssh_id_doctor.orchestrator import OrchestratorOptions, ScanOrchestrator

    fixtures_dir = Path(__file__).resolve().parent.parent / "fixtures" / "home_basic"
    ssh = fake_home / ".ssh"
    (ssh / "id_ed25519.pub").write_text((fixtures_dir / "id_ed25519.pub").read_text())
    (ssh / "id_ed25519_copy.pub").write_text((fixtures_dir / "id_ed25519_copy.pub").read_text())
    (ssh / "id_rsa.pub").write_text((fixtures_dir / "id_rsa.pub").read_text())
    (ssh / "config").write_text((fixtures_dir / "config").read_text())

    config_d = ssh / "config.d"
    config_d.mkdir(exist_ok=True)
    inc_text = (fixtures_dir / "config.d" / "included.conf").read_text()
    cyc_text = (fixtures_dir / "config.d" / "cycle.conf").read_text()
    if "Include cycle.conf" in inc_text:
        inc_text = inc_text.replace("Include cycle.conf", "Include config.d/cycle.conf")
    if "Include included.conf" in cyc_text:
        cyc_text = cyc_text.replace("Include included.conf", "Include config.d/included.conf")
    (config_d / "included.conf").write_text(inc_text)
    (config_d / "cycle.conf").write_text(cyc_text)

    (ssh / "id_canary.pub").unlink(missing_ok=True)

    class FakeAgent:
        def list_identities(self) -> AgentResult:
            return AgentResult(state=AgentState.SKIPPED, detail="skipped")

    class FakeGitHub:
        def list_keys(self) -> RegistryResult:
            return RegistryResult(state=RegistryState.SKIPPED, detail="skipped")

    orchestrator = ScanOrchestrator(
        agent_adapter=FakeAgent(),  # type: ignore[arg-type]
        github_adapter=FakeGitHub(),
    )
    opts = OrchestratorOptions(
        home=fake_home,
        ssh_dir=ssh,
        config_path=ssh / "config",
        check_agent=False,
        check_github=False,
    )
    snapshot = orchestrator.run(opts)

    id001_findings = [f for f in snapshot.findings if f.rule_id == "ID001"]
    assert len(id001_findings) >= 1
    dup_finding = id001_findings[0]
    ev_details = {ev.detail for ev in dup_finding.evidence}
    assert any("id_ed25519.pub" in d for d in ev_details)
    assert any("id_ed25519_copy.pub" in d for d in ev_details)

    for f in snapshot.findings:
        for field_name in ("id", "rule_id", "severity", "confidence", "title", "summary"):
            val = str(getattr(f, field_name)).lower()
            assert "unused" not in val, f"Finding {f.id} has unused in {field_name}"
        for ev in f.evidence:
            assert "unused" not in ev.source.lower()
            assert "unused" not in ev.detail.lower()
        for rem in f.manual_remediation:
            assert "unused" not in rem.lower()
