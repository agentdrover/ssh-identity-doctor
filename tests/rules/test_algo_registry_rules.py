"""Tests for algorithm and registry rules ALG001 and REG001 (sdd-spec FR-008)."""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path

import pytest

from ssh_id_doctor.aggregate import ScanObservations, build_snapshot
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
from ssh_id_doctor.inspectors.keygen import KeyInfo, PublicKeyInspector
from ssh_id_doctor.process import ProcessResult, ProcessStatus
from ssh_id_doctor.rules import get_default_rules, run_rules
from ssh_id_doctor.rules.algo_registry_rules import (
    ALG001,
    LEGACY_ALGORITHMS,
    REG001,
    RULES,
    ALG001Rule,
    REG001Rule,
)
from ssh_id_doctor.scanner import PublicKeyObservation

KEY_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "keys"

# Recorded shape of `ssh-keygen -l -E sha256 -f <rsa-1024.pub>`; no real key is
# generated or stored — the inspector only sees this text through a fake run.
_RSA1024_PUB = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDshortrsa1024notarealkey short@example"
_RSA1024_KEYGEN_OUT = (
    "1024 SHA256:ShortRsa1024RecordedOutput0000000000000000000 short@example (RSA)\n"
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


def test_alg001_flags_dsa_and_short_rsa_only() -> None:
    """AC-1: Given identities ssh-dss 1024, ssh-rsa 1024, ssh-rsa 3072, ssh-ed25519.

    When ALG001 executes: exactly 2 findings (warning, certain) for ssh-dss and
    ssh-rsa 1024; rsa-3072 and ed25519 produce no findings.
    """
    fp_dss = "SHA256:dssdssdssdssdssdssdssdssdssdssdssdssdssdss"
    fp_rsa1024 = "SHA256:rsa1024102410241024102410241024102410241024"
    fp_rsa3072 = "SHA256:rsa3072307230723072307230723072307230723072"
    fp_ed25519 = "SHA256:ed25519ed25519ed25519ed25519ed25519ed25519"

    ident_dss = Identity(
        fingerprint=fp_dss,
        algorithm="ssh-dss",
        bits_or_curve="1024",
        comments=("legacy-dsa",),
    )
    ident_rsa1024 = Identity(
        fingerprint=fp_rsa1024,
        algorithm="ssh-rsa",
        bits_or_curve="1024",
        comments=("short-rsa",),
    )
    ident_rsa3072 = Identity(
        fingerprint=fp_rsa3072,
        algorithm="ssh-rsa",
        bits_or_curve="3072",
        comments=("modern-rsa",),
    )
    ident_ed25519 = Identity(
        fingerprint=fp_ed25519,
        algorithm="ssh-ed25519",
        bits_or_curve="256",
        comments=("ed25519-key",),
    )

    snapshot = _make_snapshot(
        identities=(ident_dss, ident_rsa1024, ident_rsa3072, ident_ed25519),
    )

    findings = ALG001.evaluate(snapshot)

    assert len(findings) == 2

    flagged_fps = [f.affected_fingerprints[0] for f in findings]
    assert fp_dss in flagged_fps
    assert fp_rsa1024 in flagged_fps
    assert fp_rsa3072 not in flagged_fps
    assert fp_ed25519 not in flagged_fps

    for finding in findings:
        assert finding.rule_id == "ALG001"
        assert finding.severity is Severity.WARNING
        assert finding.confidence is Confidence.CERTAIN
        assert len(finding.evidence) >= 1
        _assert_never_says_unused(finding)
        _assert_never_says_insecure(finding)
        _assert_remediation_not_destructive(finding)
        assert any(
            "rotation" in rem.lower() or "replacement" in rem.lower()
            for rem in finding.manual_remediation
        )
        assert any(
            "redundant" in rem.lower() or "backup" in rem.lower()
            for rem in finding.manual_remediation
        )


def _snapshot_via_keygen(
    monkeypatch: pytest.MonkeyPatch, pub_line: str, keygen_stdout: str
) -> ScanSnapshot:
    """PublicKeyInspector on recorded ssh-keygen output -> build_snapshot, as a scan does."""

    def fake_run(argv: list[str], *, timeout: float, max_output: int) -> ProcessResult:
        assert argv[0] == "ssh-keygen"
        return ProcessResult(ProcessStatus.OK, 0, keygen_stdout.encode(), b"", False)

    monkeypatch.setattr("ssh_id_doctor.inspectors.keygen.process.run", fake_run)
    info = PublicKeyInspector().fingerprint(pub_line)
    assert isinstance(info, KeyInfo)
    observation = PublicKeyObservation(path="/home/u/.ssh/id.pub", resolution=Resolution.RESOLVED)
    return build_snapshot(ScanObservations(public_keys=[(observation, info)]))


def test_alg001_flags_short_rsa_from_real_ssh_keygen_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Finding 900d1c6ba5b063f2: ALG001 on a snapshot built from ssh-keygen output.

    RSA 1024 through PublicKeyInspector -> Identity is flagged; the recorded
    rsa3072 fixture is not. Synthetic bits_or_curve cannot hide the inspector's shape.
    """
    short = _snapshot_via_keygen(monkeypatch, _RSA1024_PUB, _RSA1024_KEYGEN_OUT)
    (ident,) = short.identities
    assert ident.algorithm == "ssh-rsa"
    findings = ALG001.evaluate(short)
    assert [f.affected_fingerprints for f in findings] == [(ident.fingerprint,)]
    assert findings[0].confidence is Confidence.CERTAIN

    modern = _snapshot_via_keygen(
        monkeypatch,
        (KEY_FIXTURES / "rsa3072.pub").read_text().strip("\n"),
        (KEY_FIXTURES / "rsa3072.sha256.txt").read_text(),
    )
    assert len(modern.identities) == 1
    assert ALG001.evaluate(modern) == []


@pytest.mark.parametrize("unreadable", ["", "RSA", "unknown"])
def test_alg001_rsa_with_unreadable_size_is_not_a_certain_finding(unreadable: str) -> None:
    """A size nobody could read is not certainly short: skipped, never guessed."""
    ident = Identity(
        fingerprint="SHA256:rsaunknownsize000000000000000000000000000",
        algorithm="ssh-rsa",
        bits_or_curve=unreadable,
    )
    assert ALG001.evaluate(_make_snapshot(identities=(ident,))) == []


def test_reg001_github_key_without_local_or_agent_match() -> None:
    """AC-2: Given GitHub coverage=available, keys 'old-laptop' and 'ci' (in agent).

    When REG001 executes: exactly one finding REG001 (info, heuristic) for 'old-laptop'
    with title and created_at in evidence; finding text does not contain 'unused'
    or 'safe to delete'.
    """
    fp_laptop = "SHA256:laptoplaptoplaptoplaptoplaptoplaptoplaptop"
    fp_ci = "SHA256:cicicicicicicicicicicicicicicicicicicicici"

    cov = SourceCoverage(
        source="github",
        state=CoverageState.AVAILABLE,
        required=False,
    )

    rb_laptop = RegistryBinding(
        registry="github",
        fingerprint=fp_laptop,
        title="old-laptop",
        created_at="2022-01-01T00:00:00Z",
    )
    rb_ci = RegistryBinding(
        registry="github",
        fingerprint=fp_ci,
        title="ci",
        created_at="2023-01-01T00:00:00Z",
    )

    ident_laptop = Identity(
        fingerprint=fp_laptop,
        algorithm="ssh-ed25519",
        bits_or_curve="256",
        comments=(),
        local_references=(),
        agent_presence=False,
        registry_bindings=(rb_laptop,),
    )
    ident_ci = Identity(
        fingerprint=fp_ci,
        algorithm="ssh-ed25519",
        bits_or_curve="256",
        comments=(),
        local_references=(),
        agent_presence=True,
        registry_bindings=(rb_ci,),
    )

    snapshot = _make_snapshot(
        sources=(cov,),
        identities=(ident_laptop, ident_ci),
    )

    findings = REG001.evaluate(snapshot)

    assert len(findings) == 1
    finding = findings[0]

    assert finding.rule_id == "REG001"
    assert finding.severity is Severity.INFO
    assert finding.confidence is Confidence.HEURISTIC
    assert finding.affected_fingerprints == (fp_laptop,)

    # Evidence contains title and created_at
    assert len(finding.evidence) == 1
    ev = finding.evidence[0]
    assert ev.source == "github"
    assert "old-laptop" in ev.detail
    assert "2022-01-01T00:00:00Z" in ev.detail

    # Finding text constraints (SEC-006 & FR-008)
    all_text = " ".join(_all_strings(finding)).lower()
    assert "unused" not in all_text
    assert "safe to delete" not in all_text
    _assert_never_says_unused(finding)
    _assert_remediation_not_destructive(finding)

    # Remediation directs to github.com/settings/keys
    assert any("github.com/settings/keys" in rem for rem in finding.manual_remediation)


@pytest.mark.parametrize(
    "sources",
    [
        # GitHub source coverage not requested at all
        (),
        # GitHub source coverage requested but skipped / not requested
        (SourceCoverage(source="github", state=CoverageState.SKIPPED, required=False),),
        # GitHub source coverage unavailable / not authenticated
        (SourceCoverage(source="github", state=CoverageState.UNAVAILABLE, required=False),),
        (
            SourceCoverage(
                source="github",
                state=CoverageState.UNAVAILABLE,
                required=False,
                detail="not_authenticated",
            ),
        ),
    ],
)
def test_reg001_silent_without_github_coverage(sources: tuple[SourceCoverage, ...]) -> None:
    """AC-3: Same data as AC-2, but GitHub coverage=not_requested or not_authenticated.

    When REG001 executes: no findings are produced.
    """
    fp_laptop = "SHA256:laptoplaptoplaptoplaptoplaptoplaptoplaptop"
    rb_laptop = RegistryBinding(
        registry="github",
        fingerprint=fp_laptop,
        title="old-laptop",
        created_at="2022-01-01T00:00:00Z",
    )
    ident_laptop = Identity(
        fingerprint=fp_laptop,
        algorithm="ssh-ed25519",
        bits_or_curve="256",
        comments=(),
        local_references=(),
        agent_presence=False,
        registry_bindings=(rb_laptop,),
    )

    snapshot = _make_snapshot(
        sources=sources,
        identities=(ident_laptop,),
    )

    findings = REG001.evaluate(snapshot)
    assert len(findings) == 0


def test_algo_registry_rules_metadata() -> None:
    """Verify registration of rules and default algorithms."""
    assert isinstance(ALG001, ALG001Rule)
    assert isinstance(REG001, REG001Rule)
    assert ALG001 in RULES
    assert REG001 in RULES
    defaults = get_default_rules()
    assert ALG001 in defaults
    assert REG001 in defaults

    assert "ssh-dss" in LEGACY_ALGORITHMS
    assert "ssh-rsa" in LEGACY_ALGORITHMS
    assert LEGACY_ALGORITHMS["ssh-dss"] is None
    assert LEGACY_ALGORITHMS["ssh-rsa"] == 2048


def test_alg001_with_local_references() -> None:
    """Evidence points to local files when local references exist."""
    fp = "SHA256:dssdssdssdssdssdssdssdssdssdssdssdssdssdss"
    ref = LocalReference(
        kind=LocalReferenceKind.PUBLIC_KEY,
        path="~/.ssh/id_dsa.pub",
        source_file="/home/user/.ssh/id_dsa.pub",
        source_line=1,
        resolution=Resolution.RESOLVED,
    )
    ident = Identity(
        fingerprint=fp,
        algorithm="ssh-dss",
        bits_or_curve="1024",
        comments=("dsa-key",),
        local_references=(ref,),
    )
    snapshot = _make_snapshot(identities=(ident,))
    findings = ALG001.evaluate(snapshot)

    assert len(findings) == 1
    assert findings[0].evidence[0].source == "/home/user/.ssh/id_dsa.pub"
    assert findings[0].evidence[0].line == 1
    assert "ssh-dss" in findings[0].evidence[0].detail


def test_alg001_rsa_bit_boundaries() -> None:
    """RSA >= 2048 is not legacy, < 2048 is legacy."""
    for bits, should_flag in [
        ("512", True),
        ("1024", True),
        ("2047", True),
        ("2048", False),
        ("3072", False),
        ("4096", False),
    ]:
        ident = Identity(
            fingerprint=f"SHA256:rsa{bits}bits0000000000000000000000000000",
            algorithm="ssh-rsa",
            bits_or_curve=bits,
        )
        snapshot = _make_snapshot(identities=(ident,))
        findings = ALG001.evaluate(snapshot)
        assert len(findings) == (1 if should_flag else 0), f"Failed for bits={bits}"


def test_alg001_custom_legacy_algorithms() -> None:
    """ALG001Rule can be configured with custom legacy algorithms."""
    custom_rule = ALG001Rule(legacy_algorithms={"ssh-ed25519": None})
    ident = Identity(
        fingerprint="SHA256:custom0000000000000000000000000000000000",
        algorithm="ssh-ed25519",
        bits_or_curve="256",
    )
    snapshot = _make_snapshot(identities=(ident,))

    # Default rule ignores ed25519
    assert len(ALG001.evaluate(snapshot)) == 0
    # Custom rule flags it
    assert len(custom_rule.evaluate(snapshot)) == 1


def test_reg001_matching_local_file_is_not_flagged() -> None:
    """A GitHub key that matches a local public key is not flagged."""
    fp = "SHA256:matchedkey0000000000000000000000000000000"
    cov = SourceCoverage(source="github", state=CoverageState.AVAILABLE, required=False)
    ref = LocalReference(
        kind=LocalReferenceKind.PUBLIC_KEY,
        path="~/.ssh/id_ed25519.pub",
        source_file=None,
        source_line=None,
        resolution=Resolution.RESOLVED,
    )
    rb = RegistryBinding(
        registry="github",
        fingerprint=fp,
        title="work-key",
        created_at="2024-01-01T00:00:00Z",
    )
    ident = Identity(
        fingerprint=fp,
        algorithm="ssh-ed25519",
        bits_or_curve="256",
        local_references=(ref,),
        registry_bindings=(rb,),
    )
    snapshot = _make_snapshot(sources=(cov,), identities=(ident,))
    findings = REG001.evaluate(snapshot)
    assert len(findings) == 0


def test_reg001_non_github_registry_ignored() -> None:
    """Registry bindings from non-GitHub registries are ignored by REG001."""
    fp = "SHA256:gitlabkey00000000000000000000000000000000"
    cov = SourceCoverage(source="github", state=CoverageState.AVAILABLE, required=False)
    rb = RegistryBinding(
        registry="gitlab",
        fingerprint=fp,
        title="gitlab-key",
        created_at="2024-01-01T00:00:00Z",
    )
    ident = Identity(
        fingerprint=fp,
        algorithm="ssh-ed25519",
        bits_or_curve="256",
        registry_bindings=(rb,),
    )
    snapshot = _make_snapshot(sources=(cov,), identities=(ident,))
    findings = REG001.evaluate(snapshot)
    assert len(findings) == 0


def test_run_rules_integration() -> None:
    """Integration test with run_rules engine."""
    fp_dss = "SHA256:dssdssdssdssdssdssdssdssdssdssdssdssdssdss"
    fp_laptop = "SHA256:laptoplaptoplaptoplaptoplaptoplaptoplaptop"

    cov = SourceCoverage(source="github", state=CoverageState.AVAILABLE, required=False)
    ident_dss = Identity(
        fingerprint=fp_dss,
        algorithm="ssh-dss",
        bits_or_curve="1024",
    )
    rb_laptop = RegistryBinding(
        registry="github",
        fingerprint=fp_laptop,
        title="old-laptop",
        created_at="2022-01-01T00:00:00Z",
    )
    ident_laptop = Identity(
        fingerprint=fp_laptop,
        algorithm="ssh-ed25519",
        bits_or_curve="256",
        registry_bindings=(rb_laptop,),
    )

    snapshot = _make_snapshot(
        sources=(cov,),
        identities=(ident_dss, ident_laptop),
    )

    all_findings = run_rules(snapshot)
    rule_ids = [f.rule_id for f in all_findings]
    assert "ALG001" in rule_ids
    assert "REG001" in rule_ids
