"""Tests for known_hosts rules KHS001-KHS006 (task #1789/#1795, AC-1, AC-2)."""

from __future__ import annotations

import re
from pathlib import Path

from conftest import OpenGuard
from ssh_id_doctor.domain import (
    Confidence,
    CoverageState,
    KnownHostEntry,
    Platform,
    ScanSnapshot,
    Severity,
    SourceCoverage,
    UnresolvedItem,
)
from ssh_id_doctor.orchestrator import OrchestratorOptions, ScanOrchestrator
from ssh_id_doctor.rules import get_default_rules, run_rules
from ssh_id_doctor.rules.known_hosts_rules import (
    KHS001,
    KHS002,
    KHS003,
    KHS004,
    KHS005,
    KHS006,
    RULES,
    KHS001Rule,
    KHS002Rule,
    KHS003Rule,
    KHS004Rule,
    KHS005Rule,
    KHS006Rule,
)

_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "known_hosts" / "khs_findings.txt"
_SOURCE_FILE = "/home/u/.ssh/known_hosts"

_FP_A = "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA"
_FP_B = "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbB"


def _cov(state: CoverageState) -> SourceCoverage:
    return SourceCoverage(source="known_hosts", state=state, required=False, detail="")


def _entry(
    *,
    line: int,
    hosts: tuple[str, ...],
    key_type: str = "ssh-ed25519",
    fingerprint: str = _FP_A,
    hashed: bool = False,
    marker: str | None = None,
    source_file: str = _SOURCE_FILE,
) -> KnownHostEntry:
    return KnownHostEntry(
        source_file=source_file,
        line=line,
        marker=marker,
        hosts=hosts,
        hashed=hashed,
        key_type=key_type,
        fingerprint=fingerprint,
    )


def _make_snapshot(
    *,
    sources: tuple[SourceCoverage, ...] = (),
    known_hosts: tuple[KnownHostEntry, ...] = (),
    unresolved: tuple[UnresolvedItem, ...] = (),
) -> ScanSnapshot:
    return ScanSnapshot(
        scan_id="00000000-0000-0000-0000-000000000000",
        started_at="2026-01-01T00:00:00+00:00",
        completed_at="2026-01-01T00:00:00+00:00",
        platform=Platform.LINUX,
        sources=sources,
        known_hosts=known_hosts,
        unresolved=unresolved,
    )


def test_khs_rules_fire_and_silent() -> None:
    """AC-1: KHS001-KHS006 each fire on their triggering case and stay silent otherwise;
    KHS002's host/type comparison handles each listed sub-case; coverage unavailable,
    empty, skipped, timeout and absent all keep every KHS rule silent."""
    available = (_cov(CoverageState.AVAILABLE),)

    # --- KHS001: fires on an unhashed entry, silent when every entry is hashed ---
    snap_unhashed = _make_snapshot(
        sources=available,
        known_hosts=(_entry(line=1, hosts=("plain.example.com",), hashed=False),),
    )
    findings = KHS001.evaluate(snap_unhashed)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "KHS001"
    assert f.severity is Severity.INFO
    assert f.confidence is Confidence.CERTAIN
    assert "plain.example.com" not in f.title
    assert "plain.example.com" not in f.summary
    for ev in f.evidence:
        assert "plain.example.com" not in ev.detail
    assert f.evidence[0].line == 1

    snap_hashed_only = _make_snapshot(
        sources=available,
        known_hosts=(
            _entry(
                line=1,
                hosts=("|1|AAECAwQFBgcICQoLDA0ODxAREhM=|FBUWFxgZGhscHR4fICEiIyQlJic=",),
                hashed=True,
            ),
        ),
    )
    assert KHS001.evaluate(snap_hashed_only) == []

    # a line mixing a hashed token with a plaintext host still fires: `entry.hashed`
    # is True whenever *any* token is hashed, so checking it alone would miss the
    # plaintext name sharing the line (review finding, gen1).
    snap_mixed_hosts = _make_snapshot(
        sources=available,
        known_hosts=(
            _entry(
                line=1,
                hosts=(
                    "|1|AAECAwQFBgcICQoLDA0ODxAREhM=|FBUWFxgZGhscHR4fICEiIyQlJic=",
                    "plain.example.com",
                ),
                hashed=True,
            ),
        ),
    )
    findings = KHS001.evaluate(snap_mixed_hosts)
    assert len(findings) == 1
    assert findings[0].evidence[0].line == 1

    # --- KHS002: one host, two fingerprints of the same key type -> fires ---
    snap_conflict = _make_snapshot(
        sources=available,
        known_hosts=(
            _entry(line=1, hosts=("dup.example.com",), fingerprint=_FP_A),
            _entry(line=2, hosts=("dup.example.com",), fingerprint=_FP_B),
        ),
    )
    findings = KHS002.evaluate(snap_conflict)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "KHS002"
    assert f.severity is Severity.WARNING
    assert f.confidence is Confidence.CERTAIN
    assert f.affected_hosts == ("dup.example.com",)
    assert set(f.affected_fingerprints) == {_FP_A, _FP_B}

    # same host, DIFFERENT key types -> no finding
    snap_diff_type = _make_snapshot(
        sources=available,
        known_hosts=(
            _entry(line=1, hosts=("dup.example.com",), key_type="ssh-ed25519", fingerprint=_FP_A),
            _entry(line=2, hosts=("dup.example.com",), key_type="ssh-rsa", fingerprint=_FP_B),
        ),
    )
    assert KHS002.evaluate(snap_diff_type) == []

    # same key (identical fingerprint) twice -> no finding
    snap_same_key = _make_snapshot(
        sources=available,
        known_hosts=(
            _entry(line=1, hosts=("dup.example.com",), fingerprint=_FP_A),
            _entry(line=2, hosts=("dup.example.com",), fingerprint=_FP_A),
        ),
    )
    assert KHS002.evaluate(snap_same_key) == []

    # [h]:2222 vs h -> no finding (different normalized hosts, port != 22)
    snap_port_distinct = _make_snapshot(
        sources=available,
        known_hosts=(
            _entry(line=1, hosts=("[dup.example.com]:2222",), fingerprint=_FP_A),
            _entry(line=2, hosts=("dup.example.com",), fingerprint=_FP_B),
        ),
    )
    assert KHS002.evaluate(snap_port_distinct) == []

    # [h]:22 vs h -> same normalized host (default port), fires
    snap_port_default = _make_snapshot(
        sources=available,
        known_hosts=(
            _entry(line=1, hosts=("[dup.example.com]:22",), fingerprint=_FP_A),
            _entry(line=2, hosts=("dup.example.com",), fingerprint=_FP_B),
        ),
    )
    findings = KHS002.evaluate(snap_port_default)
    assert len(findings) == 1
    assert set(findings[0].affected_hosts) == {"[dup.example.com]:22", "dup.example.com"}

    # identical hashed token, different fingerprints -> fires (compared by literal hash string)
    hashed_host_entry = "|1|AAECAwQFBgcICQoLDA0ODxAREhM=|FBUWFxgZGhscHR4fICEiIyQlJic="
    snap_hashed_conflict = _make_snapshot(
        sources=available,
        known_hosts=(
            _entry(line=1, hosts=(hashed_host_entry,), hashed=True, fingerprint=_FP_A),
            _entry(line=2, hosts=(hashed_host_entry,), hashed=True, fingerprint=_FP_B),
        ),
    )
    findings = KHS002.evaluate(snap_hashed_conflict)
    assert len(findings) == 1
    assert findings[0].affected_hosts == (hashed_host_entry,)

    # different hashed tokens, different fingerprints -> no finding (can't correlate)
    hashed_host_entry_other = "|1|AAECAwQFBgcICQoLDA0ODxAREg==|FBUWFxgZGhscHR4fICEiIyQlJic="
    snap_hashed_distinct = _make_snapshot(
        sources=available,
        known_hosts=(
            _entry(line=1, hosts=(hashed_host_entry,), hashed=True, fingerprint=_FP_A),
            _entry(line=2, hosts=(hashed_host_entry_other,), hashed=True, fingerprint=_FP_B),
        ),
    )
    assert KHS002.evaluate(snap_hashed_distinct) == []

    # a line carrying a marker never participates, even with a conflicting fingerprint
    snap_marker_excluded = _make_snapshot(
        sources=available,
        known_hosts=(
            _entry(line=1, hosts=("dup.example.com",), fingerprint=_FP_A, marker="revoked"),
            _entry(line=2, hosts=("dup.example.com",), fingerprint=_FP_B, marker="cert-authority"),
        ),
    )
    assert KHS002.evaluate(snap_marker_excluded) == []

    # patterns and negations are never compared
    snap_pattern = _make_snapshot(
        sources=available,
        known_hosts=(
            _entry(line=1, hosts=("*.example.com",), fingerprint=_FP_A),
            _entry(line=2, hosts=("*.example.com",), fingerprint=_FP_B),
            _entry(line=3, hosts=("!excluded.example.com",), fingerprint=_FP_A),
            _entry(line=4, hosts=("!excluded.example.com",), fingerprint=_FP_B),
        ),
    )
    assert KHS002.evaluate(snap_pattern) == []

    # a line listing two hosts conflicts on both: each host gets its own finding
    # with its own id, not collapsed into one (review finding, gen1 — the id
    # omitted the normalized host, so two groups sharing the same contributing
    # entries/evidence/fingerprints/key_type produced identical ids).
    snap_multi_host_conflict = _make_snapshot(
        sources=available,
        known_hosts=(
            _entry(line=1, hosts=("a.example.com", "b.example.com"), fingerprint=_FP_A),
            _entry(line=2, hosts=("a.example.com", "b.example.com"), fingerprint=_FP_B),
        ),
    )
    findings = KHS002.evaluate(snap_multi_host_conflict)
    assert len(findings) == 2
    assert len({f.id for f in findings}) == 2
    assert {f.affected_hosts for f in findings} == {
        ("a.example.com",),
        ("b.example.com",),
    }

    # --- KHS003: fires on ssh-dss, silent otherwise ---
    snap_dss = _make_snapshot(
        sources=available,
        known_hosts=(_entry(line=1, hosts=("dss.example.com",), key_type="ssh-dss"),),
    )
    findings = KHS003.evaluate(snap_dss)
    assert len(findings) == 1
    assert findings[0].severity is Severity.WARNING
    assert findings[0].confidence is Confidence.CERTAIN

    snap_no_dss = _make_snapshot(
        sources=available,
        known_hosts=(_entry(line=1, hosts=("ed.example.com",), key_type="ssh-ed25519"),),
    )
    assert KHS003.evaluate(snap_no_dss) == []

    # --- KHS004: fires on a marker line, silent otherwise ---
    snap_marker = _make_snapshot(
        sources=available,
        known_hosts=(_entry(line=1, hosts=("ca.example.com",), marker="cert-authority"),),
    )
    findings = KHS004.evaluate(snap_marker)
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO
    assert findings[0].confidence is Confidence.CERTAIN

    snap_no_marker = _make_snapshot(
        sources=available,
        known_hosts=(_entry(line=1, hosts=("ca.example.com",)),),
    )
    assert KHS004.evaluate(snap_no_marker) == []

    # --- KHS005: fires on a known_hosts-specific unresolved kind, silent otherwise ---
    snap_malformed = _make_snapshot(
        sources=(_cov(CoverageState.MALFORMED),),
        unresolved=(
            UnresolvedItem(
                kind="incomplete_line", detail="", source_file=_SOURCE_FILE, source_line=5
            ),
        ),
    )
    findings = KHS005.evaluate(snap_malformed)
    assert len(findings) == 1
    assert findings[0].severity is Severity.WARNING
    assert findings[0].confidence is Confidence.HEURISTIC

    snap_other_unresolved = _make_snapshot(
        sources=available,
        unresolved=(
            UnresolvedItem(kind="include_cycle", detail="", source_file="config", source_line=5),
        ),
    )
    assert KHS005.evaluate(snap_other_unresolved) == []

    # --- KHS006: fires on ssh-rsa, silent otherwise ---
    snap_rsa = _make_snapshot(
        sources=available,
        known_hosts=(_entry(line=1, hosts=("rsa.example.com",), key_type="ssh-rsa"),),
    )
    findings = KHS006.evaluate(snap_rsa)
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO
    assert findings[0].confidence is Confidence.CERTAIN

    snap_no_rsa = _make_snapshot(
        sources=available,
        known_hosts=(_entry(line=1, hosts=("ed.example.com",), key_type="ssh-ed25519"),),
    )
    assert KHS006.evaluate(snap_no_rsa) == []

    # --- coverage gating: unavailable/empty/skipped/timeout/absent silence every KHS rule ---
    rule_objects = (KHS001, KHS002, KHS003, KHS004, KHS005, KHS006)
    triggering_entries = (
        # Same host, same key type, different fingerprint: on its own this also
        # triggers KHS002 (not just KHS001), so the gating check below is not
        # vacuous for KHS002 either.
        _entry(line=1, hosts=("dup.example.com",), fingerprint=_FP_A),
        _entry(line=2, hosts=("dup.example.com",), fingerprint=_FP_B),
        _entry(line=3, hosts=("dss.example.com",), key_type="ssh-dss"),
        _entry(line=4, hosts=("ca.example.com",), marker="cert-authority"),
        _entry(line=5, hosts=("rsa.example.com",), key_type="ssh-rsa"),
    )
    triggering_unresolved = (
        UnresolvedItem(kind="incomplete_line", detail="", source_file=_SOURCE_FILE, source_line=9),
    )

    # Sanity check: with coverage available, these same entries fire every rule,
    # so the gating loop below actually proves gating silences them (not that
    # they were already silent for unrelated reasons).
    snap_sanity = _make_snapshot(
        sources=available, known_hosts=triggering_entries, unresolved=triggering_unresolved
    )
    for rule in rule_objects:
        assert rule.evaluate(snap_sanity), f"{rule.rule_id} unexpectedly silent with coverage"

    for state in (
        CoverageState.UNAVAILABLE,
        CoverageState.EMPTY,
        CoverageState.SKIPPED,
        CoverageState.TIMEOUT,
    ):
        snap_gated = _make_snapshot(
            sources=(_cov(state),),
            known_hosts=triggering_entries,
            unresolved=triggering_unresolved,
        )
        for rule in rule_objects:
            assert rule.evaluate(snap_gated) == [], f"{rule.rule_id} fired for {state}"

    snap_no_coverage = _make_snapshot(
        sources=(),
        known_hosts=triggering_entries,
        unresolved=triggering_unresolved,
    )
    for rule in rule_objects:
        assert rule.evaluate(snap_no_coverage) == [], f"{rule.rule_id} fired without coverage"


def test_khs_evidence_counts_and_wording() -> None:
    """Review finding (test gap): the fire/silent test never pinned down the
    KHS001 evidence cap or KHS006's wording, so a mutation widening the cap
    would pass. The KHS004/KHS005 exact-count checks live in
    ``test_khs004_khs005_exact_counts`` below."""
    available = (_cov(CoverageState.AVAILABLE),)

    # KHS001: evidence is capped at 20 lines even though more are unhashed, and
    # the summary still reports the real (uncapped) count.
    many_entries = tuple(_entry(line=n, hosts=(f"host{n}.example.com",)) for n in range(1, 26))
    snap_many = _make_snapshot(sources=available, known_hosts=many_entries)
    findings = KHS001.evaluate(snap_many)
    assert len(findings) == 1
    assert [ev.line for ev in findings[0].evidence] == list(range(1, 21))
    assert "25 known_hosts line(s)" in findings[0].summary


def test_khs004_khs005_exact_counts() -> None:
    """AC-2 (#1833): review #1795 found the KHS004/KHS005 count checks used
    ``in`` substring matching (``"2 line(s)" in summary``), which also passes
    when the rule reports ``"12 line(s)"`` — a mutation swapping the count for
    one with the same last digit goes undetected. These assert the digit run
    is exactly ``2``, not merely ending in it."""
    available = (_cov(CoverageState.AVAILABLE),)

    # KHS004: evidence lists exactly the marked lines, in order, excluding the
    # unmarked one; the summary count matches exactly (not as a substring of
    # a larger count with the same last digit).
    snap_markers = _make_snapshot(
        sources=available,
        known_hosts=(
            _entry(line=1, hosts=("a.example.com",), marker="revoked"),
            _entry(line=2, hosts=("b.example.com",)),
            _entry(line=3, hosts=("c.example.com",), marker="cert-authority"),
        ),
    )
    findings = KHS004.evaluate(snap_markers)
    assert len(findings) == 1
    assert [ev.line for ev in findings[0].evidence] == [1, 3]
    assert re.search(r"(?<!\d)2 line\(s\)(?!\d)", findings[0].summary)

    # KHS005: evidence lists exactly the malformed lines, excluding an unresolved
    # item from another source; the summary count matches exactly.
    snap_malformed_lines = _make_snapshot(
        sources=(_cov(CoverageState.MALFORMED),),
        unresolved=(
            UnresolvedItem(
                kind="incomplete_line", detail="", source_file=_SOURCE_FILE, source_line=5
            ),
            UnresolvedItem(
                kind="invalid_base64", detail="", source_file=_SOURCE_FILE, source_line=9
            ),
            UnresolvedItem(kind="include_cycle", detail="", source_file="config", source_line=7),
        ),
    )
    findings = KHS005.evaluate(snap_malformed_lines)
    assert len(findings) == 1
    assert [ev.line for ev in findings[0].evidence] == [5, 9]
    assert re.search(r"(?<!\d)2 line\(s\)(?!\d)", findings[0].summary)


def test_khs006_wording() -> None:
    """KHS006: exact title and the rsa-sha2-256/512 wording the AC calls for."""
    available = (_cov(CoverageState.AVAILABLE),)
    snap_rsa = _make_snapshot(
        sources=available,
        known_hosts=(_entry(line=1, hosts=("rsa.example.com",), key_type="ssh-rsa"),),
    )
    findings = KHS006.evaluate(snap_rsa)
    assert len(findings) == 1
    assert findings[0].title == "known_hosts entry uses ssh-rsa"
    assert "not unsafe" in findings[0].summary
    assert "rsa-sha2-256/512" in findings[0].summary


def test_khs_ids_stable_across_homes(tmp_path: Path, open_guard: OpenGuard) -> None:
    """AC-2: the same known_hosts fixture scanned under two different HOME roots
    produces identical KHS001-KHS006 finding ids (paths under HOME hash as '~/...')."""
    fixture_text = _FIXTURE.read_text()

    def _scan_under(home: Path) -> ScanSnapshot:
        ssh_dir = home / ".ssh"
        ssh_dir.mkdir(parents=True)
        (ssh_dir / "known_hosts").write_text(fixture_text)
        (ssh_dir / "config").write_text("")
        orchestrator = ScanOrchestrator()
        return orchestrator.run(
            OrchestratorOptions(
                home=home,
                ssh_dir=ssh_dir,
                config_path=ssh_dir / "config",
                check_agent=False,
                check_github=False,
            )
        )

    home_a = tmp_path / "home-a"
    home_b = tmp_path / "deeply" / "nested" / "home-b"
    home_a.mkdir()
    home_b.mkdir(parents=True)
    # AGENTS.md: these two HOME roots are built outside fake_home/_isolated_home,
    # so guard them explicitly or a private-key read here would go uncaught.
    open_guard.guard_root(home_a, home_b)

    snap_a = _scan_under(home_a)
    snap_b = _scan_under(home_b)

    khs_a = {f.rule_id: f.id for f in snap_a.findings if f.rule_id.startswith("KHS")}
    khs_b = {f.rule_id: f.id for f in snap_b.findings if f.rule_id.startswith("KHS")}

    assert khs_a
    assert set(khs_a) == {"KHS001", "KHS002", "KHS003", "KHS004", "KHS005", "KHS006"}
    assert khs_a == khs_b

    # Evidence keeps each scan's own real path (not rewritten).
    khs001_a = next(f for f in snap_a.findings if f.rule_id == "KHS001")
    khs001_b = next(f for f in snap_b.findings if f.rule_id == "KHS001")
    assert str(home_a) in khs001_a.evidence[0].source
    assert str(home_b) in khs001_b.evidence[0].source


def test_khs_rules_registration_and_defaults() -> None:
    """KHS001-KHS006 are registered in RULES and in get_default_rules()."""
    assert isinstance(KHS001, KHS001Rule)
    assert isinstance(KHS002, KHS002Rule)
    assert isinstance(KHS003, KHS003Rule)
    assert isinstance(KHS004, KHS004Rule)
    assert isinstance(KHS005, KHS005Rule)
    assert isinstance(KHS006, KHS006Rule)
    for rule in (KHS001, KHS002, KHS003, KHS004, KHS005, KHS006):
        assert rule in RULES

    defaults = get_default_rules()
    rule_ids = {r.rule_id for r in defaults}
    assert {"KHS001", "KHS002", "KHS003", "KHS004", "KHS005", "KHS006"} <= rule_ids


def test_khs_findings_never_say_insecure_and_remediation_is_non_destructive() -> None:
    """Phrasing standard shared with other rule modules: no 'insecure'/'unused' wording,
    and manual_remediation never deletes or rotates anything (SEC-006)."""
    available = (_cov(CoverageState.AVAILABLE),)
    snap = _make_snapshot(
        sources=available,
        known_hosts=(
            _entry(line=1, hosts=("plain.example.com",)),
            _entry(line=2, hosts=("dup.example.com",), fingerprint=_FP_A),
            _entry(line=3, hosts=("dup.example.com",), fingerprint=_FP_B),
            _entry(line=4, hosts=("dss.example.com",), key_type="ssh-dss"),
            _entry(line=5, hosts=("ca.example.com",), marker="cert-authority"),
            _entry(line=6, hosts=("rsa.example.com",), key_type="ssh-rsa"),
        ),
        unresolved=(
            UnresolvedItem(
                kind="incomplete_line", detail="", source_file=_SOURCE_FILE, source_line=9
            ),
        ),
    )
    findings = run_rules(snap)
    khs_findings = [f for f in findings if f.rule_id.startswith("KHS")]
    assert khs_findings
    for f in khs_findings:
        assert "insecure" not in f.summary.lower()
        assert "insecure" not in f.title.lower()
        for rem in f.manual_remediation:
            assert "insecure" not in rem.lower()
            assert "rm " not in rem
            assert "ssh-keygen -R" not in rem
            assert "delete" not in rem.lower()
