"""Configuration rules (CFG001, CFG002).

Contract: sdd-spec FR-008, §7.5, §10 SEC-006.
Pure functions over ScanSnapshot, no I/O.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import ssh_id_doctor.rules as rules_pkg
from ssh_id_doctor.domain import (
    Confidence,
    EvidenceReference,
    Finding,
    LocalReference,
    LocalReferenceKind,
    Resolution,
    ScanSnapshot,
    Severity,
)

if TYPE_CHECKING:
    from ssh_id_doctor.rules import Rule

_BROKEN_RESOLUTIONS: frozenset[Resolution] = frozenset(
    {
        Resolution.MISSING,
        Resolution.UNREADABLE,
        Resolution.OUTSIDE_ROOT,
    }
)

_CFG002_KINDS: frozenset[str] = frozenset(
    {
        "include_cycle",
        "unsupported_match",
        "unresolved_token",
        "include_missing",
    }
)


def _enclosing_host_patterns(ref: LocalReference, snapshot: ScanSnapshot) -> tuple[str, ...]:
    """Patterns of the Host block that owns the reference line, or ().

    In ssh_config a block ends at the next ``Host`` or ``Match`` line. The
    nearest of either at or above the reference in the same file is its block
    header: a ``Host`` header gives its patterns; a ``Match`` header (known
    from ``snapshot.unresolved``, kind ``unsupported_match``) or no header at
    all (a global reference) gives an empty tuple.
    """
    if ref.source_file is None or ref.source_line is None:
        return ()
    line = ref.source_line
    best_line = -1
    best_patterns: tuple[str, ...] = ()
    for hb in snapshot.host_bindings:
        if hb.source_file == ref.source_file and best_line < hb.source_line <= line:
            best_line = hb.source_line
            best_patterns = hb.patterns
    for item in snapshot.unresolved:
        if (
            item.kind == "unsupported_match"
            and item.source_file == ref.source_file
            and item.source_line is not None
            and best_line < item.source_line <= line
        ):
            best_line = item.source_line
            best_patterns = ()
    return best_patterns


class CFG001Rule:
    """CFG001: IdentityFile target cannot be resolved (missing/unreadable/outside_root).

    Severity: error, Confidence: certain.
    """

    rule_id = "CFG001"

    def evaluate(self, snapshot: ScanSnapshot) -> list[Finding]:
        seen_refs: set[tuple[str, int | None, str, str]] = set()
        broken_refs: list[LocalReference] = []

        all_refs: list[LocalReference] = list(snapshot.local_references)
        for ident in snapshot.identities:
            all_refs.extend(ident.local_references)

        for ref in all_refs:
            if ref.kind is not LocalReferenceKind.CONFIG_IDENTITY:
                continue
            if ref.resolution not in _BROKEN_RESOLUTIONS:
                continue
            key = (ref.source_file or "", ref.source_line, ref.path, ref.resolution.value)
            if key not in seen_refs:
                seen_refs.add(key)
                broken_refs.append(ref)

        broken_refs.sort(
            key=lambda r: (
                r.source_file or "",
                -1 if r.source_line is None else r.source_line,
                r.path,
            )
        )

        findings: list[Finding] = []
        for ref in broken_refs:
            affected_hosts = _enclosing_host_patterns(ref, snapshot)

            evidence = (
                EvidenceReference(
                    source=ref.source_file or "",
                    line=ref.source_line,
                    detail=ref.path,
                ),
            )
            fid = rules_pkg.finding_id(self.rule_id, evidence=evidence)

            remediation: list[str] = [f"ls -l {ref.path}"]
            if affected_hosts:
                remediation.append(f"ssh -G {affected_hosts[0]}")
            else:
                remediation.append("ssh -G <alias>")

            findings.append(
                Finding(
                    id=fid,
                    rule_id=self.rule_id,
                    severity=Severity.ERROR,
                    confidence=Confidence.CERTAIN,
                    title=f"Unresolved IdentityFile: {ref.path}",
                    summary=(
                        f"IdentityFile '{ref.path}' referenced at {ref.source_file}:"
                        f"{ref.source_line} cannot be resolved ({ref.resolution.value})."
                    ),
                    evidence=evidence,
                    affected_fingerprints=(),
                    affected_hosts=affected_hosts,
                    manual_remediation=tuple(remediation),
                )
            )

        return findings


class CFG002Rule:
    """CFG002: Include cycle, unsupported Match, or unresolved token affects analysis.

    Severity: info, Confidence: unresolved.
    """

    rule_id = "CFG002"

    def evaluate(self, snapshot: ScanSnapshot) -> list[Finding]:
        findings: list[Finding] = []
        for item in snapshot.unresolved:
            if item.kind not in _CFG002_KINDS:
                continue

            evidence = (
                EvidenceReference(
                    source=item.source_file,
                    line=item.source_line,
                    detail=item.detail,
                ),
            )
            fid = rules_pkg.finding_id(self.rule_id, evidence=evidence, kind=item.kind)

            line_str = f":{item.source_line}" if item.source_line is not None else ""
            if item.kind == "include_cycle":
                title = f"Include cycle in SSH config: {item.detail}"
                summary = f"Recursive Include directive detected at {item.source_file}{line_str}."
                remediation = (f"Review include chain around {item.source_file}{line_str}",)
            elif item.kind == "unsupported_match":
                title = "Unsupported Match directive in SSH config"
                summary = (
                    f"Match directive at {item.source_file}{line_str} "
                    f"is not evaluated: {item.detail}"
                )
                remediation = (
                    f"Review Match block at {item.source_file}{line_str} manually: ssh -G <alias>",
                )
            elif item.kind == "unresolved_token":
                title = f"Unresolved token in SSH config: {item.detail}"
                summary = (
                    f"Configuration contains unexpanded token '{item.detail}' "
                    f"at {item.source_file}{line_str}."
                )
                remediation = ("Verify token value manually for target host: ssh -G <alias>",)
            elif item.kind == "include_missing":
                title = f"Missing Include target: {item.detail}"
                summary = (
                    f"Included path '{item.detail}' referenced at "
                    f"{item.source_file}{line_str} does not exist."
                )
                remediation = (f"ls -l {item.detail}",)
            else:
                title = f"Unresolved config item: {item.kind}"
                summary = f"{item.kind} at {item.source_file}{line_str}: {item.detail}"
                remediation = (f"Inspect {item.source_file}{line_str}",)

            findings.append(
                Finding(
                    id=fid,
                    rule_id=self.rule_id,
                    severity=Severity.INFO,
                    confidence=Confidence.UNRESOLVED,
                    title=title,
                    summary=summary,
                    evidence=evidence,
                    affected_fingerprints=(),
                    affected_hosts=(),
                    manual_remediation=remediation,
                )
            )

        return findings


CFG001 = CFG001Rule()
CFG002 = CFG002Rule()

RULES: list[Rule] = [CFG001, CFG002]

__all__ = [
    "CFG001",
    "CFG002",
    "RULES",
    "CFG001Rule",
    "CFG002Rule",
]
