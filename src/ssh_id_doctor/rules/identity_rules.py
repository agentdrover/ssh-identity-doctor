"""Identity rules (ID001, ID002, LAB001).

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
    Identity,
    LocalReferenceKind,
    ScanSnapshot,
    Severity,
)

if TYPE_CHECKING:
    from ssh_id_doctor.rules import Rule

_CFG_UNRESOLVED_KINDS: frozenset[str] = frozenset(
    {
        "include_cycle",
        "unsupported_match",
        "unresolved_token",
        "include_missing",
    }
)


class ID001Rule:
    """ID001: Same fingerprint under multiple local paths or comments.

    Severity: info, Confidence: certain.
    """

    rule_id = "ID001"

    def evaluate(self, snapshot: ScanSnapshot) -> list[Finding]:
        findings: list[Finding] = []

        for ident in snapshot.identities:
            pub_refs = [
                ref for ref in ident.local_references if ref.kind is LocalReferenceKind.PUBLIC_KEY
            ]
            pub_paths = sorted({ref.path for ref in pub_refs})

            if not pub_paths:
                continue

            has_multiple_paths = len(pub_paths) >= 2
            distinct_comments = sorted({c for c in ident.comments if c.strip()})
            has_multiple_comments = len(distinct_comments) >= 2

            if not (has_multiple_paths or has_multiple_comments):
                continue

            evidence_items: list[EvidenceReference] = []
            for p in pub_paths:
                matching = [r for r in pub_refs if r.path == p]
                ref = matching[0]
                evidence_items.append(
                    EvidenceReference(
                        source=ref.source_file or ref.path,
                        line=ref.source_line,
                        detail=ref.path,
                    )
                )
            evidence = tuple(evidence_items)

            fid = rules_pkg.finding_id(
                self.rule_id,
                evidence=evidence,
                fingerprints=(ident.fingerprint,),
            )

            title = f"Duplicate public key paths or labels: {ident.fingerprint}"
            if has_multiple_paths and has_multiple_comments:
                paths_str = ", ".join(pub_paths)
                comments_str = ", ".join(distinct_comments)
                summary = (
                    f"Identity {ident.fingerprint} appears under multiple local paths "
                    f"({paths_str}) and distinct comments ({comments_str})."
                )
            elif has_multiple_paths:
                summary = (
                    f"Identity {ident.fingerprint} is stored under multiple paths: "
                    f"{', '.join(pub_paths)}."
                )
            else:
                summary = (
                    f"Identity {ident.fingerprint} has multiple labels: "
                    f"{', '.join(distinct_comments)}."
                )

            remediation = (
                "Review duplicate key files and consolidate references to the canonical path",
            )

            findings.append(
                Finding(
                    id=fid,
                    rule_id=self.rule_id,
                    severity=Severity.INFO,
                    confidence=Confidence.CERTAIN,
                    title=title,
                    summary=summary,
                    evidence=evidence,
                    affected_fingerprints=(ident.fingerprint,),
                    affected_hosts=(),
                    manual_remediation=remediation,
                )
            )

        findings.sort(key=lambda f: (f.rule_id, f.id))
        return findings


class ID002Rule:
    """ID002: Public identity exists locally with no known binding.

    Phrasing is strictly 'no known binding', never 'unused' (FR-008, SEC-006).
    Severity: warning, Confidence: heuristic.
    """

    rule_id = "ID002"

    def evaluate(self, snapshot: ScanSnapshot) -> list[Finding]:
        bound_fingerprints: set[str] = set()
        for hb in snapshot.host_bindings:
            bound_fingerprints.update(hb.resolved_fingerprints)

        has_unresolved_config = any(
            item.kind in _CFG_UNRESOLVED_KINDS for item in snapshot.unresolved
        )

        findings: list[Finding] = []

        for ident in snapshot.identities:
            pub_refs = [
                ref for ref in ident.local_references if ref.kind is LocalReferenceKind.PUBLIC_KEY
            ]
            if not pub_refs:
                continue

            if ident.fingerprint in bound_fingerprints:
                continue

            if ident.registry_bindings:
                continue

            pub_paths = sorted({ref.path for ref in pub_refs})
            evidence_items: list[EvidenceReference] = []
            for p in pub_paths:
                matching = [r for r in pub_refs if r.path == p]
                ref = matching[0]
                evidence_items.append(
                    EvidenceReference(
                        source=ref.source_file or ref.path,
                        line=ref.source_line,
                        detail=ref.path,
                    )
                )
            evidence = tuple(evidence_items)

            fid = rules_pkg.finding_id(
                self.rule_id,
                evidence=evidence,
                fingerprints=(ident.fingerprint,),
            )

            title = f"Identity has no known binding: {ident.fingerprint}"
            if has_unresolved_config:
                summary = (
                    f"Public key {ident.fingerprint} has no known binding to any configured host "
                    "or remote registry. A binding may exist in unevaluated configuration blocks "
                    "(e.g. Match directives or unresolved tokens)."
                )
            else:
                summary = (
                    f"Public key {ident.fingerprint} has no known binding to any configured host "
                    "or remote registry."
                )

            remediation = (
                "Verify whether this key is required by external services "
                "or unlisted hosts before taking action",
            )

            findings.append(
                Finding(
                    id=fid,
                    rule_id=self.rule_id,
                    severity=Severity.WARNING,
                    confidence=Confidence.HEURISTIC,
                    title=title,
                    summary=summary,
                    evidence=evidence,
                    affected_fingerprints=(ident.fingerprint,),
                    affected_hosts=(),
                    manual_remediation=remediation,
                )
            )

        findings.sort(key=lambda f: (f.rule_id, f.id))
        return findings


class LAB001Rule:
    """LAB001: Empty or ambiguous comments across identities.

    Severity: info, Confidence: heuristic.
    """

    rule_id = "LAB001"

    def evaluate(self, snapshot: ScanSnapshot) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Empty comment per identity
        for ident in snapshot.identities:
            non_empty_comments = [c.strip() for c in ident.comments if c.strip()]
            if not non_empty_comments:
                pub_refs = [
                    ref
                    for ref in ident.local_references
                    if ref.kind is LocalReferenceKind.PUBLIC_KEY
                ]
                evidence_items: list[EvidenceReference] = []
                seen_paths: set[str] = set()
                for ref in pub_refs:
                    if ref.path not in seen_paths:
                        seen_paths.add(ref.path)
                        evidence_items.append(
                            EvidenceReference(
                                source=ref.source_file or ref.path,
                                line=ref.source_line,
                                detail=ref.path,
                            )
                        )
                if not evidence_items:
                    for ref in ident.local_references:
                        if ref.path not in seen_paths:
                            seen_paths.add(ref.path)
                            evidence_items.append(
                                EvidenceReference(
                                    source=ref.source_file or ref.path,
                                    line=ref.source_line,
                                    detail=ref.path,
                                )
                            )
                evidence = tuple(evidence_items)
                fid = rules_pkg.finding_id(
                    self.rule_id,
                    evidence=evidence,
                    fingerprints=(ident.fingerprint,),
                    kind="empty_comment",
                )
                findings.append(
                    Finding(
                        id=fid,
                        rule_id=self.rule_id,
                        severity=Severity.INFO,
                        confidence=Confidence.HEURISTIC,
                        title=f"Empty comment on identity: {ident.fingerprint}",
                        summary=(
                            f"Identity {ident.fingerprint} has no descriptive comment or label."
                        ),
                        evidence=evidence,
                        affected_fingerprints=(ident.fingerprint,),
                        affected_hosts=(),
                        manual_remediation=(
                            "Add a descriptive comment to the public key to identify its purpose",
                        ),
                    )
                )

        # 2. Ambiguous comment across different identities
        identities_by_comment: dict[str, list[Identity]] = {}
        for ident in snapshot.identities:
            seen_for_ident: set[str] = set()
            for raw_c in ident.comments:
                c = raw_c.strip()
                if not c or c in seen_for_ident:
                    continue
                seen_for_ident.add(c)
                identities_by_comment.setdefault(c, []).append(ident)

        for comment, idents in sorted(identities_by_comment.items()):
            distinct_fps = sorted({i.fingerprint for i in idents})
            if len(distinct_fps) < 2:
                continue

            all_refs = [
                ref
                for i in idents
                for ref in i.local_references
                if ref.kind is LocalReferenceKind.PUBLIC_KEY
            ]
            if not all_refs:
                all_refs = [ref for i in idents for ref in i.local_references]

            seen_paths = set()
            evidence_items = []
            for ref in sorted(all_refs, key=lambda r: r.path):
                if ref.path not in seen_paths:
                    seen_paths.add(ref.path)
                    evidence_items.append(
                        EvidenceReference(
                            source=ref.source_file or ref.path,
                            line=ref.source_line,
                            detail=ref.path,
                        )
                    )

            evidence = tuple(evidence_items)
            fid = rules_pkg.finding_id(
                self.rule_id,
                evidence=evidence,
                fingerprints=distinct_fps,
                comment=comment,
            )
            findings.append(
                Finding(
                    id=fid,
                    rule_id=self.rule_id,
                    severity=Severity.INFO,
                    confidence=Confidence.HEURISTIC,
                    title=f"Ambiguous key comment shared across multiple identities: '{comment}'",
                    summary=(
                        f"Comment '{comment}' is shared across multiple distinct identities: "
                        f"{', '.join(distinct_fps)}."
                    ),
                    evidence=evidence,
                    affected_fingerprints=tuple(distinct_fps),
                    affected_hosts=(),
                    manual_remediation=(
                        "Update public key comments to uniquely identify each key and its purpose",
                    ),
                )
            )

        findings.sort(key=lambda f: (f.rule_id, f.id))
        return findings


ID001 = ID001Rule()
ID002 = ID002Rule()
LAB001 = LAB001Rule()

RULES: list[Rule] = [ID001, ID002, LAB001]

__all__ = [
    "ID001",
    "ID002",
    "LAB001",
    "RULES",
    "ID001Rule",
    "ID002Rule",
    "LAB001Rule",
]
