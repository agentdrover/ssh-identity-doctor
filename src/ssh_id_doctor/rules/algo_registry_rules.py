"""Algorithm and registry rules (ALG001, REG001).

Contract: sdd-spec FR-008, §7.5, §10 SEC-006.
Pure functions over ScanSnapshot, no I/O.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping
from typing import TYPE_CHECKING

import ssh_id_doctor.rules as rules_pkg
from ssh_id_doctor.domain import (
    Confidence,
    CoverageState,
    EvidenceReference,
    Finding,
    Identity,
    RegistryBinding,
    ScanSnapshot,
    Severity,
)

if TYPE_CHECKING:
    from ssh_id_doctor.rules import Rule

LEGACY_ALGORITHMS: dict[str, int | None] = {
    "ssh-dss": None,
    "ssh-rsa": 2048,
}
"""Default mapping of legacy key algorithms (FR-008).

Key: algorithm name (normalized wire format).
Value: minimum bit length required (None if all keys of this algorithm are legacy).
"""

_SIZE_RE = re.compile(r"\d+")


def _normalize_algo(algo: str) -> str:
    norm = algo.strip().lower()
    if norm == "dsa":
        return "ssh-dss"
    if norm == "rsa":
        return "ssh-rsa"
    return norm


def _key_size(bits_or_curve: object) -> int | None:
    """The key size from §7.2 ``bits_or_curve``, or None when it is not a plain number.

    PublicKeyInspector stores the leading number of ``ssh-keygen -l`` output
    ("3072", "1024", "256"). Anything else — an empty field, a type name like
    "RSA" — is an unknown size, never a guess pulled out of some other text.
    """
    if isinstance(bits_or_curve, int) and not isinstance(bits_or_curve, bool):
        return bits_or_curve
    if isinstance(bits_or_curve, str) and _SIZE_RE.fullmatch(bits_or_curve.strip()):
        return int(bits_or_curve.strip())
    return None


def _below_threshold(ident: Identity, threshold: int) -> bool:
    """True only when the key size is known and below ``threshold``.

    An unreadable size is deliberately NOT a finding: ALG001 is ``certain``,
    and "this RSA key is short" cannot be certain without the size. Guessing
    would either miss short keys silently or flag every RSA key, and the
    security-review constraint forbids pushing people into rushed rotation.
    Since SID-4 stores the numeric size, this branch is only reached for
    identities whose size no inspector could read (e.g. GitHub-only keys).
    """
    bits = _key_size(ident.bits_or_curve)
    return bits is not None and bits < threshold


def _is_legacy_identity(
    ident: Identity,
    legacy: Mapping[str, int | None] | Collection[str],
) -> bool:
    algo = ident.algorithm.strip().lower()
    norm_algo = _normalize_algo(ident.algorithm)

    target_key: str | None = None
    if norm_algo in legacy:
        target_key = norm_algo
    elif algo in legacy:
        target_key = algo

    if target_key is None:
        return False

    if isinstance(legacy, Mapping):
        threshold = legacy[target_key]
        if threshold is None:
            return True
        return _below_threshold(ident, threshold)

    if target_key in ("ssh-rsa", "rsa"):
        return _below_threshold(ident, 2048)
    return True


def _is_github_available(snapshot: ScanSnapshot) -> bool:
    """Return True if GitHub registry source was requested and is available (FR-008).

    REG001 must remain silent unless the GitHub source was requested and
    reported available.
    """
    for sc in snapshot.sources:
        if sc.source == "github":
            raw_state = getattr(sc.state, "value", sc.state)
            state_str = str(raw_state).lower()
            return state_str == CoverageState.AVAILABLE.value
    return False


class ALG001Rule:
    """ALG001: Public key uses a legacy or weak algorithm.

    Severity: warning, Confidence: certain.
    """

    rule_id = "ALG001"

    def __init__(
        self,
        legacy_algorithms: Mapping[str, int | None] | Collection[str] | None = None,
    ) -> None:
        self.legacy_algorithms = (
            legacy_algorithms if legacy_algorithms is not None else LEGACY_ALGORITHMS
        )

    def evaluate(self, snapshot: ScanSnapshot) -> list[Finding]:
        findings: list[Finding] = []

        for ident in snapshot.identities:
            if not _is_legacy_identity(ident, self.legacy_algorithms):
                continue

            evidence_items: list[EvidenceReference] = []
            detail_str = (
                f"{ident.algorithm} ({ident.bits_or_curve})"
                if ident.bits_or_curve
                else ident.algorithm
            )

            for ref in ident.local_references:
                evidence_items.append(
                    EvidenceReference(
                        source=ref.source_file or ref.path,
                        line=ref.source_line,
                        detail=detail_str,
                    )
                )

            if not evidence_items:
                source_name = "agent" if ident.agent_presence else "identity"
                evidence_items.append(
                    EvidenceReference(
                        source=source_name,
                        line=None,
                        detail=detail_str,
                    )
                )

            seen_ev: set[tuple[str, int | None, str]] = set()
            unique_ev: list[EvidenceReference] = []
            for ev in evidence_items:
                ev_key = (ev.source, ev.line, ev.detail)
                if ev_key not in seen_ev:
                    seen_ev.add(ev_key)
                    unique_ev.append(ev)

            evidence = tuple(unique_ev)
            fid = rules_pkg.finding_id(
                self.rule_id,
                evidence=evidence,
                fingerprints=(ident.fingerprint,),
            )

            title = f"Legacy key algorithm: {ident.fingerprint}"
            if ident.bits_or_curve:
                summary = (
                    f"Public key {ident.fingerprint} uses legacy algorithm {ident.algorithm} "
                    f"({ident.bits_or_curve} bits)."
                )
            else:
                summary = f"Public key {ident.fingerprint} uses legacy algorithm {ident.algorithm}."

            manual_remediation = (
                (
                    "Follow your key rotation plan: generate a modern replacement key "
                    "(such as Ed25519)"
                ),
                "Verify backup or redundant access to target systems before retiring this key",
            )

            findings.append(
                Finding(
                    id=fid,
                    rule_id=self.rule_id,
                    severity=Severity.WARNING,
                    confidence=Confidence.CERTAIN,
                    title=title,
                    summary=summary,
                    evidence=evidence,
                    affected_fingerprints=(ident.fingerprint,),
                    affected_hosts=(),
                    manual_remediation=manual_remediation,
                )
            )

        findings.sort(key=lambda f: (f.rule_id, f.id))
        return findings


class REG001Rule:
    """REG001: GitHub key without matching local or agent identity.

    Severity: info, Confidence: heuristic.
    """

    rule_id = "REG001"

    def evaluate(self, snapshot: ScanSnapshot) -> list[Finding]:
        if not _is_github_available(snapshot):
            return []

        matched_fingerprints: set[str] = set()
        for ident in snapshot.identities:
            if ident.local_references or ident.agent_presence:
                matched_fingerprints.add(ident.fingerprint)

        github_bindings: list[RegistryBinding] = []
        for ident in snapshot.identities:
            for b in ident.registry_bindings:
                reg = getattr(b, "registry", getattr(b, "source", ""))
                if reg == "github":
                    github_bindings.append(b)

        for b in getattr(snapshot, "registry_bindings", ()):
            reg = getattr(b, "registry", getattr(b, "source", ""))
            if reg == "github":
                github_bindings.append(b)

        findings: list[Finding] = []
        seen_fingerprints: set[str] = set()

        for b in github_bindings:
            if b.fingerprint in matched_fingerprints:
                continue
            if b.fingerprint in seen_fingerprints:
                continue
            seen_fingerprints.add(b.fingerprint)

            detail_parts: list[str] = []
            if b.title:
                detail_parts.append(f"title: {b.title}")
            if b.created_at:
                detail_parts.append(f"created_at: {b.created_at}")
            detail_str = ", ".join(detail_parts) if detail_parts else b.fingerprint

            evidence = (
                EvidenceReference(
                    source="github",
                    line=None,
                    detail=detail_str,
                ),
            )
            fid = rules_pkg.finding_id(
                self.rule_id,
                evidence=evidence,
                fingerprints=(b.fingerprint,),
            )

            title = f"GitHub key without local or agent match: {b.fingerprint}"
            title_str = f" '{b.title}'" if b.title else ""
            summary = (
                f"GitHub key{title_str} ({b.fingerprint}) does not match any public key file "
                "found locally or loaded into the SSH agent. "
                "This may be an older key or one used exclusively on another machine."
            )
            manual_remediation = (
                (
                    "Manually review registered keys at https://github.com/settings/keys "
                    "to determine if this key is needed on other machines"
                ),
            )

            findings.append(
                Finding(
                    id=fid,
                    rule_id=self.rule_id,
                    severity=Severity.INFO,
                    confidence=Confidence.HEURISTIC,
                    title=title,
                    summary=summary,
                    evidence=evidence,
                    affected_fingerprints=(b.fingerprint,),
                    affected_hosts=(),
                    manual_remediation=manual_remediation,
                )
            )

        findings.sort(key=lambda f: (f.rule_id, f.id))
        return findings


ALG001: Rule = ALG001Rule()
REG001: Rule = REG001Rule()

RULES: list[Rule] = [ALG001, REG001]

__all__ = [
    "ALG001",
    "LEGACY_ALGORITHMS",
    "REG001",
    "RULES",
    "ALG001Rule",
    "REG001Rule",
]
