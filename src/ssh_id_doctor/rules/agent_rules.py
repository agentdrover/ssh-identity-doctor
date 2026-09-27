"""Agent rules (AGT001, AGT002).

Contract: sdd-spec FR-008, §7.5, §10 SEC-006.
Pure functions over ScanSnapshot, no I/O.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import ssh_id_doctor.rules as rules_pkg
from ssh_id_doctor.domain import (
    Confidence,
    CoverageState,
    EvidenceReference,
    Finding,
    ScanSnapshot,
    Severity,
)

if TYPE_CHECKING:
    from ssh_id_doctor.rules import Rule

AGENT_EXPOSURE_THRESHOLD: int = 5
"""Threshold of agent identities at or above which AGT002 evaluates Host blocks (FR-008)."""


def _is_agent_available_with_identities(snapshot: ScanSnapshot) -> bool:
    """Return True if the SSH agent source is available with identities (FR-008).

    Rules AGT001 and AGT002 must remain silent unless the SSH agent was inspected
    and reported available with identities.
    """
    for sc in snapshot.sources:
        if sc.source == "agent":
            raw_state = getattr(sc.state, "value", sc.state)
            state_str = str(raw_state).lower()
            return state_str in (CoverageState.AVAILABLE.value, "available_with_identities")
    return False


class AGT001Rule:
    """AGT001: Agent identity has no known relationship to a local file, config, or registry.

    Severity: warning, Confidence: heuristic.
    """

    rule_id = "AGT001"

    def evaluate(self, snapshot: ScanSnapshot) -> list[Finding]:
        if not _is_agent_available_with_identities(snapshot):
            return []

        bound_fingerprints: set[str] = set()
        for hb in snapshot.host_bindings:
            bound_fingerprints.update(hb.resolved_fingerprints)

        findings: list[Finding] = []
        for ident in snapshot.identities:
            if not ident.agent_presence:
                continue
            if ident.local_references:
                continue
            if ident.fingerprint in bound_fingerprints:
                continue
            if ident.registry_bindings:
                continue

            comment_str = (
                ident.comments[0].strip() if ident.comments and ident.comments[0].strip() else ""
            )
            evidence = (
                EvidenceReference(
                    source="agent",
                    line=None,
                    detail=comment_str or ident.fingerprint,
                ),
            )
            fid = rules_pkg.finding_id(
                self.rule_id,
                evidence=evidence,
                fingerprints=(ident.fingerprint,),
            )

            title = f"Agent identity has no known relationship: {ident.fingerprint}"
            summary = (
                f"SSH agent offers identity {ident.fingerprint} with no known relationship "
                "to any local key file, host configuration, or remote registry. "
                "As a heuristic, the agent may offer this identity during connection attempts."
            )
            remediation = (
                "Verify whether this agent identity corresponds to an intended key",
                (
                    "Add 'IdentitiesOnly yes' and an explicit IdentityFile manually in SSH config "
                    "for target hosts"
                ),
                "Verify host configuration: ssh -G <alias>",
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


class AGT002Rule:
    """AGT002: Agent exposes multiple identities without IdentitiesOnly yes in Host rule.

    Severity: warning, Confidence: heuristic.
    """

    rule_id = "AGT002"

    def __init__(self, threshold: int | None = None) -> None:
        self._threshold = threshold

    @property
    def threshold(self) -> int:
        return self._threshold if self._threshold is not None else AGENT_EXPOSURE_THRESHOLD

    def evaluate(self, snapshot: ScanSnapshot) -> list[Finding]:
        if not _is_agent_available_with_identities(snapshot):
            return []

        agent_identities = [ident for ident in snapshot.identities if ident.agent_presence]
        if len(agent_identities) < self.threshold:
            return []

        findings: list[Finding] = []
        for hb in snapshot.host_bindings:
            if hb.identities_only is True:
                continue

            host_label = " ".join(hb.patterns) if hb.patterns else "*"
            evidence = (
                EvidenceReference(
                    source=hb.source_file,
                    line=hb.source_line,
                    detail=f"Host {host_label}",
                ),
            )
            fid = rules_pkg.finding_id(
                self.rule_id,
                evidence=evidence,
                hosts=sorted(hb.patterns),
            )

            target_alias = (
                hb.patterns[0]
                if (hb.patterns and "*" not in hb.patterns[0] and "?" not in hb.patterns[0])
                else "<alias>"
            )

            title = f"Multiple agent identities exposed without IdentitiesOnly: Host {host_label}"
            summary = (
                f"SSH agent offers {len(agent_identities)} identities, but host configuration "
                f"'Host {host_label}' at {hb.source_file}:{hb.source_line} does not specify "
                "'IdentitiesOnly yes'. As a heuristic, the agent may offer excessive identities "
                "during authentication, which may exceed server authentication attempt limits."
            )
            remediation = (
                f"Add 'IdentitiesOnly yes' to the Host block at {hb.source_file}:{hb.source_line}",
                "Specify explicit IdentityFile directives for required identities manually",
                f"Verify host configuration: ssh -G {target_alias}",
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
                    affected_fingerprints=(),
                    affected_hosts=hb.patterns,
                    manual_remediation=remediation,
                )
            )

        findings.sort(key=lambda f: (f.rule_id, f.id))
        return findings


AGT001 = AGT001Rule()
AGT002 = AGT002Rule()

RULES: list[Rule] = [AGT001, AGT002]

__all__ = [
    "AGENT_EXPOSURE_THRESHOLD",
    "AGT001",
    "AGT002",
    "RULES",
    "AGT001Rule",
    "AGT002Rule",
]
