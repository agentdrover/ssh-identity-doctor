"""Ordering rules for findings and identities (sdd-spec FR-010).

Stable, deterministic ordering used by all reporters:
- sort_findings: severity (error < warning < info),
  confidence (certain < heuristic < unresolved), rule_id,
  then first evidence location (source file, source line).
- sort_identities: fingerprint.
"""

from __future__ import annotations

from collections.abc import Sequence

from ssh_id_doctor.domain import Confidence, Finding, Identity, Severity

# Severity order: error < warning < info
_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.ERROR: 0,
    Severity.WARNING: 1,
    Severity.INFO: 2,
}

# Confidence order: certain < heuristic < unresolved
_CONFIDENCE_ORDER: dict[Confidence, int] = {
    Confidence.CERTAIN: 0,
    Confidence.HEURISTIC: 1,
    Confidence.UNRESOLVED: 2,
}


def _finding_sort_key(
    finding: Finding,
) -> tuple[int, int, str, str, int, str]:
    sev = _SEVERITY_ORDER.get(finding.severity, 99)
    conf = _CONFIDENCE_ORDER.get(finding.confidence, 99)
    rule = finding.rule_id
    if finding.evidence:
        first_ev = finding.evidence[0]
        ev_source = first_ev.source
        ev_line = -1 if first_ev.line is None else first_ev.line
    else:
        ev_source = ""
        ev_line = -1
    return (sev, conf, rule, ev_source, ev_line, finding.id)


def sort_findings(findings: Sequence[Finding]) -> list[Finding]:
    """Sort findings stably: severity, confidence, rule_id, first evidence location, id."""
    return sorted(findings, key=_finding_sort_key)


def sort_identities(identities: Sequence[Identity]) -> list[Identity]:
    """Sort identities by canonical fingerprint."""
    return sorted(identities, key=lambda ident: ident.fingerprint)


__all__ = [
    "sort_findings",
    "sort_identities",
]
