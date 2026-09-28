"""Finding explanation generator (SID-19, sdd-spec §5.1, §7.5, FR-008).

Explains a single finding from a ScanSnapshot:
- Rule ID and rule description (from static catalog)
- Severity and confidence
- Confidence level explanation (certain / heuristic / unresolved)
- Evidence references (source:line and detail)
- Affected fingerprints and host patterns
- Manual remediation steps
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ssh_id_doctor.domain import Confidence, Finding

SCHEMA_VERSION = "1.0"
EXPLAIN_KIND = "finding_explanation"

CONFIDENCE_EXPLANATIONS: dict[Confidence, str] = {
    Confidence.CERTAIN: (
        "Fact established directly from local configuration or key data. "
        "The observation does not rely on inferences or assumptions."
    ),
    Confidence.HEURISTIC: (
        "Inference based on observed patterns; local data may be incomplete. "
        "Manual verification is recommended before taking action."
    ),
    Confidence.UNRESOLVED: (
        "Analysis could not be fully completed because some directives or sources "
        "could not be evaluated."
    ),
}

RULE_DESCRIPTIONS: dict[str, str] = {
    "CFG001": (
        "An IdentityFile directive in SSH configuration points to a target path "
        "that cannot be resolved (missing, unreadable, or outside the expected root)."
    ),
    "CFG002": (
        "An Include directive or unsupported Match block in SSH configuration "
        "could not be evaluated, or a recursive Include cycle was detected."
    ),
    "ID001": (
        "The same public key fingerprint appears under multiple local file paths "
        "or distinct comment labels."
    ),
    "ID002": (
        "A local public key has no known binding to any configured host block "
        "or remote registry in the evaluated configuration."
    ),
    "LAB001": (
        "A public key has an empty comment label or shares an ambiguous comment "
        "with other distinct keys."
    ),
    "AGT001": (
        "An identity offered by the SSH agent has no known relationship to any "
        "local key file, configured host, or remote registry."
    ),
    "AGT002": (
        "The SSH agent offers multiple identities, but a host block does not "
        "specify 'IdentitiesOnly yes', which may lead to authentication failures."
    ),
    "ALG001": (
        "A public key uses a legacy or weak cryptographic algorithm "
        "(such as DSA or short RSA keys)."
    ),
    "REG001": (
        "A key registered in a remote registry (such as GitHub) has no matching "
        "local public key file or active agent identity."
    ),
}


@dataclass(frozen=True, slots=True)
class FindingExplanation:
    """Detailed explanation of a single finding."""

    schema_version: str
    kind: str
    finding: Finding
    rule_description: str
    confidence_explanation: str


def explain_finding(finding: Finding) -> FindingExplanation:
    """Build FindingExplanation for a given Finding."""
    rule_desc = RULE_DESCRIPTIONS.get(
        finding.rule_id,
        f"Rule {finding.rule_id} evaluation finding.",
    )
    conf_explanation = CONFIDENCE_EXPLANATIONS.get(
        finding.confidence,
        f"Confidence level: {finding.confidence.value}.",
    )
    return FindingExplanation(
        schema_version=SCHEMA_VERSION,
        kind=EXPLAIN_KIND,
        finding=finding,
        rule_description=rule_desc,
        confidence_explanation=conf_explanation,
    )


def explanation_to_dict(explanation: FindingExplanation) -> dict[str, Any]:
    """Convert FindingExplanation to JSON-serializable dictionary."""
    f = explanation.finding
    sev_str = f.severity.value if isinstance(f.severity, Enum) else str(f.severity)
    conf_str = f.confidence.value if isinstance(f.confidence, Enum) else str(f.confidence)
    return {
        "schema_version": explanation.schema_version,
        "kind": explanation.kind,
        "finding": {
            "id": f.id,
            "rule_id": f.rule_id,
            "severity": sev_str,
            "confidence": conf_str,
            "title": f.title,
            "summary": f.summary,
            "evidence": [
                {
                    "source": ev.source,
                    "line": ev.line,
                    "detail": ev.detail,
                }
                for ev in f.evidence
            ],
            "affected_fingerprints": list(f.affected_fingerprints),
            "affected_hosts": list(f.affected_hosts),
            "manual_remediation": list(f.manual_remediation),
        },
        "rule_description": explanation.rule_description,
        "confidence_explanation": explanation.confidence_explanation,
    }


def render_explain_json(explanation: FindingExplanation, *, indent: int = 2) -> str:
    """Render FindingExplanation as JSON string."""
    return json.dumps(
        explanation_to_dict(explanation),
        indent=indent,
        sort_keys=True,
        ensure_ascii=False,
    )


def render_explain_markdown(explanation: FindingExplanation) -> str:
    """Render FindingExplanation as structured Markdown."""
    f = explanation.finding
    sev_str = f.severity.value if isinstance(f.severity, Enum) else str(f.severity)
    conf_str = f.confidence.value if isinstance(f.confidence, Enum) else str(f.confidence)
    lines: list[str] = [
        f"# Finding Explanation: {f.id}",
        "",
        "## Overview",
        "",
        f"- **Finding ID**: `{f.id}`",
        f"- **Rule**: `{f.rule_id}`",
        f"- **Severity**: {sev_str}",
        f"- **Confidence**: {conf_str}",
        f"- **Title**: {f.title}",
        f"- **Summary**: {f.summary}",
        "",
        "## Rule description",
        "",
        explanation.rule_description,
        "",
        "## Confidence meaning",
        "",
        explanation.confidence_explanation,
        "",
        "## Evidence",
        "",
    ]

    if f.evidence:
        for ev in f.evidence:
            loc = f"{ev.source}:{ev.line}" if ev.line is not None else ev.source
            if ev.detail:
                lines.append(f"- `{loc}`: {ev.detail}")
            else:
                lines.append(f"- `{loc}`")
    else:
        lines.append("(none)")

    lines.extend(["", "## Affected targets", ""])
    if f.affected_hosts:
        lines.append(f"- **Hosts**: {', '.join(f'`{h}`' for h in f.affected_hosts)}")
    if f.affected_fingerprints:
        fps_str = ", ".join(f"`{fp}`" for fp in f.affected_fingerprints)
        lines.append(f"- **Fingerprints**: {fps_str}")
    if not f.affected_hosts and not f.affected_fingerprints:
        lines.append("(none)")

    lines.extend(["", "## Manual remediation", ""])
    if f.manual_remediation:
        for i, step in enumerate(f.manual_remediation, start=1):
            lines.append(f"{i}. {step}")
    else:
        lines.append("(none required)")

    return "\n".join(lines) + "\n"


def render_explain_terminal(explanation: FindingExplanation) -> str:
    """Render FindingExplanation as terminal text."""
    f = explanation.finding
    sev_str = f.severity.value if isinstance(f.severity, Enum) else str(f.severity)
    conf_str = f.confidence.value if isinstance(f.confidence, Enum) else str(f.confidence)

    lines: list[str] = [
        f"Finding: {f.id}",
        f"Rule: {f.rule_id} [{sev_str}] (confidence: {conf_str})",
        f"Title: {f.title}",
        f"Summary: {f.summary}",
        "",
        "Rule description:",
        f"  {explanation.rule_description}",
        "",
        f"Confidence ({conf_str}):",
        f"  {explanation.confidence_explanation}",
        "",
        "Evidence:",
    ]

    if f.evidence:
        for ev in f.evidence:
            loc = f"{ev.source}:{ev.line}" if ev.line is not None else ev.source
            detail_str = f" - {ev.detail}" if ev.detail else ""
            lines.append(f"  - {loc}{detail_str}")
    else:
        lines.append("  (none)")

    lines.append("")
    lines.append("Affected targets:")
    if f.affected_hosts:
        lines.append(f"  - Hosts: {', '.join(f.affected_hosts)}")
    if f.affected_fingerprints:
        lines.append(f"  - Fingerprints: {', '.join(f.affected_fingerprints)}")
    if not f.affected_hosts and not f.affected_fingerprints:
        lines.append("  (none)")

    lines.append("")
    lines.append("Manual remediation:")
    if f.manual_remediation:
        for i, step in enumerate(f.manual_remediation, start=1):
            lines.append(f"  {i}. {step}")
    else:
        lines.append("  (none required)")

    return "\n".join(lines) + "\n"
