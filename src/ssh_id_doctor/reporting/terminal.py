"""Terminal snapshot renderer (sdd-spec FR-010).

Renders a ScanSnapshot as concise, human-readable terminal output:
- First line: summary with identity count and finding counts by severity.
- Source coverage states.
- Discovered identities with canonical fingerprints.
- Ordered findings per ordering.sort_findings:
  id, rule_id, severity, confidence, title, first evidence.
- Colors: disabled when stdout is not a TTY or NO_COLOR is set.
- Never reveals private-key contents or public-key base64 bodies (SEC-001, SEC-004).
"""

from __future__ import annotations

import os
import sys

from ssh_id_doctor.domain import ScanSnapshot, Severity
from ssh_id_doctor.reporting.ordering import sort_findings, sort_identities

# ANSI escape sequences
_RESET = "\x1b[0m"
_RED = "\x1b[31m"
_YELLOW = "\x1b[33m"
_CYAN = "\x1b[36m"


def _should_use_color(color: bool | None = None) -> bool:
    if color is not None:
        return color
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _colorize(text: str, color_code: str, enable: bool) -> str:
    if not enable:
        return text
    return f"{color_code}{text}{_RESET}"


def _severity_color(severity: Severity) -> str:
    if severity == Severity.ERROR:
        return _RED
    if severity == Severity.WARNING:
        return _YELLOW
    return _CYAN


def render_terminal(snapshot: ScanSnapshot, *, color: bool | None = None) -> str:
    """Render ScanSnapshot as plain or ANSI-colored terminal text."""
    use_color = _should_use_color(color)

    error_count = sum(1 for f in snapshot.findings if f.severity == Severity.ERROR)
    warning_count = sum(1 for f in snapshot.findings if f.severity == Severity.WARNING)
    info_count = sum(1 for f in snapshot.findings if f.severity == Severity.INFO)

    err_label = "error" if error_count == 1 else "errors"
    warn_label = "warning" if warning_count == 1 else "warnings"
    info_label = "info"

    findings_counts = (
        f"Findings: {error_count} {err_label}, "
        f"{warning_count} {warn_label}, {info_count} {info_label}"
    )
    first_line = f"Identities: {len(snapshot.identities)} | {findings_counts}"

    lines: list[str] = [first_line, "", "Sources:"]
    for src in snapshot.sources:
        detail_part = f" ({src.detail})" if src.detail else ""
        lines.append(f"  - {src.source}: {src.state.value}{detail_part}")

    sorted_identities = sort_identities(snapshot.identities)
    lines.append("")
    lines.append("Identities:")
    if sorted_identities:
        for ident in sorted_identities:
            comments_part = f" ({', '.join(ident.comments)})" if ident.comments else ""
            curve_part = f" ({ident.bits_or_curve})" if ident.bits_or_curve else ""
            lines.append(f"  - {ident.fingerprint} {ident.algorithm}{curve_part}{comments_part}")
    else:
        lines.append("  (none)")

    sorted_findings = sort_findings(snapshot.findings)
    lines.append("")
    lines.append("Findings:")
    if sorted_findings:
        for f in sorted_findings:
            sev_tag = f"[{f.severity.value}]"
            sev_formatted = _colorize(sev_tag, _severity_color(f.severity), use_color)
            lines.append(f"  {f.id} {sev_formatted} ({f.rule_id}, {f.confidence.value}) {f.title}")
            if f.evidence:
                first_ev = f.evidence[0]
                loc = (
                    f"{first_ev.source}:{first_ev.line}"
                    if first_ev.line is not None
                    else first_ev.source
                )
                ev_detail = f" - {first_ev.detail}" if first_ev.detail else ""
                lines.append(f"    Evidence: {loc}{ev_detail}")
    else:
        lines.append("  (none)")

    return "\n".join(lines) + "\n"


__all__ = [
    "render_terminal",
]
