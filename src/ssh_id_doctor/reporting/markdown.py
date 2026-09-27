"""Markdown audit report renderer (sdd-spec FR-010).

Renders a ScanSnapshot as a portable, human-readable Markdown audit report:
- ## Summary: metadata and counts.
- ## Source coverage: states of all scan sources.
- ## Identities: table with fingerprint, algorithm, references, agent, github.
- ## Host bindings: table of resolved host configurations.
- ## Unresolved items: parser or config directives marked as unresolved (§14 п.6).
- ## Findings: ordered by ordering.sort_findings with evidence and manual remediation.
- ## Limitations: explicit note on unqueried remote registries (SEC-004, SEC-006).
Never reveals private-key contents or public-key base64 bodies (SEC-001, SEC-004).
"""

from __future__ import annotations

from enum import Enum

from ssh_id_doctor.domain import (
    ScanSnapshot,
    Severity,
)
from ssh_id_doctor.reporting.ordering import sort_findings, sort_identities


def render_markdown(snapshot: ScanSnapshot) -> str:
    """Render ScanSnapshot as a structured Markdown audit report."""
    platform_val = (
        snapshot.platform.value if isinstance(snapshot.platform, Enum) else str(snapshot.platform)
    )

    error_count = sum(1 for f in snapshot.findings if f.severity == Severity.ERROR)
    warning_count = sum(1 for f in snapshot.findings if f.severity == Severity.WARNING)
    info_count = sum(1 for f in snapshot.findings if f.severity == Severity.INFO)

    err_label = "error" if error_count == 1 else "errors"
    warn_label = "warning" if warning_count == 1 else "warnings"
    info_label = "info"

    findings_summary = (
        f"{len(snapshot.findings)} ({error_count} {err_label}, "
        f"{warning_count} {warn_label}, {info_count} {info_label})"
    )

    lines: list[str] = [
        "# SSH Identity Doctor Audit Report",
        "",
        "## Summary",
        "",
        f"- **Scan ID**: `{snapshot.scan_id}`",
        f"- **Platform**: `{platform_val}`",
        f"- **Started at**: `{snapshot.started_at}`",
        f"- **Completed at**: `{snapshot.completed_at}`",
        f"- **Identities**: {len(snapshot.identities)}",
        f"- **Findings**: {findings_summary}",
        f"- **Host bindings**: {len(snapshot.host_bindings)}",
        f"- **Unresolved directives**: {len(snapshot.unresolved)}",
        "",
        "## Source coverage",
        "",
        "| Source | State | Required | Detail |",
        "| --- | --- | --- | --- |",
    ]

    for src in snapshot.sources:
        req_str = "yes" if src.required else "no"
        detail_str = src.detail if src.detail else "-"
        # Escape pipes in detail
        clean_detail = detail_str.replace("|", "\\|")
        lines.append(f"| {src.source} | {src.state.value} | {req_str} | {clean_detail} |")

    sorted_identities = sort_identities(snapshot.identities)
    lines.extend(
        [
            "",
            "## Identities",
            "",
            "| Fingerprint | Algorithm | References | Agent | GitHub |",
            "| --- | --- | --- | --- | --- |",
        ]
    )

    if sorted_identities:
        for ident in sorted_identities:
            algo_str = (
                f"{ident.algorithm} ({ident.bits_or_curve})"
                if ident.bits_or_curve
                else ident.algorithm
            )
            ref_paths = [r.path for r in ident.local_references]
            refs_str = ", ".join(f"`{p}`" for p in ref_paths) if ref_paths else "-"
            agent_str = "yes" if ident.agent_presence else "no"
            gh_items = [
                b.title or b.key_id or b.registry
                for b in ident.registry_bindings
                if b.title or b.key_id or b.registry
            ]
            gh_str = ", ".join(gh_items) if gh_items else "-"
            lines.append(
                f"| `{ident.fingerprint}` | {algo_str} | {refs_str} | {agent_str} | {gh_str} |"
            )
    else:
        lines.append("| (none) | - | - | - | - |")

    lines.extend(
        [
            "",
            "## Host bindings",
            "",
            "| Patterns | HostName | User | IdentityFile | Fingerprints | Source | Confidence |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )

    if snapshot.host_bindings:
        for hb in snapshot.host_bindings:
            pats_str = ", ".join(f"`{p}`" for p in hb.patterns)
            hostname_str = f"`{hb.hostname}`" if hb.hostname else "-"
            user_str = f"`{hb.user}`" if hb.user else "-"
            id_refs_str = (
                ", ".join(f"`{r}`" for r in hb.identity_references)
                if hb.identity_references
                else "-"
            )
            fps_str = (
                ", ".join(f"`{fp}`" for fp in hb.resolved_fingerprints)
                if hb.resolved_fingerprints
                else "-"
            )
            src_str = f"`{hb.source_file}:{hb.source_line}`"
            conf_str = hb.confidence.value
            row_items = [
                pats_str,
                hostname_str,
                user_str,
                id_refs_str,
                fps_str,
                src_str,
                conf_str,
            ]
            lines.append(f"| {' | '.join(row_items)} |")
    else:
        lines.append("| (none) | - | - | - | - | - | - |")

    if snapshot.unresolved:
        lines.extend(
            [
                "",
                "## Unresolved items",
                "",
                "The following configuration directives could not be resolved "
                "and are marked as **unresolved**:",
                "",
                "| Kind | Location | Detail | Status |",
                "| --- | --- | --- | --- |",
            ]
        )
        for u in snapshot.unresolved:
            loc_str = (
                f"`{u.source_file}:{u.source_line}`"
                if u.source_line is not None
                else f"`{u.source_file}`"
            )
            detail_clean = u.detail.replace("|", "\\|")
            lines.append(f"| `{u.kind}` | {loc_str} | {detail_clean} | unresolved |")

    sorted_findings = sort_findings(snapshot.findings)
    lines.extend(
        [
            "",
            "## Findings",
        ]
    )

    if sorted_findings:
        for f in sorted_findings:
            lines.extend(
                [
                    "",
                    f"### {f.id} - {f.title}",
                    "",
                    f"- **Rule**: {f.rule_id}",
                    f"- **Severity**: {f.severity.value}",
                    f"- **Confidence**: {f.confidence.value}",
                    f"- **Summary**: {f.summary}",
                ]
            )
            if f.affected_hosts:
                lines.append(f"- **Affected hosts**: {', '.join(f.affected_hosts)}")
            if f.affected_fingerprints:
                lines.append(f"- **Affected fingerprints**: {', '.join(f.affected_fingerprints)}")

            lines.append("- **Evidence**:")
            if f.evidence:
                for ev in f.evidence:
                    loc = f"{ev.source}:{ev.line}" if ev.line is not None else ev.source
                    if ev.detail:
                        lines.append(f"  - `{loc}`: {ev.detail}")
                    else:
                        lines.append(f"  - `{loc}`")
            else:
                lines.append("  - (none)")

            lines.append("- **Manual remediation**:")
            if f.manual_remediation:
                for rem in f.manual_remediation:
                    lines.append(f"  - `{rem}`")
            else:
                lines.append("  - (none required)")
    else:
        lines.extend(["", "No findings."])

    lines.extend(
        [
            "",
            "## Limitations",
            "",
            "This report is based solely on local SSH configuration files, discovered public keys, "
            "active SSH agent identities, and explicitly queried remote registries.",
            "",
            "Remote registries (such as GitHub, GitLab, SaaS providers, or internal servers) "
            "that are not configured or queried cannot be detected by this scan. Keys may be "
            "authorized on external systems even if no local or known remote references exist.",
            "",
            "In accordance with safety principles (SEC-006), this tool does not guarantee "
            "that any key is safe to delete. Always verify with system administrators and access "
            "management records before revoking or removing any SSH key.",
            "",
        ]
    )

    return "\n".join(lines)


__all__ = [
    "render_markdown",
]
