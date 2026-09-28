"""FR-009 / sdd-spec §5.2, §7, §10: Rotation plan generator.

Generates a non-destructive manual key rotation plan containing:
1. Identity: fingerprint and non-secret metadata
2. Local references: discovered .pub and config references
3. Host aliases: host blocks that use this key
4. Agent and GitHub: known presence in agent and GitHub registry
5. Unknowns: explicit unknown remote authorized_keys, unqueried sources, and unparsed config
6. Backup access: reminder to verify out-of-band / alternative access
7. Checklist: ordered manual checklist with no destructive commands
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from ssh_id_doctor.domain import (
    CoverageState,
    HostBinding,
    Identity,
    LocalReference,
    LocalReferenceKind,
    RegistryBinding,
    ScanSnapshot,
    SourceCoverage,
    UnresolvedItem,
)

SCHEMA_VERSION = "1.0"
PLAN_KIND = "rotation_plan"


@dataclass(frozen=True, slots=True)
class IdentityMetadata:
    """Non-secret identity attributes for the rotation target (SEC-001)."""

    fingerprint: str
    algorithm: str
    bits_or_curve: str
    comments: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class HostAliasInfo:
    """A host alias or pattern bound to the target identity."""

    alias: str
    patterns: tuple[str, ...]
    source_file: str
    source_line: int
    location: str
    hostname: str | None = None
    user: str | None = None


@dataclass(frozen=True, slots=True)
class AgentAndGitHubInfo:
    """Known presence in the local SSH agent and remote GitHub registry."""

    agent_presence: bool
    agent_status: str
    github_status: str
    github_bindings: tuple[RegistryBinding, ...] = ()


@dataclass(frozen=True, slots=True)
class RotationPlan:
    """FR-009 key rotation plan with sections 1-7 in order."""

    schema_version: str
    kind: str
    fingerprint: str
    identity: IdentityMetadata
    local_references: tuple[LocalReference, ...]
    host_aliases: tuple[HostAliasInfo, ...]
    agent_and_github: AgentAndGitHubInfo
    unknowns: tuple[str, ...]
    backup_access: str
    checklist: tuple[str, ...]


def _clean_stem(path: str) -> str:
    name = Path(path).name
    if name.endswith(".pub"):
        return name[:-4]
    return name


# A query that succeeded (possibly with nothing in it) is knowledge; anything else is not.
_KNOWN_STATES = (CoverageState.AVAILABLE, CoverageState.EMPTY)


def _agent_status(present: bool, coverage: SourceCoverage | None) -> str:
    """FR-009 §4: known agent presence; a failed query is unknown, not absent."""
    if present:
        return "present"
    if coverage is None:
        return "unknown (not recorded)"
    if coverage.state == CoverageState.SKIPPED:
        return "skipped"
    if coverage.state in _KNOWN_STATES:
        return "not present"
    return f"unknown ({coverage.state.value})"


def _github_status(bindings: tuple[RegistryBinding, ...], coverage: SourceCoverage | None) -> str:
    """FR-009 §4: known GitHub registration; a failed query is unknown, not absent."""
    if coverage is not None and coverage.state == CoverageState.SKIPPED:
        return "not requested"
    if bindings:
        return "registered"
    if coverage is None:
        return "unknown (not recorded)"
    if coverage.state in _KNOWN_STATES:
        return "none registered"
    return f"unknown ({coverage.state.value})"


_INCLUDE_WORDING = {
    "include_cycle": "Include cycle",
    "include_missing": "missing Include target",
    "include_depth_exceeded": "Include depth exceeded",
}


def _describe_unresolved(item: UnresolvedItem) -> str:
    """One Unknowns line for a CFG002 item, worded by its own kind."""
    loc = (
        f"{Path(item.source_file).name}:{item.source_line}"
        if item.source_line is not None
        else Path(item.source_file).name
    )
    if item.kind == "unsupported_match" or "match" in item.detail.lower():
        return (
            f"unresolved Match directive at {loc}: {item.detail} "
            "(identity bindings may exist in unevaluated Match block)"
        )
    if item.kind.startswith("include"):
        wording = _INCLUDE_WORDING.get(item.kind, "unparsed Include")
        return (
            f"unresolved Include directive at {loc} ({wording}): {item.detail} "
            f"(identity bindings may exist in unparsed Include file)"
        )
    return (
        f"unresolved directive ({item.kind}) at {loc}: {item.detail} "
        "(identity bindings may exist in unparsed section)"
    )


def _host_uses_identity(hb: HostBinding, fingerprint: str, stems: set[str]) -> bool:
    """A host uses the key when it resolves to it; name matching only when nothing resolved."""
    if fingerprint in hb.resolved_fingerprints:
        return True
    if hb.resolved_fingerprints:
        return False
    return any(_clean_stem(ref) in stems for ref in hb.identity_references)


def _block_end(snapshot: ScanSnapshot, hb: HostBinding) -> int | None:
    """First line after hb's header that starts another block in the same file."""
    starts = [
        other.source_line
        for other in snapshot.host_bindings
        if other.source_file == hb.source_file and other.source_line > hb.source_line
    ]
    starts.extend(
        u.source_line
        for u in snapshot.unresolved
        if u.kind == "unsupported_match"
        and u.source_file == hb.source_file
        and u.source_line is not None
        and u.source_line > hb.source_line
    )
    return min(starts, default=None)


def _identityfile_line(
    snapshot: ScanSnapshot, hb: HostBinding, candidates: list[LocalReference]
) -> int:
    """Line of the IdentityFile inside hb's own block that names the key; else the header."""
    end = _block_end(snapshot, hb)
    own_stems = {_clean_stem(ref) for ref in hb.identity_references}
    lines = [
        cfg.source_line
        for cfg in candidates
        if cfg.source_file == hb.source_file
        and cfg.source_line is not None
        and cfg.source_line > hb.source_line
        and (end is None or cfg.source_line < end)
        and _clean_stem(cfg.path) in own_stems
    ]
    return min(lines, default=hb.source_line)


def _host_aliases(snapshot: ScanSnapshot, target: Identity) -> tuple[HostAliasInfo, ...]:
    """FR-009 §3: Host blocks that use the target key, each at its own IdentityFile line."""
    stems = {_clean_stem(ref.path) for ref in target.local_references if ref.path}
    own_cfg = [r for r in target.local_references if r.kind == LocalReferenceKind.CONFIG_IDENTITY]
    unbound_cfg = [
        r
        for r in snapshot.local_references
        if r.kind == LocalReferenceKind.CONFIG_IDENTITY and _clean_stem(r.path) in stems
    ]

    aliases: dict[tuple[str, str, int], HostAliasInfo] = {}
    for hb in snapshot.host_bindings:
        if not _host_uses_identity(hb, target.fingerprint, stems):
            continue
        # A resolved host is paired only with IdentityFile lines that resolved to the key.
        candidates = own_cfg if hb.resolved_fingerprints else own_cfg + unbound_cfg
        line = _identityfile_line(snapshot, hb, candidates)
        alias_name = hb.patterns[0] if hb.patterns else "default"
        key = (alias_name, hb.source_file, line)
        aliases.setdefault(
            key,
            HostAliasInfo(
                alias=alias_name,
                patterns=hb.patterns,
                source_file=hb.source_file,
                source_line=line,
                location=f"{Path(hb.source_file).name}:{line}",
                hostname=hb.hostname,
                user=hb.user,
            ),
        )
    return tuple(
        sorted(aliases.values(), key=lambda ha: (ha.source_file, ha.source_line, ha.alias))
    )


def build_rotation_plan(snapshot: ScanSnapshot, fingerprint: str) -> RotationPlan:
    """Build a RotationPlan for fingerprint from snapshot."""
    target_ident = next((i for i in snapshot.identities if i.fingerprint == fingerprint), None)
    if target_ident is None:
        raise ValueError(f"fingerprint '{fingerprint}' not found in snapshot")

    # 1. Identity metadata
    identity_meta = IdentityMetadata(
        fingerprint=target_ident.fingerprint,
        algorithm=target_ident.algorithm,
        bits_or_curve=target_ident.bits_or_curve,
        comments=target_ident.comments,
    )

    # 2. Local references
    sorted_local_refs = tuple(
        sorted(
            target_ident.local_references,
            key=lambda r: (r.kind.value, r.path, r.source_file or "", r.source_line or 0),
        )
    )

    # 3. Host aliases
    matching_host_aliases = _host_aliases(snapshot, target_ident)

    # 4. Agent and GitHub
    agent_cov = next((s for s in snapshot.sources if s.source == "agent"), None)
    github_cov = next((s for s in snapshot.sources if s.source == "github"), None)
    agent_and_github = AgentAndGitHubInfo(
        agent_presence=target_ident.agent_presence,
        agent_status=_agent_status(target_ident.agent_presence, agent_cov),
        github_status=_github_status(target_ident.registry_bindings, github_cov),
        github_bindings=target_ident.registry_bindings,
    )

    # 5. Unknowns
    unknowns_list: list[str] = [
        "remote authorized_keys and other registries are not inspected",
    ]
    if agent_cov is not None and agent_cov.state != CoverageState.AVAILABLE:
        if agent_cov.state == CoverageState.SKIPPED:
            unknowns_list.append("agent: skipped")
        else:
            unknowns_list.append(f"agent: {agent_cov.state.value}")

    if github_cov is not None and github_cov.state != CoverageState.AVAILABLE:
        if github_cov.state == CoverageState.SKIPPED:
            unknowns_list.append("github: not requested")
        else:
            unknowns_list.append(f"github: {github_cov.state.value}")

    unknowns_list.extend(_describe_unresolved(u) for u in snapshot.unresolved)

    # 6. Backup access
    backup_access_msg = (
        "Verify alternative or out-of-band access to all target systems before beginning rotation. "
        "Remote authorized_keys and registries cannot be fully inspected by local scanning, "
        "so unknown remote registrations may exist. Never proceed without confirmed backup access."
    )

    # 7. Checklist
    checklist_steps: tuple[str, ...] = (
        "Verify backup access: Ensure alternative administrative or out-of-band access "
        "to all target systems to prevent lockout.",
        "Generate replacement key: Create a new key pair using a modern algorithm "
        "(e.g. ssh-keygen -t ed25519) without modifying existing keys.",
        "Deploy new public key: Add the new public key to authorized_keys on each target host "
        "and update relevant remote registries (e.g. GitHub).",
        "Verify authentication: Test and verify successful SSH login to each target host "
        "using the new key.",
        "Retire old key manually: Only after verifying access with the new key, manually "
        "remove the old key from remote authorized_keys, remote registries, SSH agent, "
        "and local configuration.",
    )

    return RotationPlan(
        schema_version=SCHEMA_VERSION,
        kind=PLAN_KIND,
        fingerprint=fingerprint,
        identity=identity_meta,
        local_references=sorted_local_refs,
        host_aliases=matching_host_aliases,
        agent_and_github=agent_and_github,
        unknowns=tuple(unknowns_list),
        backup_access=backup_access_msg,
        checklist=checklist_steps,
    )


def plan_to_dict(plan: RotationPlan) -> dict[str, Any]:
    """Convert RotationPlan to JSON-serializable dictionary."""
    return {
        "schema_version": plan.schema_version,
        "kind": plan.kind,
        "fingerprint": plan.fingerprint,
        "identity": {
            "fingerprint": plan.identity.fingerprint,
            "algorithm": plan.identity.algorithm,
            "bits_or_curve": plan.identity.bits_or_curve,
            "comments": list(plan.identity.comments),
        },
        "local_references": [
            {
                "kind": r.kind.value if isinstance(r.kind, Enum) else str(r.kind),
                "path": r.path,
                "source_file": r.source_file,
                "source_line": r.source_line,
                "resolution": (
                    r.resolution.value if isinstance(r.resolution, Enum) else str(r.resolution)
                ),
            }
            for r in plan.local_references
        ],
        "host_aliases": [
            {
                "alias": ha.alias,
                "patterns": list(ha.patterns),
                "source_file": ha.source_file,
                "source_line": ha.source_line,
                "location": ha.location,
                "hostname": ha.hostname,
                "user": ha.user,
            }
            for ha in plan.host_aliases
        ],
        "agent_and_github": {
            "agent_presence": plan.agent_and_github.agent_presence,
            "agent_status": plan.agent_and_github.agent_status,
            "github_status": plan.agent_and_github.github_status,
            "github_bindings": [
                {
                    "registry": b.registry,
                    "fingerprint": b.fingerprint,
                    "title": b.title,
                    "key_id": b.key_id,
                    "created_at": b.created_at,
                }
                for b in plan.agent_and_github.github_bindings
            ],
        },
        "unknowns": list(plan.unknowns),
        "backup_access": plan.backup_access,
        "checklist": list(plan.checklist),
    }


def render_plan_json(plan: RotationPlan, *, indent: int = 2) -> str:
    """Render RotationPlan as formatted JSON string."""
    return json.dumps(plan_to_dict(plan), indent=indent, sort_keys=True, ensure_ascii=False)


def render_plan_markdown(plan: RotationPlan) -> str:
    """Render RotationPlan as structured Markdown with sections in order."""
    comments_str = (
        ", ".join(f"`{c}`" for c in plan.identity.comments) if plan.identity.comments else "(none)"
    )
    curve_part = f" ({plan.identity.bits_or_curve})" if plan.identity.bits_or_curve else ""

    lines: list[str] = [
        "# SSH Identity Doctor Rotation Plan",
        "",
        "## Identity",
        "",
        f"- **Fingerprint**: `{plan.identity.fingerprint}`",
        f"- **Algorithm**: {plan.identity.algorithm}{curve_part}",
        f"- **Comments**: {comments_str}",
        "",
        "## Local references",
        "",
    ]

    if plan.local_references:
        for ref in plan.local_references:
            kind_str = ref.kind.value if isinstance(ref.kind, Enum) else str(ref.kind)
            lines.append(f"- `{ref.path}` ({kind_str})")
    else:
        lines.append("(none)")

    lines.extend(["", "## Host aliases", ""])
    if plan.host_aliases:
        for ha in plan.host_aliases:
            lines.append(f"- `{ha.alias}` (`{ha.location}`)")
    else:
        lines.append("(none)")

    lines.extend(["", "## Agent and GitHub", ""])
    lines.append(f"- **SSH Agent**: {plan.agent_and_github.agent_status}")
    if plan.agent_and_github.github_bindings:
        lines.append("- **GitHub**:")
        for b in plan.agent_and_github.github_bindings:
            title_part = f" (title: {b.title})" if b.title else ""
            key_id_part = f" [id: {b.key_id}]" if b.key_id else ""
            name = b.title or b.key_id or b.registry
            lines.append(f"  - `{name}`{title_part}{key_id_part}")
    else:
        lines.append(f"- **GitHub**: {plan.agent_and_github.github_status}")

    lines.extend(["", "## Unknowns", ""])
    for u in plan.unknowns:
        lines.append(f"- {u}")

    lines.extend(["", "## Backup access", "", plan.backup_access, "", "## Checklist", ""])
    for i, step in enumerate(plan.checklist, start=1):
        lines.append(f"{i}. {step}")

    return "\n".join(lines) + "\n"


def render_plan_terminal(plan: RotationPlan) -> str:
    """Render RotationPlan as plain terminal text with sections in order."""
    comments_str = f" ({', '.join(plan.identity.comments)})" if plan.identity.comments else ""
    curve_part = f" ({plan.identity.bits_or_curve})" if plan.identity.bits_or_curve else ""

    lines: list[str] = [
        f"Rotation Plan: {plan.fingerprint}",
        "",
        "Identity:",
        f"  - Fingerprint: {plan.identity.fingerprint}",
        f"  - Algorithm: {plan.identity.algorithm}{curve_part}{comments_str}",
        "",
        "Local references:",
    ]

    if plan.local_references:
        for ref in plan.local_references:
            kind_str = ref.kind.value if isinstance(ref.kind, Enum) else str(ref.kind)
            lines.append(f"  - {ref.path} ({kind_str})")
    else:
        lines.append("  (none)")

    lines.extend(["", "Host aliases:"])
    if plan.host_aliases:
        for ha in plan.host_aliases:
            lines.append(f"  - {ha.alias} ({ha.location})")
    else:
        lines.append("  (none)")

    lines.extend(["", "Agent and GitHub:"])
    lines.append(f"  - SSH Agent: {plan.agent_and_github.agent_status}")
    if plan.agent_and_github.github_bindings:
        lines.append("  - GitHub:")
        for b in plan.agent_and_github.github_bindings:
            title_part = f" (title: {b.title})" if b.title else ""
            name = b.title or b.key_id or b.registry
            lines.append(f"    - {name}{title_part}")
    else:
        lines.append(f"  - GitHub: {plan.agent_and_github.github_status}")

    lines.extend(["", "Unknowns:"])
    for u in plan.unknowns:
        lines.append(f"  - {u}")

    lines.extend(["", "Backup access:", f"  {plan.backup_access}", "", "Checklist:"])
    for i, step in enumerate(plan.checklist, start=1):
        lines.append(f"  {i}. {step}")

    return "\n".join(lines) + "\n"


__all__ = [
    "PLAN_KIND",
    "SCHEMA_VERSION",
    "AgentAndGitHubInfo",
    "HostAliasInfo",
    "IdentityMetadata",
    "RotationPlan",
    "build_rotation_plan",
    "plan_to_dict",
    "render_plan_json",
    "render_plan_markdown",
    "render_plan_terminal",
]
