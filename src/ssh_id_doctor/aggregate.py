"""FR-007: IdentityAggregator and build_snapshot.

Aggregates observations from discovery, ssh_config, SSH agent, and GitHub registry
into a unified, deterministic ScanSnapshot.
"""

from __future__ import annotations

import os
import sys
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ssh_id_doctor.domain import (
    Confidence,
    Finding,
    HostBinding,
    Identity,
    LocalReference,
    LocalReferenceKind,
    Platform,
    RegistryBinding,
    ScanSnapshot,
    SourceCoverage,
)
from ssh_id_doctor.references import ConfigIdentityReference
from ssh_id_doctor.scanner import PublicKeyObservation
from ssh_id_doctor.ssh_config import ConfigDocument


@dataclass
class ScanObservations:
    """Observations collected across all sources before aggregation."""

    public_keys: Sequence[tuple[PublicKeyObservation, Any]] = ()
    config_references: Sequence[tuple[ConfigIdentityReference, Any]] = ()
    config_document: ConfigDocument | None = None
    agent_identities: Sequence[Identity] = ()
    registry_bindings: Sequence[RegistryBinding] = ()
    sources: Sequence[SourceCoverage] = ()
    scan_id: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    platform: Platform | None = None
    findings: Sequence[Finding] = ()


@dataclass
class _MutableIdentity:
    fingerprint: str
    algorithm: str
    bits_or_curve: str
    comments: set[str] = field(default_factory=set)
    local_references: list[LocalReference] = field(default_factory=list)
    agent_presence: bool = False
    registry_bindings: list[RegistryBinding] = field(default_factory=list)


def _detect_platform() -> Platform:
    if sys.platform == "darwin":
        return Platform.MACOS
    return Platform.LINUX


def build_snapshot(observations: ScanObservations) -> ScanSnapshot:
    """Merge observations from all sources into a deterministic ScanSnapshot.

    - Identities deduplicated by canonical SHA256 fingerprint.
    - Comments sorted and deduplicated.
    - LocalReferences deduplicated and sorted.
    - Agent presence and registry bindings attached.
    - HostBindings constructed with resolved_fingerprints in pattern order.
    - All collections deterministically sorted.
    """
    identities_by_fp: dict[str, _MutableIdentity] = {}

    def get_or_create(fp: str, algo: str = "", bits: str = "") -> _MutableIdentity:
        if fp not in identities_by_fp:
            identities_by_fp[fp] = _MutableIdentity(
                fingerprint=fp,
                algorithm=algo,
                bits_or_curve=bits,
            )
        else:
            mid = identities_by_fp[fp]
            if not mid.algorithm and algo:
                mid.algorithm = algo
            if not mid.bits_or_curve and bits:
                mid.bits_or_curve = bits
        return identities_by_fp[fp]

    # Map from canonical path -> fingerprint for resolved local references
    path_to_fingerprint: dict[str, str] = {}

    # 1. Process discovered public keys
    for pub_obs, key_info in observations.public_keys:
        loc_ref = LocalReference(
            kind=LocalReferenceKind.PUBLIC_KEY,
            path=pub_obs.path,
            source_file=None,
            source_line=None,
            resolution=pub_obs.resolution,
        )
        if key_info is not None and hasattr(key_info, "fingerprint"):
            fp = str(key_info.fingerprint)
            algo = getattr(key_info, "algorithm", "")
            bits = getattr(key_info, "bits_or_curve", "")
            mid = get_or_create(fp, algo, bits)
            mid.local_references.append(loc_ref)
            comment = getattr(key_info, "comment", "")
            if comment and comment != "no comment":
                mid.comments.add(comment)
            canonical_path = os.path.realpath(os.path.normpath(pub_obs.path))
            path_to_fingerprint[canonical_path] = fp
            path_to_fingerprint[pub_obs.path] = fp

    # 2. Process config identity references
    for cfg_ref, key_info in observations.config_references:
        # Strip public_key_text / key_line if present, convert to domain.LocalReference
        domain_loc_ref = LocalReference(
            kind=LocalReferenceKind.CONFIG_IDENTITY,
            path=cfg_ref.path,
            source_file=cfg_ref.source_file,
            source_line=cfg_ref.source_line,
            resolution=cfg_ref.resolution,
        )
        canonical_path = os.path.realpath(os.path.normpath(cfg_ref.path))
        if key_info is not None and hasattr(key_info, "fingerprint"):
            fp = str(key_info.fingerprint)
            algo = getattr(key_info, "algorithm", "")
            bits = getattr(key_info, "bits_or_curve", "")
            mid = get_or_create(fp, algo, bits)
            mid.local_references.append(domain_loc_ref)
            comment = getattr(key_info, "comment", "")
            if comment and comment != "no comment":
                mid.comments.add(comment)
            path_to_fingerprint[canonical_path] = fp
            path_to_fingerprint[cfg_ref.path] = fp
        else:
            # If cfg_ref was not keyed with key_info, check if we already resolved this path
            if canonical_path in path_to_fingerprint:
                fp = path_to_fingerprint[canonical_path]
                identities_by_fp[fp].local_references.append(domain_loc_ref)
            elif cfg_ref.path in path_to_fingerprint:
                fp = path_to_fingerprint[cfg_ref.path]
                identities_by_fp[fp].local_references.append(domain_loc_ref)

    # 3. Process agent identities
    for agent_id in observations.agent_identities:
        fp = agent_id.fingerprint
        mid = get_or_create(fp, agent_id.algorithm, agent_id.bits_or_curve)
        mid.agent_presence = True
        for c in agent_id.comments:
            if c and c != "no comment":
                mid.comments.add(c)
        for ref in agent_id.local_references:
            mid.local_references.append(ref)

    # 4. Process registry bindings
    for reg_bind in observations.registry_bindings:
        fp = reg_bind.fingerprint
        mid = get_or_create(fp)
        mid.registry_bindings.append(reg_bind)

    # Freeze identities
    final_identities: list[Identity] = []
    for _fp, mid in identities_by_fp.items():
        # Deduplicate local references
        unique_refs: dict[tuple[str, str, str | None, int | None, str], LocalReference] = {}
        for ref in mid.local_references:
            key = (ref.kind.value, ref.path, ref.source_file, ref.source_line, ref.resolution.value)
            if key not in unique_refs:
                unique_refs[key] = ref

        sorted_refs = tuple(
            sorted(
                unique_refs.values(),
                key=lambda r: (r.kind.value, r.path, r.source_file or "", r.source_line or 0),
            )
        )

        # Deduplicate registry bindings
        unique_bindings: dict[tuple[str, str, str | None, str | None], RegistryBinding] = {}
        for b in mid.registry_bindings:
            b_key = (b.registry, b.fingerprint, b.key_id, b.title)
            if b_key not in unique_bindings:
                unique_bindings[b_key] = b

        sorted_bindings = tuple(
            sorted(
                unique_bindings.values(),
                key=lambda b: (b.registry, b.key_id or "", b.title or ""),
            )
        )

        sorted_comments = tuple(sorted(mid.comments))

        final_identities.append(
            Identity(
                fingerprint=mid.fingerprint,
                algorithm=mid.algorithm,
                bits_or_curve=mid.bits_or_curve,
                comments=sorted_comments,
                local_references=sorted_refs,
                agent_presence=mid.agent_presence,
                registry_bindings=sorted_bindings,
            )
        )

    final_identities.sort(key=lambda ident: ident.fingerprint)

    # 5. Build HostBindings from ConfigDocument
    final_host_bindings: list[HostBinding] = []
    if observations.config_document is not None:
        doc = observations.config_document
        for block in doc.host_blocks:
            if not block.patterns:
                continue  # Skip blocks without patterns (like Match or global)
            id_refs = tuple(entry.path for entry in block.identity_files)
            resolved_fps: list[str] = []
            for entry in block.identity_files:
                entry_path = entry.path.strip()
                if entry_path.startswith('"') and entry_path.endswith('"') and len(entry_path) >= 2:
                    entry_path = entry_path[1:-1]

                # Check directly or via canonical paths
                found_fp = path_to_fingerprint.get(entry_path)
                if found_fp is None:
                    # Also check tilde-expanded or resolved paths
                    if entry_path.startswith("~/"):
                        home_dir = os.environ.get("HOME")
                        if home_dir:
                            expanded = os.path.normpath(os.path.join(home_dir, entry_path[2:]))
                            found_fp = path_to_fingerprint.get(expanded) or path_to_fingerprint.get(
                                os.path.realpath(expanded)
                            )
                if found_fp is None:
                    # Try resolving against doc dir or home
                    doc_dir = os.path.dirname(doc.path)
                    candidate = os.path.normpath(os.path.join(doc_dir, entry_path))
                    found_fp = path_to_fingerprint.get(candidate)
                    if found_fp is None:
                        real_candidate = os.path.realpath(candidate)
                        found_fp = path_to_fingerprint.get(real_candidate)
                # Also check matching against any registered reference path
                if found_fp is None:
                    for ref_path, ref_fp in path_to_fingerprint.items():
                        if ref_path.endswith(entry_path.lstrip("~").lstrip("/")):
                            found_fp = ref_fp
                            break
                if found_fp and found_fp not in resolved_fps:
                    resolved_fps.append(found_fp)

            header_file = block.header.file if block.header else doc.path
            header_line = block.header.line if block.header else 1
            confidence = Confidence.CERTAIN if block.patterns else Confidence.UNRESOLVED

            final_host_bindings.append(
                HostBinding(
                    patterns=block.patterns,
                    hostname=block.hostname,
                    user=block.user,
                    identity_references=id_refs,
                    resolved_fingerprints=tuple(resolved_fps),
                    identities_only=block.identities_only,
                    source_file=header_file,
                    source_line=header_line,
                    confidence=confidence,
                )
            )

    final_host_bindings.sort(key=lambda hb: (hb.source_file, hb.source_line, " ".join(hb.patterns)))

    # Sort sources
    sorted_sources = tuple(sorted(observations.sources, key=lambda s: s.source))

    # Sort findings
    sorted_findings = tuple(
        sorted(observations.findings, key=lambda f: (f.severity, f.rule_id, f.id))
    )

    now_iso = datetime.now(UTC).isoformat()
    scan_id = observations.scan_id or str(uuid.uuid4())
    started_at = observations.started_at or now_iso
    completed_at = observations.completed_at or now_iso
    platform = observations.platform or _detect_platform()

    return ScanSnapshot(
        scan_id=scan_id,
        started_at=started_at,
        completed_at=completed_at,
        platform=platform,
        sources=sorted_sources,
        identities=tuple(final_identities),
        host_bindings=tuple(final_host_bindings),
        findings=sorted_findings,
    )


__all__ = [
    "ScanObservations",
    "build_snapshot",
]
