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
from pathlib import Path
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
from ssh_id_doctor.references import (
    ConfigIdentityReference,
    _expand,  # the FR-002 normalization, not a copy
)
from ssh_id_doctor.scanner import PublicKeyObservation
from ssh_id_doctor.ssh_config import ConfigDocument, IdentityFileEntry


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
    home: str | None = None
    ssh_dir: str | None = None


@dataclass
class _MutableIdentity:
    fingerprint: str
    algorithm: str
    bits_or_curve: str
    comments: set[str] = field(default_factory=set)
    local_references: list[LocalReference] = field(default_factory=list)
    agent_presence: bool = False
    registry_bindings: list[RegistryBinding] = field(default_factory=list)


@dataclass(frozen=True)
class _EntryResolver:
    """Find the fingerprint an IdentityFile entry names, by exact normalized path.

    First by the config reference declared on the same source line (its path is
    already normalized by references.py); without one, the raw value is expanded
    the way references.py does (``~`` to HOME, relative to ``~/.ssh``) and looked
    up as the key path or its ``.pub``. Never by suffix: ``rsa`` is not ``id_rsa``.
    """

    by_source: dict[tuple[str | None, int | None], str | None]
    path_to_fingerprint: dict[str, str]
    home: str | None
    ssh_dir: str | None

    def fingerprint(self, entry: IdentityFileEntry) -> str | None:
        key = (entry.source.file, entry.source.line)
        if key in self.by_source:
            return self.by_source[key]
        raw = entry.path.strip()
        if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
            raw = raw[1:-1]
        if self.home is None and not os.path.isabs(raw):
            return None
        home_path = Path(os.path.realpath(self.home)) if self.home else None
        ssh_dir_path = Path(os.path.realpath(self.ssh_dir)) if self.ssh_dir else None
        normalized = str(_expand(raw, home_path, ssh_dir_path))
        candidates = [normalized]
        if not normalized.endswith(".pub"):
            candidates.append(normalized + ".pub")
        for candidate in candidates:
            for path in (candidate, os.path.realpath(candidate)):
                if path in self.path_to_fingerprint:
                    return self.path_to_fingerprint[path]
        return None


def _sorted_unbound(refs: Sequence[LocalReference]) -> tuple[LocalReference, ...]:
    unique = {
        (r.kind.value, r.path, r.source_file, r.source_line, r.resolution.value): r for r in refs
    }
    return tuple(
        sorted(
            unique.values(),
            key=lambda r: (r.source_file or "", r.source_line or 0, r.path, r.kind.value),
        )
    )


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

    # References that name no fingerprint and so belong to no Identity
    unbound_references: list[LocalReference] = []

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
        else:
            unbound_references.append(loc_ref)

    # Fingerprint (or None) of each config IdentityFile, keyed by where it was declared
    fingerprint_by_source: dict[tuple[str | None, int | None], str | None] = {}

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
            fingerprint_by_source[(cfg_ref.source_file, cfg_ref.source_line)] = fp
        else:
            # If cfg_ref was not keyed with key_info, check if we already resolved this path
            known_fp = path_to_fingerprint.get(canonical_path) or path_to_fingerprint.get(
                cfg_ref.path
            )
            if known_fp is not None:
                identities_by_fp[known_fp].local_references.append(domain_loc_ref)
            else:
                unbound_references.append(domain_loc_ref)
            fingerprint_by_source[(cfg_ref.source_file, cfg_ref.source_line)] = known_fp

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
        resolver = _EntryResolver(
            by_source=fingerprint_by_source,
            path_to_fingerprint=path_to_fingerprint,
            home=observations.home or os.environ.get("HOME"),
            ssh_dir=observations.ssh_dir,
        )
        for block in doc.host_blocks:
            if not block.patterns:
                continue  # Skip blocks without patterns (like Match or global)
            id_refs = tuple(entry.path for entry in block.identity_files)
            resolved_fps: list[str] = []
            unresolved_entries = 0
            for entry in block.identity_files:
                found_fp = resolver.fingerprint(entry)
                if found_fp is None:
                    unresolved_entries += 1
                elif found_fp not in resolved_fps:
                    resolved_fps.append(found_fp)

            header_file = block.header.file if block.header else doc.path
            header_line = block.header.line if block.header else 1
            # A reference that names no fingerprint (missing, private-only, token)
            # leaves the host's identity unknown.
            confidence = Confidence.UNRESOLVED if unresolved_entries else Confidence.CERTAIN

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
        local_references=_sorted_unbound(unbound_references),
    )


__all__ = [
    "ScanObservations",
    "build_snapshot",
]
