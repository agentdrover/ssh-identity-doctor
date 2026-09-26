"""Domain model, sdd-spec §7.

Immutable entities and enums only. Per §8.1 this module performs no I/O:
it must not import subprocess, os or read anything from the filesystem.
Collections are tuples so that a frozen instance is immutable all the way down.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

SCHEMA_VERSION = "1.0"
"""ScanSnapshot.schema_version (§7.1)."""


class Severity(StrEnum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class Confidence(StrEnum):
    CERTAIN = "certain"
    HEURISTIC = "heuristic"
    UNRESOLVED = "unresolved"


class Platform(StrEnum):
    MACOS = "macos"
    LINUX = "linux"


class LocalReferenceKind(StrEnum):
    PUBLIC_KEY = "public_key"
    CONFIG_IDENTITY = "config_identity"


class Resolution(StrEnum):
    RESOLVED = "resolved"
    MISSING = "missing"
    UNREADABLE = "unreadable"
    OUTSIDE_ROOT = "outside_root"
    PRIVATE_ONLY = "private_only"


class CoverageState(StrEnum):
    """State of one scan source (§5.3 note, FR-005 states, §12)."""

    AVAILABLE = "available"
    EMPTY = "empty"
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    MALFORMED = "malformed"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    """Where a finding's evidence was observed. Never carries key material."""

    source: str
    line: int | None = None
    detail: str = ""


@dataclass(frozen=True, slots=True)
class SourceCoverage:
    """How far one source (filesystem, config, agent, github) was covered."""

    source: str
    state: CoverageState
    required: bool
    detail: str = ""


@dataclass(frozen=True, slots=True)
class LocalReference:
    """§7.3."""

    kind: LocalReferenceKind
    path: str
    source_file: str | None
    source_line: int | None
    resolution: Resolution


@dataclass(frozen=True, slots=True)
class RegistryBinding:
    """A remote registry entry (GitHub in the MVP) matched by fingerprint."""

    registry: str
    fingerprint: str
    title: str | None = None
    key_id: str | None = None
    created_at: str | None = None


@dataclass(frozen=True, slots=True)
class Identity:
    """§7.2. `fingerprint` is the canonical `SHA256:<base64>` id (FR-003)."""

    fingerprint: str
    algorithm: str
    bits_or_curve: str
    comments: tuple[str, ...] = ()
    local_references: tuple[LocalReference, ...] = ()
    agent_presence: bool = False
    registry_bindings: tuple[RegistryBinding, ...] = ()


@dataclass(frozen=True, slots=True)
class HostBinding:
    """§7.4. `identities_only` is None when the config does not say."""

    patterns: tuple[str, ...]
    hostname: str | None
    user: str | None
    identity_references: tuple[str, ...]
    resolved_fingerprints: tuple[str, ...]
    identities_only: bool | None
    source_file: str
    source_line: int
    confidence: Confidence


@dataclass(frozen=True, slots=True)
class Finding:
    """§7.5. `id` is stable and derived from content by the rules engine."""

    id: str
    rule_id: str
    severity: Severity
    confidence: Confidence
    title: str
    summary: str
    evidence: tuple[EvidenceReference, ...] = ()
    affected_fingerprints: tuple[str, ...] = ()
    affected_hosts: tuple[str, ...] = ()
    manual_remediation: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ScanSnapshot:
    """§7.1. Timestamps are ISO-8601 strings, scan_id a UUID string."""

    scan_id: str
    started_at: str
    completed_at: str
    platform: Platform
    sources: tuple[SourceCoverage, ...] = ()
    identities: tuple[Identity, ...] = ()
    host_bindings: tuple[HostBinding, ...] = ()
    findings: tuple[Finding, ...] = ()
    schema_version: str = SCHEMA_VERSION
    local_references: tuple[LocalReference, ...] = ()
    """References bound to no Identity (no fingerprint: missing, private_only,
    unreadable, outside_root), sorted by (source_file, source_line, path).
    Additive to schema 1.0; bound references live in Identity.local_references."""
