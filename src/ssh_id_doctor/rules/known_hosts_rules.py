"""known_hosts(5) rules (KHS001-KHS006, task #1789/#1795).

Contract: sdd-spec FR-008, Sec. 7.5, Sec. 10 SEC-006. Pure functions over
ScanSnapshot, no I/O. All rules stay silent unless the "known_hosts" source
coverage is AVAILABLE or MALFORMED (unavailable/empty/skipped/timeout mean
there is nothing trustworthy to evaluate).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import ssh_id_doctor.rules as rules_pkg
from ssh_id_doctor.domain import (
    Confidence,
    CoverageState,
    EvidenceReference,
    Finding,
    KnownHostEntry,
    ScanSnapshot,
    Severity,
)

if TYPE_CHECKING:
    from ssh_id_doctor.rules import Rule

_KHS001_EVIDENCE_CAP = 20
"""Cap on the number of line numbers KHS001 lists as evidence for one file."""

_WILDCARD_CHARS = ("*", "?")
_BRACKET_PORT_RE = re.compile(r"^\[(.+)\]:(\d+)$")
_DEFAULT_PORT = "22"


def _exposes_plaintext_host(entry: KnownHostEntry) -> bool:
    """True if at least one of the entry's host tokens is not hashed.

    ``entry.hashed`` is set when *any* token is hashed (inspectors/known_hosts.py),
    so a mixed line like ``|1|salt|hash,plain.example.com`` has ``hashed=True``
    even though it also exposes a plaintext name; KHS001 needs the per-token
    answer instead.
    """
    for token in entry.hosts:
        candidate = token[1:] if token.startswith("!") else token
        if not candidate.startswith("|1|"):
            return True
    return False


_MALFORMED_KINDS: frozenset[str] = frozenset(
    {
        "unknown_marker",
        "missing_hosts_field",
        "incomplete_line",
        "invalid_hosts_field",
        "invalid_base64",
        "invalid_key_blob",
    }
)
"""UnresolvedItem.kind values the known_hosts(5) parser produces (inspectors/known_hosts.py).

Unique to this source: no other inspector emits these kinds, so filtering by
kind alone (without also checking source_file) is safe.
"""


def _known_hosts_coverage_active(snapshot: ScanSnapshot) -> bool:
    """True only when the known_hosts source was inspected and is usable (FR-008).

    KHS001-KHS006 must remain silent unless coverage is AVAILABLE (at least one
    entry parsed) or MALFORMED (every non-empty line was broken) -- never for
    unavailable, empty, timeout or skipped.
    """
    for sc in snapshot.sources:
        if sc.source == "known_hosts":
            raw_state = getattr(sc.state, "value", sc.state)
            state_str = str(raw_state).lower()
            return state_str in (CoverageState.AVAILABLE.value, CoverageState.MALFORMED.value)
    return False


def _khs002_token_key(token: str) -> str | None:
    """Normalized comparison key for one host token of KHS002, or None to exclude it.

    Negations and glob patterns are never compared. A hashed token compares only
    by its literal string. ``[h]:22`` normalizes to ``h``; any other port stays
    distinct from the bare name.
    """
    if token.startswith("!"):
        return None
    if any(c in token for c in _WILDCARD_CHARS):
        return None
    if token.startswith("|1|"):
        return token
    match = _BRACKET_PORT_RE.match(token)
    if match:
        host, port = match.group(1), match.group(2)
        return host if port == _DEFAULT_PORT else f"{host}:{port}"
    return token


class KHS001Rule:
    """KHS001: known_hosts stores host names in plaintext, not HashKnownHosts form.

    Severity: info, Confidence: certain. One finding per known_hosts file.
    """

    rule_id = "KHS001"

    def evaluate(self, snapshot: ScanSnapshot) -> list[Finding]:
        if not _known_hosts_coverage_active(snapshot):
            return []

        lines_by_file: dict[str, set[int]] = {}
        for entry in snapshot.known_hosts:
            if not _exposes_plaintext_host(entry):
                continue
            lines_by_file.setdefault(entry.source_file, set()).add(entry.line)

        findings: list[Finding] = []
        for source_file in sorted(lines_by_file):
            lines = sorted(lines_by_file[source_file])
            evidence = tuple(
                EvidenceReference(source=source_file, line=ln, detail="")
                for ln in lines[:_KHS001_EVIDENCE_CAP]
            )
            fid = rules_pkg.finding_id(self.rule_id, evidence=evidence)

            title = "known_hosts stores host names in plaintext"
            summary = (
                f"{len(lines)} known_hosts line(s) in {source_file} store host names in "
                "plaintext rather than OpenSSH's HashKnownHosts form."
            )
            remediation = (f"Run manually: ssh-keygen -H -f {source_file}",)

            findings.append(
                Finding(
                    id=fid,
                    rule_id=self.rule_id,
                    severity=Severity.INFO,
                    confidence=Confidence.CERTAIN,
                    title=title,
                    summary=summary,
                    evidence=evidence,
                    affected_fingerprints=(),
                    affected_hosts=(),
                    manual_remediation=remediation,
                )
            )
        return findings


class KHS002Rule:
    """KHS002: one host presents different fingerprints for the same key type.

    Severity: warning, Confidence: certain. One finding per (host, key type).
    Lines carrying a marker (@revoked/@cert-authority) never participate.
    """

    rule_id = "KHS002"

    def evaluate(self, snapshot: ScanSnapshot) -> list[Finding]:
        if not _known_hosts_coverage_active(snapshot):
            return []

        groups: dict[tuple[str, str], dict[str, list[KnownHostEntry]]] = {}
        raw_tokens: dict[tuple[str, str], set[str]] = {}

        for entry in snapshot.known_hosts:
            if entry.marker is not None:
                continue
            for token in entry.hosts:
                norm = _khs002_token_key(token)
                if norm is None:
                    continue
                group_key = (norm, entry.key_type)
                groups.setdefault(group_key, {}).setdefault(entry.fingerprint, []).append(entry)
                raw_tokens.setdefault(group_key, set()).add(token)

        findings: list[Finding] = []
        for group_key in sorted(groups):
            fp_map = groups[group_key]
            if len(fp_map) < 2:
                continue
            norm_host, key_type = group_key

            contributing = sorted(
                (e for entries in fp_map.values() for e in entries),
                key=lambda e: (e.source_file, e.line),
            )
            evidence = tuple(
                EvidenceReference(source=e.source_file, line=e.line, detail=e.fingerprint)
                for e in contributing
            )
            affected_hosts = tuple(sorted(raw_tokens[group_key]))
            fingerprints = tuple(sorted(fp_map))
            # norm_host is part of the id: two entries sharing one line can belong to
            # several (host, key_type) groups at once (a line listing multiple hosts),
            # so the same evidence/fingerprints/key_type would otherwise collide across
            # groups that differ only by which host they're keyed on.
            fid = rules_pkg.finding_id(
                self.rule_id,
                evidence=evidence,
                fingerprints=fingerprints,
                key_type=key_type,
                host=norm_host,
            )

            host_label = affected_hosts[0]
            title = f"Conflicting known_hosts key for {host_label} ({key_type})"
            summary = (
                f"known_hosts records {len(fp_map)} different {key_type} fingerprints for "
                f"host {host_label}."
            )
            remediation = (
                "Verify out of band which fingerprint is authentic for this host before "
                "trusting either known_hosts entry",
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
                    affected_fingerprints=fingerprints,
                    affected_hosts=affected_hosts,
                    manual_remediation=remediation,
                )
            )

        findings.sort(key=lambda f: f.id)
        return findings


class KHS003Rule:
    """KHS003: known_hosts entry uses the deprecated ssh-dss key type.

    Severity: warning, Confidence: certain. One finding per matching entry.
    """

    rule_id = "KHS003"
    _key_type = "ssh-dss"

    def evaluate(self, snapshot: ScanSnapshot) -> list[Finding]:
        if not _known_hosts_coverage_active(snapshot):
            return []

        findings: list[Finding] = []
        for entry in snapshot.known_hosts:
            if entry.key_type != self._key_type:
                continue

            evidence = (
                EvidenceReference(source=entry.source_file, line=entry.line, detail=self._key_type),
            )
            fid = rules_pkg.finding_id(
                self.rule_id, evidence=evidence, fingerprints=(entry.fingerprint,)
            )

            title = "known_hosts entry uses the deprecated ssh-dss key type"
            summary = (
                f"A known_hosts entry at {entry.source_file}:{entry.line} uses ssh-dss, "
                "an algorithm OpenSSH has deprecated and many servers no longer offer."
            )
            remediation = (
                "If this host still uses a DSA host key, ask its administrator to "
                "generate a modern replacement (such as Ed25519) manually",
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
                    affected_fingerprints=(entry.fingerprint,),
                    affected_hosts=(),
                    manual_remediation=remediation,
                )
            )

        findings.sort(key=lambda f: f.id)
        return findings


class KHS004Rule:
    """KHS004: known_hosts carries @revoked or @cert-authority marked entries.

    Severity: info, Confidence: certain. One finding per known_hosts file.
    """

    rule_id = "KHS004"

    def evaluate(self, snapshot: ScanSnapshot) -> list[Finding]:
        if not _known_hosts_coverage_active(snapshot):
            return []

        lines_by_file: dict[str, set[int]] = {}
        for entry in snapshot.known_hosts:
            if entry.marker is None:
                continue
            lines_by_file.setdefault(entry.source_file, set()).add(entry.line)

        findings: list[Finding] = []
        for source_file in sorted(lines_by_file):
            lines = sorted(lines_by_file[source_file])
            evidence = tuple(
                EvidenceReference(source=source_file, line=ln, detail="") for ln in lines
            )
            fid = rules_pkg.finding_id(self.rule_id, evidence=evidence)

            title = "known_hosts contains @revoked or @cert-authority entries"
            summary = (
                f"{len(lines)} line(s) in {source_file} carry an @revoked or "
                "@cert-authority marker."
            )
            remediation = (f"Review marked entries manually: grep -n '^@' {source_file}",)

            findings.append(
                Finding(
                    id=fid,
                    rule_id=self.rule_id,
                    severity=Severity.INFO,
                    confidence=Confidence.CERTAIN,
                    title=title,
                    summary=summary,
                    evidence=evidence,
                    affected_fingerprints=(),
                    affected_hosts=(),
                    manual_remediation=remediation,
                )
            )
        return findings


class KHS005Rule:
    """KHS005: known_hosts has lines that do not fit known_hosts(5) grammar.

    Severity: warning, Confidence: heuristic. One finding per known_hosts file.
    Never quotes the broken line's own content (the parser never records it).
    """

    rule_id = "KHS005"

    def evaluate(self, snapshot: ScanSnapshot) -> list[Finding]:
        if not _known_hosts_coverage_active(snapshot):
            return []

        lines_by_file: dict[str, set[int]] = {}
        for item in snapshot.unresolved:
            if item.kind not in _MALFORMED_KINDS or item.source_line is None:
                continue
            lines_by_file.setdefault(item.source_file, set()).add(item.source_line)

        findings: list[Finding] = []
        for source_file in sorted(lines_by_file):
            lines = sorted(lines_by_file[source_file])
            evidence = tuple(
                EvidenceReference(source=source_file, line=ln, detail="") for ln in lines
            )
            fid = rules_pkg.finding_id(self.rule_id, evidence=evidence)

            title = "known_hosts has malformed lines"
            summary = (
                f"{len(lines)} line(s) in {source_file} could not be parsed as "
                "known_hosts(5) grammar."
            )
            remediation = (f"Review manually: a text editor on {source_file}",)

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
                    affected_hosts=(),
                    manual_remediation=remediation,
                )
            )
        return findings


class KHS006Rule:
    """KHS006: known_hosts entry uses ssh-rsa.

    Severity: info, Confidence: certain. One finding per matching entry. The key
    itself is not unsafe; the signature algorithm it defaults to (ssh-rsa,
    SHA-1) might be, so this is informational rather than a weakness report.
    """

    rule_id = "KHS006"
    _key_type = "ssh-rsa"

    def evaluate(self, snapshot: ScanSnapshot) -> list[Finding]:
        if not _known_hosts_coverage_active(snapshot):
            return []

        findings: list[Finding] = []
        for entry in snapshot.known_hosts:
            if entry.key_type != self._key_type:
                continue

            evidence = (
                EvidenceReference(source=entry.source_file, line=entry.line, detail=self._key_type),
            )
            fid = rules_pkg.finding_id(
                self.rule_id, evidence=evidence, fingerprints=(entry.fingerprint,)
            )

            title = "known_hosts entry uses ssh-rsa"
            summary = (
                f"A known_hosts entry at {entry.source_file}:{entry.line} uses ssh-rsa. "
                "The key itself is not unsafe; verify the server also accepts the "
                "rsa-sha2-256/512 signature algorithms, since plain ssh-rsa implies SHA-1."
            )
            remediation = (
                "Verify manually which host key signature algorithms the server accepts",
            )

            findings.append(
                Finding(
                    id=fid,
                    rule_id=self.rule_id,
                    severity=Severity.INFO,
                    confidence=Confidence.CERTAIN,
                    title=title,
                    summary=summary,
                    evidence=evidence,
                    affected_fingerprints=(entry.fingerprint,),
                    affected_hosts=(),
                    manual_remediation=remediation,
                )
            )

        findings.sort(key=lambda f: f.id)
        return findings


KHS001: Rule = KHS001Rule()
KHS002: Rule = KHS002Rule()
KHS003: Rule = KHS003Rule()
KHS004: Rule = KHS004Rule()
KHS005: Rule = KHS005Rule()
KHS006: Rule = KHS006Rule()

RULES: list[Rule] = [KHS001, KHS002, KHS003, KHS004, KHS005, KHS006]

__all__ = [
    "KHS001",
    "KHS002",
    "KHS003",
    "KHS004",
    "KHS005",
    "KHS006",
    "RULES",
    "KHS001Rule",
    "KHS002Rule",
    "KHS003Rule",
    "KHS004Rule",
    "KHS005Rule",
    "KHS006Rule",
]
