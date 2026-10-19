"""Redaction transform for ScanSnapshot (sdd-spec §5.2, §9 step 10, SEC-004).

Transforms snapshot before rendering so that:
- mode 'hosts': patterns/HostName/User -> host-1, host-2... stably, affected_hosts, etc.
- mode 'paths': filesystem paths -> ~/.../<basename-hash> (or similar stable hash),
  evidence source/detail, etc.
- mode 'all': both hosts and paths, plus key comments stripped/redacted and GitHub titles/key_ids.

Redaction operates strictly on the snapshot object before rendering so that terminal,
Markdown, and JSON render identically.
"""

from __future__ import annotations

import hashlib
import os
import re
from typing import Literal

from ssh_id_doctor.domain import (
    EvidenceReference,
    Finding,
    HostBinding,
    Identity,
    LocalReference,
    RegistryBinding,
    ScanSnapshot,
    SourceCoverage,
    UnresolvedItem,
)

_WORD_CHAR = r"[A-Za-z0-9_]"
"""Used to build a ``\\b``-like boundary around a substituted literal that also
works when it starts or ends with a non-word character, such as the
``[host]:port`` known_hosts form. ``\\breal\\b`` requires a word char on
exactly one side of each edge, so it never matches ``[host]:port`` preceded
by a space (non-word on both sides of the leading ``[``). A lookaround that
simply forbids a word char immediately outside the match has no such blind
spot, and agrees with ``\\b`` whenever the literal starts/ends with a word
character.
"""

_PATH_WORD_CHAR = r"[A-Za-z0-9]"
"""Like ``_WORD_CHAR`` but excludes ``_``, for matching a registered host/user
name inside a path's *basename*. A key named after its host conventionally
uses ``_`` as the separator (``id_bridge.example.com``), so treating ``_`` as
a word character there would hide the boundary and leave the host name
unmatched, unlike in free-text sentences where ``_`` genuinely joins one
identifier.
"""


RedactMode = Literal["hosts", "paths", "all"]

_BRACKET_PORT_RE = re.compile(r"^\[(.+)\]:(\d+)$")


def _strip_known_hosts_negation(token: str) -> tuple[str, str]:
    """Split a known_hosts host token into its ``!`` negation prefix (if any) and
    the rest, without touching hashed ``|1|`` tokens (callers check those first)."""
    return ("!", token[1:]) if token.startswith("!") else ("", token)


def _known_hosts_alias_target(token: str) -> str | None:
    """The substring of a known_hosts host token to register/alias, or ``None``
    if the token must never be aliased (a hashed ``|1|`` entry stays as-is).

    Strips ``!`` negation and the ``[host]:port`` bracket wrapper so a
    known_hosts ``[host]:port`` entry shares its pseudonym with the same host
    written bare, e.g. an ssh config Host line (sdd-spec #1868).
    """
    if token.startswith("|1|"):
        return None
    _, rest = _strip_known_hosts_negation(token)
    if not rest:
        return None
    match = _BRACKET_PORT_RE.match(rest)
    return match.group(1) if match else rest


def _is_known_hosts_finding(f: Finding) -> bool:
    """True only for findings from known_hosts(5) rules (``KHS*``).

    Only those put known_hosts-grammar tokens (``!neg``, ``[host]:port``,
    hashed ``|1|...``) in ``affected_hosts``. Config/agent rules (``CFG*``,
    ``AGT*``) put raw ssh config ``Host`` patterns there instead -- whole
    strings, possibly containing ``!`` or glob chars that are part of the
    pattern itself, not known_hosts negation/brackets -- which must be
    aliased the same whole-string way as ``HostBinding.patterns`` (sdd-spec
    #1868 review finding 1).
    """
    return f.rule_id.startswith("KHS")


class Redactor:
    """Stateful redactor mapping identifiers to stable sequential pseudonyms."""

    def __init__(self, mode: RedactMode) -> None:
        self.mode = mode
        self.redact_hosts = mode in ("hosts", "all")
        self.redact_paths = mode in ("paths", "all")
        self.redact_metadata = mode == "all"

        self._host_map: dict[str, str] = {}
        self._user_map: dict[str, str] = {}
        self._path_map: dict[str, str] = {}
        self._path_alias_by_canonical: dict[str, str] = {}
        self._known_hosts_token_map: dict[str, str] = {}

    def get_host_alias(self, host: str) -> str:
        if not host:
            return host
        if host not in self._host_map:
            self._host_map[host] = f"host-{len(self._host_map) + 1}"
        return self._host_map[host]

    def get_user_alias(self, user: str) -> str:
        if not user:
            return user
        if user not in self._user_map:
            self._user_map[user] = f"user-{len(self._user_map) + 1}"
        return self._user_map[user]

    def get_path_alias(self, path: str) -> str:
        if not path:
            return path
        if path in self._path_map:
            return self._path_map[path]

        # Two spellings of the same file (an ssh config's raw, unexpanded
        # '~/...' IdentityFile value vs. the expanded absolute path computed
        # for the matching LocalReference) must share one alias (sdd-spec
        # #1908 AC-1): key the alias on the canonical form, keeping the
        # literal-spelling map (self._path_map) only for free-text matching
        # in redact_text_sub.
        canonical = self._canonical_path(path)
        if canonical not in self._path_alias_by_canonical:
            # Deterministic hash of the canonical path to preserve uniqueness
            # -- two paths with the same basename must not collide just
            # because their basename gets redacted alike.
            h = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:8]
            name = canonical.rstrip("/").split("/")[-1]
            if self.redact_hosts:
                # A key named after its host/user (id_bridge.example.com)
                # must not leak that name through the basename just because
                # host/user redaction only otherwise touches free text.
                name = self._apply(name, self._host_user_replacements(), word_char=_PATH_WORD_CHAR)
            if name.endswith(".pub"):
                clean_name = name[:-4]
                alias = f"~/.../{clean_name}-{h}.pub"
            else:
                alias = f"~/.../{name}-{h}"
            self._path_alias_by_canonical[canonical] = alias

        alias = self._path_alias_by_canonical[canonical]
        self._path_map[path] = alias
        return alias

    @staticmethod
    def _canonical_path(path: str) -> str:
        """Normalize a path for alias deduplication only (never for display):
        expand a leading ``~`` the same way ``references._expand`` does (both
        ultimately key off ``$HOME``), then ``normpath``, so an unexpanded
        config value and its already-expanded counterpart collapse to one
        canonical string and thus one alias."""
        expanded = os.path.expanduser(path) if path.startswith("~") else path
        return os.path.normpath(expanded)

    def register_known_hosts_token(self, token: str) -> str:
        """Register one known_hosts(5) host token from a KHS-rule Finding's
        ``affected_hosts`` and return its redacted rendering.

        A hashed ``|1|`` token is returned unchanged; a ``!host`` or
        ``[host]:port`` form keeps its negation/brackets/port but aliases the
        host part, so the rendering matches ``get_host_alias`` for the same
        host written bare, e.g. an ssh config ``Host`` line (sdd-spec #1868).

        Also caches the exact original token -> rendering so
        ``redact_text_sub`` can later match the *whole* token as one unit in
        free text (title/summary/remediation), ahead of any shorter alias or
        bare host/port substring it would otherwise collide with -- e.g. a
        host named ``2222`` inside ``[2222]:2222``, or a registered host name
        that happens to occur as a substring of an unrelated hashed ``|1|``
        token's salt/hash (sdd-spec #1868 review findings 2-3).
        """
        if token in self._known_hosts_token_map:
            return self._known_hosts_token_map[token]
        if token.startswith("|1|"):
            rendered = token
        else:
            prefix, rest = _strip_known_hosts_negation(token)
            match = _BRACKET_PORT_RE.match(rest) if rest else None
            if match:
                rendered = f"{prefix}[{self.get_host_alias(match.group(1))}]:{match.group(2)}"
            elif rest:
                rendered = f"{prefix}{self.get_host_alias(rest)}"
            else:
                rendered = token
        self._known_hosts_token_map[token] = rendered
        return rendered

    def redact_text_sub(self, text: str) -> str:
        """Substitute any known hosts, users, known_hosts tokens, and paths in
        strings (titles, summaries, details), in one atomic pass.

        Paths and hosts/users/known_hosts tokens are combined into the same
        single ``re.sub`` call (longest literal first) rather than two
        sequential passes, so a path alias inserted by this substitution (it
        may itself already contain a host alias like ``host-1``, baked in by
        ``get_path_alias``) is never rescanned by a second, independent hosts
        pass -- which would otherwise wrongly rewrite it if some unrelated
        registered host happened to share that literal text (sdd-spec #1908
        review finding 2; same hazard the single combined pass already
        guards against for hosts/known_hosts tokens, below).
        """
        if not text:
            return text
        replacements: dict[str, str] = {}
        if self.redact_paths:
            replacements.update(self._path_map)
        if self.redact_hosts:
            replacements.update(self._host_user_replacements())
        return self._apply(text, replacements, word_char=_WORD_CHAR)

    def _host_user_replacements(self) -> dict[str, str]:
        return {
            **self._user_map,
            **self._host_map,
            **self._known_hosts_token_map,
        }

    @staticmethod
    def _apply(text: str, replacements: dict[str, str], *, word_char: str) -> str:
        """One-pass alias substitution, longest literal first, in a single
        combined regex.

        A single pass (one ``re.sub`` call) guarantees a substituted alias is
        never rescanned by a later substitution -- unlike sequential
        per-map/per-entry ``re.sub`` or ``str.replace`` calls, which could
        re-match text an earlier substitution had just inserted (sdd-spec
        #1868 review finding 2, #1908 review finding 2). Registering whole
        known_hosts tokens (not just bare host names) in the same combined,
        longest-first alternation also makes a longer token match as one
        atomic unit ahead of any shorter embedded literal it would otherwise
        ambiguously overlap with.
        """
        if not replacements:
            return text
        literals = sorted(replacements, key=len, reverse=True)
        alternation = "|".join(re.escape(lit) for lit in literals)
        pattern = re.compile(rf"(?<!{word_char})(?:{alternation})(?!{word_char})")
        return pattern.sub(lambda m: replacements[m.group(0)], text)


def redact(snapshot: ScanSnapshot, mode: RedactMode) -> ScanSnapshot:
    """Transform snapshot by redacting sensitive data according to mode."""
    redactor = Redactor(mode)

    # 1. Pre-register hosts and users from host bindings, before any path is
    # aliased: get_path_alias redacts a registered host/user name out of a
    # path's basename (e.g. IdentityFile ~/.ssh/id_bridge.example.com for
    # Host bridge.example.com), which only works if the host/user map is
    # already populated by the time the first path is seen (sdd-spec #1908).
    if redactor.redact_hosts:
        for hb in snapshot.host_bindings:
            for pat in hb.patterns:
                redactor.get_host_alias(pat)
            if hb.hostname:
                redactor.get_host_alias(hb.hostname)
            if hb.user:
                redactor.get_user_alias(hb.user)
        for f in snapshot.findings:
            for h in f.affected_hosts:
                if _is_known_hosts_finding(f):
                    redactor.register_known_hosts_token(h)
                else:
                    redactor.get_host_alias(h)
        for kh in snapshot.known_hosts:
            for token in kh.hosts:
                target = _known_hosts_alias_target(token)
                if target is not None:
                    redactor.get_host_alias(target)

    # 2. Pre-register paths from local references & public keys
    if redactor.redact_paths:
        for ident in snapshot.identities:
            for ref in ident.local_references:
                redactor.get_path_alias(ref.path)
                if ref.source_file:
                    redactor.get_path_alias(ref.source_file)
        for ref in snapshot.local_references:
            redactor.get_path_alias(ref.path)
            if ref.source_file:
                redactor.get_path_alias(ref.source_file)
        for hb in snapshot.host_bindings:
            if hb.source_file:
                redactor.get_path_alias(hb.source_file)
            for ir in hb.identity_references:
                redactor.get_path_alias(ir)
        for item in snapshot.unresolved:
            if item.source_file:
                redactor.get_path_alias(item.source_file)
            # Detail might be an included path
            if "/" in item.detail or item.detail.endswith((".conf", ".pub", "config")):
                redactor.get_path_alias(item.detail)

    # Transform HostBindings
    new_host_bindings: list[HostBinding] = []
    for hb in snapshot.host_bindings:
        pats = (
            tuple(redactor.get_host_alias(p) for p in hb.patterns)
            if redactor.redact_hosts
            else hb.patterns
        )
        hname = (
            redactor.get_host_alias(hb.hostname)
            if redactor.redact_hosts and hb.hostname
            else hb.hostname
        )
        user = redactor.get_user_alias(hb.user) if redactor.redact_hosts and hb.user else hb.user
        id_refs = (
            tuple(redactor.get_path_alias(r) for r in hb.identity_references)
            if redactor.redact_paths
            else hb.identity_references
        )
        src_file = (
            redactor.get_path_alias(hb.source_file) if redactor.redact_paths else hb.source_file
        )
        new_host_bindings.append(
            HostBinding(
                patterns=pats,
                hostname=hname,
                user=user,
                identity_references=id_refs,
                resolved_fingerprints=hb.resolved_fingerprints,
                identities_only=hb.identities_only,
                source_file=src_file,
                source_line=hb.source_line,
                confidence=hb.confidence,
            )
        )

    new_identities: list[Identity] = []
    for ident in snapshot.identities:
        new_local_refs: list[LocalReference] = []
        for ref in ident.local_references:
            r_path = redactor.get_path_alias(ref.path) if redactor.redact_paths else ref.path
            r_src = (
                redactor.get_path_alias(ref.source_file)
                if redactor.redact_paths and ref.source_file
                else ref.source_file
            )
            new_local_refs.append(
                LocalReference(
                    kind=ref.kind,
                    path=r_path,
                    source_file=r_src,
                    source_line=ref.source_line,
                    resolution=ref.resolution,
                )
            )

        comments = () if redactor.redact_metadata else ident.comments

        new_reg_bindings: list[RegistryBinding] = []
        for b in ident.registry_bindings:
            if redactor.redact_metadata:
                new_reg_bindings.append(
                    RegistryBinding(
                        registry=b.registry,
                        fingerprint=b.fingerprint,
                        title="[REDACTED]" if b.title else None,
                        key_id=b.key_id,
                        created_at=b.created_at,
                    )
                )
            else:
                new_reg_bindings.append(b)

        new_identities.append(
            Identity(
                fingerprint=ident.fingerprint,
                algorithm=ident.algorithm,
                bits_or_curve=ident.bits_or_curve,
                comments=comments,
                local_references=tuple(new_local_refs),
                agent_presence=ident.agent_presence,
                registry_bindings=tuple(new_reg_bindings),
            )
        )

    # Transform unbound LocalReferences
    new_local_references: list[LocalReference] = []
    for ref in snapshot.local_references:
        r_path = redactor.get_path_alias(ref.path) if redactor.redact_paths else ref.path
        r_src = (
            redactor.get_path_alias(ref.source_file)
            if redactor.redact_paths and ref.source_file
            else ref.source_file
        )
        new_local_references.append(
            LocalReference(
                kind=ref.kind,
                path=r_path,
                source_file=r_src,
                source_line=ref.source_line,
                resolution=ref.resolution,
            )
        )

    # Transform UnresolvedItems
    new_unresolved: list[UnresolvedItem] = []
    for item in snapshot.unresolved:
        u_src = (
            redactor.get_path_alias(item.source_file) if redactor.redact_paths else item.source_file
        )
        u_detail = redactor.redact_text_sub(item.detail)
        new_unresolved.append(
            UnresolvedItem(
                kind=item.kind,
                detail=u_detail,
                source_file=u_src,
                source_line=item.source_line,
            )
        )

    # Transform Findings
    new_findings: list[Finding] = []
    for f in snapshot.findings:
        new_ev_list: list[EvidenceReference] = []
        for ev in f.evidence:
            ev_src = redactor.get_path_alias(ev.source) if redactor.redact_paths else ev.source
            ev_detail = redactor.redact_text_sub(ev.detail)
            new_ev_list.append(
                EvidenceReference(
                    source=ev_src,
                    line=ev.line,
                    detail=ev_detail,
                )
            )

        aff_hosts = (
            tuple(
                redactor.register_known_hosts_token(h)
                if _is_known_hosts_finding(f)
                else redactor.get_host_alias(h)
                for h in f.affected_hosts
            )
            if redactor.redact_hosts
            else f.affected_hosts
        )

        title = redactor.redact_text_sub(f.title)
        summary = redactor.redact_text_sub(f.summary)
        remediation = tuple(redactor.redact_text_sub(rem) for rem in f.manual_remediation)

        new_findings.append(
            Finding(
                id=f.id,
                rule_id=f.rule_id,
                severity=f.severity,
                confidence=f.confidence,
                title=title,
                summary=summary,
                evidence=tuple(new_ev_list),
                affected_fingerprints=f.affected_fingerprints,
                affected_hosts=aff_hosts,
                manual_remediation=remediation,
            )
        )

    # Sources detail redaction
    new_sources: list[SourceCoverage] = []
    for s in snapshot.sources:
        new_sources.append(
            SourceCoverage(
                source=s.source,
                state=s.state,
                required=s.required,
                detail=redactor.redact_text_sub(s.detail),
            )
        )

    return ScanSnapshot(
        scan_id=snapshot.scan_id,
        started_at=snapshot.started_at,
        completed_at=snapshot.completed_at,
        platform=snapshot.platform,
        sources=tuple(new_sources),
        identities=tuple(new_identities),
        host_bindings=tuple(new_host_bindings),
        findings=tuple(new_findings),
        schema_version=snapshot.schema_version,
        local_references=tuple(new_local_references),
        unresolved=tuple(new_unresolved),
        known_hosts=snapshot.known_hosts,
    )


__all__ = [
    "RedactMode",
    "Redactor",
    "redact",
]
