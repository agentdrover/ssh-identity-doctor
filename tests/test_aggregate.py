"""Tests for FR-007 / IdentityAggregator (AC-1)."""

from __future__ import annotations

from ssh_id_doctor.aggregate import ScanObservations, build_snapshot
from ssh_id_doctor.domain import (
    Confidence,
    CoverageState,
    LocalReferenceKind,
    RegistryBinding,
    Resolution,
    SourceCoverage,
)
from ssh_id_doctor.inspectors.keygen import KeyInfo
from ssh_id_doctor.references import LocalReference
from ssh_id_doctor.scanner import PublicKeyObservation
from ssh_id_doctor.ssh_config import (
    ConfigDocument,
    HostBlock,
    IdentityFileEntry,
    SourceLoc,
    UnresolvedConfigItem,
)


def test_same_fingerprint_merged_with_all_relationships() -> None:
    """AC-1: observations id_a.pub, copy_of_a.pub, config 'Host gh' -> ~/.ssh/id_a,

    agent with F, and GitHub registry key with F all merge into exactly 1 Identity with F,
    3 local_references (2 public_key + 1 config_identity), agent_presence=True,
    1 registry_binding, and HostBinding 'gh' with resolved_fingerprints=[F].
    """
    fingerprint = "SHA256:u1234567890abcdef1234567890abcdef1234567890"
    algo = "ssh-ed25519"
    bits = "ED25519"
    key_info = KeyInfo(
        fingerprint=fingerprint,
        algorithm=algo,
        bits_or_curve=bits,
        comment="test-key",
    )

    # 1. Two discovered public keys with same fingerprint
    pub1 = PublicKeyObservation(path="/home/test/.ssh/id_a.pub", resolution=Resolution.RESOLVED)
    pub2 = PublicKeyObservation(
        path="/home/test/.ssh/copy_of_a.pub", resolution=Resolution.RESOLVED
    )

    # 2. Config reference: Host gh -> ~/.ssh/id_a
    cfg_ref = LocalReference(
        kind=LocalReferenceKind.CONFIG_IDENTITY,
        path="/home/test/.ssh/id_a",
        source_file="/home/test/.ssh/config",
        source_line=3,
        resolution=Resolution.RESOLVED,
        public_key_text="ssh-ed25519 AAAAC3... test-key",
    )

    # Config document with Host gh
    host_block = HostBlock(
        patterns=("gh",),
        header=SourceLoc(file="/home/test/.ssh/config", line=2),
        identity_files=(
            IdentityFileEntry(
                path="~/.ssh/id_a", source=SourceLoc(file="/home/test/.ssh/config", line=3)
            ),
        ),
    )
    doc = ConfigDocument(
        path="/home/test/.ssh/config",
        global_block=HostBlock(patterns=(), header=None),
        host_blocks=(host_block,),
        unresolved=(),
    )

    # 3. Agent identity with fingerprint
    from ssh_id_doctor.domain import Identity as AgentIdentity

    agent_id = AgentIdentity(
        fingerprint=fingerprint,
        algorithm=algo,
        bits_or_curve=bits,
        comments=("test-key",),
        local_references=(),
        agent_presence=True,
        registry_bindings=(),
    )

    # 4. GitHub registry binding with fingerprint
    reg_binding = RegistryBinding(
        registry="github",
        fingerprint=fingerprint,
        title="work-laptop",
        key_id="12345",
        created_at="2026-01-01T00:00:00Z",
    )

    sources = [
        SourceCoverage(source="filesystem", state=CoverageState.AVAILABLE, required=True),
        SourceCoverage(source="config", state=CoverageState.AVAILABLE, required=False),
        SourceCoverage(source="agent", state=CoverageState.AVAILABLE, required=False),
        SourceCoverage(source="github", state=CoverageState.AVAILABLE, required=False),
    ]

    obs = ScanObservations(
        public_keys=[(pub1, key_info), (pub2, key_info)],
        config_references=[(cfg_ref, key_info)],
        config_document=doc,
        agent_identities=[agent_id],
        registry_bindings=[reg_binding],
        sources=sources,
    )

    snapshot = build_snapshot(obs)

    # Assertions for AC-1
    assert len(snapshot.identities) == 1
    identity = snapshot.identities[0]
    assert identity.fingerprint == fingerprint
    assert identity.agent_presence is True
    assert len(identity.registry_bindings) == 1
    assert identity.registry_bindings[0] == reg_binding

    # 3 local references: 2 public_key + 1 config_identity
    assert len(identity.local_references) == 3
    pub_refs = [r for r in identity.local_references if r.kind is LocalReferenceKind.PUBLIC_KEY]
    cfg_refs = [
        r for r in identity.local_references if r.kind is LocalReferenceKind.CONFIG_IDENTITY
    ]
    assert len(pub_refs) == 2
    assert len(cfg_refs) == 1
    assert cfg_refs[0].source_line == 3
    assert cfg_refs[0].source_file == "/home/test/.ssh/config"

    # HostBinding 'gh' has resolved_fingerprints=[F]
    gh_bindings = [hb for hb in snapshot.host_bindings if "gh" in hb.patterns]
    assert len(gh_bindings) == 1
    gh_hb = gh_bindings[0]
    assert gh_hb.resolved_fingerprints == (fingerprint,)
    assert gh_hb.confidence is Confidence.CERTAIN


def _host(pattern: str, identity_file: str, line: int) -> HostBlock:
    return HostBlock(
        patterns=(pattern,),
        header=SourceLoc(file="/h/.ssh/config", line=line),
        identity_files=(
            IdentityFileEntry(
                path=identity_file, source=SourceLoc(file="/h/.ssh/config", line=line + 1)
            ),
        ),
    )


def _doc(*blocks: HostBlock) -> ConfigDocument:
    return ConfigDocument(
        path="/h/.ssh/config",
        global_block=HostBlock(patterns=(), header=None),
        host_blocks=blocks,
        unresolved=(),
    )


def _cfg_ref(path: str, line: int, resolution: Resolution) -> LocalReference:
    return LocalReference(
        kind=LocalReferenceKind.CONFIG_IDENTITY,
        path=path,
        source_file="/h/.ssh/config",
        source_line=line,
        resolution=resolution,
    )


RSA_FP = "SHA256:Kskz06nJKSQVXxudvVa4i2SSMi4R2H2KjSMgpNUyyFE"
RSA_INFO = KeyInfo(fingerprint=RSA_FP, algorithm="ssh-rsa", bits_or_curve="3072", comment="rsa")


def test_host_binding_without_resolved_fingerprint_is_unresolved() -> None:
    """Finding 565eb2c83a220c3b: a Host whose IdentityFile resolves to no fingerprint

    (missing key, private-only key) is UNRESOLVED; a Host whose key resolves stays CERTAIN.
    """
    obs = ScanObservations(
        config_references=[
            (_cfg_ref("/h/.ssh/id_rsa", 2, Resolution.RESOLVED), RSA_INFO),
            (_cfg_ref("/h/.ssh/gone", 5, Resolution.MISSING), None),
            (_cfg_ref("/h/.ssh/secret", 8, Resolution.PRIVATE_ONLY), None),
        ],
        config_document=_doc(
            _host("server", "~/.ssh/id_rsa", 1),
            _host("missing-key", "~/.ssh/gone", 4),
            _host("private-only", "~/.ssh/secret", 7),
        ),
        home="/h",
    )

    snapshot = build_snapshot(obs)

    by_host = {hb.patterns[0]: hb for hb in snapshot.host_bindings}
    assert by_host["server"].confidence is Confidence.CERTAIN
    assert by_host["missing-key"].confidence is Confidence.UNRESOLVED
    assert by_host["private-only"].confidence is Confidence.UNRESOLVED


def test_identity_file_matched_by_normalized_path_not_suffix() -> None:
    """Finding f83d8a58db0b040c: IdentityFile 'rsa' is ~/.ssh/rsa, not a suffix of id_rsa.

    Holds both through the config reference (matched by its source line) and without
    one (path expanded like references.py: relative to ~/.ssh, ~ to HOME).
    """
    pub = PublicKeyObservation(path="/h/.ssh/id_rsa.pub", resolution=Resolution.RESOLVED)
    obs = ScanObservations(
        public_keys=[(pub, RSA_INFO)],
        config_references=[
            (_cfg_ref("/h/.ssh/id_rsa", 2, Resolution.RESOLVED), RSA_INFO),
            (_cfg_ref("/h/.ssh/rsa", 5, Resolution.MISSING), None),
        ],
        config_document=_doc(
            _host("full", "~/.ssh/id_rsa", 1),
            _host("short", "rsa", 4),
            _host("short-no-ref", "sa", 7),
            _host("full-no-ref", "id_rsa", 10),
        ),
        home="/h",
    )

    snapshot = build_snapshot(obs)

    by_host = {hb.patterns[0]: hb for hb in snapshot.host_bindings}
    assert by_host["full"].resolved_fingerprints == (RSA_FP,)
    assert by_host["short"].resolved_fingerprints == ()
    assert by_host["short-no-ref"].resolved_fingerprints == ()
    assert by_host["full-no-ref"].resolved_fingerprints == (RSA_FP,)


def test_aggregate_unresolved_items_mapped_and_sorted() -> None:
    doc = ConfigDocument(
        path="/h/.ssh/config",
        global_block=HostBlock(patterns=(), header=None),
        host_blocks=(),
        unresolved=(
            UnresolvedConfigItem(
                "match_not_evaluated", "Match host specific", "/h/.ssh/config", 20
            ),
            UnresolvedConfigItem("include_cycle", "/h/.ssh/loop.conf", "/h/.ssh/config", 5),
            UnresolvedConfigItem("malformed_line", "bad line", "/h/.ssh/config", 2),
            UnresolvedConfigItem("unresolved_token", "%h", "/h/.ssh/config", 10),
        ),
    )
    obs = ScanObservations(
        config_document=doc,
    )
    snapshot = build_snapshot(obs)
    assert len(snapshot.unresolved) == 4
    kinds_and_lines = [(u.kind, u.source_line) for u in snapshot.unresolved]
    assert kinds_and_lines == [
        ("malformed_line", 2),
        ("include_cycle", 5),
        ("unresolved_token", 10),
        ("unsupported_match", 20),
    ]
