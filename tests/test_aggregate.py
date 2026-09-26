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
from ssh_id_doctor.ssh_config import ConfigDocument, HostBlock, IdentityFileEntry, SourceLoc


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
