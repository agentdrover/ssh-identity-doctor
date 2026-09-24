"""AC-3: the §7 domain model is immutable and its enums match the spec."""

from __future__ import annotations

import dataclasses

import pytest

from ssh_id_doctor.domain import (
    Confidence,
    EvidenceReference,
    Finding,
    Identity,
    LocalReference,
    LocalReferenceKind,
    Resolution,
    Severity,
)


def test_domain_entities_are_frozen_and_enums_match_spec() -> None:
    ref = LocalReference(
        kind=LocalReferenceKind.PUBLIC_KEY,
        path="/fixture/id_ed25519.pub",
        source_file=None,
        source_line=None,
        resolution=Resolution.RESOLVED,
    )
    identity = Identity(
        fingerprint="SHA256:abc",
        algorithm="ssh-ed25519",
        bits_or_curve="ED25519",
        comments=("work",),
        local_references=(ref,),
        agent_presence=False,
        registry_bindings=(),
    )
    finding = Finding(
        id="f-1",
        rule_id="CFG001",
        severity=Severity.ERROR,
        confidence=Confidence.CERTAIN,
        title="t",
        summary="s",
        evidence=(EvidenceReference(source="/fixture/config", line=3, detail="IdentityFile"),),
        affected_fingerprints=("SHA256:abc",),
        affected_hosts=("github.com",),
        manual_remediation=("check",),
    )

    for entity, field in ((identity, "fingerprint"), (finding, "severity"), (ref, "path")):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(entity, field, "changed")

    assert {s.value for s in Severity} == {"error", "warning", "info"}
    assert {c.value for c in Confidence} == {"certain", "heuristic", "unresolved"}
    assert {r.value for r in Resolution} == {
        "resolved",
        "missing",
        "unreadable",
        "outside_root",
        "private_only",
    }
    assert {k.value for k in LocalReferenceKind} == {"public_key", "config_identity"}


def test_domain_module_imports_no_io() -> None:
    """§8.1: domain has no I/O — no subprocess, os, pathlib, io, socket, shutil imports."""
    import ast
    import inspect

    import ssh_id_doctor.domain as domain

    tree = ast.parse(inspect.getsource(domain))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported.isdisjoint({"subprocess", "os", "pathlib", "io", "socket", "shutil"})
    assert "open(" not in inspect.getsource(domain)
