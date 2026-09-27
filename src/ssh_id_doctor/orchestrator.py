"""FR-007 / sdd-spec §8, §9: ScanOrchestrator.

Orchestrates all scan steps in order:
1. FileSystemScanner: enumerate .pub files under --ssh-dir
2. SSHConfigParser: parse ~/.ssh/config and resolve IdentityFile references
3. PublicKeyInspector: fingerprint discovered public keys and config references
4. SSHAgentAdapter: inspect identities in running agent
5. GitHubRegistryAdapter: inspect remote keys (if enabled)
6. IdentityAggregator: merge observations into ScanSnapshot
7. RulesEngine: evaluate rules against snapshot
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from ssh_id_doctor import references, scanner, ssh_config
from ssh_id_doctor.adapters.github import RegistryResult
from ssh_id_doctor.aggregate import ScanObservations, build_snapshot
from ssh_id_doctor.domain import (
    CoverageState,
    RegistryBinding,
    ScanSnapshot,
    SourceCoverage,
)
from ssh_id_doctor.inspectors import RequiredSourceError
from ssh_id_doctor.inspectors.agent import AgentResult, SSHAgentAdapter
from ssh_id_doctor.inspectors.keygen import PublicKeyInspector
from ssh_id_doctor.references import LocalReference
from ssh_id_doctor.rules import Rule, run_rules
from ssh_id_doctor.scanner import PublicKeyObservation
from ssh_id_doctor.ssh_config import ConfigDocument


class FileSystemScannerProtocol(Protocol):
    def discover_public_keys(
        self, ssh_dir: str | os.PathLike[str]
    ) -> list[PublicKeyObservation]: ...


class SSHConfigParserProtocol(Protocol):
    def parse_file(self, path: str | os.PathLike[str]) -> ConfigDocument: ...


class PublicKeyInspectorProtocol(Protocol):
    def fingerprint(self, public_line: str) -> Any: ...


class SSHAgentAdapterProtocol(Protocol):
    def list_identities(self) -> AgentResult: ...


class GitHubRegistryAdapterProtocol(Protocol):
    def list_keys(self) -> RegistryResult: ...


@dataclass
class OrchestratorOptions:
    """Options for running ScanOrchestrator."""

    ssh_dir: str | Path | None = None
    config_path: str | Path | None = None
    home: str | Path | None = None
    check_agent: bool = True
    check_github: bool = False
    rules: Sequence[Rule] | None = None


class ScanOrchestrator:
    """Coordinates scan components across all sources."""

    def __init__(
        self,
        scanner_module: Any = scanner,
        config_module: Any = ssh_config,
        references_module: Any = references,
        keygen: PublicKeyInspectorProtocol | None = None,
        agent_adapter: SSHAgentAdapterProtocol | None = None,
        github_adapter: GitHubRegistryAdapterProtocol | None = None,
    ) -> None:
        self._scanner = scanner_module
        self._config = config_module
        self._references = references_module
        self._keygen = keygen if keygen is not None else PublicKeyInspector()
        if agent_adapter is not None:
            self._agent = agent_adapter
        elif isinstance(self._keygen, PublicKeyInspector):
            self._agent = SSHAgentAdapter(self._keygen)
        else:
            self._agent = SSHAgentAdapter()
        self._github = github_adapter

    def run(self, options: OrchestratorOptions | None = None) -> ScanSnapshot:
        opts = options or OrchestratorOptions()
        home = Path(opts.home) if opts.home else Path(os.environ.get("HOME", "/"))
        ssh_dir = Path(opts.ssh_dir) if opts.ssh_dir else home / ".ssh"
        config_path = Path(opts.config_path) if opts.config_path else ssh_dir / "config"

        started_at = datetime.now(UTC).isoformat()
        scan_id = str(uuid.uuid4())
        sources: list[SourceCoverage] = []

        # 1. FileSystemScanner (.pub files)
        pub_observations: list[PublicKeyObservation] = []
        if ssh_dir.is_dir():
            try:
                pub_observations = self._scanner.discover_public_keys(ssh_dir)
                sources.append(
                    SourceCoverage(
                        source="filesystem",
                        state=CoverageState.AVAILABLE,
                        required=True,
                        detail=f"{len(pub_observations)} public keys discovered",
                    )
                )
            except Exception as exc:
                sources.append(
                    SourceCoverage(
                        source="filesystem",
                        state=CoverageState.UNAVAILABLE,
                        required=True,
                        detail=str(exc),
                    )
                )
        else:
            sources.append(
                SourceCoverage(
                    source="filesystem",
                    state=CoverageState.EMPTY,
                    required=True,
                    detail="ssh directory does not exist",
                )
            )

        # 2. SSHConfigParser & Reference Resolver
        config_doc: ConfigDocument | None = None
        cfg_references: list[LocalReference] = []
        if config_path.is_file():
            try:
                config_doc = self._config.parse_file(config_path)
                id_refs = self._references.resolve_identity_references(
                    config_doc, home=home, ssh_dir=ssh_dir
                )
                cfg_references = list(id_refs.references)
                sources.append(
                    SourceCoverage(
                        source="config",
                        state=CoverageState.AVAILABLE,
                        required=False,
                        detail=f"{len(config_doc.host_blocks)} host blocks parsed",
                    )
                )
            except Exception as exc:
                sources.append(
                    SourceCoverage(
                        source="config",
                        state=CoverageState.MALFORMED,
                        required=False,
                        detail=str(exc),
                    )
                )
        else:
            sources.append(
                SourceCoverage(
                    source="config",
                    state=CoverageState.EMPTY,
                    required=False,
                    detail="config file does not exist",
                )
            )

        # 3. PublicKeyInspector (fingerprint discovered public keys & config references)
        # RequiredSourceError from keygen must propagate!
        pub_keys_with_info: list[tuple[PublicKeyObservation, Any]] = []
        for pub_obs in pub_observations:
            if pub_obs.key_line:
                info = self._keygen.fingerprint(pub_obs.key_line)
                pub_keys_with_info.append((pub_obs, info))
            else:
                pub_keys_with_info.append((pub_obs, None))

        cfg_refs_with_info: list[tuple[LocalReference, Any]] = []
        for ref in cfg_references:
            if ref.public_key_text:
                info = self._keygen.fingerprint(ref.public_key_text)
                cfg_refs_with_info.append((ref, info))
            else:
                cfg_refs_with_info.append((ref, None))

        # 4. SSHAgentAdapter (optional)
        agent_identities: list[Any] = []
        if opts.check_agent and self._agent is not None:
            try:
                agent_res = self._agent.list_identities()
                if hasattr(agent_res, "identities"):
                    agent_identities.extend(agent_res.identities)
                if hasattr(agent_res, "as_coverage"):
                    sources.append(agent_res.as_coverage())
                elif hasattr(agent_res, "coverage") and agent_res.coverage is not None:
                    sources.append(agent_res.coverage)
            except RequiredSourceError:
                # RequiredSourceError must propagate even from agent
                raise
            except Exception as exc:
                # Optional source failure should not raise
                sources.append(
                    SourceCoverage(
                        source="agent",
                        state=CoverageState.TIMEOUT
                        if "timeout" in str(exc).lower()
                        else CoverageState.UNAVAILABLE,
                        required=False,
                        detail=str(exc),
                    )
                )
        else:
            sources.append(
                SourceCoverage(
                    source="agent",
                    state=CoverageState.SKIPPED,
                    required=False,
                    detail="agent check skipped",
                )
            )

        # 5. GitHubRegistryAdapter (optional)
        registry_bindings: list[RegistryBinding] = []
        if opts.check_github and self._github is not None:
            try:
                gh_res = self._github.list_keys()
                registry_bindings.extend(gh_res.bindings)
                sources.append(gh_res.as_coverage())
            except RequiredSourceError:
                raise
            except Exception as exc:
                # Optional source failure
                sources.append(
                    SourceCoverage(
                        source="github",
                        state=CoverageState.UNAVAILABLE,
                        required=False,
                        detail=str(exc),
                    )
                )
        elif opts.check_github:
            sources.append(
                SourceCoverage(
                    source="github",
                    state=CoverageState.UNAVAILABLE,
                    required=False,
                    detail="github adapter not configured",
                )
            )
        else:
            sources.append(
                SourceCoverage(
                    source="github",
                    state=CoverageState.SKIPPED,
                    required=False,
                    detail="github check skipped",
                )
            )

        # 6. IdentityAggregator
        obs = ScanObservations(
            public_keys=pub_keys_with_info,
            config_references=cfg_refs_with_info,
            config_document=config_doc,
            agent_identities=agent_identities,
            registry_bindings=registry_bindings,
            sources=sources,
            scan_id=scan_id,
            started_at=started_at,
            home=str(home),
            ssh_dir=str(ssh_dir),
        )
        intermediate_snapshot = build_snapshot(obs)

        # 7. RulesEngine
        findings = run_rules(
            intermediate_snapshot,
            rules=opts.rules,
            home_roots=(str(home), os.path.realpath(home)),
        )

        completed_at = datetime.now(UTC).isoformat()

        # Final snapshot with findings and completed_at
        return ScanSnapshot(
            scan_id=intermediate_snapshot.scan_id,
            started_at=intermediate_snapshot.started_at,
            completed_at=completed_at,
            platform=intermediate_snapshot.platform,
            sources=intermediate_snapshot.sources,
            identities=intermediate_snapshot.identities,
            host_bindings=intermediate_snapshot.host_bindings,
            findings=tuple(findings),
            schema_version=intermediate_snapshot.schema_version,
            local_references=intermediate_snapshot.local_references,
            unresolved=intermediate_snapshot.unresolved,
        )


__all__ = [
    "FileSystemScannerProtocol",
    "GitHubRegistryAdapterProtocol",
    "OrchestratorOptions",
    "PublicKeyInspectorProtocol",
    "SSHAgentAdapterProtocol",
    "SSHConfigParserProtocol",
    "ScanOrchestrator",
]
