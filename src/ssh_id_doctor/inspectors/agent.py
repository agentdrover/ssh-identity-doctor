"""FR-005 (sdd-spec §7, §10 SEC-002, §12): SSH agent inspector.

:class:`SSHAgentAdapter` queries the active SSH agent via ``ssh-add -L``
through the audited subprocess runner :mod:`ssh_id_doctor.process`. It turns
each reported public identity line into a canonical :class:`Identity` using
:class:`ssh_id_doctor.inspectors.keygen.PublicKeyInspector`.

The adapter distinguishes five states (§5.3 note, FR-005, §12):
- ``available_with_identities``: agent returned one or more valid identities;
- ``available_empty``: agent is running but holds no keys (exit 1);
- ``unavailable``: agent socket missing/inaccessible or ssh-add absent (exit 2);
- ``timeout``: subprocess timed out;
- ``malformed_output``: process exited 0 but produced unparseable output.

Every call is read-only (SEC-002/SEC-006: never passing mutating flags like
``-d`` or ``-D``) and failures never crash the scan, reflecting instead in
:class:`SourceCoverage` (source='agent').
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ssh_id_doctor import process
from ssh_id_doctor.domain import CoverageState, Identity, SourceCoverage
from ssh_id_doctor.inspectors import RequiredSourceError, Unresolved
from ssh_id_doctor.inspectors.keygen import DEFAULT_TIMEOUT, KeyInfo, PublicKeyInspector
from ssh_id_doctor.process import ProcessStatus

DEFAULT_MAX_OUTPUT = 65536
"""Bytes. Output buffer limit for ssh-add -L."""


class AgentState(StrEnum):
    """The five states of the SSH agent inspector (sdd-spec FR-005, §12)."""

    AVAILABLE_WITH_IDENTITIES = "available_with_identities"
    AVAILABLE_EMPTY = "available_empty"
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    MALFORMED_OUTPUT = "malformed_output"


_STATE_TO_COVERAGE: dict[AgentState, CoverageState] = {
    AgentState.AVAILABLE_WITH_IDENTITIES: CoverageState.AVAILABLE,
    AgentState.AVAILABLE_EMPTY: CoverageState.EMPTY,
    AgentState.UNAVAILABLE: CoverageState.UNAVAILABLE,
    AgentState.TIMEOUT: CoverageState.TIMEOUT,
    AgentState.MALFORMED_OUTPUT: CoverageState.MALFORMED,
}


@dataclass(frozen=True, slots=True)
class AgentResult:
    """Result of querying the SSH agent via ssh-add -L."""

    state: AgentState
    identities: tuple[Identity, ...] = ()
    unresolved: tuple[Unresolved, ...] = ()
    coverage: SourceCoverage | None = None
    detail: str = ""

    def __post_init__(self) -> None:
        if self.coverage is None:
            cov = SourceCoverage(
                source="agent",
                state=_STATE_TO_COVERAGE[self.state],
                required=False,
                detail=self.detail,
            )
            object.__setattr__(self, "coverage", cov)

    def as_coverage(self) -> SourceCoverage:
        if self.coverage is not None:
            return self.coverage
        return SourceCoverage(
            source="agent",
            state=_STATE_TO_COVERAGE[self.state],
            required=False,
            detail=self.detail,
        )


def _extract_comments(line: str, key_info: KeyInfo) -> tuple[str, ...]:
    parts = line.split(None, 2)
    if len(parts) >= 3:
        comment = parts[2].strip()
        if comment:
            return (comment,)
    if key_info.comment and key_info.comment != "no comment":
        return (key_info.comment,)
    return ()


class SSHAgentAdapter:
    """Inspects public identities currently offered by the SSH agent (FR-005)."""

    def __init__(self, keygen: PublicKeyInspector | None = None) -> None:
        self._keygen = keygen if keygen is not None else PublicKeyInspector()

    def list_identities(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        *,
        max_output: int = DEFAULT_MAX_OUTPUT,
    ) -> AgentResult:
        result = process.run(
            ["ssh-add", "-L"],
            timeout=timeout,
            max_output=max_output,
        )

        if result.status is ProcessStatus.TIMEOUT:
            return AgentResult(
                state=AgentState.TIMEOUT,
                detail="ssh-add timed out",
            )

        if result.status is ProcessStatus.NOT_FOUND:
            return AgentResult(
                state=AgentState.UNAVAILABLE,
                detail="ssh-add is not installed or not on PATH",
            )

        if result.status is ProcessStatus.NOT_EXECUTABLE:
            return AgentResult(
                state=AgentState.UNAVAILABLE,
                detail="ssh-add on PATH is not executable",
            )

        if result.status is ProcessStatus.NONZERO:
            if result.returncode == 1:
                return AgentResult(
                    state=AgentState.AVAILABLE_EMPTY,
                    detail="agent has no identities",
                )
            stderr_text = result.stderr.decode("utf-8", errors="replace").strip()
            detail = stderr_text if stderr_text else f"ssh-add exited with code {result.returncode}"
            return AgentResult(
                state=AgentState.UNAVAILABLE,
                detail=detail,
            )

        stdout_text = result.stdout.decode("utf-8", errors="replace")
        lines = [line.strip() for line in stdout_text.splitlines() if line.strip()]

        if not lines or (len(lines) == 1 and "The agent has no identities" in lines[0]):
            return AgentResult(
                state=AgentState.AVAILABLE_EMPTY,
                detail="agent has no identities",
            )

        identities: list[Identity] = []
        unresolved: list[Unresolved] = []

        for line in lines:
            try:
                info = self._keygen.fingerprint(line)
            except RequiredSourceError as err:
                return AgentResult(
                    state=AgentState.UNAVAILABLE,
                    detail=f"ssh-keygen unavailable: {err}",
                )

            if isinstance(info, KeyInfo):
                comments = _extract_comments(line, info)
                identities.append(
                    Identity(
                        fingerprint=info.fingerprint,
                        algorithm=info.algorithm,
                        bits_or_curve=info.bits_or_curve,
                        comments=comments,
                        local_references=(),
                        agent_presence=True,
                        registry_bindings=(),
                    )
                )
            else:
                unresolved.append(info)

        if not identities:
            return AgentResult(
                state=AgentState.MALFORMED_OUTPUT,
                identities=(),
                unresolved=tuple(unresolved),
                detail="malformed output from ssh-add",
            )

        detail = f"{len(identities)} identities loaded"
        if result.truncated:
            detail = f"{detail} (truncated)"

        return AgentResult(
            state=AgentState.AVAILABLE_WITH_IDENTITIES,
            identities=tuple(identities),
            unresolved=tuple(unresolved),
            detail=detail,
        )


__all__ = [
    "DEFAULT_MAX_OUTPUT",
    "DEFAULT_TIMEOUT",
    "AgentResult",
    "AgentState",
    "SSHAgentAdapter",
]
