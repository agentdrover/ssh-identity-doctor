"""FR-005 (sdd-spec §7, §10 SEC-002, §12): SSH agent inspector tests (AC-1..AC-3)."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from ssh_id_doctor import process
from ssh_id_doctor.domain import CoverageState, Identity
from ssh_id_doctor.inspectors import RequiredSourceError, Unresolved
from ssh_id_doctor.inspectors.agent import (
    DEFAULT_TIMEOUT,
    AgentResult,
    AgentState,
    SSHAgentAdapter,
)
from ssh_id_doctor.inspectors.keygen import KeyInfo, PublicKeyInspector
from ssh_id_doctor.process import ProcessResult, ProcessStatus

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "agent"


def _fixture_text(name: str) -> str:
    return (FIXTURES / f"{name}.txt").read_text()


# ---------------------------------------------------------------------------
# AC-1: recorded fixture output with two keys (AC-1, §13.2)
# ---------------------------------------------------------------------------


def test_agent_with_identities_normalized(monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-1: recorded output with 2 keys (ed25519 with 'work', rsa without comment)."""
    recorded = _fixture_text("two_keys")
    real_run = process.run

    def fake_run(argv: Sequence[str], *, timeout: float, max_output: int) -> ProcessResult:
        if argv[0] == "ssh-add":
            assert list(argv) == ["ssh-add", "-L"]
            return ProcessResult(ProcessStatus.OK, 0, recorded.encode(), b"", False)
        return real_run(argv, timeout=timeout, max_output=max_output)

    monkeypatch.setattr("ssh_id_doctor.inspectors.agent.process.run", fake_run)

    adapter = SSHAgentAdapter()
    result = adapter.list_identities()

    assert isinstance(result, AgentResult)
    assert result.state == "available_with_identities"
    assert result.state is AgentState.AVAILABLE_WITH_IDENTITIES
    assert len(result.identities) == 2
    assert result.unresolved == ()

    id1, id2 = result.identities

    # ed25519 identity with comment 'work'
    assert isinstance(id1, Identity)
    assert id1.fingerprint == "SHA256:+92RsVKGXDDG2XlZkoQSG2sRjqnoPwysscnoHoCIdMk"
    assert id1.algorithm == "ssh-ed25519"
    assert id1.bits_or_curve == "256"
    assert id1.comments == ("work",)
    assert id1.agent_presence is True
    assert id1.local_references == ()

    # rsa identity without comment
    assert isinstance(id2, Identity)
    assert id2.fingerprint == "SHA256:Kskz06nJKSQVXxudvVa4i2SSMi4R2H2KjSMgpNUyyFE"
    assert id2.algorithm == "ssh-rsa"
    assert id2.bits_or_curve == "3072"
    assert id2.comments == ()
    assert id2.agent_presence is True
    assert id2.local_references == ()

    # coverage mapping
    coverage = result.coverage
    assert coverage.source == "agent"
    assert coverage.state == CoverageState.AVAILABLE
    assert coverage.required is False
    assert result.as_coverage() == coverage


# ---------------------------------------------------------------------------
# AC-2: distinguish four states from mock runs (AC-2)
# ---------------------------------------------------------------------------


def test_agent_states_are_distinguished(monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-2: four mock runs -> available_empty, unavailable, timeout, malformed_output."""
    cases: list[tuple[ProcessResult, AgentState, CoverageState]] = [
        (
            ProcessResult(ProcessStatus.NONZERO, 1, b"", b"The agent has no identities.\n", False),
            AgentState.AVAILABLE_EMPTY,
            CoverageState.EMPTY,
        ),
        (
            ProcessResult(
                ProcessStatus.NONZERO,
                2,
                b"",
                b"Could not open a connection to your authentication agent.\n",
                False,
            ),
            AgentState.UNAVAILABLE,
            CoverageState.UNAVAILABLE,
        ),
        (
            ProcessResult(ProcessStatus.TIMEOUT, None, b"", b"", False),
            AgentState.TIMEOUT,
            CoverageState.TIMEOUT,
        ),
        (
            ProcessResult(ProcessStatus.OK, 0, b"garbage line\n", b"", False),
            AgentState.MALFORMED_OUTPUT,
            CoverageState.MALFORMED,
        ),
    ]

    adapter = SSHAgentAdapter()
    real_run = process.run

    for mock_res, expected_state, expected_cov in cases:

        def make_fake(res: ProcessResult) -> Any:
            def fake_run(argv: Sequence[str], *, timeout: float, max_output: int) -> ProcessResult:
                if argv[0] == "ssh-add":
                    return res
                return real_run(argv, timeout=timeout, max_output=max_output)

            return fake_run

        monkeypatch.setattr(
            "ssh_id_doctor.inspectors.agent.process.run",
            make_fake(mock_res),
        )

        result = adapter.list_identities()

        assert result.state == expected_state
        assert result.state.value == expected_state.value
        assert result.coverage.state == expected_cov
        assert result.coverage.source == "agent"
        assert result.coverage.required is False


# ---------------------------------------------------------------------------
# AC-3: read-only argv and required timeout (AC-3, SEC-002, SEC-006)
# ---------------------------------------------------------------------------


def test_agent_uses_readonly_argv_with_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-3: argv == ['ssh-add', '-L'], timeout explicit, never mutating flags."""
    calls: list[tuple[list[str], float, int]] = []
    real_run = process.run

    def fake_run(argv: Sequence[str], *, timeout: float, max_output: int) -> ProcessResult:
        if argv[0] == "ssh-add":
            calls.append((list(argv), timeout, max_output))
            return ProcessResult(ProcessStatus.OK, 0, b"", b"", False)
        return real_run(argv, timeout=timeout, max_output=max_output)

    monkeypatch.setattr("ssh_id_doctor.inspectors.agent.process.run", fake_run)

    adapter = SSHAgentAdapter()
    result = adapter.list_identities(timeout=7.5)

    assert len(calls) == 1
    argv, timeout, max_output = calls[0]

    assert isinstance(argv, list)
    assert argv == ["ssh-add", "-L"]
    assert timeout == 7.5
    assert max_output > 0

    # SEC-002 / SEC-006: strictly read-only, never delete, add or mutate agent state
    forbidden_flags = {"-d", "-D", "-x", "-X", "-s", "-e"}
    assert not any(flag in argv for flag in forbidden_flags)
    assert result.state is AgentState.AVAILABLE_EMPTY


# ---------------------------------------------------------------------------
# Additional edge cases and contract guarantees
# ---------------------------------------------------------------------------


def test_agent_uses_default_timeout_when_unspecified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    real_run = process.run

    def fake_run(argv: Sequence[str], *, timeout: float, max_output: int) -> ProcessResult:
        if argv[0] == "ssh-add":
            captured["timeout"] = timeout
            return ProcessResult(ProcessStatus.OK, 0, b"", b"", False)
        return real_run(argv, timeout=timeout, max_output=max_output)

    monkeypatch.setattr("ssh_id_doctor.inspectors.agent.process.run", fake_run)

    adapter = SSHAgentAdapter()
    adapter.list_identities()

    assert captured["timeout"] == DEFAULT_TIMEOUT


def test_agent_one_broken_line_among_valid_identities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One broken line -> malformed for that line only, valid identities preserved."""
    recorded = _fixture_text("two_keys").splitlines()
    mixed = f"{recorded[0]}\ngarbage-noise-line\n{recorded[1]}\n"
    real_run = process.run

    def fake_run(argv: Sequence[str], *, timeout: float, max_output: int) -> ProcessResult:
        if argv[0] == "ssh-add":
            return ProcessResult(ProcessStatus.OK, 0, mixed.encode(), b"", False)
        return real_run(argv, timeout=timeout, max_output=max_output)

    monkeypatch.setattr("ssh_id_doctor.inspectors.agent.process.run", fake_run)

    adapter = SSHAgentAdapter()
    result = adapter.list_identities()

    assert result.state is AgentState.AVAILABLE_WITH_IDENTITIES
    assert len(result.identities) == 2
    assert len(result.unresolved) == 1
    assert result.unresolved[0].reason == "invalid_public_key"
    assert result.coverage.state == CoverageState.AVAILABLE


def test_agent_preserves_comments_with_spaces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Comment with multiple words and spaces is preserved in comments tuple."""
    k1 = (
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICy6m9y8JQXK/rnkedDzK3YZbu5pH10XpE6+eVYTfnB1 "
        "my personal work laptop 2026\n"
    )
    real_run = process.run

    def fake_run(argv: Sequence[str], *, timeout: float, max_output: int) -> ProcessResult:
        if argv[0] == "ssh-add":
            return ProcessResult(ProcessStatus.OK, 0, k1.encode(), b"", False)
        return real_run(argv, timeout=timeout, max_output=max_output)

    monkeypatch.setattr("ssh_id_doctor.inspectors.agent.process.run", fake_run)

    adapter = SSHAgentAdapter()
    result = adapter.list_identities()

    assert result.state is AgentState.AVAILABLE_WITH_IDENTITIES
    assert len(result.identities) == 1
    assert result.identities[0].comments == ("my personal work laptop 2026",)


def test_agent_handles_crlf_and_blank_lines(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded = _fixture_text("two_keys").splitlines()
    crlf_content = f"\r\n\r\n{recorded[0]}\r\n\r\n\r\n{recorded[1]}\r\n\r\n"
    real_run = process.run

    def fake_run(argv: Sequence[str], *, timeout: float, max_output: int) -> ProcessResult:
        if argv[0] == "ssh-add":
            return ProcessResult(ProcessStatus.OK, 0, crlf_content.encode(), b"", False)
        return real_run(argv, timeout=timeout, max_output=max_output)

    monkeypatch.setattr("ssh_id_doctor.inspectors.agent.process.run", fake_run)

    adapter = SSHAgentAdapter()
    result = adapter.list_identities()

    assert result.state is AgentState.AVAILABLE_WITH_IDENTITIES
    assert len(result.identities) == 2


def test_agent_missing_or_non_executable_ssh_add(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = SSHAgentAdapter()

    # NOT_FOUND
    monkeypatch.setattr(
        "ssh_id_doctor.inspectors.agent.process.run",
        lambda *args, **kwargs: ProcessResult(ProcessStatus.NOT_FOUND, None, b"", b"", False),
    )
    res_not_found = adapter.list_identities()
    assert res_not_found.state is AgentState.UNAVAILABLE
    assert res_not_found.coverage.state == CoverageState.UNAVAILABLE

    # NOT_EXECUTABLE
    monkeypatch.setattr(
        "ssh_id_doctor.inspectors.agent.process.run",
        lambda *args, **kwargs: ProcessResult(ProcessStatus.NOT_EXECUTABLE, None, b"", b"", False),
    )
    res_not_exec = adapter.list_identities()
    assert res_not_exec.state is AgentState.UNAVAILABLE
    assert res_not_exec.coverage.state == CoverageState.UNAVAILABLE


def test_agent_missing_ssh_keygen_raises_required_source_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Finding 9b41523a: agent answered, ssh-keygen is missing -> RequiredSourceError.

    ssh-keygen is a REQUIRED source (SID-4, exit 2); the agent is optional. When
    the agent does list keys but they cannot be fingerprinted, the failure
    belongs to ssh-keygen and must propagate, not be masked as an unavailable
    agent.
    """
    recorded = _fixture_text("two_keys")

    def fake_run(argv: Sequence[str], *, timeout: float, max_output: int) -> ProcessResult:
        return ProcessResult(ProcessStatus.OK, 0, recorded.encode(), b"", False)

    monkeypatch.setattr("ssh_id_doctor.inspectors.agent.process.run", fake_run)

    class BrokenKeygen(PublicKeyInspector):
        def fingerprint(
            self,
            public_line: str,
            *,
            timeout: float = DEFAULT_TIMEOUT,
            max_output: int = 8192,
        ) -> KeyInfo | Unresolved:
            raise RequiredSourceError("ssh-keygen is not installed or not on PATH")

    adapter = SSHAgentAdapter(keygen=BrokenKeygen())
    with pytest.raises(RequiredSourceError, match="ssh-keygen"):
        adapter.list_identities()


def test_agent_truncated_output_reported_in_detail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded = _fixture_text("two_keys")
    real_run = process.run

    def fake_run(argv: Sequence[str], *, timeout: float, max_output: int) -> ProcessResult:
        if argv[0] == "ssh-add":
            return ProcessResult(ProcessStatus.OK, 0, recorded.encode(), b"", True)
        return real_run(argv, timeout=timeout, max_output=max_output)

    monkeypatch.setattr("ssh_id_doctor.inspectors.agent.process.run", fake_run)

    adapter = SSHAgentAdapter()
    result = adapter.list_identities()

    assert result.state is AgentState.AVAILABLE_WITH_IDENTITIES
    assert "(truncated)" in result.detail


def test_agent_without_socket_is_unavailable_from_recorded_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Finding 90d3d23a: no agent socket, on RECORDED ssh-add output (no live call).

    Replaces the former live query. Recorded from OpenSSH with SSH_AUTH_SOCK
    unset: exit 2 and the reason on stderr. The state is unavailable and the
    reason reaches the coverage detail, so the report can say why.
    """
    stderr = (FIXTURES / "no_socket.stderr").read_bytes()
    calls: list[list[str]] = []

    def fake_run(argv: Sequence[str], *, timeout: float, max_output: int) -> ProcessResult:
        calls.append(list(argv))
        return ProcessResult(ProcessStatus.NONZERO, 2, b"", stderr, False)

    monkeypatch.setattr("ssh_id_doctor.inspectors.agent.process.run", fake_run)

    result = SSHAgentAdapter().list_identities()

    assert calls == [["ssh-add", "-L"]]
    assert result.state is AgentState.UNAVAILABLE
    assert result.coverage.state == CoverageState.UNAVAILABLE
    assert "Could not open a connection to your authentication agent" in result.detail
    assert result.coverage.detail == result.detail


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_agent_empty_needs_exit_1_and_no_identities_phrase(
    monkeypatch: pytest.MonkeyPatch, stream: str
) -> None:
    """Exit 1 plus 'The agent has no identities.' on either stream -> available_empty."""
    phrase = b"The agent has no identities.\n"
    out, err = (phrase, b"") if stream == "stdout" else (b"", phrase)
    monkeypatch.setattr(
        "ssh_id_doctor.inspectors.agent.process.run",
        lambda *a, **k: ProcessResult(ProcessStatus.NONZERO, 1, out, err, False),
    )

    result = SSHAgentAdapter().list_identities()

    assert result.state is AgentState.AVAILABLE_EMPTY
    assert result.coverage.state == CoverageState.EMPTY


def test_agent_exit_1_with_other_error_is_unavailable_not_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Finding 17500542: exit 1 without the phrase is a failed listing, not an empty agent.

    Classified unavailable (reason kept), not malformed_output: nothing was
    listed, so there is no output to be malformed; the agent could not be read.
    """
    stderr = b"error fetching identities: communication with agent failed\n"
    monkeypatch.setattr(
        "ssh_id_doctor.inspectors.agent.process.run",
        lambda *a, **k: ProcessResult(ProcessStatus.NONZERO, 1, b"", stderr, False),
    )

    result = SSHAgentAdapter().list_identities()

    assert result.state is AgentState.UNAVAILABLE
    assert result.coverage.state == CoverageState.UNAVAILABLE
    assert "communication with agent failed" in result.detail
    assert "exit 1" in result.detail
