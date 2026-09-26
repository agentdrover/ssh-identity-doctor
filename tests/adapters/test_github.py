"""FR-006 (sdd-spec §7, §10 SEC-002..SEC-005, §12): GitHub registry adapter tests."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from ssh_id_doctor import process
from ssh_id_doctor.adapters.github import (
    GitHubRegistryAdapter,
    RegistryResult,
    RegistryState,
)
from ssh_id_doctor.domain import CoverageState, RegistryBinding
from ssh_id_doctor.process import ProcessResult, ProcessStatus

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "github"


def _fixture_text(name: str) -> str:
    return (FIXTURES / f"{name}.json").read_text()


# ---------------------------------------------------------------------------
# AC-1: recorded fixture output with two keys fingerprinted locally (AC-1)
# ---------------------------------------------------------------------------


def test_registry_keys_fingerprinted_locally(monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-1: recorded gh api user/keys with 2 keys ('old-laptop', 'ci'), local fingerprints."""
    recorded_json = _fixture_text("two_keys")
    real_run = process.run

    def fake_run(argv: Sequence[str], *, timeout: float, max_output: int) -> ProcessResult:
        if argv == ["gh", "auth", "status"]:
            return ProcessResult(ProcessStatus.OK, 0, b"", b"", False)
        if list(argv[:2]) == ["gh", "api"]:
            return ProcessResult(ProcessStatus.OK, 0, recorded_json.encode(), b"", False)
        return real_run(argv, timeout=timeout, max_output=max_output)

    monkeypatch.setattr("ssh_id_doctor.adapters.github.process.run", fake_run)

    adapter = GitHubRegistryAdapter()
    result = adapter.list_keys()

    assert isinstance(result, RegistryResult)
    assert result.state == "available"
    assert result.state is RegistryState.AVAILABLE
    assert len(result.bindings) == 2
    assert len(result.keys) == 2
    assert len(result.registry_bindings) == 2
    assert len(result) == 2
    assert result.unresolved == ()

    b1, b2 = result.bindings

    assert isinstance(b1, RegistryBinding)
    assert b1.registry == "github"
    assert b1.title == "old-laptop"
    assert b1.created_at == "2023-01-10T12:00:00Z"
    assert b1.fingerprint == "SHA256:+92RsVKGXDDG2XlZkoQSG2sRjqnoPwysscnoHoCIdMk"
    assert b1.key_id == "1001"

    assert isinstance(b2, RegistryBinding)
    assert b2.registry == "github"
    assert b2.title == "ci"
    assert b2.created_at == "2023-06-15T09:30:00Z"
    assert b2.fingerprint == "SHA256:NJ5MTkVw6u6F+AeTRli+f0Ph9nGRWKWdvW/rlvORm8s"
    assert b2.key_id == "1002"

    coverage = result.coverage
    assert coverage is not None
    assert coverage.source == "github"
    assert coverage.state == CoverageState.AVAILABLE
    assert coverage.required is False
    assert result.as_coverage() == coverage


# ---------------------------------------------------------------------------
# AC-2: distinguish failures and degrade to unresolved without exceptions (AC-2)
# ---------------------------------------------------------------------------


def test_github_failures_degrade_to_unresolved(monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-2: gh missing, auth code 1, timeout, 'not json' produce proper states, no exceptions."""
    adapter = GitHubRegistryAdapter()

    # Case 1: gh missing (NOT_FOUND)
    def fake_run_missing(argv: Sequence[str], *, timeout: float, max_output: int) -> ProcessResult:
        return ProcessResult(ProcessStatus.NOT_FOUND, None, b"", b"", False)

    monkeypatch.setattr("ssh_id_doctor.adapters.github.process.run", fake_run_missing)
    res_missing = adapter.list_keys()
    assert res_missing.state == "gh_missing"
    assert res_missing.state is RegistryState.GH_MISSING
    assert res_missing.bindings == ()
    assert res_missing.coverage is not None
    assert res_missing.coverage.state == CoverageState.UNAVAILABLE
    assert res_missing.coverage.source == "github"

    # Case 2: gh auth status exit 1 (NOT_AUTHENTICATED)
    def fake_run_not_auth(argv: Sequence[str], *, timeout: float, max_output: int) -> ProcessResult:
        if argv == ["gh", "auth", "status"]:
            return ProcessResult(
                ProcessStatus.NONZERO,
                1,
                b"",
                b"You are not logged into any GitHub hosts.\n",
                False,
            )
        return ProcessResult(ProcessStatus.OK, 0, b"[]", b"", False)

    monkeypatch.setattr("ssh_id_doctor.adapters.github.process.run", fake_run_not_auth)
    res_not_auth = adapter.list_keys()
    assert res_not_auth.state == "not_authenticated"
    assert res_not_auth.state is RegistryState.NOT_AUTHENTICATED
    assert res_not_auth.bindings == ()
    assert res_not_auth.coverage is not None
    assert res_not_auth.coverage.state == CoverageState.UNAVAILABLE

    # Case 3: timeout
    def fake_run_timeout(argv: Sequence[str], *, timeout: float, max_output: int) -> ProcessResult:
        return ProcessResult(ProcessStatus.TIMEOUT, None, b"", b"", False)

    monkeypatch.setattr("ssh_id_doctor.adapters.github.process.run", fake_run_timeout)
    res_timeout = adapter.list_keys()
    assert res_timeout.state == "timeout"
    assert res_timeout.state is RegistryState.TIMEOUT
    assert res_timeout.bindings == ()
    assert res_timeout.coverage is not None
    assert res_timeout.coverage.state == CoverageState.TIMEOUT

    # Case 4: response 'not json' (MALFORMED_OUTPUT)
    def fake_run_not_json(argv: Sequence[str], *, timeout: float, max_output: int) -> ProcessResult:
        if argv == ["gh", "auth", "status"]:
            return ProcessResult(ProcessStatus.OK, 0, b"", b"", False)
        return ProcessResult(ProcessStatus.OK, 0, b"not json", b"", False)

    monkeypatch.setattr("ssh_id_doctor.adapters.github.process.run", fake_run_not_json)
    res_not_json = adapter.list_keys()
    assert res_not_json.state == "malformed_output"
    assert res_not_json.state is RegistryState.MALFORMED_OUTPUT
    assert res_not_json.bindings == ()
    assert res_not_json.coverage is not None
    assert res_not_json.coverage.state == CoverageState.MALFORMED


# ---------------------------------------------------------------------------
# AC-3: read-only argv and never reading/extracting token (AC-3, SEC-002, SEC-005)
# ---------------------------------------------------------------------------


def test_github_adapter_is_read_only_and_never_reads_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-3: argv is list, no token/mutating commands, all gh api calls have --method GET."""
    recorded_argvs: list[list[str]] = []
    recorded_json = _fixture_text("two_keys")
    real_run = process.run

    def fake_run(argv: Sequence[str], *, timeout: float, max_output: int) -> ProcessResult:
        recorded_argvs.append(list(argv))
        if argv == ["gh", "auth", "status"]:
            return ProcessResult(ProcessStatus.OK, 0, b"", b"", False)
        if list(argv[:2]) == ["gh", "api"]:
            return ProcessResult(ProcessStatus.OK, 0, recorded_json.encode(), b"", False)
        return real_run(argv, timeout=timeout, max_output=max_output)

    monkeypatch.setattr("ssh_id_doctor.adapters.github.process.run", fake_run)

    adapter = GitHubRegistryAdapter()
    result = adapter.list_keys(timeout=8.0)

    assert result.state is RegistryState.AVAILABLE
    assert len(recorded_argvs) >= 2

    forbidden = {"token", "--show-token", "POST", "DELETE", "PATCH", "PUT", "ssh-key"}

    for argv in recorded_argvs:
        assert isinstance(argv, list)
        for bad in forbidden:
            assert bad not in argv, f"Forbidden command/flag {bad!r} found in {argv!r}"
        if argv[:2] == ["gh", "api"]:
            assert "--method" in argv, f"--method missing in {argv!r}"
            assert "GET" in argv, f"GET missing in {argv!r}"


# ---------------------------------------------------------------------------
# Additional coverage: token marker not leaked, pagination, API error, empty
# ---------------------------------------------------------------------------


def test_github_token_marker_not_leaked_in_result(monkeypatch: pytest.MonkeyPatch) -> None:
    """SEC-005: raw output containing token tokens must never appear in results or details."""
    token_marker = "gho_SUPER_SECRET_TOKEN_DO_NOT_LEAK_789xyz"  # noqa: S105

    def fake_run_leaky_auth(
        argv: Sequence[str], *, timeout: float, max_output: int
    ) -> ProcessResult:
        return ProcessResult(
            ProcessStatus.NONZERO,
            1,
            stdout=f"github.com Token: {token_marker}\n".encode(),
            stderr=f"failed authentication with {token_marker}\n".encode(),
            truncated=False,
        )

    monkeypatch.setattr("ssh_id_doctor.adapters.github.process.run", fake_run_leaky_auth)
    adapter = GitHubRegistryAdapter()
    result = adapter.list_keys()

    assert result.state is RegistryState.NOT_AUTHENTICATED
    assert token_marker not in repr(result)
    assert token_marker not in result.detail
    assert token_marker not in str(result.coverage)

    def fake_run_leaky_api(
        argv: Sequence[str], *, timeout: float, max_output: int
    ) -> ProcessResult:
        if argv == ["gh", "auth", "status"]:
            return ProcessResult(ProcessStatus.OK, 0, b"", b"", False)
        return ProcessResult(
            ProcessStatus.NONZERO,
            1,
            stdout=b"",
            stderr=f"HTTP 401: bad credentials for {token_marker}\n".encode(),
            truncated=False,
        )

    monkeypatch.setattr("ssh_id_doctor.adapters.github.process.run", fake_run_leaky_api)
    result_api = adapter.list_keys()

    assert result_api.state is RegistryState.API_ERROR
    assert token_marker not in repr(result_api)
    assert token_marker not in result_api.detail
    assert token_marker not in str(result_api.coverage)


def test_github_pagination_multi_page_stream(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pagination: gh api --paginate yields concatenated JSON arrays without error."""
    two_keys = json.loads(_fixture_text("two_keys"))
    page1 = [two_keys[0]]
    page2 = [two_keys[1]]
    multi_page_bytes = (json.dumps(page1) + "\n" + json.dumps(page2)).encode()
    real_run = process.run

    def fake_run(argv: Sequence[str], *, timeout: float, max_output: int) -> ProcessResult:
        if argv == ["gh", "auth", "status"]:
            return ProcessResult(ProcessStatus.OK, 0, b"", b"", False)
        if list(argv[:2]) == ["gh", "api"]:
            assert "--paginate" in argv
            return ProcessResult(ProcessStatus.OK, 0, multi_page_bytes, b"", False)
        return real_run(argv, timeout=timeout, max_output=max_output)

    monkeypatch.setattr("ssh_id_doctor.adapters.github.process.run", fake_run)

    adapter = GitHubRegistryAdapter()
    result = adapter.list_keys()

    assert result.state is RegistryState.AVAILABLE
    assert len(result.bindings) == 2
    assert result.bindings[0].title == "old-laptop"
    assert result.bindings[1].title == "ci"


def test_github_empty_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty registry returns AVAILABLE with 0 bindings."""

    def fake_run(argv: Sequence[str], *, timeout: float, max_output: int) -> ProcessResult:
        if argv == ["gh", "auth", "status"]:
            return ProcessResult(ProcessStatus.OK, 0, b"", b"", False)
        if list(argv[:2]) == ["gh", "api"]:
            return ProcessResult(ProcessStatus.OK, 0, b"[]", b"", False)
        return ProcessResult(ProcessStatus.OK, 0, b"", b"", False)

    monkeypatch.setattr("ssh_id_doctor.adapters.github.process.run", fake_run)

    adapter = GitHubRegistryAdapter()
    result = adapter.list_keys()

    assert result.state is RegistryState.AVAILABLE
    assert result.bindings == ()
    assert result.coverage is not None
    assert result.coverage.state == CoverageState.AVAILABLE


def test_github_api_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Timeout during gh api call degrades to TIMEOUT."""

    def fake_run(argv: Sequence[str], *, timeout: float, max_output: int) -> ProcessResult:
        if argv == ["gh", "auth", "status"]:
            return ProcessResult(ProcessStatus.OK, 0, b"", b"", False)
        return ProcessResult(ProcessStatus.TIMEOUT, None, b"", b"", False)

    monkeypatch.setattr("ssh_id_doctor.adapters.github.process.run", fake_run)

    adapter = GitHubRegistryAdapter()
    result = adapter.list_keys()

    assert result.state is RegistryState.TIMEOUT
    assert result.coverage is not None
    assert result.coverage.state == CoverageState.TIMEOUT


def test_github_api_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nonzero exit code from gh api degrades to API_ERROR."""

    def fake_run(argv: Sequence[str], *, timeout: float, max_output: int) -> ProcessResult:
        if argv == ["gh", "auth", "status"]:
            return ProcessResult(ProcessStatus.OK, 0, b"", b"", False)
        return ProcessResult(ProcessStatus.NONZERO, 1, b"", b"403 rate limit exceeded", False)

    monkeypatch.setattr("ssh_id_doctor.adapters.github.process.run", fake_run)

    adapter = GitHubRegistryAdapter()
    result = adapter.list_keys()

    assert result.state is RegistryState.API_ERROR
    assert result.coverage is not None
    assert result.coverage.state == CoverageState.UNAVAILABLE


def test_github_invalid_key_records_unresolved(monkeypatch: pytest.MonkeyPatch) -> None:
    """Invalid public key text produces an Unresolved entry and allows scan to continue."""
    two_keys = json.loads(_fixture_text("two_keys"))
    data = [
        two_keys[0],
        {
            "id": 999,
            "key": "not-a-valid-ssh-public-key",
            "title": "broken-key",
            "created_at": "2023-01-02T00:00:00Z",
        },
    ]
    real_run = process.run

    def fake_run(argv: Sequence[str], *, timeout: float, max_output: int) -> ProcessResult:
        if argv == ["gh", "auth", "status"]:
            return ProcessResult(ProcessStatus.OK, 0, b"", b"", False)
        if list(argv[:2]) == ["gh", "api"]:
            return ProcessResult(ProcessStatus.OK, 0, json.dumps(data).encode(), b"", False)
        return real_run(argv, timeout=timeout, max_output=max_output)

    monkeypatch.setattr("ssh_id_doctor.adapters.github.process.run", fake_run)

    adapter = GitHubRegistryAdapter()
    result = adapter.list_keys()

    assert result.state is RegistryState.AVAILABLE
    assert len(result.bindings) == 1
    assert result.bindings[0].title == "old-laptop"
    assert len(result.unresolved) == 1
    assert result.unresolved[0].reason == "invalid_public_key"
