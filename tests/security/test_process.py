"""SEC-002: process.run is the one audited subprocess runner (AC-1, AC-2)."""

from __future__ import annotations

import subprocess
import time
from typing import Any

import pytest

from ssh_id_doctor import process
from ssh_id_doctor.process import ProcessStatus

METACHARACTERS = "a b; rm -rf /tmp/x $(id)"


@pytest.fixture
def popen_calls(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    real_popen = subprocess.Popen

    def spy(*args: Any, **kwargs: Any) -> Any:
        calls.append({"args": args, **kwargs})
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", spy)
    return calls


def test_run_rejects_string_argv_and_keeps_metacharacters_inert(
    popen_calls: list[dict[str, Any]],
) -> None:
    result = process.run(["printf", "%s", METACHARACTERS], timeout=5, max_output=4096)

    assert result.status is ProcessStatus.OK
    assert result.stdout.decode() == METACHARACTERS
    assert len(popen_calls) == 1

    with pytest.raises(TypeError):
        process.run("echo hi", timeout=5, max_output=4096)  # type: ignore[arg-type]

    assert len(popen_calls) == 1, "a string argv must be refused before anything starts"
    assert all(call["shell"] is False for call in popen_calls)
    assert all(isinstance(call["args"][0], list) for call in popen_calls)


def test_run_reports_timeout_and_missing_executable() -> None:
    started = time.monotonic()
    slow = process.run(["sleep", "5"], timeout=0.2, max_output=1024)
    elapsed = time.monotonic() - started

    assert slow.status is ProcessStatus.TIMEOUT
    assert slow.returncode is None
    assert elapsed < 1.0

    missing = process.run(["nonexistent-binary-xyz"], timeout=1, max_output=1024)
    assert missing.status is ProcessStatus.NOT_FOUND


def test_run_bounds_captured_output_and_reports_nonzero() -> None:
    result = process.run(
        ["sh", "-c", "yes | head -c 100000; exit 3"], timeout=5, max_output=10
    )  # a test-only fixture program; product code never passes sh -c

    assert result.status is ProcessStatus.NONZERO
    assert result.returncode == 3
    assert result.stdout == b"y\ny\ny\ny\ny\n"
    assert result.truncated is True


def test_run_passes_only_whitelisted_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SID_SECRET_PROBE", "leak")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/nonexistent/agent.sock")

    result = process.run(["env"], timeout=5, max_output=65536)

    names = {line.split("=", 1)[0] for line in result.stdout.decode().splitlines() if line}
    assert "SID_SECRET_PROBE" not in names
    assert "SSH_AUTH_SOCK" in names
    assert names <= set(process.ENV_WHITELIST)
