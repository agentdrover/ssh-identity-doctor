"""FR-003 (sdd-spec §7.2, §12): SHA-256 fingerprint via ssh-keygen (AC-1..AC-4)."""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path
from typing import Any

import pytest

from ssh_id_doctor import process
from ssh_id_doctor.inspectors import RequiredSourceError, Unresolved
from ssh_id_doctor.inspectors.keygen import KeyInfo, PublicKeyInspector
from ssh_id_doctor.process import ProcessResult, ProcessStatus

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "keys"


def _fixture_pub(name: str) -> str:
    return (FIXTURES / f"{name}.pub").read_text().strip("\n")


def _fixture_recorded(name: str) -> str:
    return (FIXTURES / f"{name}.sha256.txt").read_text()


@pytest.fixture
def inspector() -> PublicKeyInspector:
    return PublicKeyInspector()


@pytest.fixture
def real_ssh_keygen() -> None:
    if shutil.which("ssh-keygen") is None:
        pytest.skip("ssh-keygen not installed in this environment")


# ---------------------------------------------------------------------------
# AC-1: recorded fixture output for each key family (§13.2: contract fixtures;
# this test_ref must work on a *recorded* output, no live ssh-keygen)
# ---------------------------------------------------------------------------


def test_fingerprint_ed25519_matches_recorded_output(
    inspector: PublicKeyInspector, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-1: given the ed25519 fixture and its recorded ssh-keygen output, no live process."""
    recorded = _fixture_recorded("ed25519")

    def fake_run(argv: list[str], *, timeout: float, max_output: int) -> ProcessResult:
        assert argv[0] == "ssh-keygen"
        return ProcessResult(ProcessStatus.OK, 0, recorded.encode(), b"", False)

    monkeypatch.setattr("ssh_id_doctor.inspectors.keygen.process.run", fake_run)

    info = inspector.fingerprint(_fixture_pub("ed25519"))

    assert isinstance(info, KeyInfo)
    assert info.fingerprint.startswith("SHA256:")
    assert info.fingerprint == "SHA256:+92RsVKGXDDG2XlZkoQSG2sRjqnoPwysscnoHoCIdMk"
    assert info.algorithm == "ssh-ed25519"
    assert info.bits_or_curve == "256"
    assert info.comment == "work@example"


@pytest.mark.parametrize(
    ("fixture_name", "algorithm", "bits_or_curve"),
    [
        ("rsa3072", "ssh-rsa", "3072"),
        ("ecdsa256", "ecdsa-sha2-nistp256", "256"),
    ],
)
def test_fingerprint_matches_recorded_output_for_other_key_families(
    inspector: PublicKeyInspector,
    monkeypatch: pytest.MonkeyPatch,
    fixture_name: str,
    algorithm: str,
    bits_or_curve: str,
) -> None:
    """AC-1 (contract fixtures, §13.2): parses a *recorded* ssh-keygen output, no live process."""
    recorded = _fixture_recorded(fixture_name)

    def fake_run(argv: list[str], *, timeout: float, max_output: int) -> ProcessResult:
        assert argv[0] == "ssh-keygen"
        return ProcessResult(ProcessStatus.OK, 0, recorded.encode(), b"", False)

    monkeypatch.setattr("ssh_id_doctor.inspectors.keygen.process.run", fake_run)

    info = inspector.fingerprint(_fixture_pub(fixture_name))

    assert isinstance(info, KeyInfo)
    assert info.fingerprint.startswith("SHA256:")
    assert info.algorithm == algorithm
    assert info.bits_or_curve == bits_or_curve


@pytest.mark.usefixtures("real_ssh_keygen")
@pytest.mark.parametrize("fixture_name", ["ed25519", "rsa3072", "ecdsa256"])
def test_live_ssh_keygen_still_matches_recorded_fixture(
    inspector: PublicKeyInspector, fixture_name: str
) -> None:
    """Risk mitigation (spec risks): catch ssh-keygen output drift; skipped if not installed."""
    recorded = _fixture_recorded(fixture_name)
    recorded_fingerprint = next(p for p in recorded.split() if p.startswith("SHA256:"))

    info = inspector.fingerprint(_fixture_pub(fixture_name))

    assert isinstance(info, KeyInfo)
    assert info.fingerprint == recorded_fingerprint


# ---------------------------------------------------------------------------
# AC-2: invalid material -> Unresolved
# ---------------------------------------------------------------------------


def test_invalid_material_becomes_unresolved(
    inspector: PublicKeyInspector, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-2: invalid public material -> Unresolved(reason='invalid_public_key')."""
    calls: list[list[str]] = []

    def fake_run(argv: list[str], *, timeout: float, max_output: int) -> ProcessResult:
        calls.append(list(argv))
        return ProcessResult(ProcessStatus.NONZERO, 1, b"", b"not a public key\n", False)

    monkeypatch.setattr("ssh_id_doctor.inspectors.keygen.process.run", fake_run)

    result = inspector.fingerprint("ssh-ed25519 not-base64!!")

    assert result == Unresolved(reason="invalid_public_key", detail="ssh-keygen rejected the key")
    assert len(calls) == 1
    assert "-y" not in calls[0]


# ---------------------------------------------------------------------------
# AC-3: ssh-keygen missing -> RequiredSourceError
# ---------------------------------------------------------------------------


def test_missing_ssh_keygen_is_required_source_failure(
    inspector: PublicKeyInspector, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-3: ssh-keygen not found -> RequiredSourceError, argv is a list, no '-y'."""
    captured: dict[str, Any] = {}

    def fake_run(argv: list[str], *, timeout: float, max_output: int) -> ProcessResult:
        captured["argv"] = argv
        captured["timeout"] = timeout
        return ProcessResult(ProcessStatus.NOT_FOUND, None, b"", b"", False)

    monkeypatch.setattr("ssh_id_doctor.inspectors.keygen.process.run", fake_run)

    public_line = _fixture_pub("ed25519")
    with pytest.raises(RequiredSourceError) as excinfo:
        inspector.fingerprint(public_line)

    assert isinstance(captured["argv"], list)
    assert "-y" not in captured["argv"]
    assert captured["argv"][0] == "ssh-keygen"
    assert captured["timeout"] > 0
    message = str(excinfo.value)
    assert "AAAA" not in message  # no key material in the message
    key_body = public_line.split()[1]
    assert key_body not in message


# ---------------------------------------------------------------------------
# AC-4: ssh-keygen present but not executable -> RequiredSourceError, no traceback
# ---------------------------------------------------------------------------


def test_non_executable_ssh_keygen_is_required_source_failure(
    inspector: PublicKeyInspector, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-4: non-executable file / directory named ssh-keygen -> clean RequiredSourceError."""
    public_line = _fixture_pub("ed25519")

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "ssh-keygen"
    fake.write_text("#!/bin/sh\necho should-not-run\n")
    fake.chmod(0o644)  # no +x: review SID-2 finding, process.run must not raise PermissionError
    monkeypatch.setenv("PATH", str(bin_dir))

    with pytest.raises(RequiredSourceError) as excinfo:
        inspector.fingerprint(public_line)
    assert "AAAA" not in str(excinfo.value)

    fake.unlink()
    (bin_dir / "ssh-keygen").mkdir()  # a directory named ssh-keygen shadows the real one

    with pytest.raises(RequiredSourceError) as excinfo_dir:
        inspector.fingerprint(public_line)
    assert "AAAA" not in str(excinfo_dir.value)

    os.rmdir(bin_dir / "ssh-keygen")


# ---------------------------------------------------------------------------
# Boundary inputs called out by the task (each must degrade cleanly, no traceback)
# ---------------------------------------------------------------------------


def test_ssh_keygen_timeout_becomes_unresolved(
    inspector: PublicKeyInspector, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(argv: list[str], *, timeout: float, max_output: int) -> ProcessResult:
        return ProcessResult(ProcessStatus.TIMEOUT, None, b"", b"", False)

    monkeypatch.setattr("ssh_id_doctor.inspectors.keygen.process.run", fake_run)

    result = inspector.fingerprint(_fixture_pub("ed25519"))

    assert result == Unresolved(reason="ssh_keygen_timeout", detail="ssh-keygen did not return")


def test_empty_stdout_at_exit_zero_becomes_unresolved(
    inspector: PublicKeyInspector, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(argv: list[str], *, timeout: float, max_output: int) -> ProcessResult:
        return ProcessResult(ProcessStatus.OK, 0, b"", b"", False)

    monkeypatch.setattr("ssh_id_doctor.inspectors.keygen.process.run", fake_run)

    result = inspector.fingerprint(_fixture_pub("ed25519"))

    assert isinstance(result, Unresolved)
    assert result.reason == "empty_ssh_keygen_output"


def test_output_with_extra_whitespace_and_no_comment_still_parses(
    inspector: PublicKeyInspector, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(argv: list[str], *, timeout: float, max_output: int) -> ProcessResult:
        return ProcessResult(
            ProcessStatus.OK, 0, b"  256   SHA256:abcDEF123+/=   (ED25519)  \n", b"", False
        )

    monkeypatch.setattr("ssh_id_doctor.inspectors.keygen.process.run", fake_run)

    result = inspector.fingerprint(_fixture_pub("ed25519"))

    assert isinstance(result, KeyInfo)
    assert result.fingerprint == "SHA256:abcDEF123+/="
    assert result.bits_or_curve == "256"
    assert result.comment == ""


def test_output_with_embedded_newlines_is_unresolved_not_a_crash(
    inspector: PublicKeyInspector, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(argv: list[str], *, timeout: float, max_output: int) -> ProcessResult:
        return ProcessResult(
            ProcessStatus.OK,
            0,
            b"warning: something\n256 SHA256:abcDEF123 comment (ED25519)\n",
            b"",
            False,
        )

    monkeypatch.setattr("ssh_id_doctor.inspectors.keygen.process.run", fake_run)

    result = inspector.fingerprint(_fixture_pub("ed25519"))

    assert isinstance(result, Unresolved)
    assert result.reason == "unparseable_ssh_keygen_output"


def test_unknown_algorithm_marker_is_unresolved_not_a_crash(
    inspector: PublicKeyInspector, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(argv: list[str], *, timeout: float, max_output: int) -> ProcessResult:
        return ProcessResult(ProcessStatus.NONZERO, 1, b"", b"unknown key algorithm\n", False)

    monkeypatch.setattr("ssh_id_doctor.inspectors.keygen.process.run", fake_run)

    result = inspector.fingerprint("ssh-mystery-algo AAAAsomekeydata comment")

    assert isinstance(result, Unresolved)
    assert result.reason == "invalid_public_key"


def test_multiline_public_material_is_unresolved_before_calling_ssh_keygen(
    inspector: PublicKeyInspector, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], *, timeout: float, max_output: int) -> ProcessResult:
        calls.append(list(argv))
        return ProcessResult(ProcessStatus.OK, 0, b"", b"", False)

    monkeypatch.setattr("ssh_id_doctor.inspectors.keygen.process.run", fake_run)

    result = inspector.fingerprint("ssh-ed25519 AAAA\nssh-ed25519 BBBB comment")

    assert result == Unresolved(reason="invalid_public_key", detail="not one public-key line")
    assert calls == [], "ssh-keygen must never be invoked on multi-line input"


def test_blank_public_line_is_unresolved_before_calling_ssh_keygen(
    inspector: PublicKeyInspector, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], *, timeout: float, max_output: int) -> ProcessResult:
        calls.append(list(argv))
        return ProcessResult(ProcessStatus.OK, 0, b"", b"", False)

    monkeypatch.setattr("ssh_id_doctor.inspectors.keygen.process.run", fake_run)

    result = inspector.fingerprint("   \n")

    assert result == Unresolved(reason="invalid_public_key", detail="not one public-key line")
    assert calls == []


def test_scratch_file_is_removed_after_success_and_after_failure(
    inspector: PublicKeyInspector, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The temp file ssh-keygen reads from is 0600 and removed on every path (finally)."""
    seen_paths: list[str] = []

    def fake_run_ok(argv: list[str], *, timeout: float, max_output: int) -> ProcessResult:
        path = argv[argv.index("-f") + 1]
        seen_paths.append(path)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600
        return ProcessResult(ProcessStatus.OK, 0, _fixture_recorded("ed25519").encode(), b"", False)

    monkeypatch.setattr("ssh_id_doctor.inspectors.keygen.process.run", fake_run_ok)
    inspector.fingerprint(_fixture_pub("ed25519"))
    assert seen_paths and not os.path.exists(seen_paths[0])

    def fake_run_crash(argv: list[str], *, timeout: float, max_output: int) -> ProcessResult:
        path = argv[argv.index("-f") + 1]
        seen_paths.append(path)
        raise RuntimeError("boom")

    monkeypatch.setattr("ssh_id_doctor.inspectors.keygen.process.run", fake_run_crash)
    with pytest.raises(RuntimeError):
        inspector.fingerprint(_fixture_pub("ed25519"))
    assert not os.path.exists(seen_paths[-1])


def test_fingerprint_never_passes_dash_y(
    inspector: PublicKeyInspector, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SEC-001: -y (derive public from private) must never appear in the argv."""
    seen: list[list[str]] = []

    def fake_run(argv: list[str], *, timeout: float, max_output: int) -> ProcessResult:
        seen.append(list(argv))
        return ProcessResult(ProcessStatus.OK, 0, _fixture_recorded("ed25519").encode(), b"", False)

    monkeypatch.setattr("ssh_id_doctor.inspectors.keygen.process.run", fake_run)
    inspector.fingerprint(_fixture_pub("ed25519"))

    assert seen
    for argv in seen:
        assert "-y" not in argv
        assert isinstance(argv, list)


def test_process_run_is_the_one_subprocess_call(
    inspector: PublicKeyInspector, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SEC-002: the inspector goes through process.run, not subprocess directly."""
    called = {"count": 0}
    real_run = process.run

    def spy(argv: list[str], *, timeout: float, max_output: int) -> ProcessResult:
        called["count"] += 1
        return real_run(argv, timeout=timeout, max_output=max_output)

    monkeypatch.setattr("ssh_id_doctor.inspectors.keygen.process.run", spy)
    if shutil.which("ssh-keygen") is None:
        pytest.skip("ssh-keygen not installed in this environment")

    inspector.fingerprint(_fixture_pub("ed25519"))

    assert called["count"] == 1
