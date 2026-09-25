"""FR-004a (sdd-spec §7.4, §10 SEC-001/SEC-003): ssh_config(5) lexing and evaluation.

Covers AC-1..AC-4 of SID-5. Include, glob and cycle behavior (FR-004b) lives in
``tests/ssh_config/test_include.py``.
"""

from __future__ import annotations

import builtins
import io
import os
import threading
from pathlib import Path
from typing import Any

import pytest

from conftest import CANARY, CANARY_PRIVATE_KEY, OpenGuard
from ssh_id_doctor import fs, ssh_config
from ssh_id_doctor.ssh_config import IdentityFileEntry, ResolvedIdentityFile, SourceLoc


def _real(path: str | os.PathLike[str]) -> str:
    return os.path.realpath(os.fspath(path))


@pytest.fixture
def opened_paths(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Real path of every open (any route, any mode), layered over the private-open guard."""
    calls: list[str] = []
    inner_open = builtins.open
    inner_os_open = os.open

    def recording_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(file, str | bytes | os.PathLike):
            calls.append(os.path.realpath(os.fsdecode(os.fspath(file))))
        return inner_open(file, *args, **kwargs)

    def recording_os_open(path: Any, *args: Any, **kwargs: Any) -> int:
        calls.append(os.path.realpath(os.fsdecode(os.fspath(path))))
        return inner_os_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", recording_open)
    monkeypatch.setattr(io, "open", recording_open)
    monkeypatch.setattr(os, "open", recording_os_open)
    return calls


def test_first_value_wins_with_global_and_host_blocks(tmp_path: Path) -> None:
    """AC-1: a global option beats a later per-host one; HostName/IdentityFile come from the
    block that actually names the alias, not from an unrelated ``Host *`` fallback."""
    lines = [
        "User global",  # line 1
        "",  # line 2
        "Host gh github.com",  # line 3
        "HostName github.com",  # line 4
        "User git",  # line 5
        "IdentityFile ~/.ssh/gh_ed25519",  # line 6
        "",  # line 7
        "Host *",  # line 8
        "User other",  # line 9
    ]
    config = tmp_path / "config"
    config.write_text("\n".join(lines) + "\n")

    document = ssh_config.parse_file(config)
    resolved = document.evaluate("gh")

    assert document.unresolved == ()
    assert resolved.user == "global"
    assert resolved.user_source == SourceLoc(_real(config), 1)
    assert resolved.hostname == "github.com"
    assert resolved.hostname_source == SourceLoc(_real(config), 4)
    assert resolved.identity_files == (
        ResolvedIdentityFile("~/.ssh/gh_ed25519", SourceLoc(_real(config), 6)),
    )
    assert resolved.patterns == ("gh", "github.com")


def test_identityfile_accumulates_scalars_first_wins(tmp_path: Path) -> None:
    """AC-2: IdentityFile accumulates across every matching block, in file order; a scalar
    option (IdentitiesOnly) still takes only its first matching value."""
    lines = [
        "Host work",  # line 1
        "IdentityFile a",  # line 2
        "IdentitiesOnly yes",  # line 3
        "Host *",  # line 4
        "IdentityFile b",  # line 5
        "IdentitiesOnly no",  # line 6
    ]
    config = tmp_path / "config"
    config.write_text("\n".join(lines) + "\n")

    resolved = ssh_config.parse_file(config).evaluate("work")

    assert [entry.path for entry in resolved.identity_files] == ["a", "b"]
    assert resolved.identities_only is True
    assert resolved.identities_only_source == SourceLoc(_real(config), 3)


def test_lexer_quotes_equals_case_and_bad_line(tmp_path: Path) -> None:
    """AC-3: a quoted ``Key=Value`` pair, a case-insensitive keyword, a whole-line comment and
    one malformed line (with no keyword before its separator) that does not stop the parse."""
    lines = [
        'IdentityFile="/path with space/key"',  # line 1
        "hostname   Example.COM",  # line 2
        "# comment",  # line 3
        "",  # line 4
        "",  # line 5
        "",  # line 6
        "=== ",  # line 7
    ]
    config = tmp_path / "config"
    config.write_text("\n".join(lines) + "\n")

    document = ssh_config.parse_file(config)

    assert document.global_block.identity_files == (
        IdentityFileEntry("/path with space/key", SourceLoc(_real(config), 1)),
    )
    assert document.global_block.hostname == "Example.COM"
    assert document.global_block.hostname_source == SourceLoc(_real(config), 2)
    assert len(document.unresolved) == 1
    bad = document.unresolved[0]
    assert bad.reason == "malformed_line"
    assert bad.source_line == 7
    assert bad.source_file == _real(config)


def test_host_pattern_negation_excludes_block(tmp_path: Path) -> None:
    """Scope_in: a negated pattern (``!pattern``) excludes the whole Host line from matching,
    even when another pattern on the same line would otherwise match."""
    lines = [
        "Host *.example.com !staging.example.com",
        "User prod",
    ]
    config = tmp_path / "config"
    config.write_text("\n".join(lines) + "\n")
    document = ssh_config.parse_file(config)

    assert document.evaluate("web.example.com").user == "prod"
    assert document.evaluate("staging.example.com").user is None


def test_config_read_refuses_fifo_oversize_and_private_material(
    fake_home: Path,
    opened_paths: list[str],
    open_guard: OpenGuard,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC-4: parse_file goes through fs.read_config_text, which refuses (a) a config symlink
    to a FIFO without ever opening it and without hanging, (b) a config over the size limit,
    and (c) a config holding a private-key header — in every case as an unresolved item with a
    reason, never file content, and the surrounding scan is not interrupted."""
    ssh = fake_home / ".ssh"

    # (a) config -> FIFO, inside fake_home; must not hang and must never open the FIFO.
    fifo = ssh / "pipe_target"
    os.mkfifo(fifo)
    alias_config = ssh / "config"
    alias_config.unlink()  # fake_home already ships a plain config; replace it for this case
    alias_config.symlink_to(fifo)

    result: list[ssh_config.ConfigDocument] = []
    errors: list[BaseException] = []

    def run() -> None:
        try:
            result.append(ssh_config.parse_file(alias_config))
        except BaseException as exc:  # surfaced in the main thread below
            errors.append(exc)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout=5)
    if worker.is_alive():
        writer = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        os.close(writer)
        worker.join(timeout=5)
        pytest.fail("parse_file blocked opening a FIFO behind a config symlink")
    assert errors == []
    assert os.path.realpath(fifo) not in opened_paths

    fifo_document = result[0]
    assert fifo_document.host_blocks == ()
    assert len(fifo_document.unresolved) == 1
    assert fifo_document.unresolved[0].reason == "not_a_config_file"

    # (b) config over MAX_CONFIG_BYTES.
    oversize_dir = ssh / "oversize"
    oversize_dir.mkdir()
    oversize_config = oversize_dir / "config"
    oversize_config.write_text("HostName " + "A" * (fs.MAX_CONFIG_BYTES + 1024) + "\n")

    oversize_document = ssh_config.parse_file(oversize_config)

    assert oversize_document.host_blocks == ()
    assert len(oversize_document.unresolved) == 1
    oversize_item = oversize_document.unresolved[0]
    assert oversize_item.reason == "not_a_config_file"
    assert "A" * 100 not in oversize_item.detail
    assert len(oversize_item.detail) < 200

    # (c) config holding a private-key header on some line.
    private_dir = ssh / "private"
    private_dir.mkdir()
    private_config = private_dir / "config"
    private_config.write_text("Host x\n" + CANARY_PRIVATE_KEY)

    private_document = ssh_config.parse_file(private_config)

    assert private_document.host_blocks == ()
    assert len(private_document.unresolved) == 1
    private_item = private_document.unresolved[0]
    assert private_item.reason == "private_key_material"
    assert CANARY not in private_item.detail

    # The scan is not interrupted: a normal config right after still parses fine.
    normal_dir = ssh / "normal"
    normal_dir.mkdir()
    normal_config = normal_dir / "config"
    normal_config.write_text("HostName example.com\n")
    normal_document = ssh_config.parse_file(normal_config)
    assert normal_document.global_block.hostname == "example.com"

    out, err = capsys.readouterr()
    assert CANARY not in out + err
    assert open_guard.violations == []


@pytest.mark.parametrize("match_keyword", ["Match", "match", "MATCH"])
def test_match_opens_unresolved_stanza_not_merged_into_neighbours(
    tmp_path: Path, match_keyword: str
) -> None:
    """Review #593: a ``Match`` line starts its own stanza (SID-6 evaluates it — see summary
    for the ``match_not_evaluated``/``unsupported_match`` naming decision). Until then the
    stanza is an unresolved item with file:line, and none of its options leak into the
    preceding ``Host`` block, the global block, or any alias's ``evaluate()``; the next
    ``Host`` closes it as usual. Checked against ``ssh -G -F <file> <alias>``."""
    lines = [
        f"{match_keyword} host never",  # line 1: Match before the first Host
        "User from_match",  # line 2
        "IdentityFile /from/match",  # line 3
        "Host special",  # line 4
        "IdentityFile /special/key",  # line 5
        f"{match_keyword} host other",  # line 6: Match after a Host
        "IdentityFile /leaked/key",  # line 7
        "HostName leaked.example",  # line 8
        "IdentitiesOnly yes",  # line 9
        "Host real",  # line 10
        "User from_host",  # line 11
    ]
    config = tmp_path / "config"
    config.write_text("\n".join(lines) + "\n")

    document = ssh_config.parse_file(config)

    match_items = [item for item in document.unresolved if item.reason == "match_not_evaluated"]
    assert [(item.source_file, item.source_line) for item in match_items] == [
        (_real(config), 1),
        (_real(config), 6),
    ]
    assert document.global_block.user is None
    assert document.global_block.identity_files == ()
    assert [block.patterns for block in document.host_blocks] == [("special",), ("real",)]

    special = document.evaluate("special")
    assert special.identity_files == (
        ResolvedIdentityFile("/special/key", SourceLoc(_real(config), 5)),
    )
    assert special.hostname is None
    assert special.identities_only is None
    assert special.user is None

    real = document.evaluate("real")
    assert real.user == "from_host"
    assert real.user_source == SourceLoc(_real(config), 11)
    assert real.identity_files == ()

    for alias in ("never", "other"):
        resolved = document.evaluate(alias)
        assert resolved.user is None
        assert resolved.hostname is None
        assert resolved.identities_only is None
        assert resolved.identity_files == ()


def test_value_with_unresolved_token_kept_literal_and_flagged(tmp_path: Path) -> None:
    """scope_in: a value with %h/%r/%d/%u or ${VAR} is never expanded; it is kept as its
    literal text and paired with an ``unresolved_token`` item naming the line."""
    lines = [
        "Host h",  # line 1
        "IdentityFile ~/.ssh/%h_key",  # line 2
        "User ${REMOTE_USER}",  # line 3
    ]
    config = tmp_path / "config"
    config.write_text("\n".join(lines) + "\n")

    document = ssh_config.parse_file(config)
    resolved = document.evaluate("h")

    assert resolved.identity_files == (
        ResolvedIdentityFile("~/.ssh/%h_key", SourceLoc(_real(config), 2)),
    )
    assert resolved.user == "${REMOTE_USER}"
    token_items = {(item.source_line, item.detail) for item in document.unresolved}
    assert token_items == {
        (2, "~/.ssh/%h_key"),
        (3, "${REMOTE_USER}"),
    }
    assert all(item.reason == "unresolved_token" for item in document.unresolved)
