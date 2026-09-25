"""FR-004b (sdd-spec §7.4, §10 SEC-001/SEC-002/SEC-003): Include, cycles, Match, tokens.

Covers AC-1..AC-3, plus the SID-2 lesson about a private key disguised as an
Include target and the NFR-002 depth limit.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from conftest import CANARY, OpenGuard
from ssh_id_doctor import ssh_config
from ssh_id_doctor.ssh_config import ResolvedIdentityFile, SourceLoc


def _real(path: str | os.PathLike[str]) -> str:
    return os.path.realpath(os.fspath(path))


def test_include_quotes_tilde_and_sorted_glob(fake_home: Path, open_guard: OpenGuard) -> None:
    """AC-1: a quoted glob argument and a ``~``-relative one, both on one Include line, expand
    in sorted glob order followed by argument order; each Host block's location is the real
    included file and the line inside it, not the top-level config."""
    ssh = fake_home / ".ssh"
    config = ssh / "config"
    config.write_text('Include "config.d/*.conf" ~/.ssh/extra\n')

    config_d = ssh / "config.d"
    config_d.mkdir()
    (config_d / "b.conf").write_text("Host b\n")
    (config_d / "a.conf").write_text("Host a\n")
    extra = ssh / "extra"
    extra.write_text("Host x\n")
    open_guard.allow(extra)  # not .conf/config/known_hosts: an explicit Include target

    document = ssh_config.parse_file(config)

    assert document.unresolved == ()
    assert [block.patterns for block in document.host_blocks] == [("a",), ("b",), ("x",)]
    assert document.host_blocks[0].header == SourceLoc(_real(config_d / "a.conf"), 1)
    assert document.host_blocks[1].header == SourceLoc(_real(config_d / "b.conf"), 1)
    assert document.host_blocks[2].header == SourceLoc(_real(extra), 1)
    assert open_guard.violations == []


def test_include_cycle_terminates_with_unresolved_item(tmp_path: Path) -> None:
    """AC-2: config -> loop.conf -> config is a cycle; the parse still terminates, exactly one
    ``include_cycle`` item names the file and line that closed the loop, and config's own
    block is not processed (and so not duplicated) a second time."""
    config = tmp_path / "config"
    config.write_text("Host top\nInclude loop.conf\n")  # lines 1, 2
    loop = tmp_path / "loop.conf"
    loop.write_text("Include config\n")  # line 1

    document = ssh_config.parse_file(config)

    assert [block.patterns for block in document.host_blocks] == [("top",)]
    assert len(document.unresolved) == 1
    cycle = document.unresolved[0]
    assert cycle.reason == "include_cycle"
    assert cycle.source_file == _real(loop)
    assert cycle.source_line == 1


def test_missing_include_match_and_tokens_are_unresolved(tmp_path: Path) -> None:
    """AC-3: a missing explicit Include, an unevaluated Match (whose ``exec`` never runs), and
    an unexpandable ``%h`` token in an IdentityFile value are each their own unresolved item;
    the Match's IdentityFile reaches no alias, and ``h``'s IdentityFile keeps its literal
    ``%h`` text, paired with an ``unresolved_token`` item on its own line."""
    pwned_marker = tmp_path / "pwned"
    lines = [
        "",  # line 1
        "",  # line 2
        "",  # line 3
        "Include missing.conf",  # line 4
        "",  # line 5
        f'Match host *.corp exec "touch {pwned_marker}"',  # line 6
        "IdentityFile ~/.ssh/corp",  # line 7
        "",  # line 8
        "Host h",  # line 9
        "IdentityFile ~/.ssh/%h_key",  # line 10
    ]
    config = tmp_path / "config"
    config.write_text("\n".join(lines) + "\n")

    document = ssh_config.parse_file(config)

    by_reason_and_line = {(item.reason, item.source_line) for item in document.unresolved}
    assert ("include_missing", 4) in by_reason_and_line
    assert ("match_not_evaluated", 6) in by_reason_and_line
    assert ("unresolved_token", 10) in by_reason_and_line
    for item in document.unresolved:
        assert item.source_file == _real(config)

    resolved_h = document.evaluate("h")
    assert resolved_h.identity_files == (
        ResolvedIdentityFile("~/.ssh/%h_key", SourceLoc(_real(config), 10)),
    )

    # The Match stanza's IdentityFile never reaches any alias, including one its own
    # pattern would textually match.
    assert document.evaluate("server.corp").identity_files == ()
    assert all(
        entry.path != "~/.ssh/corp"
        for block in document.host_blocks
        for entry in block.identity_files
    )

    # Match's `exec` is never run (SEC-002): the marker it would have touched does not exist.
    assert not pwned_marker.exists()


def test_include_of_private_key_is_refused_and_unresolved(
    fake_home: Path,
    open_guard: OpenGuard,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """SID-2 lesson: ``Include id_canary`` resolves to a real, readable file — the path-level
    guard (SEC-003) has no reason to refuse it by name, the way it would a non-config file.
    The content-level guard (SEC-001, fs.read_config_text) is what refuses it, after reading:
    an unresolved item, and the private payload never appears in the message or in output."""
    ssh = fake_home / ".ssh"
    config = ssh / "config"
    config.write_text("Include id_canary\n")
    canary = ssh / "id_canary"
    # This path is exactly what the parser is expected to attempt, per the Include line
    # above — not a general widening of which files may be opened inside fake_home.
    open_guard.allow(canary)

    document = ssh_config.parse_file(config)

    assert document.host_blocks == ()
    assert len(document.unresolved) == 1
    item = document.unresolved[0]
    assert item.reason == "private_key_material"
    assert item.source_file == _real(canary)
    assert CANARY not in item.detail

    out, err = capsys.readouterr()
    assert CANARY not in out + err
    assert open_guard.violations == []


def test_include_depth_limit_terminates_deep_non_cyclic_chain(tmp_path: Path) -> None:
    """scope_in / NFR-002: a depth limit (16) bounds Include recursion even without a literal
    cycle, so a very deep (but acyclic) chain still terminates deterministically."""
    chain_len = 20
    for i in range(chain_len):
        content = f"Host level{i}\n"
        if i + 1 < chain_len:
            content += f"Include level{i + 1}.conf\n"
        (tmp_path / f"level{i}.conf").write_text(content)

    document = ssh_config.parse_file(tmp_path / "level0.conf")

    assert len(document.host_blocks) == 17  # depths 0..16 are read; the include at 16 is cut
    assert any(item.reason == "include_depth_exceeded" for item in document.unresolved)


def test_include_empty_glob_is_not_an_error(tmp_path: Path) -> None:
    """scope_in: a wildcard Include that matches nothing is not an error, unlike an explicit
    (non-glob) target that is missing."""
    config = tmp_path / "config"
    config.write_text("Include nothing.d/*.conf\nHost after\n")

    document = ssh_config.parse_file(config)

    assert document.unresolved == ()
    assert [block.patterns for block in document.host_blocks] == [("after",)]
