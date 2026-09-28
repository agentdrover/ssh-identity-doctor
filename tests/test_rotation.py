"""Tests for rotation-plan command (FR-009, SID-18).

Acceptance criteria AC-1 to AC-4.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from conftest import OpenGuard
from ssh_id_doctor import process
from ssh_id_doctor.cli import main
from ssh_id_doctor.domain import (
    Confidence,
    CoverageState,
    HostBinding,
    Identity,
    LocalReference,
    LocalReferenceKind,
    Platform,
    Resolution,
    ScanSnapshot,
    SourceCoverage,
    UnresolvedItem,
)
from ssh_id_doctor.exit_codes import ExitCode
from ssh_id_doctor.inspectors.keygen import PublicKeyInspector
from ssh_id_doctor.process import ProcessResult, ProcessStatus
from ssh_id_doctor.rotation import build_rotation_plan, render_plan_markdown, render_plan_terminal

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "home_basic"
CANARY = "CANARY-PRIVATE-7f3a"
CANARY_PRIVATE_KEY = (
    f"-----BEGIN OPENSSH PRIVATE KEY-----\n{CANARY}\n-----END OPENSSH PRIVATE KEY-----\n"
)

_ED25519_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHf1xYl0lq7mJ0Ra0cWm9vQn2c9c5b3nq1F0mX4bY0Zs a@test\n"
)


def _setup_home_basic(fake_home: Path) -> Path:
    ssh = fake_home / ".ssh"
    ssh.mkdir(mode=0o700, parents=True, exist_ok=True)
    for p in FIXTURES_DIR.glob("*.pub"):
        (ssh / p.name).write_text(p.read_text())
    (ssh / "config").write_text((FIXTURES_DIR / "config").read_text())
    config_d = ssh / "config.d"
    config_d.mkdir(exist_ok=True)
    for p in (FIXTURES_DIR / "config.d").glob("*.conf"):
        text = p.read_text()
        if "Include cycle.conf" in text:
            text = text.replace("Include cycle.conf", "Include config.d/cycle.conf")
        if "Include included.conf" in text:
            text = text.replace("Include included.conf", "Include config.d/included.conf")
        (config_d / p.name).write_text(text)

    (ssh / "id_canary.pub").unlink(missing_ok=True)
    (ssh / "id_canary").write_text(CANARY_PRIVATE_KEY)
    (ssh / "id_canary").chmod(0o600)
    return fake_home


@pytest.fixture
def home_basic(fake_home: Path) -> Path:
    """Fixture providing populated home_basic."""
    return _setup_home_basic(fake_home)


def _setup_ac1_scenario(
    fake_home: Path,
) -> tuple[str, Path, Path]:
    """Given home_basic, fingerprint F of key id_a: files id_a.pub and copy_of_a.pub,

    alias 'gh' (config:3), recorded agent and GitHub with F.
    """
    ssh_dir = fake_home / ".ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True)

    id_a_pub = ssh_dir / "id_a.pub"
    copy_a_pub = ssh_dir / "copy_of_a.pub"
    id_a_pub.write_text(_ED25519_KEY)
    copy_a_pub.write_text(_ED25519_KEY)

    # config:
    # 1: Host gh
    # 2:     HostName github.com
    # 3:     IdentityFile ~/.ssh/id_a
    config = ssh_dir / "config"
    config.write_text("Host gh\n    HostName github.com\n    IdentityFile ~/.ssh/id_a\n")

    keygen = PublicKeyInspector()
    info = keygen.fingerprint(_ED25519_KEY)
    return info.fingerprint, ssh_dir, config


def _patch_agent_and_github(
    monkeypatch: pytest.MonkeyPatch, key_text: str, github_title: str = "work-laptop"
) -> None:
    real_run = process.run
    gh_keys = json.dumps([{"id": 42, "key": key_text.strip(), "title": github_title}])

    def fake_run(argv: Sequence[str], *, timeout: float, max_output: int) -> ProcessResult:
        tool = argv[0]
        if tool == "ssh-keygen":
            return real_run(argv, timeout=timeout, max_output=max_output)
        if tool == "ssh-add":
            return ProcessResult(ProcessStatus.OK, 0, key_text.encode(), b"", False)
        if tool == "gh" and list(argv[1:3]) == ["auth", "status"]:
            return ProcessResult(ProcessStatus.OK, 0, b"", b"", False)
        if tool == "gh":
            return ProcessResult(ProcessStatus.OK, 0, gh_keys.encode(), b"", False)
        raise AssertionError(f"unexpected external tool {tool!r}")

    monkeypatch.setattr(process, "run", fake_run)


def test_rotation_plan_lists_known_relationships_in_fr009_order(
    fake_home: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC-1: Given home_basic, fingerprint F of key id_a: files id_a.pub and copy_of_a.pub,

    alias 'gh' (config:3), recorded agent and GitHub with F.
    When `ssh-id-doctor rotation-plan F --format md --github`.
    Then exit 0; Markdown contains sections in order Identity, Local references,
    Host aliases, Agent and GitHub, Unknowns, Backup access, Checklist;
    both paths listed, 'gh' with config:3, agent presence, and GitHub key title.
    """
    f_fingerprint, ssh_dir, config = _setup_ac1_scenario(fake_home)
    _patch_agent_and_github(monkeypatch, _ED25519_KEY, github_title="work-laptop")

    exit_code = main(
        [
            "rotation-plan",
            f_fingerprint,
            "--format",
            "md",
            "--github",
            "--ssh-dir",
            str(ssh_dir),
            "--config",
            str(config),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == ExitCode.OK

    md = captured.out
    # Check section order
    sections = [
        "## Identity",
        "## Local references",
        "## Host aliases",
        "## Agent and GitHub",
        "## Unknowns",
        "## Backup access",
        "## Checklist",
    ]
    positions = [md.index(s) for s in sections]
    assert positions == sorted(positions), f"Sections not in FR-009 order: {positions}"

    # Check both paths listed
    assert "id_a.pub" in md
    assert "copy_of_a.pub" in md

    # Check alias 'gh' with config:3
    assert "gh" in md
    assert "config:3" in md

    # Check agent presence
    assert "present" in md

    # Check GitHub key title
    assert "work-laptop" in md


def test_rotation_plan_states_unknowns_and_has_no_destructive_commands(
    fake_home: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC-2: Given same scenario, but without --github and with --no-agent.

    When rotation-plan F in formats terminal, md, json.
    Then Unknowns section contains phrase about uninspected remote authorized_keys
    and items 'agent: skipped', 'github: not requested';
    none of the formats contain substrings:
    'rm ', 'ssh-add -d', 'ssh-add -D', 'gh ssh-key delete', 'sed -i', 'safe to delete'.
    """
    f_fingerprint, ssh_dir, config = _setup_ac1_scenario(fake_home)
    destructive_substrings = (
        "rm ",
        "ssh-add -d",
        "ssh-add -D",
        "gh ssh-key delete",
        "sed -i",
        "safe to delete",
    )

    for fmt in ("terminal", "md", "json"):
        exit_code = main(
            [
                "rotation-plan",
                f_fingerprint,
                "--format",
                fmt,
                "--no-agent",
                "--ssh-dir",
                str(ssh_dir),
                "--config",
                str(config),
            ]
        )
        captured = capsys.readouterr()
        assert exit_code == ExitCode.OK, f"Format {fmt} failed with code {exit_code}"

        out = captured.out
        # Unknowns checks
        assert "remote authorized_keys and other registries are not inspected" in out, (
            f"Missing remote authorized_keys phrase in {fmt}"
        )
        assert "agent: skipped" in out, f"Missing 'agent: skipped' in {fmt}"
        assert "github: not requested" in out, f"Missing 'github: not requested' in {fmt}"

        # No destructive commands or 'safe to delete'
        for forbidden in destructive_substrings:
            assert forbidden not in out, f"Forbidden substring '{forbidden}' found in {fmt} output"


def test_rotation_plan_rejects_bad_or_unknown_fingerprint(
    home_basic: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC-3: Given home_basic.

    When (a) rotation-plan MD5:aa:bb; (b) rotation-plan SHA256:несуществующий.
    Then both exit 1; stderr explains expected format SHA256:<base64>
    or that fingerprint not found among known identities.
    """
    ssh_dir = str(home_basic / ".ssh")
    config = str(home_basic / ".ssh" / "config")

    # (a) Bad format MD5:aa:bb -> exit 1
    rc_a = main(
        [
            "rotation-plan",
            "MD5:aa:bb",
            "--no-agent",
            "--ssh-dir",
            ssh_dir,
            "--config",
            config,
        ]
    )
    captured_a = capsys.readouterr()
    assert rc_a == ExitCode.INVALID_ARGS
    assert "SHA256:<base64>" in captured_a.err

    # (b) Bad format / unknown cyrillic -> exit 1
    rc_b = main(
        [
            "rotation-plan",
            "SHA256:несуществующий",
            "--no-agent",
            "--ssh-dir",
            ssh_dir,
            "--config",
            config,
        ]
    )
    captured_b = capsys.readouterr()
    assert rc_b == ExitCode.INVALID_ARGS
    assert "SHA256:<base64>" in captured_b.err or "not found" in captured_b.err

    # (c) Well-formed SHA256:<base64> that does not exist in snapshot -> exit 1
    unknown_fp = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    rc_c = main(
        [
            "rotation-plan",
            unknown_fp,
            "--no-agent",
            "--ssh-dir",
            ssh_dir,
            "--config",
            config,
        ]
    )
    captured_c = capsys.readouterr()
    assert rc_c == ExitCode.INVALID_ARGS
    assert "not found among known identities" in captured_c.err


def test_rotation_plan_end_to_end_on_real_home_basic(
    open_guard: OpenGuard,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC-4: Given real fixture tests/fixtures/home_basic from repo (no snapshot substitution):

    id_ed25519.pub and copy id_ed25519_copy.pub with fingerprint E,
    config with 'Host gh github.com' (IdentityFile on line 4), Match on line 20, Include cycle;
    fingerprint E computed by scan, not hardcoded.
    When CLI run:
    `ssh-id-doctor rotation-plan E --format json --no-agent ...`
    Then exit 0; JSON plan ({schema_version:'1.0', kind:'rotation_plan'}) lists both real .pub paths
    and alias 'gh' with config:4; Unknowns contains phrase about remote authorized_keys,
    'agent: skipped', and unresolved config items of real scan (Match on config:20, Include cycle);
    no destructive commands.
    """
    # 1. Compute fingerprint E by scanning id_ed25519.pub
    pub_path = FIXTURES_DIR / "id_ed25519.pub"
    keygen = PublicKeyInspector()
    key_info = keygen.fingerprint(pub_path.read_text())
    e_fingerprint = key_info.fingerprint

    # 2. Run CLI
    exit_code = main(
        [
            "rotation-plan",
            e_fingerprint,
            "--format",
            "json",
            "--no-agent",
            "--ssh-dir",
            str(FIXTURES_DIR),
            "--config",
            str(FIXTURES_DIR / "config"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == ExitCode.OK

    # 3. Validate JSON structure
    data = json.loads(captured.out)
    assert data["schema_version"] == "1.0"
    assert data["kind"] == "rotation_plan"

    # Both real .pub paths listed
    ref_paths = [r["path"] for r in data["local_references"]]
    assert any(p.endswith("id_ed25519.pub") for p in ref_paths)
    assert any(p.endswith("id_ed25519_copy.pub") for p in ref_paths)

    # Alias 'gh' with config:4 listed
    gh_matches = [
        ha
        for ha in data["host_aliases"]
        if (ha["alias"] == "gh" or "gh" in ha["patterns"])
        and (ha["location"] == "config:4" or ha["source_line"] == 4)
    ]
    assert len(gh_matches) > 0, f"Expected alias 'gh' with config:4, got {data['host_aliases']}"

    # Unknowns contains:
    unknowns = data["unknowns"]
    assert any(
        "remote authorized_keys and other registries are not inspected" in u for u in unknowns
    )
    assert any("agent: skipped" in u for u in unknowns)
    # Match on config:20
    assert any("unresolved Match directive at config:20" in u for u in unknowns), unknowns
    # Include items of the real scan. The parser resolves the nested Include lines of
    # config.d/*.conf against the fixture root, so it reports them as include_missing,
    # not as a cycle -- and the plan must name them as what the parser reported.
    for loc in ("cycle.conf:4", "included.conf:5"):
        assert any(f"unresolved Include directive at {loc}" in u for u in unknowns), unknowns

    # No destructive commands
    destructive_substrings = (
        "rm ",
        "ssh-add -d",
        "ssh-add -D",
        "gh ssh-key delete",
        "sed -i",
        "safe to delete",
    )
    for forbidden in destructive_substrings:
        assert forbidden not in captured.out

    # open_guard clean
    assert open_guard.violations == []


def test_rotation_plan_atomic_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--output writes report atomically with 0600 mode and refuses writing inside ssh_dir."""
    pub_path = FIXTURES_DIR / "id_ed25519.pub"
    keygen = PublicKeyInspector()
    e_fingerprint = keygen.fingerprint(pub_path.read_text()).fingerprint

    out_file = tmp_path / "sub" / "plan.json"
    rc = main(
        [
            "rotation-plan",
            e_fingerprint,
            "--format",
            "json",
            "--no-agent",
            "--ssh-dir",
            str(FIXTURES_DIR),
            "--config",
            str(FIXTURES_DIR / "config"),
            "--output",
            str(out_file),
        ]
    )
    assert rc == ExitCode.OK
    assert out_file.exists()
    assert (out_file.stat().st_mode & 0o777) == 0o600
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["kind"] == "rotation_plan"

    # Refuse writing inside ssh_dir
    rc_bad = main(
        [
            "rotation-plan",
            e_fingerprint,
            "--format",
            "json",
            "--no-agent",
            "--ssh-dir",
            str(FIXTURES_DIR),
            "--config",
            str(FIXTURES_DIR / "config"),
            "--output",
            str(FIXTURES_DIR / "plan.json"),
        ]
    )
    captured = capsys.readouterr()
    assert rc_bad == ExitCode.INVALID_ARGS
    assert "forbidden" in captured.err


def test_rotation_plan_redaction(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--redact transforms hosts and paths in rotation plan outputs."""
    pub_path = FIXTURES_DIR / "id_ed25519.pub"
    keygen = PublicKeyInspector()
    e_fingerprint = keygen.fingerprint(pub_path.read_text()).fingerprint

    for mode in ("hosts", "paths", "all"):
        rc = main(
            [
                "rotation-plan",
                e_fingerprint,
                "--format",
                "json",
                "--no-agent",
                "--ssh-dir",
                str(FIXTURES_DIR),
                "--config",
                str(FIXTURES_DIR / "config"),
                "--redact",
                mode,
            ]
        )
        captured = capsys.readouterr()
        assert rc == ExitCode.OK
        data = json.loads(captured.out)
        if mode in ("hosts", "all"):
            for ha in data["host_aliases"]:
                assert "gh" not in ha["patterns"]
                assert any(p.startswith("host-") for p in ha["patterns"])
        if mode in ("paths", "all"):
            for lr in data["local_references"]:
                assert str(REPO_ROOT) not in lr["path"]
                assert lr["path"].startswith("~/.../")


# --- Review findings (machine review #706) -------------------------------------------------

_FP_A = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
_FP_B = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
_CFG = "/h/.ssh/config"


def _host(
    alias: str,
    header_line: int,
    identity_refs: tuple[str, ...],
    resolved: tuple[str, ...],
    source_file: str = _CFG,
) -> HostBinding:
    return HostBinding(
        patterns=(alias,),
        hostname=None,
        user=None,
        identity_references=identity_refs,
        resolved_fingerprints=resolved,
        identities_only=None,
        source_file=source_file,
        source_line=header_line,
        confidence=Confidence.CERTAIN if resolved else Confidence.UNRESOLVED,
    )


def _cfg_ref(path: str, line: int, source_file: str = _CFG) -> LocalReference:
    return LocalReference(
        kind=LocalReferenceKind.CONFIG_IDENTITY,
        path=path,
        source_file=source_file,
        source_line=line,
        resolution=Resolution.RESOLVED,
    )


def _snapshot(
    *,
    config_lines: Sequence[int] = (),
    host_bindings: Sequence[HostBinding] = (),
    sources: Sequence[SourceCoverage] = (),
    unresolved: Sequence[UnresolvedItem] = (),
) -> ScanSnapshot:
    pub = LocalReference(
        kind=LocalReferenceKind.PUBLIC_KEY,
        path="/h/.ssh/id_ed25519.pub",
        source_file=None,
        source_line=None,
        resolution=Resolution.RESOLVED,
    )
    refs = (pub, *(_cfg_ref("/h/.ssh/id_ed25519", line) for line in config_lines))
    ident = Identity(
        fingerprint=_FP_A,
        algorithm="ED25519",
        bits_or_curve="256",
        local_references=refs,
    )
    return ScanSnapshot(
        scan_id="t",
        started_at="2026-09-28T00:00:00Z",
        completed_at="2026-09-28T00:00:00Z",
        platform=Platform.LINUX,
        sources=tuple(sources),
        identities=(ident,),
        host_bindings=tuple(host_bindings),
        unresolved=tuple(unresolved),
    )


def test_host_alias_of_other_key_with_same_basename_is_not_listed() -> None:
    """Finding cacf9bcf1aadd1ed: stem fallback only for hosts with unresolved fingerprints."""
    snapshot = _snapshot(
        config_lines=(3,),
        host_bindings=(
            _host("good", 1, ("~/.ssh/id_ed25519",), (_FP_A,)),
            _host("other", 5, ("/work/id_ed25519",), (_FP_B,)),
            _host("unknown-key", 9, ("~/.ssh/id_ed25519",), ()),
        ),
    )
    plan = build_rotation_plan(snapshot, _FP_A)
    aliases = [ha.alias for ha in plan.host_aliases]
    assert "other" not in aliases, aliases
    assert aliases == ["good", "unknown-key"]


def test_each_host_alias_reports_identityfile_line_of_its_own_block() -> None:
    """Finding 271a878d0151a53a: location is the IdentityFile line of THIS Host block."""
    # 1 Host good / 3 IdentityFile ; 5 Host also-good / 7 IdentityFile
    snapshot = _snapshot(
        config_lines=(3, 7),
        host_bindings=(
            _host("good", 1, ("~/.ssh/id_ed25519",), (_FP_A,)),
            _host("also-good", 5, ("~/.ssh/id_ed25519",), (_FP_A,)),
        ),
    )
    plan = build_rotation_plan(snapshot, _FP_A)
    locations = {ha.alias: ha.location for ha in plan.host_aliases}
    assert locations == {"good": "config:3", "also-good": "config:7"}


def test_failed_agent_or_github_query_is_unknown_not_absent() -> None:
    """Finding 80b8195962f14b75: a failed source is unknown presence, not absence."""
    failed = (CoverageState.TIMEOUT, CoverageState.UNAVAILABLE, CoverageState.MALFORMED)
    for state in failed:
        snapshot = _snapshot(
            sources=(
                SourceCoverage(source="agent", state=state, required=False),
                SourceCoverage(source="github", state=state, required=False),
            )
        )
        plan = build_rotation_plan(snapshot, _FP_A)
        assert plan.agent_and_github.agent_status == f"unknown ({state.value})"
        assert plan.agent_and_github.github_status == f"unknown ({state.value})"
        for out in (render_plan_markdown(plan), render_plan_terminal(plan)):
            assert "not present" not in out
            assert "none registered" not in out
        assert f"agent: {state.value}" in plan.unknowns
        assert f"github: {state.value}" in plan.unknowns

    # A successful query that found nothing is still known absence.
    for state in (CoverageState.AVAILABLE, CoverageState.EMPTY):
        snapshot = _snapshot(
            sources=(
                SourceCoverage(source="agent", state=state, required=False),
                SourceCoverage(source="github", state=state, required=False),
            )
        )
        plan = build_rotation_plan(snapshot, _FP_A)
        assert plan.agent_and_github.agent_status == "not present"
        assert plan.agent_and_github.github_status == "none registered"


def test_only_include_cycle_is_described_as_a_cycle() -> None:
    """Finding 14c1f449843fb41f: cycle wording only for kind=include_cycle."""
    snapshot = _snapshot(
        unresolved=(
            UnresolvedItem(
                kind="include_missing", detail="nope.conf", source_file=_CFG, source_line=4
            ),
            UnresolvedItem(
                kind="include_depth_exceeded", detail=_CFG, source_file=_CFG, source_line=6
            ),
            UnresolvedItem(kind="include_cycle", detail="a.conf", source_file=_CFG, source_line=8),
        )
    )
    unknowns = build_rotation_plan(snapshot, _FP_A).unknowns
    by_line = {line: next(u for u in unknowns if f"config:{line}" in u) for line in (4, 6, 8)}
    assert "cycle" not in by_line[4]
    assert "missing" in by_line[4]
    assert "cycle" not in by_line[6]
    assert "depth" in by_line[6]
    assert "Include cycle" in by_line[8]


def test_include_item_with_match_in_detail_is_not_a_match_directive() -> None:
    """Finding 733684454a30503d: classify by kind only, never by substrings of detail.

    The positive Match case (kind=unsupported_match) is pinned by AC-4 on the real fixture.
    """
    details = ("mismatch.conf", "matching.conf", "/h/.ssh/conf.d/match.conf")
    snapshot = _snapshot(
        unresolved=tuple(
            UnresolvedItem(kind="include_missing", detail=d, source_file=_CFG, source_line=line)
            for line, d in enumerate(details, start=2)
        )
    )
    unknowns = build_rotation_plan(snapshot, _FP_A).unknowns
    for line in (2, 3, 4):
        entry = next(u for u in unknowns if f"config:{line}" in u)
        assert "Match" not in entry, entry
        assert entry.startswith(f"unresolved Include directive at config:{line}"), entry
