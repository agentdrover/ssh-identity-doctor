"""E2E redaction tests (AC-3, AC-4)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from conftest import OpenGuard
from ssh_id_doctor.cli import main
from ssh_id_doctor.exit_codes import ExitCode

_KHS_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "known_hosts" / "khs_findings.txt"
_FIXTURE_HOST_NAMES = (
    "exposed-plain.example.com",
    "bridge.example.com",
    "weak-dss.example.com",
    "revoked-host.example.com",
    "legacy-rsa.example.com",
)


def test_redact_all_consistent_across_formats(
    home_basic: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC-3: Given home_basic with host 'client-acme.internal' and path '.ssh/acme/id_ed25519.pub'.

    When scan --redact all in terminal, md, and json formats,
    Then neither format contains 'client-acme', 'acme/', or username from HOME;
    same aliases (host-1 etc.) across all three formats; fingerprints preserved.
    """
    ssh_dir = home_basic / ".ssh"

    # Add acme directory and key
    acme_dir = ssh_dir / "acme"
    acme_dir.mkdir(exist_ok=True)
    orig_pub = (ssh_dir / "id_ed25519.pub").read_text()
    (acme_dir / "id_ed25519.pub").write_text(orig_pub)

    # Append host to config
    config_path = ssh_dir / "config"
    with open(config_path, "a", encoding="utf-8") as f:
        f.write(
            "\nHost client-acme.internal\n"
            "    IdentityFile ~/.ssh/acme/id_ed25519\n"
            "    IdentityFile ~/.ssh/missing_client_acme_key\n"
        )

    user_name = home_basic.name

    outputs: dict[str, str] = {}
    for fmt in ["terminal", "md", "json"]:
        rc = main(
            [
                "scan",
                "--format",
                fmt,
                "--no-agent",
                "--redact",
                "all",
                "--ssh-dir",
                str(ssh_dir),
                "--config",
                str(config_path),
            ]
        )
        assert rc == ExitCode.OK
        captured = capsys.readouterr()
        out = captured.out
        outputs[fmt] = out

        # Check absence of sensitive strings
        assert "client-acme" not in out
        assert "acme/" not in out
        if user_name:
            assert f"/{user_name}" not in out
            assert f"~{user_name}" not in out

        # Fingerprints must be preserved
        assert "SHA256:+92RsVKGXDDG2XlZkoQSG2sRjqnoPwysscnoHoCIdMk" in out

    # Host patterns from host_bindings and findings
    alias_re = re.compile(r"\bhost-\d+\b")
    md_hosts = set(alias_re.findall(outputs["md"]))
    json_hosts = set(alias_re.findall(outputs["json"]))

    assert md_hosts == json_hosts
    assert len(md_hosts) > 0
    # In terminal output, host aliases may appear if host bindings or findings display them;
    # verify that any alias appearing in terminal is in md/json set.
    term_hosts = set(alias_re.findall(outputs["terminal"]))
    assert term_hosts <= md_hosts


def test_redact_known_hosts_names(
    fake_home: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC-4: Given a known_hosts fixture whose host names (including the
    '[bridge.example.com]:2222' form) occur only in known_hosts, never in config.

    When scan --redact hosts, --redact all in terminal/md/json,
    Then no fixture host name appears in any output.
    When scan --redact paths in json,
    Then the known_hosts path is masked in both Finding evidence and unresolved.
    """
    ssh_dir = fake_home / ".ssh"
    config_path = ssh_dir / "config"
    known_hosts_path = ssh_dir / "known_hosts"
    known_hosts_path.write_text(_KHS_FIXTURE.read_text())
    # fake_home's default config has 'Host example', a substring of the fixture's
    # '*.example.com' host names; an empty config keeps this test about
    # known_hosts redaction only, not an incidental collision with that pattern.
    config_path.write_text("")

    base_args = [
        "--no-agent",
        "--ssh-dir",
        str(ssh_dir),
        "--config",
        str(config_path),
    ]

    # Sanity: unredacted output actually shows the bracketed host, so the
    # redaction check below is meaningful rather than vacuous.
    rc_plain = main(["scan", "--format", "json", *base_args])
    assert rc_plain == ExitCode.OK
    plain_out = capsys.readouterr().out
    assert "[bridge.example.com]:2222" in plain_out
    data_plain = json.loads(plain_out)
    khs002 = next(f for f in data_plain["findings"] if f["rule_id"] == "KHS002")
    assert "[bridge.example.com]:2222" in khs002["title"]

    for mode in ("hosts", "all"):
        for fmt in ("terminal", "md", "json"):
            rc = main(["scan", "--format", fmt, "--redact", mode, *base_args])
            assert rc == ExitCode.OK
            out = capsys.readouterr().out
            assert "[bridge.example.com]:2222" not in out
            for host in _FIXTURE_HOST_NAMES:
                assert host not in out, f"{host!r} leaked in --redact {mode} ({fmt})"

    # --redact paths: the known_hosts path is masked in evidence and unresolved.
    rc_paths = main(["scan", "--format", "json", "--redact", "paths", *base_args])
    assert rc_paths == ExitCode.OK
    data_paths = json.loads(capsys.readouterr().out)

    raw_path = str(known_hosts_path)
    assert raw_path not in json.dumps(data_paths)

    khs_with_evidence = [
        f for f in data_paths["findings"] if f["rule_id"].startswith("KHS") and f["evidence"]
    ]
    assert khs_with_evidence
    for finding in khs_with_evidence:
        for ev in finding["evidence"]:
            assert raw_path not in ev["source"]
            assert ev["source"].startswith("~/")

    assert data_paths["unresolved"]
    for item in data_paths["unresolved"]:
        assert raw_path not in item["source_file"]
        assert item["source_file"].startswith("~/")


_KEY_BLOB_A = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
_KEY_BLOB_B = "AAAAC3NzaC1lZDI1NTE5AAAAIAMKERgfJi00O0JJUFdeZWxzeoGIj5adpKuyucDHztXc"
_KEY_BLOB_C = "AAAAC3NzaC1lZDI1NTE5AAAAIMwKQfiW86Yu6eXH3bYIk94OnoidaKLausFeWb3nT/iL"
_HASHED_TOKEN = "|1|QUFBQUFBQUFBQUFBQUFBQUFBQUE=|QkJCQkJCQkJCQkJCQkJCQkJCQkI="  # noqa: S105


def test_redact_known_hosts_port_form_shares_host_alias(
    fake_home: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC-1 (#1868): a ssh config Host and the same host's known_hosts
    '[host]:port' form must share one pseudonym in a masked report, and the
    host name must not leak through either form, in any format.

    Given ssh config 'Host example.com' and known_hosts with two
    '[example.com]:2222' lines (different fingerprints, so KHS002 fires and
    names the host in its title/affected_hosts) plus one hashed '|1|' line,
    when scanning with --redact hosts/all in terminal/md/json,
    then 'example.com' never leaks, and the '[host]:port' alias used in the
    KHS002 finding is the same alias as the ssh config Host binding's.
    """
    ssh_dir = fake_home / ".ssh"
    config_path = ssh_dir / "config"
    known_hosts_path = ssh_dir / "known_hosts"

    config_path.write_text("Host example.com\n    IdentityFile ~/.ssh/id_canary\n")
    known_hosts_path.write_text(
        f"[example.com]:2222 ssh-ed25519 {_KEY_BLOB_A}\n"
        f"[example.com]:2222 ssh-ed25519 {_KEY_BLOB_B}\n"
        f"{_HASHED_TOKEN} ssh-ed25519 {_KEY_BLOB_C}\n"
    )

    base_args = [
        "--no-agent",
        "--ssh-dir",
        str(ssh_dir),
        "--config",
        str(config_path),
    ]

    for mode in ("hosts", "all"):
        for fmt in ("terminal", "md", "json"):
            rc = main(["scan", "--format", fmt, "--redact", mode, *base_args])
            assert rc == ExitCode.OK
            out = capsys.readouterr().out
            assert "example.com" not in out
            assert "[example.com]:2222" not in out

    rc_json = main(["scan", "--format", "json", "--redact", "all", *base_args])
    assert rc_json == ExitCode.OK
    data = json.loads(capsys.readouterr().out)

    host_binding = next(hb for hb in data["host_bindings"] if hb["identity_references"])
    (config_alias,) = host_binding["patterns"]
    assert re.fullmatch(r"host-\d+", config_alias)

    khs002 = next(f for f in data["findings"] if f["rule_id"] == "KHS002")
    match = re.fullmatch(r"\[(host-\d+)\]:2222", khs002["affected_hosts"][0])
    assert match is not None
    assert match.group(1) == config_alias
    assert khs002["title"] == f"Conflicting known_hosts key for [{config_alias}]:2222 (ssh-ed25519)"


def test_redact_config_host_pattern_not_parsed_as_known_hosts_token(
    fake_home: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Regression (#1868 review finding 1): a CFG001/AGT002 finding's
    affected_hosts holds raw ssh config Host patterns, not known_hosts
    tokens -- a '!'-negated pattern there must be aliased as the whole
    string (like HostBinding.patterns), not have its '!' stripped the way a
    known_hosts negation would be.

    Given 'Host *.example.com !private.example.com' with a missing
    IdentityFile (fires CFG001, affected_hosts = the Host block's patterns),
    when scanning with --redact all,
    then the host_bindings.patterns alias and the CFG001 finding's
    affected_hosts alias agree for both patterns, and manual_remediation
    (which embeds affected_hosts[0] as free text) uses the same alias too.
    """
    ssh_dir = fake_home / ".ssh"
    config_path = ssh_dir / "config"
    config_path.write_text(
        "Host *.example.com !private.example.com\n    IdentityFile ~/.ssh/missing_key\n"
    )

    rc = main(
        [
            "scan",
            "--format",
            "json",
            "--no-agent",
            "--redact",
            "all",
            "--ssh-dir",
            str(ssh_dir),
            "--config",
            str(config_path),
        ]
    )
    assert rc == ExitCode.OK
    out = capsys.readouterr().out
    assert "example.com" not in out
    data = json.loads(out)

    host_binding = next(hb for hb in data["host_bindings"] if len(hb["patterns"]) == 2)
    glob_alias, negated_alias = host_binding["patterns"]
    assert re.fullmatch(r"host-\d+", glob_alias)
    assert re.fullmatch(r"host-\d+", negated_alias)
    assert glob_alias != negated_alias

    cfg001 = next(f for f in data["findings"] if f["rule_id"] == "CFG001")
    assert cfg001["affected_hosts"] == [glob_alias, negated_alias]
    assert any(f"ssh -G {glob_alias}" in rem for rem in cfg001["manual_remediation"])


_KEY_BLOB_HOST_SALT = "host+IKuUgBlGozMIKWLmx69tm8="
"""A valid (20-byte-decoding) known_hosts hash salt chosen so it starts with
the literal 'host' immediately followed by '+' -- i.e. with a non-word
character on both sides -- to exercise the boundary that the per-literal
substitution regex also uses for a bare registered host name."""
_HASHED_TOKEN_WITH_HOST_SALT = f"|1|{_KEY_BLOB_HOST_SALT}|QkJCQkJCQkJCQkJCQkJCQkJCQkI="


def test_redact_hashed_known_hosts_token_not_corrupted_by_unrelated_host_alias(
    fake_home: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Regression (#1868 review finding 3): a hashed '|1|...' known_hosts
    token must never be altered by text substitution, even when its
    salt/hash coincidentally contains another registered host's bare name
    as a boundary-matching substring.

    Given ssh config 'Host host' (registers alias host-1 for the bare name
    'host') and known_hosts with two identical hashed tokens whose salt
    starts with 'host+' (different key blobs, so KHS002 fires and its
    title/affected_hosts embed the raw hashed token),
    when scanning with --redact all,
    then the hashed token is byte-for-byte unchanged in both affected_hosts
    and the title -- 'host' is not replaced with 'host-1' inside it.
    """
    ssh_dir = fake_home / ".ssh"
    config_path = ssh_dir / "config"
    known_hosts_path = ssh_dir / "known_hosts"

    config_path.write_text("Host host\n    IdentityFile ~/.ssh/id_canary\n")
    known_hosts_path.write_text(
        f"{_HASHED_TOKEN_WITH_HOST_SALT} ssh-ed25519 {_KEY_BLOB_A}\n"
        f"{_HASHED_TOKEN_WITH_HOST_SALT} ssh-ed25519 {_KEY_BLOB_B}\n"
    )

    rc = main(
        [
            "scan",
            "--format",
            "json",
            "--no-agent",
            "--redact",
            "all",
            "--ssh-dir",
            str(ssh_dir),
            "--config",
            str(config_path),
        ]
    )
    assert rc == ExitCode.OK
    data = json.loads(capsys.readouterr().out)

    host_binding = next(hb for hb in data["host_bindings"] if hb["identity_references"])
    (config_alias,) = host_binding["patterns"]
    assert config_alias == "host-1"

    khs002 = next(f for f in data["findings"] if f["rule_id"] == "KHS002")
    assert khs002["affected_hosts"] == [_HASHED_TOKEN_WITH_HOST_SALT]
    assert khs002["title"] == (
        f"Conflicting known_hosts key for {_HASHED_TOKEN_WITH_HOST_SALT} (ssh-ed25519)"
    )


def test_redact_known_hosts_port_like_host_name_stays_consistent(
    fake_home: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Regression (#1868 review finding 2): a host whose name is literally a
    port-looking number must not have the port in its own '[host]:port'
    known_hosts form corrupted by a second, ambiguous substitution of the
    same literal.

    Given ssh config 'Host 2222' and known_hosts with two '[2222]:2222'
    lines (different fingerprints, so KHS002 fires),
    when scanning with --redact all,
    then the finding's title and affected_hosts both read
    '[host-N]:2222' -- the port digits are never themselves replaced with
    the host alias.
    """
    ssh_dir = fake_home / ".ssh"
    config_path = ssh_dir / "config"
    known_hosts_path = ssh_dir / "known_hosts"

    config_path.write_text("Host 2222\n    IdentityFile ~/.ssh/id_canary\n")
    known_hosts_path.write_text(
        f"[2222]:2222 ssh-ed25519 {_KEY_BLOB_A}\n[2222]:2222 ssh-ed25519 {_KEY_BLOB_B}\n"
    )

    rc = main(
        [
            "scan",
            "--format",
            "json",
            "--no-agent",
            "--redact",
            "all",
            "--ssh-dir",
            str(ssh_dir),
            "--config",
            str(config_path),
        ]
    )
    assert rc == ExitCode.OK
    data = json.loads(capsys.readouterr().out)

    host_binding = next(hb for hb in data["host_bindings"] if hb["identity_references"])
    (config_alias,) = host_binding["patterns"]
    assert re.fullmatch(r"host-\d+", config_alias)

    khs002 = next(f for f in data["findings"] if f["rule_id"] == "KHS002")
    assert khs002["affected_hosts"] == [f"[{config_alias}]:2222"]
    assert khs002["title"] == f"Conflicting known_hosts key for [{config_alias}]:2222 (ssh-ed25519)"


def test_redact_hides_host_name_inside_key_file_name(
    fake_home: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC-1 (#1908): a key named after its host must not leak the host name
    through its file *name* in a masked report, even though
    ``get_path_alias`` only hashed the full path and kept the basename as-is.

    Given ssh config 'Host bridge.example.com' with IdentityFile
    '~/.ssh/id_bridge.example.com' (missing), a second Host whose
    IdentityFile is the absolute '<ssh_dir>/archive/id_bridge.example.com'
    (missing too) -- a different full path sharing the same basename -- and
    an 'Include' of that same absolute archive path (which also resolves to
    nothing, since the file is missing and the pattern has no wildcard, so
    it becomes an 'include_missing' unresolved item naming that same path),
    when scanning with --redact all in terminal/md/json,
    then 'bridge.example.com' never leaks (not even via the file name), the
    path alias is the same alias everywhere it is rendered in the JSON --
    host_bindings, findings (evidence/title), local_references, AND
    unresolved (#1908 critic cycle 1, P2) -- including between
    HostBinding.identity_references (the raw, unexpanded value as written in
    the config) and LocalReference.path / finding evidence for the very same
    IdentityFile (the expanded absolute form) -- and the two paths that
    share a basename get two different aliases.
    """
    ssh_dir = fake_home / ".ssh"
    config_path = ssh_dir / "config"
    archive_dir = ssh_dir / "archive"
    archive_dir.mkdir()
    archive_identity_path = str(archive_dir / "id_bridge.example.com")

    config_path.write_text(
        "Host bridge.example.com\n"
        "    IdentityFile ~/.ssh/id_bridge.example.com\n"
        "Host old-bridge.example.com\n"
        f"    IdentityFile {archive_identity_path}\n"
        f"Include {archive_identity_path}\n"
    )

    base_args = [
        "--no-agent",
        "--ssh-dir",
        str(ssh_dir),
        "--config",
        str(config_path),
    ]

    outputs: dict[str, str] = {}
    for fmt in ("terminal", "md", "json"):
        rc = main(["scan", "--format", fmt, "--redact", "all", *base_args])
        assert rc == ExitCode.OK
        out = capsys.readouterr().out
        outputs[fmt] = out
        assert "bridge.example.com" not in out, f"leaked in --redact all ({fmt})"

    data = json.loads(outputs["json"])

    alias_re = re.compile(r"~/\.\.\./id_host-\d+-[0-9a-f]{8}")

    # host_bindings: two different (raw, as written in config) IdentityFile
    # paths sharing the basename "id_bridge.example.com" get two different
    # aliases, neither of which exposes the host name.
    assert len(data["host_bindings"]) == 2
    hb_alias_by_source_line = {
        hb["source_line"]: hb["identity_references"][0] for hb in data["host_bindings"]
    }
    assert len(set(hb_alias_by_source_line.values())) == 2
    for alias in hb_alias_by_source_line.values():
        assert alias_re.fullmatch(alias)

    # local_references / CFG001 findings: same story for the two (expanded)
    # paths, and a given exact path string gets the *same* alias wherever it
    # is rendered -- matched here by the shared config source_line.
    local_refs_by_line = {ref["source_line"]: ref["path"] for ref in data["local_references"]}
    assert len(local_refs_by_line) == 2
    for alias in local_refs_by_line.values():
        assert alias_re.fullmatch(alias)
    assert len(set(local_refs_by_line.values())) == 2

    # The Host line (source_line N) and its IdentityFile line (N + 1) refer
    # to the very same file via two different spellings (raw vs. expanded);
    # they must resolve to the same alias (#1908 critic finding 1).
    for hb_line, alias in hb_alias_by_source_line.items():
        assert local_refs_by_line[hb_line + 1] == alias

    # CFG001 findings (one per missing IdentityFile): evidence detail and
    # title use that very same alias too (#1908 critic cycle 1, P2 -- the
    # AC's "findings" place of consistency, not just host_bindings/
    # local_references).
    cfg001_findings = [f for f in data["findings"] if f["rule_id"] == "CFG001"]
    assert len(cfg001_findings) == 2
    cfg001_by_line = {f["evidence"][0]["line"]: f for f in cfg001_findings}
    assert len(cfg001_by_line) == 2
    for hb_line, alias in hb_alias_by_source_line.items():
        finding = cfg001_by_line[hb_line + 1]
        assert finding["evidence"][0]["detail"] == alias
        assert finding["title"] == f"Unresolved IdentityFile: {alias}"

    # unresolved: the Include of the very same archive path (a non-glob
    # pattern that resolves to nothing) is reported as an 'include_missing'
    # unresolved item naming that path -- it must get that path's one alias
    # too, not a fresh one (the AC's "unresolved" place of consistency).
    archive_alias = local_refs_by_line[4]
    include_missing = [u for u in data["unresolved"] if u["kind"] == "include_missing"]
    assert len(include_missing) == 1
    assert include_missing[0]["detail"] == archive_alias


def test_redact_path_alias_not_corrupted_by_unrelated_host_named_like_alias(
    fake_home: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Regression (#1908 critic finding 2): a path alias generated by
    ``get_path_alias`` embeds a host alias in its basename (e.g. 'host-1' for
    a key named 'key-bridge.example.com'); that generated alias text must not
    be rescanned and mangled by a second, unrelated host's registration just
    because that unrelated host's own literal name happens to equal the
    already-generated alias text (e.g. a second Host literally named
    'host-1', registered as alias 'host-2').

    Given 'Host bridge.example.com' (-> alias host-1) with IdentityFile
    '~/.ssh/key-bridge.example.com' (dash-separated, so the host name is
    inside the basename), and a second, unrelated 'Host host-1' (-> alias
    host-2, since registered second),
    when scanning with --redact all,
    then the CFG001 finding for the first Host's missing IdentityFile shows
    the SAME alias in its JSON evidence/local_references (not run through
    any text substitution) and in its title/summary (run through
    redact_text_sub) -- 'host-1' embedded in the path alias is not rewritten
    to 'host-2'.
    """
    ssh_dir = fake_home / ".ssh"
    config_path = ssh_dir / "config"

    config_path.write_text(
        "Host bridge.example.com\n"
        "    IdentityFile ~/.ssh/key-bridge.example.com\n"
        "Host host-1\n"
        "    IdentityFile ~/.ssh/id_canary\n"
    )

    rc = main(
        [
            "scan",
            "--format",
            "json",
            "--no-agent",
            "--redact",
            "all",
            "--ssh-dir",
            str(ssh_dir),
            "--config",
            str(config_path),
        ]
    )
    assert rc == ExitCode.OK
    data = json.loads(capsys.readouterr().out)

    local_ref = next(ref for ref in data["local_references"] if ref["kind"] == "config_identity")
    path_alias = local_ref["path"]
    assert re.fullmatch(r"~/\.\.\./key-host-\d+-[0-9a-f]{8}", path_alias)

    cfg001 = next(f for f in data["findings"] if f["rule_id"] == "CFG001")
    assert cfg001["evidence"][0]["detail"] == path_alias
    assert cfg001["title"] == f"Unresolved IdentityFile: {path_alias}"
    assert path_alias in cfg001["summary"]
    assert cfg001["manual_remediation"][0] == f"ls -l {path_alias}"


def test_redact_path_alias_shared_for_relative_identity_file_value(
    fake_home: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Regression (#1908 critic finding, cycle 2): an IdentityFile value with
    no '~/' prefix (a bare relative filename, resolved against ssh_dir per
    references._expand, not HOME) must canonicalize to the very same alias
    as the matching, already-expanded LocalReference.path -- the earlier fix
    for the raw-vs-expanded mismatch only canonicalized the '~/...' form
    (sdd-spec #1908 AC-1), leaving this relative form unmerged (two aliases
    for one file: the host name itself still doesn't leak, but
    host_bindings.identity_references and local_references/findings.evidence
    disagree about this key's alias).

    Given 'Host bridge.example.com' with IdentityFile 'id_bridge.example.com'
    (no leading '~/' or '/', missing file) and the default --ssh-dir
    (fake_home/.ssh, so relative resolution and HOME resolution agree on the
    directory -- isolating this from the ssh_dir-only... case),
    when scanning with --redact all,
    then host_bindings.identity_references[0] equals local_references[0].path
    equals the CFG001 finding's evidence detail -- one alias everywhere.
    """
    ssh_dir = fake_home / ".ssh"
    config_path = ssh_dir / "config"
    config_path.write_text("Host bridge.example.com\n    IdentityFile id_bridge.example.com\n")

    rc = main(
        [
            "scan",
            "--format",
            "json",
            "--no-agent",
            "--redact",
            "all",
            "--ssh-dir",
            str(ssh_dir),
            "--config",
            str(config_path),
        ]
    )
    assert rc == ExitCode.OK
    out = capsys.readouterr().out
    assert "bridge.example.com" not in out
    data = json.loads(out)

    host_binding = next(hb for hb in data["host_bindings"] if hb["identity_references"])
    (id_ref_alias,) = host_binding["identity_references"]
    assert re.fullmatch(r"~/\.\.\./id_host-\d+-[0-9a-f]{8}", id_ref_alias)

    local_ref = next(ref for ref in data["local_references"] if ref["kind"] == "config_identity")
    assert local_ref["path"] == id_ref_alias

    cfg001 = next(f for f in data["findings"] if f["rule_id"] == "CFG001")
    assert cfg001["evidence"][0]["detail"] == id_ref_alias
    assert cfg001["title"] == f"Unresolved IdentityFile: {id_ref_alias}"


def test_redact_path_alias_not_merged_across_unresolved_token(
    fake_home: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Regression (#1908 critic cycle 1, P1#1): a path alias must never merge
    two paths across an unexpanded token (``${VAR}``/``%h``/etc.) just
    because ``os.path.normpath`` happens to cancel a literal ``..`` against
    the token as if it were one path segment.

    Given 'Host bridge.example.com' with IdentityFile
    '~/.ssh/id_bridge.example.com' (plain, missing) and a second Host whose
    IdentityFile is '~/.ssh/${KEY_DIR}/../id_bridge.example.com' (token-
    bearing: if KEY_DIR were e.g. 'team/prod' this would name a different
    file, so its real identity is unknown and must never be treated as
    identical to the plain path's just because naive normpath cancels
    '${KEY_DIR}/..' to nothing),
    when scanning with --redact all,
    then the two get two different aliases, and the token-bearing one is
    reported in 'unresolved' (never as a LocalReference, since
    references.py deliberately never resolves a token) with that same
    (distinct) alias in its detail.
    """
    ssh_dir = fake_home / ".ssh"
    config_path = ssh_dir / "config"
    config_path.write_text(
        "Host bridge.example.com\n"
        "    IdentityFile ~/.ssh/id_bridge.example.com\n"
        "Host token-bridge.example.com\n"
        "    IdentityFile ~/.ssh/${KEY_DIR}/../id_bridge.example.com\n"
    )

    rc = main(
        [
            "scan",
            "--format",
            "json",
            "--no-agent",
            "--redact",
            "all",
            "--ssh-dir",
            str(ssh_dir),
            "--config",
            str(config_path),
        ]
    )
    assert rc == ExitCode.OK
    data = json.loads(capsys.readouterr().out)

    alias_re = re.compile(r"~/\.\.\./id_host-\d+-[0-9a-f]{8}")
    hb_plain = next(hb for hb in data["host_bindings"] if hb["source_line"] == 1)
    hb_token = next(hb for hb in data["host_bindings"] if hb["source_line"] == 3)
    (plain_alias,) = hb_plain["identity_references"]
    (token_alias,) = hb_token["identity_references"]
    assert alias_re.fullmatch(plain_alias)
    assert alias_re.fullmatch(token_alias)
    assert plain_alias != token_alias

    assert len(data["unresolved"]) == 1
    (unresolved_item,) = data["unresolved"]
    assert unresolved_item["kind"] == "unresolved_token"
    assert unresolved_item["detail"] == token_alias


def test_redact_path_alias_shared_across_whitespace_and_quoting(
    fake_home: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Regression (#1908 critic cycle 1, P1#2): references.resolve_identity_references
    strips surrounding whitespace (and a matching pair of double quotes) from
    an IdentityFile value before expanding it; path-alias canonicalization
    must mirror that exact preprocessing, or a HostBinding's raw
    identity_references spelling disagrees with the LocalReference/finding
    evidence alias for the very same entry.

    Given two Host blocks whose IdentityFile values both name the same real
    file, one plain ('~/.ssh/id_bridge.example.com') and one with leading/
    trailing whitespace inside a quoted value ('" ~/.ssh/id_bridge.example.com "'),
    when scanning with --redact all,
    then both HostBinding.identity_references entries get the very same
    alias.
    """
    ssh_dir = fake_home / ".ssh"
    config_path = ssh_dir / "config"
    config_path.write_text(
        "Host bridge.example.com\n"
        "    IdentityFile ~/.ssh/id_bridge.example.com\n"
        "Host whitespace-bridge.example.com\n"
        '    IdentityFile " ~/.ssh/id_bridge.example.com "\n'
    )

    rc = main(
        [
            "scan",
            "--format",
            "json",
            "--no-agent",
            "--redact",
            "all",
            "--ssh-dir",
            str(ssh_dir),
            "--config",
            str(config_path),
        ]
    )
    assert rc == ExitCode.OK
    data = json.loads(capsys.readouterr().out)

    hb_plain = next(hb for hb in data["host_bindings"] if hb["source_line"] == 1)
    hb_quoted = next(hb for hb in data["host_bindings"] if hb["source_line"] == 3)
    (plain_alias,) = hb_plain["identity_references"]
    (quoted_alias,) = hb_quoted["identity_references"]
    assert re.fullmatch(r"~/\.\.\./id_host-\d+-[0-9a-f]{8}", plain_alias)
    assert quoted_alias == plain_alias


def test_redact_path_alias_not_merged_by_whitespace_in_resolved_path(
    fake_home: Path,
    open_guard: OpenGuard,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Regression (#1908 critic cycle 2, P1): path-alias canonicalization must
    strip surrounding whitespace/quoting only from a raw, unexpanded
    ssh_config value (a HostBinding.identity_references entry) -- never from
    a value that is already a resolved, absolute path (HostBinding.source_file,
    LocalReference.path, evidence source, ...). A resolved path's trailing
    space can be a real, significant character of its final path component:
    two config files literally named 'config' and 'config ' are two
    different files, and must not collapse onto one alias just because an
    unconditional ``.strip()`` would make their canonical forms equal.

    Given an ssh config 'config' that Includes a second, real file in the
    same directory literally named 'config ' (trailing space, written
    quoted so ssh_config(5) tokenizing keeps the space) -- each file defining
    one Host block -- when scanning with --redact all,
    then the two HostBinding.source_file aliases differ (AC-1: 'разные пути
    не сливаются').
    """
    ssh_dir = fake_home / ".ssh"
    config_path = ssh_dir / "config"
    included_path = ssh_dir / "config "  # trailing space: a distinct real file

    included_path.write_text("Host beta.example.com\n    IdentityFile ~/.ssh/id_beta\n")
    open_guard.allow(included_path)
    config_path.write_text(
        'Host alpha.example.com\n    IdentityFile ~/.ssh/id_alpha\nInclude "config "\n'
    )

    rc = main(
        [
            "scan",
            "--format",
            "json",
            "--no-agent",
            "--redact",
            "all",
            "--ssh-dir",
            str(ssh_dir),
            "--config",
            str(config_path),
        ]
    )
    assert rc == ExitCode.OK
    data = json.loads(capsys.readouterr().out)

    assert len(data["host_bindings"]) == 2
    source_aliases = [hb["source_file"] for hb in data["host_bindings"]]
    assert len(set(source_aliases)) == 2, "distinct files merged onto one alias"
    for alias in source_aliases:
        assert re.fullmatch(r"~/\.\.\./config ?-[0-9a-f]{8}", alias)
