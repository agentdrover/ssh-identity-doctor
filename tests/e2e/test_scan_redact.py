"""E2E redaction tests (AC-3, AC-4)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

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
