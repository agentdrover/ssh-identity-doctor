"""E2E redaction tests (AC-3)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from ssh_id_doctor.cli import main
from ssh_id_doctor.exit_codes import ExitCode


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
