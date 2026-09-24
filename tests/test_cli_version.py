"""AC-1: `ssh-id-doctor version` prints the package version and exits 0."""

from __future__ import annotations

import tomllib
from importlib.metadata import entry_points, version
from pathlib import Path

import pytest

from ssh_id_doctor.cli import main

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_version_prints_package_version_and_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    declared = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["version"]
    assert version("ssh-id-doctor") == declared

    scripts = {ep.name: ep.value for ep in entry_points(group="console_scripts")}
    assert scripts.get("ssh-id-doctor") == "ssh_id_doctor.cli:main"

    code = main(["version"])

    out = capsys.readouterr().out
    assert code == 0
    assert out.strip() == f"ssh-id-doctor {declared}"
