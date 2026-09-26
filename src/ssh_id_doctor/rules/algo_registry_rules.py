"""Algorithm and registry rules (ALG001, REG001)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ssh_id_doctor.rules import Rule

RULES: list[Rule] = []
