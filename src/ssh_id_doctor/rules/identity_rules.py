"""Identity rules (ID001, ID002, LAB001)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ssh_id_doctor.rules import Rule

RULES: list[Rule] = []
