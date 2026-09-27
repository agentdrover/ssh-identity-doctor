"""Reporting module for SSH Identity Doctor (sdd-spec FR-010).

Provides snapshot serialization and formatting with deterministic ordering and
schema validation.
"""

from __future__ import annotations

from ssh_id_doctor.reporting.json_report import render_json
from ssh_id_doctor.reporting.ordering import sort_findings, sort_identities

__all__ = [
    "render_json",
    "sort_findings",
    "sort_identities",
]
