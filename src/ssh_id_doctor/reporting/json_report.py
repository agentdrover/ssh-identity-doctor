"""FR-010 (sdd-spec §7.1-7.5): JSON snapshot renderer.

Serializes a ScanSnapshot according to schema_version "1.0".
Ensures deterministic key order (sort_keys=True) and ordered findings/identities.
Never includes private-key custody material or raw file contents (SEC-001).
"""

from __future__ import annotations

import json
from dataclasses import asdict
from enum import Enum
from typing import Any

from ssh_id_doctor.domain import ScanSnapshot
from ssh_id_doctor.reporting.ordering import sort_findings, sort_identities


def _custom_serializer(obj: Any) -> Any:
    if isinstance(obj, Enum):
        return obj.value
    raise TypeError(f"Type {type(obj)} not serializable")


def _to_serializable(obj: Any) -> Any:
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, (list, tuple)):
        return [_to_serializable(item) for item in obj]
    if isinstance(obj, dict):
        return {k: _to_serializable(v) for k, v in obj.items()}
    return obj


def render_json(snapshot: ScanSnapshot, *, indent: int = 2) -> str:
    """Render a ScanSnapshot as a deterministic JSON string conforming to schema 1.0."""
    sorted_snapshot_findings = sort_findings(snapshot.findings)
    sorted_snapshot_identities = sort_identities(snapshot.identities)

    # Convert snapshot dataclass to dict
    platform_val = (
        snapshot.platform.value if isinstance(snapshot.platform, Enum) else snapshot.platform
    )
    data: dict[str, Any] = {
        "schema_version": snapshot.schema_version,
        "scan_id": snapshot.scan_id,
        "started_at": snapshot.started_at,
        "completed_at": snapshot.completed_at,
        "platform": platform_val,
        "sources": [_to_serializable(asdict(s)) for s in snapshot.sources],
        "identities": [_to_serializable(asdict(i)) for i in sorted_snapshot_identities],
        "host_bindings": [_to_serializable(asdict(hb)) for hb in snapshot.host_bindings],
        "findings": [_to_serializable(asdict(f)) for f in sorted_snapshot_findings],
        "local_references": [_to_serializable(asdict(lr)) for lr in snapshot.local_references],
        "unresolved": [_to_serializable(asdict(u)) for u in snapshot.unresolved],
    }

    return json.dumps(data, indent=indent, sort_keys=True, ensure_ascii=False)


__all__ = [
    "render_json",
]
