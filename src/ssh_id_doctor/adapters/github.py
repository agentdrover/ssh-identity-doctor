"""FR-006 (sdd-spec §7, §10 SEC-002/SEC-004/SEC-005, §12): GitHub key registry adapter.

:class:`GitHubRegistryAdapter` queries the user's registered SSH keys on
GitHub via the official GitHub CLI (``gh``) through the audited subprocess
runner :mod:`ssh_id_doctor.process`. It turns each reported public key into a
canonical :class:`RegistryBinding` using
:class:`ssh_id_doctor.inspectors.keygen.PublicKeyInspector`.

Security invariants:
- **SEC-005 (no token extraction):** Authentication is reused exclusively
  through the ambient ``gh`` configuration in ``HOME``. The adapter never calls
  ``gh auth token``, never passes ``--show-token``, never reads credentials
  files, and never stores or echoes token material. Raw output from ``gh`` is
  never placed into diagnostic detail strings.
- **SEC-002/SEC-006 (read-only subprocesses):** Every subprocess call is
  strictly read-only (``gh auth status`` and ``gh api --paginate --method GET``).
  Mutating operations (POST, PUT, PATCH, DELETE, ``gh ssh-key``) are forbidden.
- **Degradation to unresolved:** If ``gh`` is missing, not authenticated, times
  out, returns an API error, or produces malformed output, the adapter yields
  an unresolved result rather than crashing the scan.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from ssh_id_doctor import process
from ssh_id_doctor.domain import CoverageState, RegistryBinding, SourceCoverage
from ssh_id_doctor.inspectors import Unresolved
from ssh_id_doctor.inspectors.keygen import KeyInfo, PublicKeyInspector
from ssh_id_doctor.process import ProcessStatus

DEFAULT_TIMEOUT: float = 10.0
"""Seconds. gh network calls may take several seconds."""

DEFAULT_MAX_OUTPUT: int = 1_048_576
"""Bytes (1 MiB). Bounded buffer for paginated registry responses."""


class RegistryState(StrEnum):
    """States of the GitHub registry source (sdd-spec FR-006, §12)."""

    AVAILABLE = "available"
    GH_MISSING = "gh_missing"
    NOT_AUTHENTICATED = "not_authenticated"
    TIMEOUT = "timeout"
    MALFORMED_OUTPUT = "malformed_output"
    API_ERROR = "api_error"


_STATE_TO_COVERAGE: dict[RegistryState, CoverageState] = {
    RegistryState.AVAILABLE: CoverageState.AVAILABLE,
    RegistryState.GH_MISSING: CoverageState.UNAVAILABLE,
    RegistryState.NOT_AUTHENTICATED: CoverageState.UNAVAILABLE,
    RegistryState.TIMEOUT: CoverageState.TIMEOUT,
    RegistryState.MALFORMED_OUTPUT: CoverageState.MALFORMED,
    RegistryState.API_ERROR: CoverageState.UNAVAILABLE,
}


@dataclass(frozen=True, slots=True)
class RegistryResult:
    """Result of querying the GitHub SSH key registry via gh (sdd-spec FR-006)."""

    state: RegistryState
    bindings: tuple[RegistryBinding, ...] = ()
    unresolved: tuple[Unresolved, ...] = ()
    coverage: SourceCoverage | None = None
    detail: str = ""

    def __post_init__(self) -> None:
        if self.coverage is None:
            cov = SourceCoverage(
                source="github",
                state=_STATE_TO_COVERAGE.get(self.state, CoverageState.UNAVAILABLE),
                required=False,
                detail=self.detail,
            )
            object.__setattr__(self, "coverage", cov)

    def as_coverage(self) -> SourceCoverage:
        if self.coverage is not None:
            return self.coverage
        return SourceCoverage(
            source="github",
            state=_STATE_TO_COVERAGE.get(self.state, CoverageState.UNAVAILABLE),
            required=False,
            detail=self.detail,
        )

    @property
    def keys(self) -> tuple[RegistryBinding, ...]:
        return self.bindings

    @property
    def registry_bindings(self) -> tuple[RegistryBinding, ...]:
        return self.bindings

    def __iter__(self) -> Iterator[RegistryBinding]:
        return iter(self.bindings)

    def __len__(self) -> int:
        return len(self.bindings)


def _parse_json_records(stdout: bytes) -> list[dict[str, Any]]:
    """Parse JSON records from gh api stdout, handling pagination streams.

    gh api --paginate prints separate JSON arrays for each page. We support
    single arrays, multiple concatenated arrays, and slurped outer arrays.
    """
    text = stdout.decode("utf-8", errors="replace").strip()
    if not text:
        return []
    decoder = json.JSONDecoder()
    pos = 0
    records: list[dict[str, Any]] = []
    length = len(text)
    while pos < length:
        while pos < length and text[pos].isspace():
            pos += 1
        if pos >= length:
            break
        obj, end_pos = decoder.raw_decode(text, pos)
        pos = end_pos
        if isinstance(obj, list):
            for item in obj:
                if isinstance(item, list):
                    for sub_item in item:
                        if not isinstance(sub_item, dict):
                            raise ValueError(
                                f"expected dict in key list, got {type(sub_item).__name__}"
                            )
                        records.append(sub_item)
                elif isinstance(item, dict):
                    records.append(item)
                else:
                    raise ValueError(f"expected dict in key list, got {type(item).__name__}")
        elif isinstance(obj, dict):
            records.append(obj)
        else:
            raise ValueError(f"expected array or object from gh api, got {type(obj).__name__}")
    return records


class GitHubRegistryAdapter:
    """Inspects SSH keys registered on GitHub via the gh CLI (FR-006)."""

    def __init__(self, keygen: PublicKeyInspector | None = None) -> None:
        self._keygen = keygen if keygen is not None else PublicKeyInspector()

    def list_keys(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        *,
        max_output: int = DEFAULT_MAX_OUTPUT,
    ) -> RegistryResult:
        # Step 1: Session check via gh auth status (SEC-005: never reading or logging tokens)
        auth_result = process.run(
            ["gh", "auth", "status"],
            timeout=timeout,
            max_output=max_output,
        )

        if auth_result.status is ProcessStatus.NOT_FOUND:
            return RegistryResult(
                state=RegistryState.GH_MISSING,
                detail="gh is not installed or not on PATH",
            )

        if auth_result.status is ProcessStatus.NOT_EXECUTABLE:
            return RegistryResult(
                state=RegistryState.GH_MISSING,
                detail="gh on PATH is not executable",
            )

        if auth_result.status is ProcessStatus.TIMEOUT:
            return RegistryResult(
                state=RegistryState.TIMEOUT,
                detail="gh auth status timed out",
            )

        if auth_result.status is ProcessStatus.NONZERO:
            return RegistryResult(
                state=RegistryState.NOT_AUTHENTICATED,
                detail="gh is not authenticated",
            )

        # Step 2: Query public keys via gh api GET user/keys with pagination
        api_result = process.run(
            ["gh", "api", "--paginate", "--method", "GET", "user/keys"],
            timeout=timeout,
            max_output=max_output,
        )

        if api_result.status is ProcessStatus.NOT_FOUND:
            return RegistryResult(
                state=RegistryState.GH_MISSING,
                detail="gh is not installed or not on PATH",
            )

        if api_result.status is ProcessStatus.NOT_EXECUTABLE:
            return RegistryResult(
                state=RegistryState.GH_MISSING,
                detail="gh on PATH is not executable",
            )

        if api_result.status is ProcessStatus.TIMEOUT:
            return RegistryResult(
                state=RegistryState.TIMEOUT,
                detail="gh api timed out",
            )

        if api_result.status is ProcessStatus.NONZERO:
            return RegistryResult(
                state=RegistryState.API_ERROR,
                detail=f"gh api failed with exit code {api_result.returncode}",
            )

        # Step 3: Parse JSON records
        try:
            records = _parse_json_records(api_result.stdout)
        except (json.JSONDecodeError, ValueError):
            return RegistryResult(
                state=RegistryState.MALFORMED_OUTPUT,
                detail="malformed output from gh api",
            )

        # Step 4: Fingerprint keys locally via PublicKeyInspector
        bindings: list[RegistryBinding] = []
        unresolved: list[Unresolved] = []

        for record in records:
            key_text = record.get("key")
            if not isinstance(key_text, str) or not key_text.strip():
                unresolved.append(
                    Unresolved(reason="invalid_public_key", detail="missing public key text")
                )
                continue

            info = self._keygen.fingerprint(key_text.strip(), timeout=timeout)
            if isinstance(info, KeyInfo):
                raw_id = record.get("id")
                key_id = str(raw_id) if raw_id is not None else None
                title = record.get("title")
                title_str = str(title) if title is not None else None
                created_at = record.get("created_at")
                created_at_str = str(created_at) if created_at is not None else None

                bindings.append(
                    RegistryBinding(
                        registry="github",
                        fingerprint=info.fingerprint,
                        title=title_str,
                        key_id=key_id,
                        created_at=created_at_str,
                    )
                )
            elif isinstance(info, Unresolved):
                unresolved.append(info)

        if records and not bindings:
            return RegistryResult(
                state=RegistryState.MALFORMED_OUTPUT,
                bindings=(),
                unresolved=tuple(unresolved),
                detail="malformed output from gh api",
            )

        detail = f"{len(bindings)} keys loaded from GitHub"
        if api_result.truncated:
            detail = f"{detail} (truncated)"

        return RegistryResult(
            state=RegistryState.AVAILABLE,
            bindings=tuple(bindings),
            unresolved=tuple(unresolved),
            detail=detail,
        )


GitHubAdapter = GitHubRegistryAdapter
GitHubResult = RegistryResult
GitHubState = RegistryState

__all__ = [
    "DEFAULT_MAX_OUTPUT",
    "DEFAULT_TIMEOUT",
    "GitHubAdapter",
    "GitHubRegistryAdapter",
    "GitHubResult",
    "GitHubState",
    "RegistryResult",
    "RegistryState",
]
