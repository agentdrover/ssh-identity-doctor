"""Process exit codes, sdd-spec §5.3."""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """The only exit codes the CLI may return."""

    OK = 0
    """Scan completed; no execution failure. Findings may exist."""
    INVALID_ARGS = 1
    """Invalid arguments or configuration."""
    REQUIRED_SCAN_FAILED = 2
    """Required local scan failed."""
    STRICT_FINDINGS = 3
    """`--strict` was used and an error-severity finding exists."""
    REPORT_WRITE_FAILED = 4
    """Report could not be written."""
