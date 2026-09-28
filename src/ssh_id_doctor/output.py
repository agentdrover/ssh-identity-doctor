"""SEC-003 / sdd-spec §5.2, §12: Safe atomic output writing.

Writes report text to a file atomically via a temporary file in the same directory,
sets permissions to 0600 (owner read/write only), and replaces the destination.
Never truncates or damages an existing report on failure.
Refuses writing inside ssh_dir.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from ssh_id_doctor.exit_codes import ExitCode

REPORT_MODE = 0o600


class OutputWriteError(Exception):
    """Raised when writing the report to the destination path fails."""


def is_within_dir(candidate: Path, parent: Path) -> bool:
    """Check if candidate path is within parent directory."""
    try:
        cand_real = os.path.realpath(candidate)
        parent_real = os.path.realpath(parent)
        return cand_real == parent_real or cand_real.startswith(parent_real.rstrip(os.sep) + os.sep)
    except OSError:
        return False


def validate_output_path(output_path: str | Path, ssh_dir: str | Path) -> Path:
    """Validate output path. Refuses writing inside ssh_dir with exit 1."""
    dest = Path(output_path).resolve()
    ssh_dir_path = Path(ssh_dir).resolve()
    if is_within_dir(dest, ssh_dir_path):
        raise ValueError(f"writing report inside ssh directory ({ssh_dir}) is forbidden")
    return dest


def write_report_atomically(content: str, destination: str | Path) -> None:
    """Write content to destination path atomically with mode 0600.

    Creates a temporary file in destination's parent directory, writes content,
    sets 0600 permissions, and atomically replaces destination via os.replace.
    On any failure, temporary file is cleaned up and OutputWriteError is raised.
    """
    dest = Path(destination).resolve()
    parent = dest.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise OutputWriteError(f"cannot create parent directory {parent}: {exc}") from exc

    fd: int | None = None
    tmp_path: str | None = None
    try:
        fd, tmp_path = tempfile.mkstemp(
            prefix=".report-tmp-",
            dir=str(parent),
            text=True,
        )
        os.fchmod(fd, REPORT_MODE)
        with open(fd, "w", encoding="utf-8") as f:
            f.write(content)
        fd = None  # open() took ownership and closed it
        os.replace(tmp_path, dest)
    except OSError as exc:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        raise OutputWriteError(f"failed to write report to {dest}: {exc}") from exc


__all__ = [
    "ExitCode",
    "OutputWriteError",
    "is_within_dir",
    "validate_output_path",
    "write_report_atomically",
]
