"""SSH Identity Doctor: a local, read-only SSH identity inventory CLI."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("ssh-id-doctor")
except PackageNotFoundError:  # pragma: no cover - running from an uninstalled tree
    __version__ = "0+unknown"

__all__ = ["__version__"]
