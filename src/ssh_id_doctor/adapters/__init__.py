"""Adapters for external registries and services (sdd-spec §8.1)."""

from __future__ import annotations

from ssh_id_doctor.adapters.github import (
    DEFAULT_MAX_OUTPUT,
    DEFAULT_TIMEOUT,
    GitHubAdapter,
    GitHubRegistryAdapter,
    GitHubResult,
    GitHubState,
    RegistryResult,
    RegistryState,
)

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
