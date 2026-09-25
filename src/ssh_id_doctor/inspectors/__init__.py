"""Shared inspector types, sdd-spec §12.

An inspector resolves one piece of local evidence, usually by calling a
required external program through :mod:`ssh_id_doctor.process`. Invalid input
material is reported as :class:`Unresolved` (the scan continues); the
required program itself being unusable — missing, not executable, or hung —
is a :class:`RequiredSourceError` (exit 2, §5.3), because without it no
identity in the scan can be trusted.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Unresolved:
    """One source item that could not be resolved; the scan still continues.

    ``reason`` is a short stable code (e.g. ``invalid_public_key``); ``detail``
    is free text for diagnostics and never carries key material.
    """

    reason: str
    detail: str = ""


class RequiredSourceError(RuntimeError):
    """A required external source could not be used at all (sdd-spec §12).

    The message names the failure only (missing, not executable, timed out);
    it never contains key material.
    """


__all__ = ["RequiredSourceError", "Unresolved"]
