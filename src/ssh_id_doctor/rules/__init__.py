"""Rule engine protocol and registry for SSH Identity Doctor.

Rules evaluate a ScanSnapshot and return a list of Finding objects.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, is_dataclass
from typing import Any, Protocol

from ssh_id_doctor.domain import Finding, ScanSnapshot
from ssh_id_doctor.rules import (
    agent_rules,
    algo_registry_rules,
    config_rules,
    identity_rules,
)


class Rule(Protocol):
    """Protocol for rules evaluating a ScanSnapshot."""

    rule_id: str

    def evaluate(self, snapshot: ScanSnapshot) -> list[Finding]:
        """Evaluate snapshot and return findings."""
        ...


_HOME_ROOTS: ContextVar[tuple[str, ...]] = ContextVar("finding_id_home_roots", default=())
"""Roots of the scanned HOME for the rules run in progress; set only by run_rules."""


@contextmanager
def _home_roots_context(home_roots: Sequence[str]) -> Iterator[None]:
    roots = {r.rstrip("/") for r in home_roots}
    roots.discard("")
    # Longest root first, so a nested spelling (realpath) wins over a shorter one.
    token = _HOME_ROOTS.set(tuple(sorted(roots, key=lambda r: (-len(r), r))))
    try:
        yield
    finally:
        _HOME_ROOTS.reset(token)


def _canonical_home_path(value: str, home_roots: Sequence[str]) -> str:
    """Rewrite a path under the scanned HOME as '~/...'; other strings stay as-is."""
    for root in home_roots:
        if value == root:
            return "~"
        if value.startswith(root + "/"):
            return "~/" + value[len(root) + 1 :]
    return value


def finding_id(
    rule_id: str,
    evidence: Sequence[Any] | None = None,
    fingerprints: Sequence[str] | None = None,
    **extra: Any,
) -> str:
    """Stable content-derived finding id (§7.5): f'{rule_id}-{sha256(canonical JSON)[:12]}'.

    Does not depend on scan_id, timestamps or the scan root: while run_rules
    evaluates, paths under the scanned HOME are hashed as '~/...', so the same
    layout under different HOMEs yields the same ids. Evidence in the Finding
    itself keeps the real paths; only the hash input is canonicalized.
    """
    home_roots = _HOME_ROOTS.get()

    def _normalize(obj: Any) -> Any:
        if is_dataclass(obj) and not isinstance(obj, type):
            return {k: _normalize(v) for k, v in asdict(obj).items()}
        if isinstance(obj, (list, tuple)):
            return [_normalize(x) for x in obj]
        if isinstance(obj, set):
            return sorted([_normalize(x) for x in obj], key=lambda x: str(x))
        if isinstance(obj, dict):
            return {str(k): _normalize(v) for k, v in sorted(obj.items())}
        if isinstance(obj, str):
            return _canonical_home_path(obj, home_roots)
        return obj

    payload: dict[str, Any] = {
        "rule_id": rule_id,
        "evidence": _normalize(list(evidence or ())),
        "fingerprints": sorted(list(fingerprints or ())),
    }
    if extra:
        payload["extra"] = _normalize(extra)

    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()[:12]
    return f"{rule_id}-{digest}"


def get_default_rules() -> list[Rule]:
    """Return all rules registered across all rule modules."""
    rules: list[Rule] = []
    for mod in (config_rules, identity_rules, agent_rules, algo_registry_rules):
        mod_rules = getattr(mod, "RULES", None)
        if isinstance(mod_rules, Iterable):
            rules.extend(mod_rules)
    return rules


def run_rules(
    snapshot: ScanSnapshot,
    rules: Sequence[Rule] | None = None,
    *,
    home_roots: Sequence[str] = (),
) -> list[Finding]:
    """Run all given rules (or default rules) against snapshot and return sorted findings.

    home_roots are the spellings of the scanned HOME (as given and resolved);
    finding ids hash paths under them as '~/...' (see finding_id).
    """
    active_rules = get_default_rules() if rules is None else list(rules)
    findings: list[Finding] = []
    with _home_roots_context(home_roots):
        for rule in active_rules:
            findings.extend(rule.evaluate(snapshot))

    findings.sort(key=lambda f: (f.severity, f.rule_id, f.id))
    return findings


__all__ = [
    "Rule",
    "finding_id",
    "get_default_rules",
    "run_rules",
]
