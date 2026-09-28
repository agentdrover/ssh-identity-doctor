"""SEC-004 / SEC-005 / SEC-006: static boundaries AST checks (AC-1, AC-2).

Enforces:
1. No network module imports across src/ssh_id_doctor/**/*.py.
2. No filesystem mutation operations across src/ssh_id_doctor/**/*.py, except
   the explicitly documented exceptions in output.py (SEC-003 safe atomic report writing).
3. All literal argv with "gh" as first element:
   - after "api", must have "--method" "GET";
   - no "-X", "POST", "PUT", "PATCH", "DELETE", "ssh-key", "auth" (except "auth status"),
     "-f", "--field", "--input".
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

import pytest

SRC_ROOT = Path(__file__).resolve().parents[2] / "src" / "ssh_id_doctor"

# Network modules forbidden from being imported anywhere in src/ (SEC-004)
FORBIDDEN_NETWORK_MODULES: frozenset[str] = frozenset(
    {
        "socket",
        "ssl",
        "urllib",
        "http",
        "requests",
        "httpx",
        "aiohttp",
        "ftplib",
        "smtplib",
        "telnetlib",
        "xmlrpc",
    }
)

# Filesystem mutating functions and methods forbidden in src/ (SEC-006)
FORBIDDEN_OS_FUNCS: frozenset[str] = frozenset(
    {
        "remove",
        "unlink",
        "rmdir",
        "removedirs",
        "chmod",
        "chown",
        "utime",
        "rename",
    }
)
FORBIDDEN_SHUTIL_FUNCS: frozenset[str] = frozenset(
    {
        "rmtree",
        "move",
    }
)
FORBIDDEN_PATH_METHODS: frozenset[str] = frozenset(
    {
        "unlink",
        "rmdir",
        "chmod",
        "rename",
        "touch",
    }
)


class FsException(NamedTuple):
    filename: str
    operation: str
    reason: str


# Explicit whitelist of permitted FS mutation operations: file + operation + reason
FS_MUTATION_EXCEPTIONS: tuple[FsException, ...] = (
    FsException(
        filename="output.py",
        operation="os.fchmod",
        reason="SEC-003: report file must be owner read/write only (0600) upon creation",
    ),
    FsException(
        filename="output.py",
        operation="os.replace",
        reason="SEC-003: report file is written to temporary path and atomically replaced",
    ),
    FsException(
        filename="output.py",
        operation="os.unlink",
        reason="SEC-003: clean up temporary report file if writing/replacing fails",
    ),
    FsException(
        filename="keygen.py",
        operation="os.fchmod",
        reason="FR-003 / SEC-001: temporary scratch file for ssh-keygen -l must be mode 0600",
    ),
    FsException(
        filename="keygen.py",
        operation="os.unlink",
        reason="FR-003 / SEC-001: temporary scratch file for ssh-keygen -l cleaned up",
    ),
)


@dataclass(frozen=True, slots=True)
class Violation:
    file: str
    line: int
    rule: str
    detail: str


def _get_call_name(node: ast.Call) -> tuple[str | None, str]:
    """Return (base_obj, method_or_func_name) for a call node."""
    func = node.func
    if isinstance(func, ast.Name):
        return None, func.id
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name):
            return func.value.id, func.attr
        if isinstance(func.value, ast.Attribute) and isinstance(func.value.value, ast.Name):
            return f"{func.value.value.id}.{func.value.attr}", func.attr
        return "__expr__", func.attr
    return None, ""


def find_network_violations(source_code: str, filename: str) -> list[Violation]:
    """Find imports of network modules."""
    violations: list[Violation] = []
    tree = ast.parse(source_code, filename=filename)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top_pkg = alias.name.split(".")[0]
                if top_pkg in FORBIDDEN_NETWORK_MODULES:
                    violations.append(
                        Violation(
                            file=filename,
                            line=node.lineno,
                            rule="SEC-004",
                            detail=f"forbidden network import: {alias.name}",
                        )
                    )
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                top_pkg = node.module.split(".")[0]
                if top_pkg in FORBIDDEN_NETWORK_MODULES:
                    violations.append(
                        Violation(
                            file=filename,
                            line=node.lineno,
                            rule="SEC-004",
                            detail=f"forbidden network import: {node.module}",
                        )
                    )
    return violations


def find_fs_mutation_violations(
    source_code: str,
    filename: str,
    allowed_exceptions: Iterable[FsException] = (),
) -> list[Violation]:
    """Find destructive/mutating filesystem calls."""
    violations: list[Violation] = []
    tree = ast.parse(source_code, filename=filename)
    base_filename = Path(filename).name

    exceptions_map: dict[str, set[str]] = {}
    for exc in allowed_exceptions:
        exceptions_map.setdefault(exc.filename, set()).add(exc.operation)

    allowed_ops = exceptions_map.get(base_filename, set())

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        base_obj, func_name = _get_call_name(node)

        # 1. os.<func> calls
        if base_obj == "os" and func_name in (FORBIDDEN_OS_FUNCS | {"fchmod", "replace"}):
            full_op = f"os.{func_name}"
            if full_op not in allowed_ops:
                violations.append(
                    Violation(
                        file=filename,
                        line=node.lineno,
                        rule="SEC-006",
                        detail=f"forbidden filesystem call: {full_op}",
                    )
                )

        # 2. Directly imported os/shutil functions, e.g. remove(...) or rmtree(...)
        elif base_obj is None and func_name in (
            FORBIDDEN_OS_FUNCS | FORBIDDEN_SHUTIL_FUNCS | {"fchmod", "replace"}
        ):
            full_op = f"os.{func_name}"
            shutil_op = f"shutil.{func_name}"
            if full_op not in allowed_ops and shutil_op not in allowed_ops:
                violations.append(
                    Violation(
                        file=filename,
                        line=node.lineno,
                        rule="SEC-006",
                        detail=f"forbidden filesystem call: {func_name}",
                    )
                )

        # 3. shutil.<func> calls
        elif base_obj == "shutil" and func_name in FORBIDDEN_SHUTIL_FUNCS:
            full_op = f"shutil.{func_name}"
            if full_op not in allowed_ops:
                violations.append(
                    Violation(
                        file=filename,
                        line=node.lineno,
                        rule="SEC-006",
                        detail=f"forbidden filesystem call: {full_op}",
                    )
                )

        # 4. Method calls on paths/objects (.unlink(), .rmdir(), .chmod(), .rename(), .touch())
        elif func_name in FORBIDDEN_PATH_METHODS:
            method_op = f".{func_name}()"
            if method_op not in allowed_ops and func_name not in allowed_ops:
                violations.append(
                    Violation(
                        file=filename,
                        line=node.lineno,
                        rule="SEC-006",
                        detail=f"forbidden path method: .{func_name}()",
                    )
                )

    return violations


def _extract_string_literals(node: ast.AST) -> list[str] | None:
    """Extract list of constant string elements from a list or tuple AST node."""
    if not isinstance(node, (ast.List, ast.Tuple)):
        return None
    elements: list[str] = []
    for elt in node.elts:
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            elements.append(elt.value)
        else:
            return None
    return elements


def find_gh_argv_violations(source_code: str, filename: str) -> list[Violation]:
    """Find literal argv lists where first element is "gh" and enforce read-only GET constraints."""
    violations: list[Violation] = []
    tree = ast.parse(source_code, filename=filename)

    for node in ast.walk(tree):
        elements = _extract_string_literals(node)
        if elements is None or not elements:
            continue

        if elements[0] != "gh":
            continue

        lineno = getattr(node, "lineno", 1)

        # Forbidden tokens in any position of gh argv
        forbidden_tokens = {"-X", "POST", "PUT", "PATCH", "DELETE", "-f", "--field", "--input"}
        found_forbidden = [t for t in elements if t in forbidden_tokens]
        if found_forbidden:
            violations.append(
                Violation(
                    file=filename,
                    line=lineno,
                    rule="SEC-005/006",
                    detail=f"forbidden tokens in gh argv: {found_forbidden}",
                )
            )

        # Subcommand "ssh-key" forbidden
        if "ssh-key" in elements:
            violations.append(
                Violation(
                    file=filename,
                    line=lineno,
                    rule="SEC-006",
                    detail="forbidden gh subcommand: ssh-key",
                )
            )

        # Subcommand "auth": only "auth status" permitted
        if "auth" in elements:
            idx = elements.index("auth")
            if idx + 1 >= len(elements) or elements[idx + 1] != "status":
                violations.append(
                    Violation(
                        file=filename,
                        line=lineno,
                        rule="SEC-005",
                        detail=f"forbidden gh auth command (not 'auth status'): {elements}",
                    )
                )

        # If "api" is invoked, after "api" there must be "--method" "GET"
        if "api" in elements:
            api_idx = elements.index("api")
            tail = elements[api_idx + 1 :]
            has_method_get = False
            for i in range(len(tail) - 1):
                if tail[i] == "--method" and tail[i + 1] == "GET":
                    has_method_get = True
                    break
            if not has_method_get:
                violations.append(
                    Violation(
                        file=filename,
                        line=lineno,
                        rule="SEC-005",
                        detail=f"gh api invocation without '--method GET': {elements}",
                    )
                )

    return violations


def test_fs_exceptions_reference_existing_files() -> None:
    """Every entry in FS_MUTATION_EXCEPTIONS must reference a file that actually exists in src."""
    validate_fs_exceptions(FS_MUTATION_EXCEPTIONS)


def validate_fs_exceptions(exceptions: Iterable[FsException]) -> None:
    """Validate that every exception references an existing file with operation and reason."""
    for exc in exceptions:
        matches = list(SRC_ROOT.rglob(exc.filename))
        if len(matches) != 1 or not matches[0].is_file():
            raise AssertionError(f"Exception references non-existent file {exc.filename}")
        if not exc.operation:
            raise AssertionError("Exception must specify operation")
        if not exc.reason:
            raise AssertionError("Exception must specify reason")


def test_src_imports_no_network_modules() -> None:
    """AC-1: No module in src/ imports forbidden network modules (SEC-004)."""
    all_violations: list[Violation] = []
    for py_file in sorted(SRC_ROOT.rglob("*.py")):
        source = py_file.read_text(encoding="utf-8")
        rel_path = str(py_file.relative_to(SRC_ROOT.parents[1]))
        all_violations.extend(find_network_violations(source, rel_path))

    assert all_violations == [], (
        f"Network module imports detected in src: {[v.detail for v in all_violations]}"
    )


def test_src_has_no_unapproved_fs_mutations() -> None:
    """AC-1: No module in src/ performs FS mutations outside exceptions list (SEC-006)."""
    all_violations: list[Violation] = []
    for py_file in sorted(SRC_ROOT.rglob("*.py")):
        source = py_file.read_text(encoding="utf-8")
        rel_path = str(py_file.relative_to(SRC_ROOT.parents[1]))
        all_violations.extend(
            find_fs_mutation_violations(source, rel_path, allowed_exceptions=FS_MUTATION_EXCEPTIONS)
        )

    assert all_violations == [], (
        f"Filesystem mutations detected in src: {[v.detail for v in all_violations]}"
    )


def test_src_gh_argv_read_only() -> None:
    """AC-1: All literal gh argv in src/ are read-only (SEC-005/SEC-006)."""
    all_violations: list[Violation] = []
    for py_file in sorted(SRC_ROOT.rglob("*.py")):
        source = py_file.read_text(encoding="utf-8")
        rel_path = str(py_file.relative_to(SRC_ROOT.parents[1]))
        all_violations.extend(find_gh_argv_violations(source, rel_path))

    assert all_violations == [], (
        f"Mutating gh invocations detected in src: {[v.detail for v in all_violations]}"
    )


def test_checkers_catch_synthetic_violations(tmp_path: Path) -> None:
    """AC-2: Checkers catch violations in synthetic source files and report file and line."""
    synthetic_code = """
import socket
from urllib.request import urlopen
import os
import shutil
from pathlib import Path

def mutate(p):
    os.remove(p)
    os.unlink(p)
    os.rmdir(p)
    os.chmod(p, 0o777)
    shutil.rmtree(p)
    Path(p).unlink()
    Path(p).chmod(0o600)
    cmd1 = ["gh", "api", "-X", "POST", "user/keys"]
    cmd2 = ["gh", "ssh-key", "add", "key.pub"]
    cmd3 = ["gh", "auth", "token"]
    cmd4 = ["gh", "api", "--paginate", "user/keys"]
    cmd5 = ["gh", "api", "--field", "title=foo", "user/keys"]
"""
    synth_file = tmp_path / "synthetic_bad.py"
    synth_file.write_text(synthetic_code, encoding="utf-8")
    content = synth_file.read_text(encoding="utf-8")
    filename = synth_file.name

    # 1. Network checks
    net_viols = find_network_violations(content, filename)
    assert len(net_viols) >= 2
    assert any(v.file == filename and v.line == 2 and "socket" in v.detail for v in net_viols)
    assert any(v.file == filename and v.line == 3 and "urllib" in v.detail for v in net_viols)

    # Comments and docstrings must not count
    comment_only_code = "# import socket\n'''from urllib import request'''\n"
    assert find_network_violations(comment_only_code, "test.py") == []

    # 2. FS mutation checks
    fs_viols = find_fs_mutation_violations(content, filename)
    assert len(fs_viols) >= 7
    assert any(v.file == filename and "os.remove" in v.detail for v in fs_viols)
    assert any(v.file == filename and "os.unlink" in v.detail for v in fs_viols)
    assert any(v.file == filename and "os.rmdir" in v.detail for v in fs_viols)
    assert any(v.file == filename and "os.chmod" in v.detail for v in fs_viols)
    assert any(v.file == filename and "shutil.rmtree" in v.detail for v in fs_viols)
    assert any(v.file == filename and ".unlink()" in v.detail for v in fs_viols)
    assert any(v.file == filename and ".chmod()" in v.detail for v in fs_viols)

    # 3. Exception for non-existent file must fail validation
    fake_exc = FsException(
        filename="nonexistent_module.py",
        operation="os.remove",
        reason="Testing non-existent exception file rejection",
    )
    with pytest.raises(AssertionError, match="non-existent file"):
        validate_fs_exceptions([fake_exc])

    # 4. GH argv checks
    gh_viols = find_gh_argv_violations(content, filename)
    assert len(gh_viols) >= 5
    assert any((v.file == filename and "-X" in v.detail) or "POST" in v.detail for v in gh_viols)
    assert any(v.file == filename and "ssh-key" in v.detail for v in gh_viols)
    assert any(v.file == filename and "auth" in v.detail for v in gh_viols)
    assert any(v.file == filename and "--method GET" in v.detail for v in gh_viols)
    assert any(v.file == filename and "--field" in v.detail for v in gh_viols)
