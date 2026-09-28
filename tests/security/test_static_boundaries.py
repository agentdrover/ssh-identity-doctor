"""SEC-004 / SEC-005 / SEC-006: static boundaries of src/ssh_id_doctor (AC-1, AC-2).

AST of every src/ssh_id_doctor/**/*.py (comments and docstrings do not count):
1. No network module imports (socket, ssl, urllib, http, requests, httpx, ...).
2. No filesystem mutations (os.remove/unlink/rmdir/chmod/fchmod/chown/fchown/...,
   shutil.rmtree/move, .unlink()/.rmdir()/.chmod()/.rename()/.touch()) except an
   explicit list keyed by the exact triple (file, enclosing function, call).
3. Every literal argv starting with "gh" is read-only: "api" is followed by
   "--method" "GET"; no -X, POST/PUT/PATCH/DELETE, ssh-key, auth other than
   "auth status", -f/-F/--field/--raw-field/--input.
"""

from __future__ import annotations

import ast
import itertools
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

# Filesystem mutating functions and methods forbidden in src/ (SEC-006).
# fchmod/fchown/lchmod/lchown count as mutations on a par with chmod/chown
# (owner answer on #1450); replace/renames are renames.
FORBIDDEN_OS_FUNCS: frozenset[str] = frozenset(
    {
        "remove",
        "unlink",
        "rmdir",
        "removedirs",
        "chmod",
        "fchmod",
        "lchmod",
        "chown",
        "fchown",
        "lchown",
        "utime",
        "rename",
        "renames",
        "replace",
    }
)
FORBIDDEN_SHUTIL_FUNCS: frozenset[str] = frozenset(
    {
        "rmtree",
        "move",
    }
)
# Method calls on path-like objects. ``.replace()`` is deliberately absent:
# ``str.replace`` is everywhere in src and cannot be told apart statically.
FORBIDDEN_PATH_METHODS: frozenset[str] = frozenset(
    {
        "unlink",
        "rmdir",
        "chmod",
        "lchmod",
        "rename",
        "touch",
    }
)
_FORBIDDEN_BY_MODULE: dict[str, frozenset[str]] = {
    "os": FORBIDDEN_OS_FUNCS,
    "shutil": FORBIDDEN_SHUTIL_FUNCS,
}


class FsException(NamedTuple):
    """One permitted mutation: exactly (file, enclosing function, call).

    ``file`` is relative to src/ssh_id_doctor. A whole file is never exempt:
    the same call in any other function of that file is still a violation.
    """

    file: str
    function: str
    call: str
    reason: str


# Explicit list of permitted FS mutations — only what exists on main.
FS_MUTATION_EXCEPTIONS: tuple[FsException, ...] = (
    FsException(
        file="output.py",
        function="write_report_atomically",
        call="os.fchmod",
        reason="SEC-003: --output report temp file is set to owner-only 0600 on creation",
    ),
    FsException(
        file="output.py",
        function="write_report_atomically",
        call="os.replace",
        reason="SEC-003: --output report is written to a temp file and atomically replaced",
    ),
    FsException(
        file="output.py",
        function="write_report_atomically",
        call="os.unlink",
        reason="SEC-003: the report's own temp file is removed when writing/replacing fails",
    ),
    FsException(
        file="inspectors/keygen.py",
        function="_write_scratch_pub",
        call="os.fchmod",
        reason="scratch .pub from tempfile.mkstemp (inspector's own file) is set to 0600",
    ),
    FsException(
        file="inspectors/keygen.py",
        function="_remove_scratch",
        call="os.unlink",
        reason="scratch .pub from tempfile.mkstemp (inspector's own file) is removed",
    ),
)


@dataclass(frozen=True, slots=True)
class Violation:
    file: str
    line: int
    rule: str
    detail: str


def _is_network_module(name: str) -> bool:
    return name.split(".")[0] in FORBIDDEN_NETWORK_MODULES


def _dynamic_import_target(node: ast.Call) -> str | None:
    """Literal module name of ``__import__("x")`` / ``importlib.import_module("x")``."""
    func = node.func
    is_dunder = isinstance(func, ast.Name) and func.id == "__import__"
    is_importlib = isinstance(func, ast.Attribute) and func.attr == "import_module"
    if not (is_dunder or is_importlib) or not node.args:
        return None
    first = node.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value
    return None


def _imported_modules(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]
    if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
        return [node.module]
    if isinstance(node, ast.Call):
        target = _dynamic_import_target(node)
        return [target] if target else []
    return []


def find_network_violations(source_code: str, filename: str) -> list[Violation]:
    """Imports (static or literal dynamic) of network modules (SEC-004)."""
    tree = ast.parse(source_code, filename=filename)
    return [
        Violation(
            file=filename,
            line=getattr(node, "lineno", 1),
            rule="SEC-004",
            detail=f"forbidden network import: {name}",
        )
        for node in ast.walk(tree)
        for name in _imported_modules(node)
        if _is_network_module(name)
    ]


@dataclass(frozen=True, slots=True)
class FsCall:
    """A mutating filesystem call found in source, with its enclosing function."""

    line: int
    function: str
    call: str


def _module_aliases(tree: ast.AST) -> tuple[dict[str, str], dict[str, str]]:
    """Map local names to modules (``import os as o``) and functions (``from os import rm``)."""
    modules: dict[str, str] = {}
    functions: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in _FORBIDDEN_BY_MODULE:
                    modules[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            forbidden = _FORBIDDEN_BY_MODULE.get(node.module or "")
            if forbidden is None:
                continue
            for alias in node.names:
                if alias.name in forbidden:
                    functions[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return modules, functions


def _classify_call(
    node: ast.Call, modules: dict[str, str], functions: dict[str, str]
) -> str | None:
    """Return the canonical mutating operation a call performs, or None."""
    func = node.func
    if isinstance(func, ast.Name):
        return functions.get(func.id)
    if not isinstance(func, ast.Attribute):
        return None
    if isinstance(func.value, ast.Name) and func.value.id in modules:
        module = modules[func.value.id]
        if func.attr in _FORBIDDEN_BY_MODULE[module]:
            return f"{module}.{func.attr}"
        return None
    if func.attr in FORBIDDEN_PATH_METHODS:
        return f".{func.attr}()"
    return None


class _FsCallCollector(ast.NodeVisitor):
    def __init__(self, modules: dict[str, str], functions: dict[str, str]) -> None:
        self._modules = modules
        self._functions = functions
        self._scope: list[str] = []
        self.calls: list[FsCall] = []

    def _visit_scope(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> None:
        self._scope.append(node.name)
        self.generic_visit(node)
        self._scope.pop()

    visit_FunctionDef = _visit_scope
    visit_AsyncFunctionDef = _visit_scope
    visit_ClassDef = _visit_scope

    def visit_Call(self, node: ast.Call) -> None:
        op = _classify_call(node, self._modules, self._functions)
        if op is not None:
            where = ".".join(self._scope) or "<module>"
            self.calls.append(FsCall(line=node.lineno, function=where, call=op))
        self.generic_visit(node)


def collect_fs_mutations(source_code: str, filename: str) -> list[FsCall]:
    """Every mutating filesystem call in the source, with its enclosing function."""
    tree = ast.parse(source_code, filename=filename)
    collector = _FsCallCollector(*_module_aliases(tree))
    collector.visit(tree)
    return collector.calls


def find_fs_mutation_violations(
    source_code: str,
    filename: str,
    allowed_exceptions: Iterable[FsException] = (),
    rel_file: str | None = None,
) -> list[Violation]:
    """Mutating FS calls not covered by an exact (file, function, call) exception."""
    key_file = rel_file if rel_file is not None else Path(filename).name
    allowed = {(e.file, e.function, e.call) for e in allowed_exceptions}
    return [
        Violation(
            file=filename,
            line=c.line,
            rule="SEC-006",
            detail=f"forbidden filesystem call: {c.call} in {c.function}()",
        )
        for c in collect_fs_mutations(source_code, filename)
        if (key_file, c.function, c.call) not in allowed
    ]


_GH_FORBIDDEN_TOKENS: frozenset[str] = frozenset(
    {"-X", "POST", "PUT", "PATCH", "DELETE", "-f", "-F", "--field", "--raw-field", "--input"}
)
# ``--method=POST`` / ``-XPOST`` / ``--field=a=b`` spellings of the same flags.
_GH_FORBIDDEN_PREFIXES: tuple[str, ...] = (
    "-X",
    "--method=",
    "--field=",
    "--raw-field=",
    "--input=",
)


def _gh_argv(node: ast.AST) -> list[str | None] | None:
    """Elements of a list/tuple literal whose first element is the literal "gh".

    Non-literal elements come back as None so the caller can refuse them.
    """
    if not isinstance(node, (ast.List, ast.Tuple)) or not node.elts:
        return None
    first = node.elts[0]
    if not (isinstance(first, ast.Constant) and first.value == "gh"):
        return None
    return [
        elt.value if isinstance(elt, ast.Constant) and isinstance(elt.value, str) else None
        for elt in node.elts
    ]


def _gh_problems(argv: list[str | None]) -> list[str]:
    elements = [e for e in argv if e is not None]
    if len(elements) != len(argv):
        return [f"non-literal element in gh argv: {argv}"]
    problems: list[str] = []
    forbidden = [
        t
        for t in elements
        if t in _GH_FORBIDDEN_TOKENS
        or (t.startswith(_GH_FORBIDDEN_PREFIXES) and t != "--method=GET")
    ]
    if forbidden:
        problems.append(f"forbidden tokens in gh argv: {forbidden}")
    if "ssh-key" in elements:
        problems.append("forbidden gh subcommand: ssh-key")
    if "auth" in elements and elements[elements.index("auth") + 1 :][:1] != ["status"]:
        problems.append(f"forbidden gh auth command (not 'auth status'): {elements}")
    if "api" in elements:
        tail = elements[elements.index("api") + 1 :]
        has_get = "--method=GET" in tail or any(
            a == "--method" and b == "GET" for a, b in itertools.pairwise(tail)
        )
        if not has_get:
            problems.append(f"gh api invocation without '--method GET': {elements}")
    return problems


def find_gh_argv_violations(source_code: str, filename: str) -> list[Violation]:
    """Literal argv starting with "gh" must be read-only (SEC-005, §13.4)."""
    tree = ast.parse(source_code, filename=filename)
    violations: list[Violation] = []
    for node in ast.walk(tree):
        argv = _gh_argv(node)
        if argv is None:
            continue
        line = getattr(node, "lineno", 1)
        violations.extend(
            Violation(file=filename, line=line, rule="SEC-005", detail=problem)
            for problem in _gh_problems(argv)
        )
    return violations


def _src_files() -> list[Path]:
    return sorted(SRC_ROOT.rglob("*.py"))


def _display(py_file: Path) -> str:
    return str(py_file.relative_to(SRC_ROOT.parents[1]))


def _rel(py_file: Path) -> str:
    return py_file.relative_to(SRC_ROOT).as_posix()


def validate_fs_exceptions(exceptions: Iterable[FsException], src_root: Path = SRC_ROOT) -> None:
    """Each exception names an existing file, a reason, and a call that is really there.

    An exception whose file, function or call is absent is stale and fails: the
    list may only name what exists, never carry dead permissions.
    """
    for exc in exceptions:
        path = src_root / exc.file
        if not path.is_file():
            raise AssertionError(f"exception references non-existent file {exc.file}")
        if not exc.reason.strip():
            raise AssertionError(f"exception {exc.file}::{exc.function} has no reason")
        found = {
            (c.function, c.call)
            for c in collect_fs_mutations(path.read_text(encoding="utf-8"), str(path))
        }
        if (exc.function, exc.call) not in found:
            raise AssertionError(
                f"exception {exc.file}::{exc.function} -> {exc.call} matches no call in src"
            )


def test_fs_exceptions_reference_existing_calls() -> None:
    """Every (file, function, call) exception points at a call that exists in src."""
    validate_fs_exceptions(FS_MUTATION_EXCEPTIONS)


def test_src_imports_no_network_modules() -> None:
    """AC-1: No module in src/ imports a network module (SEC-004)."""
    violations = [
        v
        for f in _src_files()
        for v in find_network_violations(f.read_text(encoding="utf-8"), _display(f))
    ]
    assert violations == [], f"Network module imports detected in src: {violations}"


def test_src_has_no_unapproved_fs_mutations() -> None:
    """AC-1: No FS mutation in src/ outside the (file, function, call) exceptions (SEC-006)."""
    violations = [
        v
        for f in _src_files()
        for v in find_fs_mutation_violations(
            f.read_text(encoding="utf-8"),
            _display(f),
            allowed_exceptions=FS_MUTATION_EXCEPTIONS,
            rel_file=_rel(f),
        )
    ]
    assert violations == [], f"Filesystem mutations detected in src: {violations}"


def test_src_gh_argv_read_only() -> None:
    """AC-1: All literal gh argv in src/ are read-only (SEC-005, §13.4)."""
    violations = [
        v
        for f in _src_files()
        for v in find_gh_argv_violations(f.read_text(encoding="utf-8"), _display(f))
    ]
    assert violations == [], f"Mutating gh invocations detected in src: {violations}"


_SYNTHETIC = """
import socket
from urllib.request import urlopen
import os
import shutil
from pathlib import Path
from os import remove as rm

def mutate(p):
    os.remove(p)
    os.unlink(p)
    os.rmdir(p)
    os.chmod(p, 0o777)
    os.fchmod(3, 0o777)
    os.fchown(3, 0, 0)
    shutil.rmtree(p)
    Path(p).unlink()
    Path(p).chmod(0o600)
    rm(p)
    cmd1 = ["gh", "api", "-X", "POST", "user/keys"]
    cmd2 = ["gh", "ssh-key", "add", "key.pub"]
    cmd3 = ["gh", "auth", "token"]
    cmd4 = ["gh", "api", "--paginate", "user/keys"]
    cmd5 = ["gh", "api", "--field", "title=foo", "user/keys"]
    cmd6 = ["gh", "api", "--method=POST", "user/keys"]
"""

_COMMENTS_ONLY = "# import socket\n'''from urllib import request'''\n"


def test_checkers_catch_synthetic_violations(tmp_path: Path) -> None:
    """AC-2: each checker reports file and line on a synthetic source; stale exception fails."""
    synth_file = tmp_path / "synthetic_bad.py"
    synth_file.write_text(_SYNTHETIC, encoding="utf-8")
    content = synth_file.read_text(encoding="utf-8")
    name = synth_file.name
    lines = content.splitlines()

    def line_of(fragment: str) -> int:
        return next(i for i, text in enumerate(lines, start=1) if fragment in text)

    # 1. Network: import socket / urllib, each at its own line; comments do not count.
    net = {(v.file, v.line) for v in find_network_violations(content, name)}
    assert (name, line_of("import socket")) in net
    assert (name, line_of("from urllib")) in net
    assert find_network_violations(_COMMENTS_ONLY, "c.py") == []

    # 2. FS mutations: every forbidden spelling is found at its own line.
    fs = {(v.file, v.line) for v in find_fs_mutation_violations(content, name)}
    for fragment in (
        "os.remove(p)",
        "os.unlink(p)",
        "os.rmdir(p)",
        "os.chmod(p",
        "os.fchmod(3",
        "os.fchown(3",
        "shutil.rmtree(p)",
        "Path(p).unlink()",
        "Path(p).chmod(",
        "rm(p)",
    ):
        assert (name, line_of(fragment)) in fs, fragment

    # 3. An exception for a file that does not exist is itself a failure.
    ghost = FsException("nonexistent_module.py", "f", "os.remove", "stale")
    with pytest.raises(AssertionError, match="non-existent file"):
        validate_fs_exceptions([ghost])

    # 4. gh argv: -X POST, ssh-key, auth token, api without GET, --field, --method=POST.
    gh = find_gh_argv_violations(content, name)
    assert all(v.file == name for v in gh)
    gh_lines = {v.line for v in gh}
    for n in range(1, 7):
        assert line_of(f"cmd{n} =") in gh_lines, f"cmd{n}"


def test_fs_exception_is_scoped_to_function_and_call() -> None:
    """The keygen.py exceptions cover one function and one call each, not the whole file."""
    source = (SRC_ROOT / "inspectors" / "keygen.py").read_text(encoding="utf-8")
    appended_from = len(source.splitlines()) + 1
    source += "\n\ndef _elsewhere(path: str) -> None:\n    os.unlink(path)\n"
    source += "\n\ndef _remove_scratch_mode(path: str) -> None:\n    os.fchmod(3, 0o600)\n"
    violations = find_fs_mutation_violations(
        source, "keygen.py", FS_MUTATION_EXCEPTIONS, rel_file="inspectors/keygen.py"
    )
    # Only the appended functions are judged here; the live file is the job of
    # test_src_has_no_unapproved_fs_mutations.
    assert {v.detail for v in violations if v.line >= appended_from} == {
        "forbidden filesystem call: os.unlink in _elsewhere()",
        "forbidden filesystem call: os.fchmod in _remove_scratch_mode()",
    }

    # A call permitted in _remove_scratch is not permitted in _write_scratch_pub.
    swapped = FsException("inspectors/keygen.py", "_write_scratch_pub", "os.unlink", "wrong")
    with pytest.raises(AssertionError, match="matches no call"):
        validate_fs_exceptions([swapped])
