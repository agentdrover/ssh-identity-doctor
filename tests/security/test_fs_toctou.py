"""fs.py TOCTOU-by-ancestor-directory tests (task #1802, review #1794 finding #5).

AC-1: a monkeypatch over ``os.open`` swaps exactly one chosen ancestor directory
for a symlink to an outside location holding a same-named file, immediately
before that ancestor's own fd would be obtained -- never earlier, so every
check that runs on the untouched tree (``resolve_within``, the pre-open
``os.stat``) still sees the real thing. Every one of the three readers, plus
known_hosts's own ``ssh_dir`` and ``ssh_dir``'s parent, must refuse instead of
following the swapped ancestor into the outside file.

AC-2: the per-component walk must leak no file descriptor on any path: plain
success, a symlinked alias resolved to its real target, a FIFO refused before
any open, a denied mid-walk ancestor open, and a failing ``fdopen`` of the
final fd -- and ``open_guard`` must still catch a disallowed relative open
routed through ``dir_fd``.
"""

from __future__ import annotations

import contextlib
import os
import traceback
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from conftest import DenyOpen, OpenGuard
from ssh_id_doctor import fs

OUTSIDE_MARKER = "OUTSIDE-NOT-THE-CHECKED-LOCATION-7f3a"


def _remove_directory(path: str) -> None:
    """Remove a directory tree without ``os.open`` (unlike ``shutil.rmtree``, whose
    fd-relative walk would itself be caught by ``open_guard``'s ``os.open`` wrapper
    as a spurious "read" of the very ancestor this helper is about to swap out)."""
    root = Path(path)
    for entry in sorted(root.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if entry.is_symlink() or not entry.is_dir():
            entry.unlink()
        else:
            entry.rmdir()
    root.rmdir()


SwapAncestor = Callable[
    [str | os.PathLike[str], str | os.PathLike[str]],
    contextlib.AbstractContextManager[Callable[[], bool]],
]


@pytest.fixture
def swap_ancestor_once(open_guard: OpenGuard, monkeypatch: pytest.MonkeyPatch) -> SwapAncestor:
    """A context manager factory: the first time something is about to be opened at
    or under ``ancestor``, ``ancestor`` itself is replaced by a symlink to
    ``outside`` -- never before that moment, so every check that ran earlier saw the
    untouched tree. The walk opens strictly outside-in, so the first call whose
    resolved path is ``ancestor`` or something under it is necessarily the call
    opening ``ancestor``'s own fd (nothing under it can be reached first). Returns a
    callable reporting whether the swap fired, so a test can tell "refused" apart
    from "never exercised the vulnerable path".
    """

    @contextlib.contextmanager
    def _swap(
        ancestor: str | os.PathLike[str], outside: str | os.PathLike[str]
    ) -> Iterator[Callable[[], bool]]:
        target = os.path.realpath(os.fspath(ancestor))
        replacement = os.path.realpath(os.fspath(outside))
        fired = False
        current_os_open = os.open

        def hook(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
            nonlocal fired
            if not fired and not isinstance(path, int):
                dir_fd = kwargs.get("dir_fd")
                resolved = (
                    open_guard.resolve_relative(path, dir_fd)
                    if dir_fd is not None
                    else os.path.realpath(os.fspath(path))
                )
                if resolved == target or resolved.startswith(target + os.sep):
                    fired = True
                    _remove_directory(target)
                    os.symlink(replacement, target)
            return current_os_open(path, flags, *args, **kwargs)

        with monkeypatch.context() as ctx:
            ctx.setattr(os, "open", hook)
            yield lambda: fired

    return _swap


def _no_full_path_leaked(exc: BaseException, *paths: str | os.PathLike[str]) -> None:
    rendered = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    for path in paths:
        text = str(path)
        assert text not in str(exc), f"{text} leaked into the message"
        assert text not in rendered, f"{text} leaked into the traceback"


def _build_case(case_name: str, root: Path) -> tuple[Path, Path, Callable[[], str]]:
    """Return (target, ancestor_to_swap, read_callable) for one parametrized case."""
    if case_name == "public_key":
        nested = root / "keys"
        nested.mkdir()
        target = nested / "work.pub"
        target.write_text("ssh-ed25519 AAAAC3genuinekeymaterial work@test\n")
        return target, nested, lambda: fs.read_public_text(target)

    if case_name == "config":
        nested = root / "confs"
        nested.mkdir()
        target = nested / "config"
        target.write_text("Host example\n  HostName example.com\n")
        return target, nested, lambda: fs.read_config_text(target)

    ssh_dir = root / ".ssh"
    subdir = ssh_dir / "subdir"
    subdir.mkdir(parents=True)
    target = subdir / "known_hosts"
    target.write_text("example.com ssh-ed25519 AAAA\n")
    read = lambda: fs.read_known_hosts_text(target, ssh_dir=ssh_dir)  # noqa: E731
    if case_name == "known_hosts_nested_ancestor":
        return target, subdir, read
    if case_name == "known_hosts_ssh_dir_itself":
        return target, ssh_dir, read
    if case_name == "known_hosts_ssh_dir_parent":
        return target, root, read
    raise ValueError(case_name)


@pytest.mark.parametrize(
    "case_name",
    [
        "public_key",
        "config",
        "known_hosts_nested_ancestor",
        "known_hosts_ssh_dir_itself",
        "known_hosts_ssh_dir_parent",
    ],
)
def test_a_swapped_ancestor_directory_is_never_followed(
    case_name: str,
    tmp_path: Path,
    open_guard: OpenGuard,
    opened_paths: list[str],
    swap_ancestor_once: SwapAncestor,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    open_guard.guard_root(root)
    outside_root = tmp_path / "outside"
    outside_root.mkdir()

    target, ancestor, read = _build_case(case_name, root)

    # Mirror the exact suffix the swapped ancestor would still have to resolve
    # through, with the same marker content, so a bypass actually succeeds in
    # reading it instead of merely hitting ENOENT.
    suffix = target.relative_to(ancestor)
    outside_leaf = outside_root / suffix
    outside_leaf.parent.mkdir(parents=True, exist_ok=True)
    outside_leaf.write_text(OUTSIDE_MARKER)
    outside_leaf_real = os.path.realpath(outside_leaf)

    opened_paths.clear()
    with swap_ancestor_once(ancestor, outside_root) as fired:
        with pytest.raises(OSError) as excinfo:
            read()
        assert fired(), "the swap never fired -- this case never reaches the ancestor open"

    assert outside_leaf_real not in opened_paths, "the outside file must never be opened"
    assert OUTSIDE_MARKER not in str(excinfo.value)
    _no_full_path_leaked(excinfo.value, ancestor, outside_root, outside_leaf_real)


def test_component_open_leaks_no_descriptors(
    tmp_path: Path,
    open_guard: OpenGuard,
    opened_paths: list[str],
    deny_open: DenyOpen,
    fd_balance: Callable[[], int],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    open_guard.guard_root(root)

    # 1. Plain success, each of the three readers.
    pub = root / "key.pub"
    pub.write_text("ssh-ed25519 AAAAC3genuinekeymaterial a@b\n")
    assert fs.read_public_text(pub) == pub.read_text()
    assert fd_balance() == 0

    cfg = root / "config"
    cfg.write_text("Host x\n  HostName x.example.com\n")
    assert fs.read_config_text(cfg) == cfg.read_text()
    assert fd_balance() == 0

    ssh_dir = root / "ssh"
    ssh_dir.mkdir()
    kh = ssh_dir / "known_hosts"
    kh.write_text("example.com ssh-ed25519 AAAA\n")
    assert fs.read_known_hosts_text(kh, ssh_dir=ssh_dir) == kh.read_text()
    assert fd_balance() == 0

    # 2. alias.pub -> target.pub inside the same directory: the real target gets
    # opened, not the alias name, and no descriptor leaks either way.
    real_target = root / "target.pub"
    real_target.write_text("ssh-ed25519 AAAAC3genuinekeymaterial real@target\n")
    alias = root / "alias.pub"
    alias.symlink_to(real_target)
    assert fs.read_public_text(alias) == real_target.read_text()
    assert fd_balance() == 0

    # 3. Missing file: refused before any open.
    (ssh_dir / "known_hosts").unlink()
    with pytest.raises(FileNotFoundError):
        fs.read_known_hosts_text(ssh_dir / "known_hosts", ssh_dir=ssh_dir)
    assert fd_balance() == 0

    # 4. FIFO: refused by the pre-open regular-file check, before any open.
    fifo = root / "fifo.pub"
    os.mkfifo(fifo)
    with pytest.raises(fs.NotAPublicKeyFile):
        fs.read_public_text(fifo)
    assert fd_balance() == 0

    # 5. A mid-walk ancestor open is denied (EACCES): every fd opened so far for
    # this call is still closed.
    denied_dir = root / "denied"
    inner = denied_dir / "inner"
    inner.mkdir(parents=True)
    guarded_cfg = inner / "config"
    guarded_cfg.write_text("Host y\n  HostName y.example.com\n")
    with deny_open(denied_dir), pytest.raises(OSError):
        fs.read_config_text(guarded_cfg)
    assert fd_balance() == 0

    # 6. fdopen itself fails after the final os.open already succeeded: the fd
    # must still be closed, not leaked.
    fdopen_target = root / "fdopen.pub"
    fdopen_target.write_text("ssh-ed25519 AAAAC3genuinekeymaterial c@d\n")
    real_fdopen = os.fdopen

    def failing_fdopen(fd: int, *args: Any, **kwargs: Any) -> Any:
        # Do not close fd here: fs.py's own `except BaseException: os.close(fd)`
        # around this call is what this test is proving closes it exactly once.
        raise ValueError("simulated fdopen failure")

    monkeypatch.setattr(os, "fdopen", failing_fdopen)
    with pytest.raises(ValueError, match="simulated fdopen failure"):
        fs.read_public_text(fdopen_target)
    monkeypatch.setattr(os, "fdopen", real_fdopen)
    assert fd_balance() == 0

    # 7. open_guard itself catches a disallowed relative open routed through a
    # directory fd, not only an absolute one.
    private = root / "id_private"
    private.write_text("private material, not a .pub/.conf/config/known_hosts name\n")
    dir_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(AssertionError):
            os.close(os.open("id_private", os.O_RDONLY, dir_fd=dir_fd))
    finally:
        os.close(dir_fd)
    assert len(open_guard.violations) == 1
    open_guard.violations.clear()  # deliberate violation; do not fail teardown
