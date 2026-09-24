# SSH Identity Doctor — rules for executor agents

Contract: `sdd-spec` (CLI §5, exit codes §5.3, data model §7, module
boundaries §8.1, security §10). Python 3.12+, managed with `uv`.

## The one check

```sh
uv sync --locked
make check   # ruff check, ruff format --check, mypy --strict src, pytest -q
```

`make check` is what CI (`.github/workflows/haiplane-ci.yml`, ubuntu and
macOS) runs and what the review gate judges. Confirm it by exit code
(`make check; echo rc=$?`), not by the tail of the output.

## Security invariants (non-negotiable)

- **Never touch the real `~/.ssh`.** Tests build synthetic SSH directories
  under `tmp_path`; `tests/conftest.py` points `HOME` at a temporary directory
  and unsets `SSH_AUTH_SOCK` for every test. Do not bypass it.
- **No private-key custody (SEC-001).** Never open a file identified as
  private-key material, never call `ssh-keygen -y` on it, never print it.
- **Safe subprocesses (SEC-002).** Argument arrays only; no `shell=True`,
  `sh -c` or string-built commands; always an explicit timeout.
- **Filesystem safety (SEC-003).** Normalize paths; do not follow symlinks out
  of the scan root; never change permissions or timestamps.
- **Read-only (SEC-006).** No code that modifies, deletes, revokes or rotates
  keys, config, agent state or remote registries.
- **No network (SEC-004)** unless an optional adapter such as `--github` is
  explicitly selected. No telemetry.

## Layout

- `src/ssh_id_doctor/domain.py` — frozen dataclasses and enums of §7; **no
  I/O** and no `os`/`subprocess`/`pathlib` imports (a test enforces this).
- `src/ssh_id_doctor/exit_codes.py` — `ExitCode` 0–4 of §5.3; the CLI returns
  nothing else (argparse errors map to 1, not argparse's default 2).
- `src/ssh_id_doctor/cli.py` — argparse entry point `ssh-id-doctor`.
- Later slices add `scanner`, `ssh_config`, `inspectors`, `adapters/github`,
  `aggregate`, `rules`, `reporting` per §8.1, each with its own tests.

## Dependencies

Add them only with `uv add` using an exact `==` pin, and commit `uv.lock`.
Do not add a second CI workflow; extend `haiplane-ci.yml`.
