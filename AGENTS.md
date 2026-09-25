# SSH Identity Doctor — rules for executor agents

Contract: `sdd-spec` (CLI §5, exit codes §5.3, data model §7, module
boundaries §8.1, security §10). Python 3.12+, managed with `uv`.

## The one check

```sh
uv sync --locked
make check   # ruff check, ruff format --check, mypy --strict src, pytest -q
```

`make check` is what CI (`.github/workflows/haiplane-ci.yml`) runs, one step
per target, and what the review gate judges: ubuntu on every push and pull
request, macOS only on a push to `main` or a manual `workflow_dispatch`. Confirm it by exit code
(`make check; echo rc=$?`), not by the tail of the output.

## Security invariants (non-negotiable)

- **Never touch the real `~/.ssh`.** Tests build synthetic SSH directories
  under `tmp_path`; `tests/conftest.py` points `HOME` at a temporary directory
  and unsets `SSH_AUTH_SOCK` for every test. Do not bypass it.
- **No private-key custody (SEC-001).** Never open a file identified as
  private-key material, never call `ssh-keygen -y` on it, never print it.
- **Safe subprocesses (SEC-002).** Start programs only through
  `ssh_id_doctor.process.run` (argv list, `shell=False`, required timeout,
  bounded output, whitelisted env). No `subprocess` anywhere else.
- **Filesystem safety (SEC-003).** Discover with `ssh_id_doctor.fs.safe_walk`
  / `resolve_within`; read only with `fs.read_public_text` (refuses non-`.pub`
  before opening). No `open(` elsewhere in `src` — a test greps for it.
- **Private-key trap.** An autouse guard in `tests/conftest.py` fails any test
  that reads a non-`.pub`, non-config file inside the synthetic HOME; the
  `fake_home` fixture plants `~/.ssh/id_canary` (bytes `CANARY-PRIVATE-7f3a`).
  Build SSH fixtures on `fake_home`, never on a directory of your own.
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
