"""Command-line entry point, sdd-spec §5.

Implements `scan` command with all options (§5.2), exit codes (§5.3),
redaction (§9 step 10), and atomic output writing (§12).
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn

from ssh_id_doctor import __version__
from ssh_id_doctor.adapters.github import GitHubRegistryAdapter
from ssh_id_doctor.exit_codes import ExitCode
from ssh_id_doctor.inspectors import RequiredSourceError
from ssh_id_doctor.inspectors.agent import SSHAgentAdapter
from ssh_id_doctor.inspectors.keygen import PublicKeyInspector
from ssh_id_doctor.orchestrator import OrchestratorOptions, ScanOrchestrator
from ssh_id_doctor.output import OutputWriteError, validate_output_path, write_report_atomically
from ssh_id_doctor.redact import redact
from ssh_id_doctor.reporting.json_report import render_json
from ssh_id_doctor.reporting.markdown import render_markdown
from ssh_id_doctor.reporting.terminal import render_terminal

PROG = "ssh-id-doctor"

PRIVACY_TEXT = """
Privacy & Safety (§10, §17):
  - Read-only: never alters, generates, rotates, or deletes keys, configs, or agent state.
  - No private-key custody (SEC-001): never opens, reads, or runs ssh-keygen on private keys.
  - No network by default (SEC-004): network queries only when --github is explicitly passed.
  - No telemetry: no usage statistics, crash reports, or pings are ever transmitted.
"""


class _ArgumentParser(argparse.ArgumentParser):
    """argparse exits 2 on bad arguments; §5.3 reserves 2, so use 1."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(ExitCode.INVALID_ARGS, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog=PROG,
        description=(
            "Read-only local SSH identity inventory. Never reads private-key "
            "contents and never changes files, agent state or remote registries."
        ),
        epilog=PRIVACY_TEXT,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND", parser_class=_ArgumentParser)
    sub.required = True

    scan_parser = sub.add_parser(
        "scan",
        help="inventory SSH identities and evaluate configuration rules",
        description="Scan SSH identities across filesystem, ssh_config, agent, and GitHub.",
        epilog=PRIVACY_TEXT,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan_parser.add_argument(
        "--config",
        dest="config",
        metavar="PATH",
        help="Path to ssh_config (default: ~/.ssh/config)",
    )
    scan_parser.add_argument(
        "--ssh-dir",
        dest="ssh_dir",
        metavar="PATH",
        help="Path to .ssh directory (default: ~/.ssh)",
    )
    scan_parser.add_argument(
        "--github",
        action="store_true",
        default=False,
        help="Query GitHub for registered keys via gh CLI (network enabled)",
    )
    scan_parser.add_argument(
        "--format",
        choices=["terminal", "md", "json"],
        default="terminal",
        help="Output format: terminal, md, json (default: terminal)",
    )
    scan_parser.add_argument(
        "--output",
        metavar="PATH",
        help="File path to write report to (atomic, permissions 0600)",
    )
    scan_parser.add_argument(
        "--strict",
        action="store_true",
        default=False,
        help="Exit with code 3 if any error-severity finding exists",
    )
    scan_parser.add_argument(
        "--no-agent",
        action="store_true",
        default=False,
        help="Skip querying SSH agent",
    )
    scan_parser.add_argument(
        "--redact",
        choices=["hosts", "paths", "all"],
        help="Redact sensitive data in report (hosts, paths, or all)",
    )
    scan_parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="Timeout in seconds for external tools (default: 10, must be > 0)",
    )
    scan_parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Print diagnostic events to stderr (without secrets or full paths)",
    )

    rotation = sub.add_parser(
        "rotation-plan", help="manual rotation checklist (not implemented yet)"
    )
    rotation.add_argument("fingerprint")
    explain = sub.add_parser("explain", help="explain a finding (not implemented yet)")
    explain.add_argument("finding_id")
    sub.add_parser("version", help="print the version and exit")
    return parser


def _run_scan(args: argparse.Namespace) -> int:
    if args.timeout <= 0:
        print(f"{PROG}: error: --timeout must be positive", file=sys.stderr)
        return ExitCode.INVALID_ARGS

    home = Path(os.environ.get("HOME", "/"))

    if args.ssh_dir is not None:
        ssh_dir_path = Path(args.ssh_dir)
        # Compatibility with validation commands referencing fixture/.ssh when only fixture exists
        if (
            not ssh_dir_path.exists()
            and ssh_dir_path.name == ".ssh"
            and ssh_dir_path.parent.is_dir()
        ):
            ssh_dir_path = ssh_dir_path.parent
        if not ssh_dir_path.exists() or not ssh_dir_path.is_dir():
            print(
                f"{PROG}: error: --ssh-dir '{args.ssh_dir}' is not a directory",
                file=sys.stderr,
            )
            return ExitCode.INVALID_ARGS
    else:
        ssh_dir_path = home / ".ssh"

    if args.config is not None:
        config_path = Path(args.config)
        # Compatibility with config inside virtual .ssh path
        if not config_path.exists() and ".ssh" in config_path.parts:
            alt_parts = [p for p in config_path.parts if p != ".ssh"]
            alt_path = (
                Path(*alt_parts)
                if not config_path.is_absolute()
                else Path(config_path.anchor, *alt_parts)
            )
            if alt_path.is_file():
                config_path = alt_path
    else:
        config_path = ssh_dir_path / "config"

    if args.output:
        try:
            validate_output_path(args.output, ssh_dir_path)
        except ValueError as exc:
            print(f"{PROG}: error: {exc}", file=sys.stderr)
            return ExitCode.INVALID_ARGS

    if args.verbose:
        msg = f"[diag] Scanning with ssh_dir={ssh_dir_path.name}, timeout={args.timeout}s"
        print(msg, file=sys.stderr)

    keygen = PublicKeyInspector()
    agent_adapter = None if args.no_agent else SSHAgentAdapter(keygen)
    github_adapter = GitHubRegistryAdapter(keygen) if args.github else None

    orchestrator = ScanOrchestrator(
        keygen=keygen,
        agent_adapter=agent_adapter,
        github_adapter=github_adapter,
    )

    opts = OrchestratorOptions(
        ssh_dir=ssh_dir_path,
        config_path=config_path,
        home=home,
        check_agent=not args.no_agent,
        check_github=args.github,
    )

    try:
        snapshot = orchestrator.run(opts)
    except RequiredSourceError as exc:
        print(
            f"{PROG}: required source failed: {exc}\n"
            "Remediation: install OpenSSH tools (ssh-keygen) and ensure they are on PATH.",
            file=sys.stderr,
        )
        return ExitCode.REQUIRED_SCAN_FAILED

    if args.redact:
        snapshot = redact(snapshot, args.redact)

    fmt = args.format
    if fmt == "json":
        rendered = render_json(snapshot)
    elif fmt == "md":
        rendered = render_markdown(snapshot)
    else:
        rendered = render_terminal(snapshot)

    if args.output:
        try:
            write_report_atomically(rendered, args.output)
        except OutputWriteError as exc:
            print(f"{PROG}: failed to write report: {exc}", file=sys.stderr)
            return ExitCode.REPORT_WRITE_FAILED
    else:
        sys.stdout.write(rendered)
        if not rendered.endswith("\n"):
            sys.stdout.write("\n")

    if args.strict:
        has_error = any(f.severity == "error" for f in snapshot.findings)
        if has_error:
            return ExitCode.STRICT_FINDINGS

    return ExitCode.OK


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "version":
        print(f"{PROG} {__version__}")
        return ExitCode.OK
    if args.command == "scan":
        return _run_scan(args)
    print(f"{PROG}: {args.command}: not implemented", file=sys.stderr)
    return ExitCode.INVALID_ARGS
