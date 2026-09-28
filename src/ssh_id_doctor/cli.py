"""Command-line entry point, sdd-spec §5.

Implements `scan` command with all options (§5.2), exit codes (§5.3),
redaction (§9 step 10), and atomic output writing (§12).
"""

from __future__ import annotations

import argparse
import math
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn

from ssh_id_doctor import __version__
from ssh_id_doctor.adapters.github import GitHubRegistryAdapter
from ssh_id_doctor.exit_codes import ExitCode
from ssh_id_doctor.explain import (
    explain_finding,
    render_explain_json,
    render_explain_markdown,
    render_explain_terminal,
)
from ssh_id_doctor.inspectors import RequiredSourceError
from ssh_id_doctor.inspectors.agent import SSHAgentAdapter
from ssh_id_doctor.inspectors.keygen import _FINGERPRINT_RE, PublicKeyInspector
from ssh_id_doctor.orchestrator import OrchestratorOptions, ScanOrchestrator
from ssh_id_doctor.output import OutputWriteError, validate_output_path, write_report_atomically
from ssh_id_doctor.redact import redact
from ssh_id_doctor.reporting.json_report import render_json
from ssh_id_doctor.reporting.markdown import render_markdown
from ssh_id_doctor.reporting.terminal import render_terminal
from ssh_id_doctor.rotation import (
    build_rotation_plan,
    render_plan_json,
    render_plan_markdown,
    render_plan_terminal,
)

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


def _add_common_scan_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config",
        dest="config",
        metavar="PATH",
        help="Path to ssh_config (default: ~/.ssh/config)",
    )
    parser.add_argument(
        "--ssh-dir",
        dest="ssh_dir",
        metavar="PATH",
        help="Path to .ssh directory (default: ~/.ssh)",
    )
    parser.add_argument(
        "--github",
        action="store_true",
        default=False,
        help="Query GitHub for registered keys via gh CLI (network enabled)",
    )
    parser.add_argument(
        "--format",
        choices=["terminal", "md", "json"],
        default="terminal",
        help="Output format: terminal, md, json (default: terminal)",
    )
    parser.add_argument(
        "--output",
        metavar="PATH",
        help="File path to write report to (atomic, permissions 0600)",
    )
    parser.add_argument(
        "--no-agent",
        action="store_true",
        default=False,
        help="Skip querying SSH agent",
    )
    parser.add_argument(
        "--redact",
        choices=["hosts", "paths", "all"],
        help="Redact sensitive data in report (hosts, paths, or all)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="Timeout in seconds for external tools (default: 10, must be > 0)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Print diagnostic events to stderr (without secrets or full paths)",
    )


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
    _add_common_scan_args(scan_parser)
    scan_parser.add_argument(
        "--strict",
        action="store_true",
        default=False,
        help="Exit with code 3 if any error-severity finding exists",
    )

    rotation = sub.add_parser(
        "rotation-plan",
        help="generate a manual key rotation checklist (§5.2, FR-009)",
        description="Generate a safe, read-only checklist for rotating an SSH key.",
        epilog=PRIVACY_TEXT,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    rotation.add_argument(
        "fingerprint",
        metavar="FINGERPRINT",
        help="SHA256 fingerprint of the identity to rotate (format SHA256:<base64>)",
    )
    _add_common_scan_args(rotation)

    explain = sub.add_parser(
        "explain",
        help="explain a finding by stable id (§5.1)",
        description="Explain a finding by stable id with evidence and manual remediation.",
        epilog=PRIVACY_TEXT,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    explain.add_argument(
        "finding_id",
        metavar="FINDING_ID",
        help="Stable ID of the finding to explain (format <RULE>-<12 hex>)",
    )
    _add_common_scan_args(explain)
    sub.add_parser("version", help="print the version and exit")
    return parser


def _run_scan(args: argparse.Namespace) -> int:
    if not (math.isfinite(args.timeout) and args.timeout > 0):
        print(f"{PROG}: error: --timeout must be positive", file=sys.stderr)
        return ExitCode.INVALID_ARGS

    home = Path(os.environ.get("HOME", "/"))

    if args.ssh_dir is not None:
        ssh_dir_path = Path(args.ssh_dir)
        if not ssh_dir_path.exists() or not ssh_dir_path.is_dir():
            print(
                f"{PROG}: error: --ssh-dir '{args.ssh_dir}' is not a directory",
                file=sys.stderr,
            )
            return ExitCode.INVALID_ARGS
    else:
        ssh_dir_path = home / ".ssh"

    config_path = Path(args.config) if args.config is not None else ssh_dir_path / "config"

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
        timeout=args.timeout,
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


def _run_rotation_plan(args: argparse.Namespace) -> int:
    if not (math.isfinite(args.timeout) and args.timeout > 0):
        print(f"{PROG}: error: --timeout must be positive", file=sys.stderr)
        return ExitCode.INVALID_ARGS

    if not _FINGERPRINT_RE.match(args.fingerprint):
        print(
            f"{PROG}: error: invalid fingerprint format '{args.fingerprint}', "
            "expected SHA256:<base64>",
            file=sys.stderr,
        )
        return ExitCode.INVALID_ARGS

    home = Path(os.environ.get("HOME", "/"))

    if args.ssh_dir is not None:
        ssh_dir_path = Path(args.ssh_dir)
        if not ssh_dir_path.exists() or not ssh_dir_path.is_dir():
            print(
                f"{PROG}: error: --ssh-dir '{args.ssh_dir}' is not a directory",
                file=sys.stderr,
            )
            return ExitCode.INVALID_ARGS
    else:
        ssh_dir_path = home / ".ssh"

    config_path = Path(args.config) if args.config is not None else ssh_dir_path / "config"

    if args.output:
        try:
            validate_output_path(args.output, ssh_dir_path)
        except ValueError as exc:
            print(f"{PROG}: error: {exc}", file=sys.stderr)
            return ExitCode.INVALID_ARGS

    if args.verbose:
        msg = (
            f"[diag] Generating rotation plan for {args.fingerprint} with "
            f"ssh_dir={ssh_dir_path.name}, timeout={args.timeout}s"
        )
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
        timeout=args.timeout,
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

    known_fps = {i.fingerprint for i in snapshot.identities}
    if args.fingerprint not in known_fps:
        print(
            f"{PROG}: error: fingerprint '{args.fingerprint}' not found among known identities",
            file=sys.stderr,
        )
        return ExitCode.INVALID_ARGS

    if args.redact:
        snapshot = redact(snapshot, args.redact)

    plan = build_rotation_plan(snapshot, args.fingerprint)

    fmt = args.format
    if fmt == "json":
        rendered = render_plan_json(plan)
    elif fmt == "md":
        rendered = render_plan_markdown(plan)
    else:
        rendered = render_plan_terminal(plan)

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

    return ExitCode.OK


def _run_explain(args: argparse.Namespace) -> int:
    if not (math.isfinite(args.timeout) and args.timeout > 0):
        print(f"{PROG}: error: --timeout must be positive", file=sys.stderr)
        return ExitCode.INVALID_ARGS

    home = Path(os.environ.get("HOME", "/"))

    if args.ssh_dir is not None:
        ssh_dir_path = Path(args.ssh_dir)
        if not ssh_dir_path.exists() or not ssh_dir_path.is_dir():
            print(
                f"{PROG}: error: --ssh-dir '{args.ssh_dir}' is not a directory",
                file=sys.stderr,
            )
            return ExitCode.INVALID_ARGS
    else:
        ssh_dir_path = home / ".ssh"

    config_path = Path(args.config) if args.config is not None else ssh_dir_path / "config"

    if args.output:
        try:
            validate_output_path(args.output, ssh_dir_path)
        except ValueError as exc:
            print(f"{PROG}: error: {exc}", file=sys.stderr)
            return ExitCode.INVALID_ARGS

    if args.verbose:
        msg = (
            f"[diag] Explaining finding {args.finding_id} with "
            f"ssh_dir={ssh_dir_path.name}, timeout={args.timeout}s"
        )
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
        timeout=args.timeout,
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

    target_finding = next((f for f in snapshot.findings if f.id == args.finding_id), None)
    if target_finding is None:
        print(
            f"{PROG}: error: finding '{args.finding_id}' not found",
            file=sys.stderr,
        )
        print(
            "Run 'ssh-id-doctor scan' with the same options to discover current findings.",
            file=sys.stderr,
        )
        rule_prefix = args.finding_id.split("-")[0] if "-" in args.finding_id else args.finding_id
        matching_findings = [f for f in snapshot.findings if f.rule_id == rule_prefix]
        if matching_findings:
            print(f"Existing findings for rule {rule_prefix}:", file=sys.stderr)
            for mf in matching_findings:
                print(f"  - {mf.id}", file=sys.stderr)
        return ExitCode.INVALID_ARGS

    if args.redact:
        snapshot = redact(snapshot, args.redact)
        target_finding = next(f for f in snapshot.findings if f.id == args.finding_id)

    explanation = explain_finding(target_finding)

    fmt = args.format
    if fmt == "json":
        rendered = render_explain_json(explanation)
    elif fmt == "md":
        rendered = render_explain_markdown(explanation)
    else:
        rendered = render_explain_terminal(explanation)

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

    return ExitCode.OK


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "version":
        print(f"{PROG} {__version__}")
        return ExitCode.OK
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "rotation-plan":
        return _run_rotation_plan(args)
    if args.command == "explain":
        return _run_explain(args)
    print(f"{PROG}: {args.command}: not implemented", file=sys.stderr)
    return ExitCode.INVALID_ARGS
