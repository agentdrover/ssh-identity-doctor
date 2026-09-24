"""Command-line entry point, sdd-spec §5.

Only `version` works in this slice; scan, rotation-plan and explain are
declared so the command surface is fixed, and exit 1 until implemented.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import NoReturn

from ssh_id_doctor import __version__
from ssh_id_doctor.exit_codes import ExitCode

PROG = "ssh-id-doctor"


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
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND", parser_class=_ArgumentParser)
    sub.required = True

    sub.add_parser("scan", help="inventory SSH identities (not implemented yet)")
    rotation = sub.add_parser(
        "rotation-plan", help="manual rotation checklist (not implemented yet)"
    )
    rotation.add_argument("fingerprint")
    explain = sub.add_parser("explain", help="explain a finding (not implemented yet)")
    explain.add_argument("finding_id")
    sub.add_parser("version", help="print the version and exit")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "version":
        print(f"{PROG} {__version__}")
        return ExitCode.OK
    print(f"{PROG}: {args.command}: not implemented", file=sys.stderr)
    return ExitCode.INVALID_ARGS
