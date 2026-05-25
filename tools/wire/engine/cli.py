"""Command-line interface skeleton for tools/wire."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence


COMMANDS = (
    "doctor",
    "create-endpoint",
    "destroy-endpoint",
    "exec",
    "upload",
    "download",
    "collect-artifacts",
    "ssh-info",
    "list-endpoints",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wire",
        description="Create and operate one wire endpoint at a time.",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="command")
    for command in COMMANDS:
        subparser = subparsers.add_parser(
            command,
            help="reserved for a later implementation",
        )
        subparser.set_defaults(command_name=command)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the wire command-line interface."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "command", None) is None:
        parser.print_help(sys.stdout)
        return 0
    parser.error(f"{args.command_name!r} is not implemented yet")
    return 2
