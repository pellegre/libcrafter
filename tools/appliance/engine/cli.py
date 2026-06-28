"""Command-line interface scaffold for tools/appliance."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path


PACKAGE_NAME = "appliance"
COMMANDS = ("info",)


def repo_root() -> Path:
    """Return the libcrafter repository root for appliance commands."""
    configured = os.environ.get("LIBCRAFTER_REPO_ROOT")
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parents[3]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="appliance",
        description="Plan and run libcrafter appliance workloads.",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="command")

    info = subparsers.add_parser(
        "info",
        help="print appliance package metadata",
        description="Print deterministic appliance package metadata.",
    )
    info.set_defaults(command_name="info")

    return parser


def info_payload() -> dict[str, object]:
    return {
        "ok": True,
        "package": PACKAGE_NAME,
        "repo_root": str(repo_root()),
    }


def _write_json(payload: dict[str, object]) -> None:
    sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True))
    sys.stdout.write("\n")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the appliance command-line interface."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "command", None) is None:
        parser.print_help(sys.stdout)
        return 0
    if args.command_name == "info":
        _write_json(info_payload())
        return 0
    parser.error(f"{args.command_name!r} is not implemented yet")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
