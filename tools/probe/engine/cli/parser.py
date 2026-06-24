"""Argparse construction for the probe CLI.

This module holds the parser-building concern lifted out of
:mod:`engine.cli.main` without any behavior change. ``_build_parser`` is
re-imported back into the CLI body's namespace so ``cli._build_parser`` stays
resolvable (the profile suite reads and calls it as a ``cli`` attribute) and so
``main()`` keeps constructing the parser identically. The ``--help`` output is
byte-identical to the former single-module parser: the same ``prog``,
description, and argument definitions are emitted in the same order.
"""

from __future__ import annotations

import argparse

from ..cases import DEFAULT_PROFILE
from ..lab import probe_provider_names


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tools/probe/run",
        description="Run libcrafter probe validation.",
    )
    parser.add_argument(
        "--provider",
        choices=probe_provider_names(),
        required=True,
        help="probe provider to use",
    )
    parser.add_argument(
        "--profile",
        default=DEFAULT_PROFILE,
        help=(
            "probe sampling profile (default: %(default)s); "
            "'behavior' selects the full DNS/DHCP/ARP/UDP suite"
        ),
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=1,
        help="deterministic probe selection seed (default: %(default)s)",
    )
    parser.add_argument(
        "--count",
        type=_positive_int,
        default=None,
        help=(
            "number of probe cases to plan "
            "(default: profile default, smoke=5, behavior=40)"
        ),
    )
    parser.add_argument(
        "--case",
        dest="case_names",
        action="append",
        help="probe case name to include; may be repeated or comma-separated",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="write a deterministic non-mutating probe plan and report",
    )
    parser.add_argument(
        "--confirm-live-run",
        action="store_true",
        help="confirm protected non-dry-run provider execution",
    )
    parser.add_argument(
        "--out",
        help="probe report output directory or report.json path",
    )
    return parser
