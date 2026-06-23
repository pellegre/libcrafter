"""``offline`` subcommand wiring."""

from __future__ import annotations

import argparse

from ..main import _offline
from ..options import _add_common_options, _add_generation_options


def register(subparsers: argparse._SubParsersAction) -> None:
    offline_parser = subparsers.add_parser(
        "offline",
        help="run offline validation",
        description="Run offline oracle validation.",
    )
    _add_common_options(offline_parser)
    _add_generation_options(offline_parser)
    offline_parser.add_argument(
        "--direction",
        choices=("reference_to_libcrafter", "libcrafter_to_reference"),
        default="reference_to_libcrafter",
        help="offline validation direction (default: %(default)s)",
    )
    offline_parser.add_argument(
        "--corpus",
        help="read packet plans from a corpus plans.json artifact",
    )
    offline_parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help="keep intermediate vector and decoded artifacts for successful runs",
    )
    offline_parser.add_argument(
        "--dry-plan",
        action="store_true",
        help="print generated packet plans without invoking a backend",
    )
    offline_parser.add_argument(
        "--emit-vectors",
        action="store_true",
        help="print Scapy-materialized packet vectors without invoking libcrafter",
    )
    offline_parser.add_argument(
        "--emit-decoded",
        action="store_true",
        help="print normalized Scapy-decoded packet models without invoking libcrafter",
    )
    offline_parser.set_defaults(func=_offline)
