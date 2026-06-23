"""``pcap`` subcommand wiring."""

from __future__ import annotations

import argparse

from ..main import _pcap
from ..options import _add_common_options, _add_generation_options


def register(subparsers: argparse._SubParsersAction) -> None:
    pcap_parser = subparsers.add_parser(
        "pcap",
        help="run pcap validation",
        description="Run pcap oracle validation.",
    )
    _add_common_options(pcap_parser)
    _add_generation_options(pcap_parser)
    pcap_parser.add_argument(
        "--direction",
        choices=("reference_to_libcrafter", "libcrafter_to_reference", "roundtrip"),
        default="roundtrip",
        help="pcap validation direction (default: %(default)s)",
    )
    pcap_parser.add_argument(
        "--corpus",
        help="read packet plans from a corpus plans.json artifact",
    )
    pcap_parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help="keep intermediate pcap and bridge artifacts for successful runs",
    )
    pcap_parser.add_argument(
        "--dry-plan",
        "--dry-run",
        dest="dry_plan",
        action="store_true",
        help="print deterministic pcap plans without invoking a backend",
    )
    pcap_parser.set_defaults(func=_pcap)
