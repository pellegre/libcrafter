"""``backend-info`` subcommand wiring."""

from __future__ import annotations

import argparse

from ...backends import registered_backend_names
from ..main import _backend_info


def register(subparsers: argparse._SubParsersAction) -> None:
    backend_info_parser = subparsers.add_parser(
        "backend-info",
        help="print backend dependency and version metadata",
        description="Print oracle backend dependency and version metadata.",
    )
    backend_info_parser.add_argument(
        "--backend",
        choices=registered_backend_names(),
        default="scapy",
        help="backend to inspect (default: %(default)s)",
    )
    backend_info_parser.set_defaults(func=_backend_info)
