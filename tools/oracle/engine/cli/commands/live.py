"""``live`` subcommand wiring."""

from __future__ import annotations

import argparse

from ..main import _live
from ..options import _add_common_options, _add_generation_options


def register(subparsers: argparse._SubParsersAction) -> None:
    live_parser = subparsers.add_parser(
        "live",
        help="run live validation",
        description="Run live oracle validation.",
    )
    _add_common_options(live_parser)
    _add_generation_options(live_parser)
    from ...providers.registry import registered_provider_names

    live_parser.add_argument(
        "--provider",
        choices=("local-dry-run", *registered_provider_names()),
        required=True,
        help="live provider to use",
    )
    live_parser.add_argument(
        "--direction",
        choices=("libcrafter_to_reference", "reference_to_libcrafter", "live_exchange"),
        default="live_exchange",
        help="live validation direction (default: %(default)s)",
    )
    live_parser.add_argument(
        "--corpus",
        help="read packet plans from a corpus plans.json artifact",
    )
    live_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="plan provider-backed live validation without creating infrastructure",
    )
    live_parser.add_argument(
        "--confirm-live-run",
        action="store_true",
        help="confirm protected non-dry-run provider execution",
    )
    live_parser.add_argument(
        "--keep-wire-endpoints",
        action="store_true",
        help="keep provider endpoints after a non-dry-run for debugging",
    )
    live_parser.set_defaults(func=_live)
