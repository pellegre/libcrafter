"""``generate`` subcommand wiring."""

from __future__ import annotations

import argparse

from ..main import _generate
from ..options import _add_common_options, _add_generation_options


def register(subparsers: argparse._SubParsersAction) -> None:
    generate_parser = subparsers.add_parser(
        "generate",
        help="generate deterministic packet plans",
        description="Generate deterministic oracle packet plans.",
    )
    _add_common_options(generate_parser)
    _add_generation_options(generate_parser)
    generate_parser.add_argument(
        "--direction",
        default="reference_to_libcrafter",
        choices=(
            "reference_to_libcrafter",
            "libcrafter_to_reference",
            "roundtrip",
            "live",
            "live_exchange",
        ),
        help="plan direction metadata (default: %(default)s)",
    )
    generate_parser.set_defaults(func=_generate)
