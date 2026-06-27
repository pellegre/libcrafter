"""``corpus`` subcommand wiring."""

from __future__ import annotations

import argparse

from ...report import DEFAULT_OUTPUT_ROOT
from ...directions import FEATURE_DIRECTIONS
from ..main import _corpus
from ..options import _add_generation_options, _direction_value


def register(subparsers: argparse._SubParsersAction) -> None:
    corpus_parser = subparsers.add_parser(
        "corpus",
        help="generate a reusable packet corpus",
        description="Generate a reusable oracle packet corpus artifact.",
    )
    corpus_parser.add_argument(
        "--out",
        default=str(DEFAULT_OUTPUT_ROOT / "corpus"),
        help="corpus output root (default: %(default)s)",
    )
    _add_generation_options(corpus_parser)
    corpus_parser.add_argument(
        "--direction",
        default="backend_to_libcrafter",
        type=_direction_value,
        choices=FEATURE_DIRECTIONS,
        help="plan direction metadata (default: %(default)s)",
    )
    corpus_parser.set_defaults(func=_corpus)
