"""``self-check`` subcommand wiring."""

from __future__ import annotations

import argparse

from ..main import _self_check


def register(subparsers: argparse._SubParsersAction) -> None:
    self_check_parser = subparsers.add_parser(
        "self-check",
        help="run oracle engine self checks",
        description="Run lightweight oracle engine self checks.",
    )
    self_check_parser.set_defaults(func=_self_check)
