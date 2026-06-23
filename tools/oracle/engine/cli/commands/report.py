"""``report`` subcommand wiring."""

from __future__ import annotations

import argparse

from ...report import DEFAULT_OUTPUT_ROOT
from ..main import _report


def register(subparsers: argparse._SubParsersAction) -> None:
    report_parser = subparsers.add_parser(
        "report",
        help="run final oracle validation and write a summary",
        description="Run final oracle validation and write a summary.",
    )
    report_parser.add_argument(
        "--out",
        default=str(DEFAULT_OUTPUT_ROOT / "final"),
        help="final report output directory (default: %(default)s)",
    )
    report_parser.set_defaults(func=_report)
