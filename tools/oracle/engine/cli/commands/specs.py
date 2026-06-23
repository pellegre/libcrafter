"""``specs`` subcommand wiring (``validate`` and ``suite``)."""

from __future__ import annotations

import argparse

from ...report import DEFAULT_OUTPUT_ROOT
from ..main import _specs_suite, _specs_validate


def register(subparsers: argparse._SubParsersAction) -> None:
    specs_parser = subparsers.add_parser(
        "specs",
        help="inspect executable oracle specs",
        description="Inspect executable oracle specs.",
    )
    specs_subparsers = specs_parser.add_subparsers(
        dest="specs_command",
        metavar="COMMAND",
        required=True,
    )
    specs_validate_parser = specs_subparsers.add_parser(
        "validate",
        help="load and validate all executable oracle specs",
        description="Load and validate all executable oracle specs.",
    )
    specs_validate_parser.add_argument(
        "--json",
        action="store_true",
        help="print the validation summary as JSON",
    )
    specs_validate_parser.add_argument(
        "--strict",
        action="store_true",
        help="run strict cross-file spec validation",
    )
    specs_validate_parser.set_defaults(func=_specs_validate)

    specs_suite_parser = specs_subparsers.add_parser(
        "suite",
        help="emit the reproducible offline case suite for a protocol family",
        description=(
            "Emit every offline-eligible supported case for a protocol family in "
            "each direction it declares, derived from the feature spec's "
            "supported_cases (directions + byte_policy). structured_error cases are "
            "excluded because the oracle has no offline malformed pathway. "
            "contract_only cases are reported in JSON without runnable commands."
        ),
    )
    specs_suite_parser.add_argument(
        "--family",
        default="dns",
        help="protocol family to emit the offline suite for (default: %(default)s)",
    )
    specs_suite_parser.add_argument(
        "--backend",
        default="scapy",
        choices=("scapy", "wireshark"),
        help="reference backend for the emitted commands (default: %(default)s)",
    )
    specs_suite_parser.add_argument(
        "--profile",
        default="ci",
        help="sampling profile for the emitted commands (default: %(default)s)",
    )
    specs_suite_parser.add_argument(
        "--seed",
        type=int,
        default=2701,
        help="base seed; per-case seeds derive deterministically (default: %(default)s)",
    )
    specs_suite_parser.add_argument(
        "--out",
        default=str(DEFAULT_OUTPUT_ROOT),
        help="artifact output root for the emitted commands (default: %(default)s)",
    )
    specs_suite_parser.add_argument(
        "--json",
        action="store_true",
        help="print the suite plan as JSON",
    )
    specs_suite_parser.add_argument(
        "--run",
        action="store_true",
        help="execute each emitted offline command and report the aggregate result",
    )
    specs_suite_parser.set_defaults(func=_specs_suite)
