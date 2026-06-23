"""Shared argparse option helpers for the oracle CLI subcommands.

These helpers build the common option groups (output root, generation
parameters) that several subcommands reuse. They are protocol-agnostic parser
wiring with no dependence on the live-provider machinery, so they live here and
are imported by the per-command modules under :mod:`.commands`. They are also
re-exported from :mod:`.main` so historical ``cli.<name>`` lookups keep working.
"""

from __future__ import annotations

import argparse

from ..backends import registered_backend_names
from ..report import DEFAULT_OUTPUT_ROOT


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--out",
        default=str(DEFAULT_OUTPUT_ROOT),
        help="artifact output root (default: %(default)s)",
    )


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return parsed


def _add_generation_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--backend",
        choices=registered_backend_names(),
        default="scapy",
        help="reference backend to target (default: %(default)s)",
    )
    parser.add_argument(
        "--profile",
        default="smoke",
        help="sampling profile from profiles.yaml (default: %(default)s)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=1,
        help="deterministic generator seed (default: %(default)s)",
    )
    parser.add_argument(
        "--count",
        type=_positive_int,
        default=10,
        help="number of generated packet plans (default: %(default)s)",
    )
    parser.add_argument(
        "--case",
        dest="case_name",
        help="case name filter or reproduction coordinate",
    )
    parser.add_argument(
        "--feature",
        help="feature name filter or reproduction coordinate",
    )
    parser.add_argument(
        "--family",
        help="protocol family filter from stacks.yaml",
    )
    parser.add_argument(
        "--root",
        help="root decoder filter from stacks.yaml, such as link:ethernet or l3:ipv4",
    )
    parser.add_argument(
        "--index",
        type=_non_negative_int,
        help="generate one packet plan at the selected index",
    )
