"""Command-line interface for oracle packet validation."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from .model import dumps_json
from .report import DEFAULT_OUTPUT_ROOT


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--out",
        default=str(DEFAULT_OUTPUT_ROOT),
        help="artifact output root (default: %(default)s)",
    )


def _not_implemented(args: argparse.Namespace) -> int:
    print(
        f"oracle {args.mode} mode is not implemented yet; parsed output root: {args.out}",
        file=sys.stderr,
    )
    return 2


def _backend_info(args: argparse.Namespace) -> int:
    if args.backend == "scapy":
        from .backends.scapy.bootstrap import backend_info

        sys.stdout.write(dumps_json(backend_info()))
        return 0

    print(f"unsupported backend: {args.backend}", file=sys.stderr)
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tools/oracle/run",
        description="Run libcrafter oracle validation.",
    )
    subparsers = parser.add_subparsers(
        dest="mode",
        metavar="MODE",
        required=True,
    )

    for mode in ("offline", "pcap", "live"):
        mode_parser = subparsers.add_parser(
            mode,
            help=f"run {mode} validation",
            description=f"Run {mode} oracle validation.",
        )
        _add_common_options(mode_parser)
        mode_parser.set_defaults(func=_not_implemented)

    backend_info_parser = subparsers.add_parser(
        "backend-info",
        help="print backend dependency and version metadata",
        description="Print oracle backend dependency and version metadata.",
    )
    backend_info_parser.add_argument(
        "--backend",
        choices=("scapy",),
        default="scapy",
        help="backend to inspect (default: %(default)s)",
    )
    backend_info_parser.set_defaults(func=_backend_info)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
