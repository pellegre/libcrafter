"""Command-line interface for oracle packet validation."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from .model import RunReport, dumps_json
from .report import DEFAULT_OUTPUT_ROOT


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
        choices=("scapy",),
        default="scapy",
        help="reference backend to target (default: %(default)s)",
    )
    parser.add_argument(
        "--profile",
        choices=("smoke", "ci", "wild", "boundary", "fuzz"),
        default="smoke",
        help="sampling profile (default: %(default)s)",
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
        choices=("ipv4", "ipv6"),
        help="protocol family filter",
    )
    parser.add_argument(
        "--index",
        type=_non_negative_int,
        help="generate one packet plan at the selected index",
    )


def _not_implemented(args: argparse.Namespace) -> int:
    print(
        f"oracle {args.mode} mode is not implemented yet; parsed output root: {args.out}",
        file=sys.stderr,
    )
    return 2


def _offline(args: argparse.Namespace) -> int:
    if not args.dry_plan:
        return _not_implemented(args)

    from .generator import generate_plans

    plans = generate_plans(
        seed=args.seed,
        profile=args.profile,
        count=args.count,
        family=args.family,
        case=args.case_name,
        feature=args.feature,
        index=args.index,
    )
    report = RunReport(
        mode="offline",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(plans),
        status="dry-plan",
        selected_specs=["builtin-stack-grammar"],
        metadata={
            "dry_plan": True,
            "requested_count": args.count,
            "plans": [plan.to_dict() for plan in plans],
        },
    )
    sys.stdout.write(dumps_json(report))
    return 0


def _backend_info(args: argparse.Namespace) -> int:
    if args.backend == "scapy":
        from .backends.scapy.bootstrap import backend_info

        sys.stdout.write(dumps_json(backend_info()))
        return 0

    print(f"unsupported backend: {args.backend}", file=sys.stderr)
    return 2


def _self_check(args: argparse.Namespace) -> int:
    from .generator import run_self_checks

    run_self_checks()
    sys.stdout.write(dumps_json({"status": "ok", "checks": ["generator"]}))
    return 0


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

    offline_parser = subparsers.add_parser(
        "offline",
        help="run offline validation",
        description="Run offline oracle validation.",
    )
    _add_common_options(offline_parser)
    _add_generation_options(offline_parser)
    offline_parser.add_argument(
        "--dry-plan",
        action="store_true",
        help="print generated packet plans without invoking a backend",
    )
    offline_parser.set_defaults(func=_offline)

    for mode in ("pcap", "live"):
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

    self_check_parser = subparsers.add_parser(
        "self-check",
        help="run oracle engine self checks",
        description="Run lightweight oracle engine self checks.",
    )
    self_check_parser.set_defaults(func=_self_check)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
