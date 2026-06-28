"""Emit a non-mutating LAN reachability dry-run plan."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping, Sequence
from typing import TextIO

from tools.appliance.checks.common import environment, failure, resolve_value, write_json


CHECK_NAME = "lan-reachability-plan"
DEFAULT_IFACE_ENV = "LIBCRAFTER_IFACE"
DEFAULT_TARGET = "192.0.2.1"


def build_lan_reachability_plan(iface: str, *, target: str = DEFAULT_TARGET) -> dict[str, object]:
    """Return a documentation-safe LAN reachability plan."""

    return {
        "ok": True,
        "check": CHECK_NAME,
        "iface": iface,
        "target": target,
        "dry_run": True,
        "live_transmit": False,
        "plan": {
            "kind": "arp-or-icmp-link-check",
            "description": "Build and inspect a reachability packet plan before any live send.",
            "requires_live_gate": True,
            "suggested_followup": "run generated tool with an explicit live flag only in an authorized LAN",
        },
    }


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    stdout: TextIO = sys.stdout,
) -> int:
    """Run the LAN reachability planner and emit one JSON result."""

    args = _parser().parse_args(argv)
    env = environment(environ)
    iface, iface_env = resolve_value(explicit=args.iface, env_name=args.iface_env, environ=env)
    if not args.dry_run:
        payload = failure(
            CHECK_NAME,
            "live_check_rejected",
            "lan reachability check only emits a dry-run plan",
            iface=iface,
            target=args.target,
            dry_run=False,
            live_transmit=False,
            requires_live_gate=True,
        )
        write_json(payload, stdout)
        return 1
    if not iface:
        payload = failure(
            CHECK_NAME,
            "missing_interface_env",
            f"{args.iface_env} is not set",
            iface="",
            iface_env=args.iface_env,
            target=args.target,
            dry_run=True,
            live_transmit=False,
        )
        write_json(payload, stdout)
        return 1

    payload = build_lan_reachability_plan(iface, target=args.target)
    if iface_env:
        payload["iface_env"] = iface_env
    write_json(payload, stdout)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Plan LAN reachability without transmitting.")
    parser.add_argument("--dry-run", action="store_true", help="emit a non-mutating plan")
    parser.add_argument("--iface", default="", help="interface name to plan against")
    parser.add_argument(
        "--iface-env",
        default=DEFAULT_IFACE_ENV,
        help="environment variable that names the interface",
    )
    parser.add_argument("--target", default=DEFAULT_TARGET, help="documentation-safe target address")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
