"""Emit a gated, non-mutating 802.11 injection smoke-test plan."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping, Sequence
from typing import TextIO

from tools.appliance.checks.common import environment, failure, resolve_value, write_json


CHECK_NAME = "dot11-injection-smoke"
DEFAULT_IFACE_ENV = "LIBCRAFTER_DOT11_IFACE"
DEFAULT_CHANNEL_ENV = "LIBCRAFTER_DOT11_CHANNEL"


def build_dot11_injection_smoke_plan(
    iface: str,
    *,
    channel: str = "",
) -> dict[str, object]:
    """Return a dry-run radiotap injection smoke plan."""

    return {
        "ok": True,
        "check": CHECK_NAME,
        "iface": iface,
        "channel": channel,
        "dry_run": True,
        "live_transmit": False,
        "requires_live_gate": True,
        "plan": {
            "kind": "radiotap-dot11-injection-smoke",
            "description": "Build and inspect a minimal radiotap injection candidate without transmitting.",
            "packet_root": "Radiotap",
            "interface_must_be_monitor_mode": True,
        },
    }


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    stdout: TextIO = sys.stdout,
) -> int:
    """Run the dot11 injection smoke planner and emit one JSON result."""

    args = _parser().parse_args(argv)
    env = environment(environ)
    iface, iface_env = resolve_value(explicit=args.iface, env_name=args.iface_env, environ=env)
    channel, channel_env = resolve_value(
        explicit=args.channel,
        env_name=args.channel_env,
        environ=env,
    )
    if not args.dry_run:
        payload = failure(
            CHECK_NAME,
            "live_check_rejected",
            "dot11 injection smoke only emits a dry-run plan",
            iface=iface,
            channel=channel,
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
            channel=channel,
            dry_run=True,
            live_transmit=False,
            requires_live_gate=True,
        )
        write_json(payload, stdout)
        return 1

    payload = build_dot11_injection_smoke_plan(iface, channel=channel)
    if iface_env:
        payload["iface_env"] = iface_env
    if channel_env:
        payload["channel_env"] = channel_env
    write_json(payload, stdout)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Plan dot11 injection smoke without transmitting.")
    parser.add_argument("--dry-run", action="store_true", help="emit a non-mutating plan")
    parser.add_argument("--iface", default="", help="monitor interface name to plan against")
    parser.add_argument(
        "--iface-env",
        default=DEFAULT_IFACE_ENV,
        help="environment variable that names the monitor interface",
    )
    parser.add_argument("--channel", default="", help="already-pinned RF channel")
    parser.add_argument(
        "--channel-env",
        default=DEFAULT_CHANNEL_ENV,
        help="environment variable that names the pinned channel",
    )
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
