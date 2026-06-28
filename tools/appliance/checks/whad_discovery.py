"""Check that WHAD discovery can be invoked without RF transmission."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping, Sequence
from typing import TextIO

from tools.appliance.checks.common import (
    CommandRunner,
    command_fields,
    environment,
    failure,
    resolve_value,
    run_command,
    write_json,
)


CHECK_NAME = "whad-discovery"
DEFAULT_DEVICE_ENV = "LIBCRAFTER_WHAD_DEVICE"


def check_whad_discovery(
    *,
    tool: str,
    device: str = "",
    runner: CommandRunner | None = None,
    timeout_seconds: float = 5.0,
) -> dict[str, object]:
    """Return a structured readiness result for a WHAD discovery command."""

    command_argv = [tool, "discover"]
    if device:
        command_argv.extend(["--device", device])
    result = run_command(command_argv, runner=runner, timeout_seconds=timeout_seconds)
    fields = command_fields(result)
    fields["command_argv"] = command_argv
    fields["device"] = device
    fields["live_transmit"] = False
    fields["tool"] = tool
    if result.returncode != 0:
        return failure(
            CHECK_NAME,
            "whad_discovery_failed",
            "WHAD discovery command failed",
            **fields,
        )
    return {
        "ok": True,
        "check": CHECK_NAME,
        **fields,
    }


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    stdout: TextIO = sys.stdout,
    runner: CommandRunner | None = None,
) -> int:
    """Run the WHAD discovery check and emit one JSON result."""

    args = _parser().parse_args(argv)
    env = environment(environ)
    device, device_env = resolve_value(explicit=args.device, env_name=args.device_env, environ=env)
    payload = check_whad_discovery(
        tool=args.tool,
        device=device,
        runner=runner,
        timeout_seconds=args.timeout,
    )
    if device_env:
        payload["device_env"] = device_env
    write_json(payload, stdout)
    return 0 if payload["ok"] else 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check WHAD discovery readiness.")
    parser.add_argument("--device", default="", help="WHAD serial device path")
    parser.add_argument(
        "--device-env",
        default=DEFAULT_DEVICE_ENV,
        help="environment variable that names the WHAD serial device",
    )
    parser.add_argument("--tool", default="whad", help="WHAD command to execute")
    parser.add_argument("--timeout", type=float, default=5.0, help="command timeout in seconds")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
