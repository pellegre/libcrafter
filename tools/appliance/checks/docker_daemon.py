"""Check that Docker daemon inspection is available."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping, Sequence
from typing import TextIO

from tools.appliance.checks.common import CommandRunner, command_fields, failure, run_command, write_json


CHECK_NAME = "docker-daemon"


def check_docker_daemon(
    docker: str,
    *,
    runner: CommandRunner | None = None,
    timeout_seconds: float = 5.0,
) -> dict[str, object]:
    """Return a structured readiness result for Docker daemon access."""

    command_argv = [docker, "info", "--format", "{{json .ServerVersion}}"]
    result = run_command(command_argv, runner=runner, timeout_seconds=timeout_seconds)
    fields = command_fields(result)
    fields["command_argv"] = command_argv
    fields["docker"] = docker
    if result.returncode != 0:
        return failure(
            CHECK_NAME,
            "docker_daemon_unavailable",
            "docker daemon is not available",
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
    """Run the Docker daemon check and emit one JSON result."""

    del environ
    args = _parser().parse_args(argv)
    payload = check_docker_daemon(args.docker, runner=runner, timeout_seconds=args.timeout)
    write_json(payload, stdout)
    return 0 if payload["ok"] else 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check Docker daemon readiness.")
    parser.add_argument("--docker", default="docker", help="docker command to execute")
    parser.add_argument("--timeout", type=float, default=5.0, help="command timeout in seconds")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
