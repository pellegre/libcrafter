"""Check that a Docker image is available locally."""

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


CHECK_NAME = "image-available"
DEFAULT_IMAGE_ENV = "LIBCRAFTER_APPLIANCE_IMAGE"


def check_image_available(
    docker: str,
    image: str,
    *,
    runner: CommandRunner | None = None,
    timeout_seconds: float = 5.0,
) -> dict[str, object]:
    """Return a structured readiness result for one Docker image tag."""

    command_argv = [docker, "image", "inspect", image, "--format", "{{json .Id}}"]
    result = run_command(command_argv, runner=runner, timeout_seconds=timeout_seconds)
    fields = command_fields(result)
    fields["command_argv"] = command_argv
    fields["docker"] = docker
    fields["image"] = image
    if result.returncode != 0:
        return failure(
            CHECK_NAME,
            "image_not_available",
            f"appliance image is not available: {image}",
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
    """Run the Docker image check and emit one JSON result."""

    args = _parser().parse_args(argv)
    env = environment(environ)
    image, image_env = resolve_value(explicit=args.image, env_name=args.image_env, environ=env)
    if not image:
        payload = failure(
            CHECK_NAME,
            "missing_image",
            f"{args.image_env} is not set",
            image="",
            image_env=args.image_env,
        )
        write_json(payload, stdout)
        return 1

    payload = check_image_available(
        args.docker,
        image,
        runner=runner,
        timeout_seconds=args.timeout,
    )
    if image_env:
        payload["image_env"] = image_env
    write_json(payload, stdout)
    return 0 if payload["ok"] else 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check local appliance image availability.")
    parser.add_argument("--docker", default="docker", help="docker command to execute")
    parser.add_argument("--image", default="", help="image tag to inspect")
    parser.add_argument(
        "--image-env",
        default=DEFAULT_IMAGE_ENV,
        help="environment variable that names the image tag",
    )
    parser.add_argument("--timeout", type=float, default=5.0, help="command timeout in seconds")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
