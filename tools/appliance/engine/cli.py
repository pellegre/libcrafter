"""Command-line interface scaffold for tools/appliance."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from . import image


PACKAGE_NAME = "appliance"
COMMANDS = ("info", "image")

CommandRunner = Callable[[Sequence[str]], object]


def repo_root() -> Path:
    """Return the libcrafter repository root for appliance commands."""
    configured = os.environ.get("LIBCRAFTER_REPO_ROOT")
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parents[3]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="appliance",
        description="Plan and run libcrafter appliance workloads.",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="command")

    info = subparsers.add_parser(
        "info",
        help="print appliance package metadata",
        description="Print deterministic appliance package metadata.",
    )
    info.set_defaults(command_name="info")

    image_parser = subparsers.add_parser(
        "image",
        help="plan, inspect, and build the appliance Docker image",
        description="Plan, inspect, and build the libcrafter appliance Docker image.",
    )
    image_parser.set_defaults(command_name="image")
    image_subparsers = image_parser.add_subparsers(
        dest="image_command",
        metavar="image-command",
        required=True,
    )

    plan = image_subparsers.add_parser(
        "plan",
        help="print deterministic image metadata and Docker argv",
        description="Print deterministic image metadata and Docker argv without running Docker.",
    )
    plan.add_argument(
        "--json",
        action="store_true",
        help="print JSON output",
    )
    plan.set_defaults(image_command_name="plan")

    inspect = image_subparsers.add_parser(
        "inspect",
        help="inspect the configured appliance image with Docker",
        description="Run Docker image inspect for the configured appliance image.",
    )
    inspect.set_defaults(image_command_name="inspect")

    build = image_subparsers.add_parser(
        "build",
        help="build the configured appliance image with Docker",
        description="Run Docker build for the configured appliance image.",
    )
    build.set_defaults(image_command_name="build")

    return parser


def info_payload() -> dict[str, object]:
    return {
        "ok": True,
        "package": PACKAGE_NAME,
        "repo_root": str(repo_root()),
    }


def _write_json(payload: dict[str, object]) -> None:
    sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True))
    sys.stdout.write("\n")


def image_plan_payload() -> dict[str, object]:
    """Return the deterministic image plan payload for CLI output."""

    metadata = image.appliance_image_metadata()
    return {
        "image_tag": metadata["tag"],
        "context_digest": metadata["context_digest"],
        "dockerfile_path": metadata["dockerfile_path"],
        "context_path": metadata["context_dir"],
        "inspect_argv": metadata["inspect_argv"],
        "build_argv": metadata["build_argv"],
    }


def _write_image_plan_text(payload: dict[str, object]) -> None:
    inspect_argv = [str(part) for part in payload["inspect_argv"]]
    build_argv = [str(part) for part in payload["build_argv"]]
    sys.stdout.write(f"image_tag: {payload['image_tag']}\n")
    sys.stdout.write(f"context_digest: {payload['context_digest']}\n")
    sys.stdout.write(f"dockerfile_path: {payload['dockerfile_path']}\n")
    sys.stdout.write(f"context_path: {payload['context_path']}\n")
    sys.stdout.write(f"inspect_argv: {shlex.join(inspect_argv)}\n")
    sys.stdout.write(f"build_argv: {shlex.join(build_argv)}\n")


def _default_command_runner(argv: Sequence[str]) -> int:
    return subprocess.run(list(argv), check=False).returncode


def _return_code(result: object) -> int:
    if isinstance(result, int):
        return result
    return int(getattr(result, "returncode"))


def _run_image_command(args: argparse.Namespace, runner: CommandRunner) -> int:
    payload = image_plan_payload()
    if args.image_command_name == "plan":
        if args.json:
            _write_json(payload)
        else:
            _write_image_plan_text(payload)
        return 0
    if args.image_command_name == "inspect":
        return _return_code(runner([str(part) for part in payload["inspect_argv"]]))
    if args.image_command_name == "build":
        return _return_code(runner([str(part) for part in payload["build_argv"]]))
    raise ValueError(f"unknown image command: {args.image_command_name}")


def main(
    argv: Sequence[str] | None = None,
    *,
    command_runner: CommandRunner = _default_command_runner,
) -> int:
    """Run the appliance command-line interface."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "command", None) is None:
        parser.print_help(sys.stdout)
        return 0
    if args.command_name == "info":
        _write_json(info_payload())
        return 0
    if args.command_name == "image":
        return _run_image_command(args, command_runner)
    parser.error(f"{args.command_name!r} is not implemented yet")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
