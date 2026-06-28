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
from . import modules as module_registry
from . import profiles as profile_registry


PACKAGE_NAME = "appliance"
COMMANDS = ("info", "image", "profiles", "modules")

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

    profiles_parser = subparsers.add_parser(
        "profiles",
        help="list and inspect appliance runtime profiles",
        description="List and inspect built-in appliance runtime profiles.",
    )
    profiles_parser.set_defaults(command_name="profiles")
    profile_subparsers = profiles_parser.add_subparsers(
        dest="profiles_command",
        metavar="profiles-command",
        required=True,
    )

    profiles_list = profile_subparsers.add_parser(
        "list",
        help="list built-in appliance runtime profiles",
        description="List built-in appliance runtime profiles in deterministic order.",
    )
    profiles_list.add_argument("--json", action="store_true", help="print JSON output")
    profiles_list.set_defaults(profiles_command_name="list")

    profiles_show = profile_subparsers.add_parser(
        "show",
        help="show one appliance runtime profile",
        description="Show one appliance runtime profile manifest.",
    )
    profiles_show.add_argument("profile", metavar="PROFILE", help="profile name to show")
    profiles_show.add_argument("--json", action="store_true", help="print JSON output")
    profiles_show.set_defaults(profiles_command_name="show")

    modules_parser = subparsers.add_parser(
        "modules",
        help="list and inspect appliance modules",
        description="List and inspect built-in appliance modules.",
    )
    modules_parser.set_defaults(command_name="modules")
    module_subparsers = modules_parser.add_subparsers(
        dest="modules_command",
        metavar="modules-command",
        required=True,
    )

    modules_list = module_subparsers.add_parser(
        "list",
        help="list built-in appliance modules",
        description="List built-in appliance modules in deterministic order.",
    )
    modules_list.add_argument("--json", action="store_true", help="print JSON output")
    modules_list.set_defaults(modules_command_name="list")

    modules_show = module_subparsers.add_parser(
        "show",
        help="show one appliance module",
        description="Show one appliance module manifest.",
    )
    modules_show.add_argument("module", metavar="MODULE", help="module name to show")
    modules_show.add_argument("--json", action="store_true", help="print JSON output")
    modules_show.set_defaults(modules_command_name="show")

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


def _profile_list_payload() -> dict[str, object]:
    loaded = profile_registry.load_profiles()
    return {
        "ok": True,
        "profiles": [loaded[name].to_dict() for name in sorted(loaded)],
    }


def _module_list_payload() -> dict[str, object]:
    loaded = module_registry.load_modules()
    return {
        "ok": True,
        "modules": [loaded[name].to_dict() for name in sorted(loaded)],
    }


def _profile_show_payload(name: str) -> dict[str, object]:
    return {
        "ok": True,
        "profile": profile_registry.resolve_profile(name).to_dict(),
    }


def _module_show_payload(name: str) -> dict[str, object]:
    return {
        "ok": True,
        "module": module_registry.resolve_module(name).to_dict(),
    }


def _write_profile_list_text(payload: dict[str, object]) -> None:
    for profile in payload["profiles"]:
        if isinstance(profile, dict):
            sys.stdout.write(f"{profile['name']}\t{profile.get('description', '')}\n")


def _write_module_list_text(payload: dict[str, object]) -> None:
    for module in payload["modules"]:
        if isinstance(module, dict):
            sys.stdout.write(f"{module['name']}\t{module.get('description', '')}\n")


def _write_profile_text(payload: dict[str, object]) -> None:
    profile = payload["profile"]
    if not isinstance(profile, dict):
        return
    sys.stdout.write(f"name: {profile['name']}\n")
    sys.stdout.write(f"description: {profile.get('description', '')}\n")
    sys.stdout.write(f"image: {profile.get('image', '')}\n")
    sys.stdout.write(f"network_mode: {profile.get('network_mode', '')}\n")


def _write_module_text(payload: dict[str, object]) -> None:
    module = payload["module"]
    if not isinstance(module, dict):
        return
    profiles = module.get("profiles", [])
    profile_text = ", ".join(str(profile) for profile in profiles) if isinstance(profiles, list) else ""
    sys.stdout.write(f"name: {module['name']}\n")
    sys.stdout.write(f"description: {module.get('description', '')}\n")
    sys.stdout.write(f"profiles: {profile_text}\n")


def _registry_error_payload(
    command: str,
    error: str,
    exc: profile_registry.UnknownApplianceProfileError | module_registry.UnknownApplianceModuleError,
) -> dict[str, object]:
    return {
        "ok": False,
        "command": command,
        "error": error,
        "message": str(exc),
        "name": exc.name,
        "known": list(exc.known),
    }


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


def _run_profiles_command(args: argparse.Namespace) -> int:
    if args.profiles_command_name == "list":
        payload = _profile_list_payload()
        if args.json:
            _write_json(payload)
        else:
            _write_profile_list_text(payload)
        return 0
    if args.profiles_command_name == "show":
        try:
            payload = _profile_show_payload(args.profile)
        except profile_registry.UnknownApplianceProfileError as exc:
            if args.json:
                _write_json(_registry_error_payload("profiles show", "unknown_profile", exc))
            else:
                print(str(exc), file=sys.stderr)
            return 2
        if args.json:
            _write_json(payload)
        else:
            _write_profile_text(payload)
        return 0
    raise ValueError(f"unknown profiles command: {args.profiles_command_name}")


def _run_modules_command(args: argparse.Namespace) -> int:
    if args.modules_command_name == "list":
        payload = _module_list_payload()
        if args.json:
            _write_json(payload)
        else:
            _write_module_list_text(payload)
        return 0
    if args.modules_command_name == "show":
        try:
            payload = _module_show_payload(args.module)
        except module_registry.UnknownApplianceModuleError as exc:
            if args.json:
                _write_json(_registry_error_payload("modules show", "unknown_module", exc))
            else:
                print(str(exc), file=sys.stderr)
            return 2
        if args.json:
            _write_json(payload)
        else:
            _write_module_text(payload)
        return 0
    raise ValueError(f"unknown modules command: {args.modules_command_name}")


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
    if args.command_name == "profiles":
        return _run_profiles_command(args)
    if args.command_name == "modules":
        return _run_modules_command(args)
    parser.error(f"{args.command_name!r} is not implemented yet")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
