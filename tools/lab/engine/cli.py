"""Command-line interface scaffold for tools/lab."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence


COMMANDS = (
    "providers",
    "plan",
    "doctor",
    "create",
    "destroy",
    "list-sessions",
    "session-info",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lab",
        description="Plan and operate provider-backed multi-endpoint lab sessions.",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="command")

    providers = subparsers.add_parser(
        "providers",
        help="list registered lab providers",
        description="List registered lab providers and their wire mappings.",
    )
    providers.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    providers.set_defaults(command_name="providers")

    doctor = subparsers.add_parser(
        "doctor",
        help="check provider prerequisites",
        description="Check whether one lab provider request can run.",
    )
    doctor.add_argument("--provider", required=True, help="lab provider to check")
    doctor.add_argument("--dry-run", action="store_true", help="check without making changes")
    doctor.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    doctor.set_defaults(command_name="doctor")

    plan = subparsers.add_parser(
        "plan",
        help="plan a lab session",
        description="Plan a provider-backed role topology without creating resources.",
    )
    _add_session_request_options(plan)
    plan.add_argument("--dry-run", action="store_true", help="plan without making changes")
    plan.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    plan.set_defaults(command_name="plan")

    create = subparsers.add_parser(
        "create",
        help="create a lab session",
        description="Create a provider-backed role topology after explicit confirmation.",
    )
    _add_session_request_options(create)
    create.add_argument(
        "--confirm-live-run",
        action="store_true",
        help="confirm protected non-dry-run provider execution",
    )
    create.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    create.set_defaults(command_name="create")

    destroy = subparsers.add_parser(
        "destroy",
        help="destroy a lab session",
        description="Destroy tracked endpoints and resources for one lab session.",
    )
    destroy.add_argument("--session", required=True, help="lab session id to destroy")
    destroy.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    destroy.set_defaults(command_name="destroy")

    list_sessions = subparsers.add_parser(
        "list-sessions",
        help="list tracked lab sessions",
        description="List tracked lab sessions.",
    )
    list_sessions.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    list_sessions.set_defaults(command_name="list-sessions")

    session_info = subparsers.add_parser(
        "session-info",
        help="inspect one lab session",
        description="Show tracked metadata for one lab session.",
    )
    session_info.add_argument("session_id", metavar="SESSION_ID", help="lab session to inspect")
    session_info.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    session_info.set_defaults(command_name="session-info")

    return parser


def _add_session_request_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--provider", required=True, help="lab provider to use")
    parser.add_argument(
        "--profile",
        default="smoke",
        help="lab profile name (default: %(default)s)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=1,
        help="deterministic lab planning seed (default: %(default)s)",
    )
    parser.add_argument(
        "--role",
        dest="roles",
        action="append",
        required=True,
        help="role to include in the lab session; may be repeated",
    )


def _run_not_implemented(args: argparse.Namespace) -> int:
    output = {
        "ok": False,
        "command": args.command_name,
        "error": "not_implemented",
        "message": "lab command is scaffolded but not implemented yet",
    }
    if getattr(args, "json", False):
        sys.stdout.write(json.dumps(output, indent=2, sort_keys=True))
        sys.stdout.write("\n")
    else:
        print(f"lab {args.command_name}: not implemented yet", file=sys.stderr)
    return 2


def main(argv: Sequence[str] | None = None) -> int:
    """Run the lab command-line interface."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "command", None) is None:
        parser.print_help(sys.stdout)
        return 0
    if args.command_name in COMMANDS:
        return _run_not_implemented(args)
    parser.error(f"{args.command_name!r} is not implemented yet")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
