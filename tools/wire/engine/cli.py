"""Command-line interface skeleton for tools/wire."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from .model import dumps_json
from .providers import hetzner
from .registry import ProviderExposureError


COMMANDS = (
    "doctor",
    "create-endpoint",
    "destroy-endpoint",
    "exec",
    "upload",
    "download",
    "collect-artifacts",
    "ssh-info",
    "list-endpoints",
)


def _absolute_local_path(value: str) -> str:
    if not Path(value).is_absolute():
        raise argparse.ArgumentTypeError(f"{value!r} must be an absolute local path")
    return value


def _add_provider_exposure_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--provider",
        required=True,
        metavar="PROVIDER",
        help="endpoint provider, for example: hetzner",
    )
    parser.add_argument(
        "--exposure",
        required=True,
        metavar="EXPOSURE",
        help="endpoint exposure, for example: wan or private",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wire",
        description="Create and operate one wire endpoint at a time.",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="command")

    doctor = subparsers.add_parser(
        "doctor",
        help="check provider and exposure prerequisites",
        description="Check whether one provider/exposure endpoint request can run.",
    )
    _add_provider_exposure_options(doctor)
    doctor.add_argument("--dry-run", action="store_true", help="check without making changes")
    doctor.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    doctor.set_defaults(command_name="doctor")

    create_endpoint = subparsers.add_parser(
        "create-endpoint",
        help="create one endpoint",
        description="Create one endpoint for a provider and exposure.",
    )
    _add_provider_exposure_options(create_endpoint)
    create_endpoint.add_argument(
        "--role",
        metavar="ROLE",
        default="libcrafter",
        help="caller-defined endpoint role label",
    )
    create_endpoint.add_argument(
        "--private-group",
        metavar="GROUP",
        help="private exposure coordination group",
    )
    create_endpoint.add_argument(
        "--private-ip",
        metavar="IPV4",
        help="requested private IPv4 address for private exposure",
    )
    create_endpoint.add_argument(
        "--dry-run",
        action="store_true",
        help="plan endpoint creation without creating provider resources",
    )
    create_endpoint.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    create_endpoint.set_defaults(command_name="create-endpoint")

    destroy_endpoint = subparsers.add_parser(
        "destroy-endpoint",
        help="destroy one endpoint",
        description="Destroy one endpoint and its tracked provider resources.",
    )
    destroy_endpoint.add_argument("endpoint_id", metavar="ENDPOINT_ID", help="endpoint to destroy")
    destroy_endpoint.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    destroy_endpoint.set_defaults(command_name="destroy-endpoint")

    exec_endpoint = subparsers.add_parser(
        "exec",
        usage="wire exec [-h] ENDPOINT_ID -- COMMAND...",
        help="run a command on one endpoint",
        description="Run COMMAND on one endpoint over SSH.",
    )
    exec_endpoint.add_argument("endpoint_id", metavar="ENDPOINT_ID", help="endpoint to use")
    exec_endpoint.add_argument(
        "remote_command",
        metavar="COMMAND",
        nargs=argparse.REMAINDER,
        help="remote command and arguments; pass after --",
    )
    exec_endpoint.set_defaults(command_name="exec")

    upload = subparsers.add_parser(
        "upload",
        help="upload a local file or directory to one endpoint",
        description="Upload LOCAL_ABS to REMOTE_ABS on one endpoint.",
    )
    upload.add_argument("endpoint_id", metavar="ENDPOINT_ID", help="endpoint to use")
    upload.add_argument(
        "local_path",
        metavar="LOCAL_ABS",
        type=_absolute_local_path,
        help="absolute local source path",
    )
    upload.add_argument("remote_path", metavar="REMOTE_ABS", help="absolute remote destination path")
    upload.set_defaults(command_name="upload")

    download = subparsers.add_parser(
        "download",
        help="download a remote file or directory from one endpoint",
        description="Download REMOTE_ABS from one endpoint to LOCAL_ABS.",
    )
    download.add_argument("endpoint_id", metavar="ENDPOINT_ID", help="endpoint to use")
    download.add_argument("remote_path", metavar="REMOTE_ABS", help="absolute remote source path")
    download.add_argument(
        "local_path",
        metavar="LOCAL_ABS",
        type=_absolute_local_path,
        help="absolute local destination path",
    )
    download.set_defaults(command_name="download")

    collect_artifacts = subparsers.add_parser(
        "collect-artifacts",
        help="collect artifacts for one endpoint",
        description="Print the local artifact directory and optionally collect REMOTE_ABS.",
    )
    collect_artifacts.add_argument("endpoint_id", metavar="ENDPOINT_ID", help="endpoint to use")
    collect_artifacts.add_argument(
        "--remote",
        metavar="REMOTE_ABS",
        help="absolute remote artifact path to collect",
    )
    collect_artifacts.set_defaults(command_name="collect-artifacts")

    ssh_info = subparsers.add_parser(
        "ssh-info",
        help="print SSH connection details for one endpoint",
        description="Print SSH host, user, identity, and known-hosts details for one endpoint.",
    )
    ssh_info.add_argument("endpoint_id", metavar="ENDPOINT_ID", help="endpoint to inspect")
    ssh_info.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    ssh_info.set_defaults(command_name="ssh-info")

    list_endpoints = subparsers.add_parser(
        "list-endpoints",
        help="list tracked endpoints",
        description="List tracked wire endpoints.",
    )
    list_endpoints.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    list_endpoints.set_defaults(command_name="list-endpoints")

    return parser


def _run_doctor(args: argparse.Namespace) -> int:
    try:
        report = hetzner.doctor(
            provider=args.provider,
            exposure=args.exposure,
            dry_run=args.dry_run,
        )
    except ProviderExposureError as exc:
        if args.json:
            sys.stdout.write(
                dumps_json(
                    {
                        "provider": args.provider,
                        "exposure": args.exposure,
                        "dry_run": args.dry_run,
                        "ok": False,
                        "error": str(exc),
                    }
                )
            )
        else:
            print(str(exc), file=sys.stderr)
        return 2

    if args.json:
        sys.stdout.write(dumps_json(report))
    else:
        _print_doctor_report(report)

    if args.dry_run:
        return 0
    return 0 if bool(report["ok"]) else 1


def _print_doctor_report(report: dict[str, object]) -> None:
    status = "ok" if bool(report["ok"]) else "failed"
    print(
        "wire doctor: "
        f"provider={report['provider']} exposure={report['exposure']} "
        f"dry_run={str(report['dry_run']).lower()} status={status}"
    )
    checks = report["checks"]
    if not isinstance(checks, list):
        return
    for check in checks:
        if not isinstance(check, dict):
            continue
        check_status = "ok" if bool(check.get("ok")) else "failed"
        print(f"- {check.get('name')}: {check_status}: {check.get('message')}")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the wire command-line interface."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "command", None) is None:
        parser.print_help(sys.stdout)
        return 0
    if args.command_name == "doctor":
        return _run_doctor(args)
    parser.error(f"{args.command_name!r} is not implemented yet")
    return 2
