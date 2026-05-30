"""Command-line interface skeleton for tools/wire."""

from __future__ import annotations

import argparse
import shlex
import sys
from collections.abc import Sequence
from pathlib import Path
from posixpath import basename

from .model import EndpointManifest, dumps_json, write_json
from .process import CommandResult, run_command
from .providers import resolve_provider
from .registry import ProviderExposureError
from .ssh import (
    CommandRunner,
    download as ssh_download,
    run_ssh_command,
    ssh_argv,
    upload as ssh_upload,
)
from .state import (
    endpoint_known_hosts_path,
    endpoint_private_key_path,
    list_endpoint_manifests,
    read_endpoint_manifest,
    write_endpoint_manifest,
)


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


def _absolute_remote_path(value: str) -> str:
    if not Path(value).is_absolute():
        raise argparse.ArgumentTypeError(f"{value!r} must be an absolute remote path")
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
        "--private-cidr",
        metavar="CIDR",
        help="private network IPv4 CIDR for private exposure",
    )
    create_endpoint.add_argument(
        "--dry-run",
        action="store_true",
        help="plan endpoint creation without creating provider resources",
    )
    create_endpoint.add_argument(
        "--write-manifest",
        action="store_true",
        help="persist the endpoint manifest; required for dry-run manifest writes",
    )
    create_endpoint.add_argument(
        "--confirm-live-run",
        action="store_true",
        help="confirm protected non-dry-run provider execution",
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
    upload.add_argument(
        "remote_path",
        metavar="REMOTE_ABS",
        type=_absolute_remote_path,
        help="absolute remote destination path",
    )
    upload.set_defaults(command_name="upload")

    download = subparsers.add_parser(
        "download",
        help="download a remote file or directory from one endpoint",
        description="Download REMOTE_ABS from one endpoint to LOCAL_ABS.",
    )
    download.add_argument("endpoint_id", metavar="ENDPOINT_ID", help="endpoint to use")
    download.add_argument(
        "remote_path",
        metavar="REMOTE_ABS",
        type=_absolute_remote_path,
        help="absolute remote source path",
    )
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
        type=_absolute_remote_path,
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
        provider = resolve_provider(args.provider, args.exposure)
        report = provider.doctor(
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


def _run_create_endpoint(args: argparse.Namespace) -> int:
    try:
        provider = resolve_provider(args.provider, args.exposure)
        create_kwargs: dict[str, object] = {
            "provider": args.provider,
            "exposure": args.exposure,
            "role": args.role,
            "private_group": args.private_group,
            "private_ip": args.private_ip,
            "dry_run": args.dry_run,
            "confirm_live_run": args.confirm_live_run,
        }
        if args.private_cidr is not None:
            create_kwargs["private_cidr"] = args.private_cidr
        manifest = provider.create_endpoint(**create_kwargs)
    except (
        NotImplementedError,
        PermissionError,
        ProviderExposureError,
        RuntimeError,
        ValueError,
    ) as exc:
        if args.json:
            sys.stdout.write(
                dumps_json(
                    {
                        "provider": args.provider,
                        "exposure": args.exposure,
                        "dry_run": args.dry_run,
                        "created": False,
                        "ok": False,
                        "error": str(exc),
                    }
                )
            )
        else:
            print(str(exc), file=sys.stderr)
        return 2

    if args.write_manifest or not args.dry_run:
        stored_manifest = EndpointManifest.from_dict(manifest)
        manifest_path = write_endpoint_manifest(stored_manifest)
        manifest["state_dir"] = str(manifest_path.parent)
        manifest["manifest_path"] = str(manifest_path)

    if args.json:
        sys.stdout.write(dumps_json(_provider_cli_output_manifest(provider, manifest)))
    else:
        _print_create_endpoint_report(manifest)
    return 0


def _run_destroy_endpoint(args: argparse.Namespace) -> int:
    try:
        manifest = read_endpoint_manifest(args.endpoint_id)
        provider = resolve_provider(manifest.provider, manifest.exposure)
        output = provider.destroy_endpoint(manifest)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        if args.json:
            sys.stdout.write(
                dumps_json(
                    {
                        "endpoint_id": args.endpoint_id,
                        "ok": False,
                        "destroyed": False,
                        "error": str(exc),
                    }
                )
            )
        else:
            print(str(exc), file=sys.stderr)
        return 1

    if args.json:
        sys.stdout.write(dumps_json(output))
    else:
        _print_destroy_endpoint_report(output)
    return 0


def _provider_cli_output_manifest(
    provider: object,
    manifest: dict[str, object],
) -> dict[str, object]:
    formatter = getattr(provider, "cli_output_manifest", None)
    if formatter is None:
        return manifest
    output = formatter(manifest)
    if not isinstance(output, dict):
        raise TypeError("provider cli_output_manifest must return a JSON object")
    return output


def exec_endpoint(
    manifest: EndpointManifest,
    remote_command: Sequence[str],
    *,
    runner: CommandRunner = run_command,
) -> CommandResult:
    """Run a remote command for one endpoint and write stdout/stderr artifacts."""

    command = _remote_command_parts(remote_command)
    stdout_path, stderr_path = _exec_artifact_paths(manifest)
    result = run_ssh_command(
        host=manifest.ssh.host,
        user=manifest.ssh.user,
        port=manifest.ssh.port,
        identity_file=manifest.ssh.identity_file
        or endpoint_private_key_path(manifest.endpoint_id),
        known_hosts=manifest.ssh.known_hosts_file
        or endpoint_known_hosts_path(manifest.endpoint_id),
        command=command,
        runner=runner,
    )
    stdout_path.write_text(result.stdout, encoding="utf-8")
    stderr_path.write_text(result.stderr, encoding="utf-8")
    return result


def _run_exec_endpoint(args: argparse.Namespace) -> int:
    try:
        manifest = read_endpoint_manifest(args.endpoint_id)
        result = exec_endpoint(manifest, args.remote_command)
    except (FileNotFoundError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if result.error:
        print(result.error, file=sys.stderr)
    return result.exit_code


def upload_endpoint(
    manifest: EndpointManifest,
    local_path: str | Path,
    remote_path: str,
    *,
    runner: CommandRunner = run_command,
) -> CommandResult:
    """Upload a local path to one endpoint and write transfer artifacts."""

    result = ssh_upload(
        host=manifest.ssh.host,
        user=manifest.ssh.user,
        port=manifest.ssh.port,
        identity_file=manifest.ssh.identity_file
        or endpoint_private_key_path(manifest.endpoint_id),
        known_hosts=manifest.ssh.known_hosts_file
        or endpoint_known_hosts_path(manifest.endpoint_id),
        local_path=local_path,
        remote_path=remote_path,
        recursive=Path(local_path).is_dir(),
        runner=runner,
    )
    _write_transfer_artifacts(
        manifest,
        operation="upload",
        result=result,
        local_path=local_path,
        remote_path=remote_path,
    )
    return result


def download_endpoint(
    manifest: EndpointManifest,
    remote_path: str,
    local_path: str | Path,
    *,
    runner: CommandRunner = run_command,
) -> CommandResult:
    """Download a remote path from one endpoint and write transfer artifacts."""

    result = ssh_download(
        host=manifest.ssh.host,
        user=manifest.ssh.user,
        port=manifest.ssh.port,
        identity_file=manifest.ssh.identity_file
        or endpoint_private_key_path(manifest.endpoint_id),
        known_hosts=manifest.ssh.known_hosts_file
        or endpoint_known_hosts_path(manifest.endpoint_id),
        remote_path=remote_path,
        local_path=local_path,
        recursive=True,
        runner=runner,
    )
    _write_transfer_artifacts(
        manifest,
        operation="download",
        result=result,
        local_path=local_path,
        remote_path=remote_path,
    )
    return result


def collect_artifacts(
    manifest: EndpointManifest,
    remote_path: str | None = None,
    *,
    runner: CommandRunner = run_command,
) -> dict[str, object]:
    """Return the endpoint artifact directory and optionally download one remote path."""

    artifact_dir = Path(manifest.artifact_dir).resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    output: dict[str, object] = {
        "endpoint_id": manifest.endpoint_id,
        "artifact_dir": str(artifact_dir),
        "collected": False,
    }
    if remote_path is None:
        return output

    artifact_name = basename(remote_path.rstrip("/")) or "artifact"
    local_path = artifact_dir / artifact_name
    result = download_endpoint(manifest, remote_path, local_path, runner=runner)
    output.update(
        {
            "collected": result.ok,
            "remote_path": remote_path,
            "local_path": str(local_path),
            "exit_code": result.exit_code,
            "ok": result.ok,
        }
    )
    return output


def _run_upload_endpoint(args: argparse.Namespace) -> int:
    try:
        manifest = read_endpoint_manifest(args.endpoint_id)
        result = upload_endpoint(manifest, args.local_path, args.remote_path)
    except (FileNotFoundError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    return _forward_command_result(result)


def _run_download_endpoint(args: argparse.Namespace) -> int:
    try:
        manifest = read_endpoint_manifest(args.endpoint_id)
        result = download_endpoint(manifest, args.remote_path, args.local_path)
    except (FileNotFoundError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    return _forward_command_result(result)


def _run_collect_artifacts(args: argparse.Namespace) -> int:
    try:
        manifest = read_endpoint_manifest(args.endpoint_id)
        output = collect_artifacts(manifest, args.remote)
    except (FileNotFoundError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(output["artifact_dir"])
    return 0 if bool(output.get("ok", True)) else int(output.get("exit_code", 1))


def _run_ssh_info(args: argparse.Namespace) -> int:
    try:
        manifest = read_endpoint_manifest(args.endpoint_id)
    except (FileNotFoundError, ValueError) as exc:
        if args.json:
            sys.stdout.write(
                dumps_json(
                    {
                        "endpoint_id": args.endpoint_id,
                        "ok": False,
                        "error": str(exc),
                    }
                )
            )
        else:
            print(str(exc), file=sys.stderr)
        return 1

    output = _ssh_info_output(manifest)
    if args.json:
        sys.stdout.write(dumps_json(output))
    else:
        _print_ssh_info(output)
    return 0


def _run_list_endpoints(args: argparse.Namespace) -> int:
    try:
        manifests = list_endpoint_manifests()
    except (FileNotFoundError, ValueError) as exc:
        if args.json:
            sys.stdout.write(dumps_json({"endpoints": [], "ok": False, "error": str(exc)}))
        else:
            print(str(exc), file=sys.stderr)
        return 1

    output = {"endpoints": [manifest.to_dict() for manifest in manifests]}
    if args.json:
        sys.stdout.write(dumps_json(output))
    else:
        _print_endpoint_list(output)
    return 0


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


def _print_create_endpoint_report(manifest: dict[str, object]) -> None:
    created = str(bool(manifest["created"])).lower()
    print(
        "wire create-endpoint: "
        f"provider={manifest['provider']} exposure={manifest['exposure']} "
        f"endpoint_id={manifest['endpoint_id']} created={created}"
    )
    print(f"state: {manifest['manifest_path']}")
    print(f"artifacts: {manifest['artifact_dir']}")


def _print_destroy_endpoint_report(output: dict[str, object]) -> None:
    print(
        "wire destroy-endpoint: "
        f"endpoint_id={output['endpoint_id']} status={output['status']} "
        f"destroyed={str(bool(output['destroyed'])).lower()}"
    )
    if output.get("manifest_path"):
        print(f"state: {output['manifest_path']}")
    if output.get("artifact_dir"):
        print(f"artifacts: {output['artifact_dir']}")


def _print_ssh_info(output: dict[str, object]) -> None:
    print(
        "wire ssh-info: "
        f"endpoint_id={output['endpoint_id']} host={output.get('host')} "
        f"user={output.get('user')} port={output.get('port')}"
    )
    print(f"identity: {output['identity_file']}")
    print(f"known_hosts: {output['known_hosts_file']}")
    print(f"ssh: {output['ssh_command']}")


def _print_endpoint_list(output: dict[str, object]) -> None:
    endpoints = output["endpoints"]
    if not isinstance(endpoints, list) or not endpoints:
        print("wire list-endpoints: no endpoints")
        return
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            continue
        print(
            f"{endpoint.get('endpoint_id')}\t"
            f"{endpoint.get('provider')}\t"
            f"{endpoint.get('exposure')}\t"
            f"{endpoint.get('status')}"
        )


def _remote_command_parts(remote_command: Sequence[str]) -> list[str]:
    command = list(remote_command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise ValueError("wire exec requires COMMAND after ENDPOINT_ID --")
    return command


def _exec_artifact_paths(manifest: EndpointManifest) -> tuple[Path, Path]:
    artifact_dir = Path(manifest.artifact_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    return artifact_dir / "stdout", artifact_dir / "stderr"


def _write_transfer_artifacts(
    manifest: EndpointManifest,
    *,
    operation: str,
    result: CommandResult,
    local_path: str | Path,
    remote_path: str,
) -> None:
    stdout_path, stderr_path, report_path = _transfer_artifact_paths(manifest, operation)
    stdout_path.write_text(result.stdout, encoding="utf-8")
    stderr_path.write_text(result.stderr, encoding="utf-8")
    write_json(
        report_path,
        {
            "operation": operation,
            "endpoint_id": manifest.endpoint_id,
            "local_path": str(local_path),
            "remote_path": remote_path,
            "exit_code": result.exit_code,
            "ok": result.ok,
            "timed_out": result.timed_out,
            "timeout": result.timeout,
            "error": result.error,
            "command": result.command,
            "artifacts": {
                "stdout": stdout_path,
                "stderr": stderr_path,
            },
        },
    )


def _ssh_info_output(manifest: EndpointManifest) -> dict[str, object]:
    identity_file = manifest.ssh.identity_file or str(
        endpoint_private_key_path(manifest.endpoint_id)
    )
    known_hosts_file = manifest.ssh.known_hosts_file or str(
        endpoint_known_hosts_path(manifest.endpoint_id)
    )
    argv = ssh_argv(
        host=manifest.ssh.host,
        user=manifest.ssh.user,
        port=manifest.ssh.port,
        identity_file=identity_file,
        known_hosts=known_hosts_file,
    )
    return {
        "endpoint_id": manifest.endpoint_id,
        "provider": manifest.provider,
        "exposure": manifest.exposure,
        "status": manifest.status,
        "host": manifest.ssh.host,
        "port": manifest.ssh.port,
        "user": manifest.ssh.user,
        "identity_file": identity_file,
        "known_hosts_file": known_hosts_file,
        "ssh_command": shlex.join(argv),
        "ssh": {
            **manifest.ssh.to_dict(),
            "identity_file": identity_file,
            "known_hosts_file": known_hosts_file,
            "command": argv,
        },
    }


def _transfer_artifact_paths(manifest: EndpointManifest, operation: str) -> tuple[Path, Path, Path]:
    if operation not in {"upload", "download"}:
        raise ValueError(f"unsupported transfer operation: {operation}")
    artifact_dir = Path(manifest.artifact_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    return (
        artifact_dir / f"{operation}.stdout",
        artifact_dir / f"{operation}.stderr",
        artifact_dir / f"{operation}.json",
    )


def _forward_command_result(result: CommandResult) -> int:
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if result.error:
        print(result.error, file=sys.stderr)
    return result.exit_code


def main(argv: Sequence[str] | None = None) -> int:
    """Run the wire command-line interface."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "command", None) is None:
        parser.print_help(sys.stdout)
        return 0
    if args.command_name == "doctor":
        return _run_doctor(args)
    if args.command_name == "create-endpoint":
        return _run_create_endpoint(args)
    if args.command_name == "destroy-endpoint":
        return _run_destroy_endpoint(args)
    if args.command_name == "exec":
        return _run_exec_endpoint(args)
    if args.command_name == "upload":
        return _run_upload_endpoint(args)
    if args.command_name == "download":
        return _run_download_endpoint(args)
    if args.command_name == "collect-artifacts":
        return _run_collect_artifacts(args)
    if args.command_name == "ssh-info":
        return _run_ssh_info(args)
    if args.command_name == "list-endpoints":
        return _run_list_endpoints(args)
    parser.error(f"{args.command_name!r} is not implemented yet")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
