"""Command-line interface skeleton for tools/endpoint."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from json import JSONDecodeError
from pathlib import Path
from posixpath import basename

from tools.appliance.engine.profile import ApplianceProfile
from tools.appliance.engine.profiles import resolve_profile

from .appliance import (
    EndpointApplianceTarget,
    collect_endpoint_appliance_run_artifacts,
    deploy_endpoint_appliance_target,
    read_endpoint_appliance_target,
    render_endpoint_appliance_deploy_plan,
    render_endpoint_appliance_run_plan,
    render_endpoint_appliance_sync_plan,
    run_endpoint_appliance_command,
    sync_endpoint_appliance_workspace,
)
from .assets import (
    AssetHardware,
    AssetSSHInfo,
    EndpointAsset,
    acquire_endpoint_asset_lease_by_profile,
    asset_lease_artifact_root,
    asset_profile_environment,
    asset_record_path,
    asset_ssh_docker_target,
    check_endpoint_asset,
    list_endpoint_assets,
    read_endpoint_asset,
    release_endpoint_asset_lease,
    resolve_endpoint_asset_lease,
    write_endpoint_asset,
)
from .model import EndpointManifest, dumps_json, to_jsonable, write_json
from .model import json_object
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
    "appliance",
    "asset",
    "doctor",
    "create",
    "destroy",
    "virtualbox",
    "exec",
    "upload",
    "download",
    "collect-artifacts",
    "ssh-info",
    "list",
)


@dataclass(frozen=True, slots=True)
class _ApplianceTargetContext:
    target: EndpointApplianceTarget
    profile: ApplianceProfile
    lease_id: str | None = None
    asset_id: str | None = None
    lease_artifact_root: Path | None = None
    release_after_run: dict[str, object] | None = None
    profile_environment: dict[str, str] | None = None


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


def _add_appliance_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "endpoint_id",
        metavar="ENDPOINT_ID",
        nargs="?",
        help="endpoint to use, or lease:LEASE_ID for a persistent asset lease",
    )
    parser.add_argument(
        "profile",
        metavar="PROFILE",
        nargs="?",
        help="appliance profile to use",
    )
    parser.add_argument(
        "--lease",
        dest="lease_id",
        metavar="LEASE_ID",
        help="persistent endpoint asset lease to use instead of ENDPOINT_ID",
    )
    parser.add_argument(
        "--work-dir",
        metavar="PATH",
        help="local workspace directory to sync before planning or running",
    )
    parser.add_argument(
        "--artifact-dir",
        metavar="PATH",
        help="local artifact directory override",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="render appliance operations without running SSH, SCP, Docker, or tar",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")


def _add_appliance_command_argv(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "remote_command",
        metavar="COMMAND",
        nargs="*",
        help="container command and arguments; pass after --",
    )


def _add_asset_json_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="endpoint",
        description="Create and operate one provider endpoint at a time.",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="command")

    appliance = subparsers.add_parser(
        "appliance",
        help="plan and run appliance operations on one endpoint",
        description="Plan, deploy, run, and collect endpoint appliance work.",
    )
    appliance.set_defaults(command_name="appliance")
    appliance_subparsers = appliance.add_subparsers(
        dest="appliance_command",
        metavar="appliance-command",
    )

    appliance_plan = appliance_subparsers.add_parser(
        "plan",
        usage=(
            "endpoint appliance plan [-h] [options] "
            "[ENDPOINT_ID|lease:LEASE_ID] PROFILE -- COMMAND..."
        ),
        help="render an endpoint appliance run plan",
        description="Render endpoint appliance deploy, optional sync, and run plans.",
    )
    _add_appliance_common_options(appliance_plan)
    _add_appliance_command_argv(appliance_plan)
    appliance_plan.set_defaults(command_name="appliance", appliance_command_name="plan")

    appliance_check = appliance_subparsers.add_parser(
        "check",
        usage=(
            "endpoint appliance check [-h] [options] "
            "[ENDPOINT_ID|lease:LEASE_ID] PROFILE [-- COMMAND...]"
        ),
        help="render endpoint appliance readiness checks",
        description="Render endpoint Docker and profile readiness checks.",
    )
    _add_appliance_common_options(appliance_check)
    _add_appliance_command_argv(appliance_check)
    appliance_check.set_defaults(command_name="appliance", appliance_command_name="check")

    appliance_deploy = appliance_subparsers.add_parser(
        "deploy",
        usage=(
            "endpoint appliance deploy [-h] [options] "
            "[ENDPOINT_ID|lease:LEASE_ID] PROFILE [-- COMMAND...]"
        ),
        help="prepare one endpoint for appliance execution",
        description="Prepare one endpoint to run the selected appliance image.",
    )
    _add_appliance_common_options(appliance_deploy)
    _add_appliance_command_argv(appliance_deploy)
    appliance_deploy.set_defaults(command_name="appliance", appliance_command_name="deploy")

    appliance_run = appliance_subparsers.add_parser(
        "run",
        usage=(
            "endpoint appliance run [-h] [options] "
            "[ENDPOINT_ID|lease:LEASE_ID] PROFILE -- COMMAND..."
        ),
        help="run an appliance command on one endpoint",
        description="Optionally sync a workspace, then run COMMAND in the appliance.",
    )
    _add_appliance_common_options(appliance_run)
    _add_appliance_command_argv(appliance_run)
    appliance_run.set_defaults(command_name="appliance", appliance_command_name="run")

    appliance_collect = appliance_subparsers.add_parser(
        "collect",
        usage=(
            "endpoint appliance collect [-h] [options] "
            "[ENDPOINT_ID|lease:LEASE_ID] PROFILE [-- COMMAND...]"
        ),
        help="collect remote artifacts for an appliance run",
        description="Collect remote appliance artifacts for the selected endpoint/profile run.",
    )
    _add_appliance_common_options(appliance_collect)
    _add_appliance_command_argv(appliance_collect)
    appliance_collect.set_defaults(command_name="appliance", appliance_command_name="collect")

    asset = subparsers.add_parser(
        "asset",
        help="register and inspect persistent endpoint assets",
        description="Register, list, and inspect prepared reusable endpoint assets.",
    )
    asset.set_defaults(command_name="asset")
    asset_subparsers = asset.add_subparsers(dest="asset_command", metavar="asset-command")

    asset_register = asset_subparsers.add_parser(
        "register",
        help="register one persistent endpoint asset",
        description="Persist one prepared endpoint asset under the endpoint state root.",
    )
    asset_register.add_argument("asset_id", metavar="ASSET_ID", help="asset ID or name")
    asset_register.add_argument(
        "--substrate",
        required=True,
        metavar="NAME",
        help="asset substrate",
    )
    asset_register.add_argument(
        "--profile",
        action="append",
        dest="profiles",
        required=True,
        metavar="PROFILE",
        help="supported appliance profile; may be passed more than once",
    )
    asset_register.add_argument("--ssh-host", required=True, metavar="HOST", help="SSH host")
    asset_register.add_argument("--ssh-user", required=True, metavar="USER", help="SSH user")
    asset_register.add_argument(
        "--ssh-port",
        type=int,
        default=22,
        metavar="PORT",
        help="SSH port",
    )
    asset_register.add_argument(
        "--identity-file",
        type=_absolute_local_path,
        metavar="PATH",
        help="absolute SSH identity file path",
    )
    asset_register.add_argument(
        "--known-hosts-file",
        type=_absolute_local_path,
        metavar="PATH",
        help="absolute SSH known_hosts file path",
    )
    asset_register.add_argument(
        "--docker-command",
        metavar="COMMAND",
        help="Docker command available on the asset",
    )
    asset_register.add_argument(
        "--metadata-json",
        metavar="JSON",
        help="asset metadata JSON object",
    )
    asset_register.add_argument(
        "--provider-metadata-json",
        metavar="JSON",
        help="provider metadata JSON object stored under metadata.provider",
    )
    asset_register.add_argument(
        "--hardware-json",
        metavar="JSON",
        help="hardware metadata JSON object",
    )
    _add_asset_json_option(asset_register)
    asset_register.set_defaults(command_name="asset", asset_command_name="register")

    asset_list = asset_subparsers.add_parser(
        "list",
        help="list persistent endpoint assets",
        description="List registered persistent endpoint assets.",
    )
    _add_asset_json_option(asset_list)
    asset_list.set_defaults(command_name="asset", asset_command_name="list")

    asset_info = asset_subparsers.add_parser(
        "info",
        help="inspect one persistent endpoint asset",
        description="Print one registered persistent endpoint asset record.",
    )
    asset_info.add_argument("asset_id", metavar="ASSET_ID", help="asset to inspect")
    _add_asset_json_option(asset_info)
    asset_info.set_defaults(command_name="asset", asset_command_name="info")

    asset_check = asset_subparsers.add_parser(
        "check",
        help="run readiness checks for one persistent endpoint asset",
        description="Lock one asset, verify SSH Docker access, and render profile readiness checks.",
    )
    asset_check.add_argument("asset_id", metavar="ASSET_ID", help="asset to check")
    asset_check.add_argument(
        "--profile",
        required=True,
        metavar="PROFILE",
        help="supported appliance profile to check",
    )
    _add_asset_json_option(asset_check)
    asset_check.set_defaults(command_name="asset", asset_command_name="check")

    asset_acquire = asset_subparsers.add_parser(
        "acquire",
        help="lease one persistent endpoint asset by appliance profile",
        description="Lease one available persistent endpoint asset for a supported profile.",
    )
    asset_acquire.add_argument(
        "--profile",
        required=True,
        metavar="PROFILE",
        help="supported appliance profile to lease",
    )
    asset_acquire.add_argument(
        "--lease-ttl",
        required=True,
        metavar="DURATION",
        help="lease TTL as seconds or with s, m, or h suffix",
    )
    asset_acquire.add_argument(
        "--owner",
        metavar="OWNER",
        help="optional owner label stored in lease metadata",
    )
    asset_acquire.add_argument(
        "--metadata-json",
        metavar="JSON",
        help="additional lease metadata JSON object",
    )
    asset_acquire.add_argument(
        "--wait",
        action="store_true",
        help="plan waiting for a busy asset without blocking indefinitely",
    )
    _add_asset_json_option(asset_acquire)
    asset_acquire.set_defaults(command_name="asset", asset_command_name="acquire")

    asset_release = asset_subparsers.add_parser(
        "release",
        help="release one persistent endpoint asset lease",
        description="Release a persistent endpoint asset by lease ID.",
    )
    asset_release.add_argument("lease_id", metavar="LEASE_ID", help="lease ID to release")
    _add_asset_json_option(asset_release)
    asset_release.set_defaults(command_name="asset", asset_command_name="release")

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
        "create",
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
    create_endpoint.set_defaults(command_name="create")

    destroy_endpoint = subparsers.add_parser(
        "destroy",
        help="destroy one endpoint",
        description="Destroy one endpoint and its tracked provider resources.",
    )
    destroy_endpoint.add_argument("endpoint_id", metavar="ENDPOINT_ID", help="endpoint to destroy")
    destroy_endpoint.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    destroy_endpoint.set_defaults(command_name="destroy")

    virtualbox = subparsers.add_parser(
        "virtualbox",
        help="run VirtualBox provider maintenance operations",
        description="Run bounded VirtualBox provider maintenance operations.",
    )
    virtualbox.set_defaults(command_name="virtualbox")
    virtualbox_subparsers = virtualbox.add_subparsers(
        dest="virtualbox_command",
        metavar="virtualbox-command",
    )
    normalize_groups = virtualbox_subparsers.add_parser(
        "normalize-groups",
        help="normalize tracked VirtualBox VMs into the libcrafter appliance group",
        description=(
            "Inspect tracked VirtualBox endpoint manifests and endpoint assets, "
            "then plan or apply the libcrafter appliance group."
        ),
    )
    normalize_groups.add_argument(
        "--dry-run",
        action="store_true",
        help="report planned group changes without mutating VirtualBox",
    )
    normalize_groups.add_argument(
        "--confirm-live-run",
        action="store_true",
        help="confirm protected VirtualBox group mutation",
    )
    normalize_groups.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    normalize_groups.set_defaults(
        command_name="virtualbox",
        virtualbox_command_name="normalize-groups",
    )

    exec_endpoint = subparsers.add_parser(
        "exec",
        usage="endpoint exec [-h] ENDPOINT_ID -- COMMAND...",
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
        "list",
        help="list tracked endpoints",
        description="List tracked endpoints.",
    )
    list_endpoints.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    list_endpoints.set_defaults(command_name="list")

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


def _run_virtualbox(args: argparse.Namespace) -> int:
    subcommand = getattr(args, "virtualbox_command_name", None)
    if subcommand is None:
        print("endpoint virtualbox: missing virtualbox command", file=sys.stderr)
        return 2
    if subcommand != "normalize-groups":
        print(f"endpoint virtualbox: unsupported command {subcommand!r}", file=sys.stderr)
        return 2

    from .providers.virtualbox.groups import normalize_tracked_vm_groups

    try:
        output = normalize_tracked_vm_groups(
            dry_run=args.dry_run,
            confirm_live_run=args.confirm_live_run,
            command_runner=run_command,
        )
    except (PermissionError, RuntimeError, ValueError) as exc:
        output = {
            "kind": "virtualbox-normalize-groups",
            "ok": False,
            "dry_run": args.dry_run,
            "confirmed": args.confirm_live_run,
            "error": str(exc),
        }
        if args.json:
            sys.stdout.write(dumps_json(output))
        else:
            print(str(exc), file=sys.stderr)
        return 2

    if args.json:
        sys.stdout.write(dumps_json(output))
    else:
        _print_virtualbox_normalize_groups_report(output)
    return 0 if output.get("ok") is not False else 1


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


def _run_asset(args: argparse.Namespace) -> int:
    subcommand = getattr(args, "asset_command_name", None)
    if subcommand is None:
        print("endpoint asset: missing asset command", file=sys.stderr)
        return 2
    try:
        if subcommand == "register":
            output = _asset_register_output(args)
            return _emit_asset_output(args, output, default_label="register")
        if subcommand == "list":
            output = _asset_list_output()
            return _emit_asset_output(args, output, default_label="list")
        if subcommand == "info":
            output = _asset_info_output(args.asset_id)
            return _emit_asset_output(args, output, default_label="info")
        if subcommand == "check":
            output = _asset_check_output(args)
            return _emit_asset_output(args, output, default_label="check")
        if subcommand == "acquire":
            output = _asset_acquire_output(args)
            return _emit_asset_output(args, output, default_label="acquire")
        if subcommand == "release":
            output = _asset_release_output(args)
            return _emit_asset_output(args, output, default_label="release")
    except (FileNotFoundError, JSONDecodeError, ValueError, RuntimeError) as exc:
        return _emit_asset_error(args, str(exc))
    print(f"endpoint asset: unsupported asset command {subcommand!r}", file=sys.stderr)
    return 2


def _asset_register_output(args: argparse.Namespace) -> dict[str, object]:
    record_path = asset_record_path(args.asset_id)
    if record_path.exists():
        raise ValueError(f"endpoint asset already registered: {args.asset_id}")

    profiles = _validated_asset_profiles(args.profiles)
    metadata = _json_option_object(args.metadata_json, "metadata-json")
    provider_metadata = _json_option_object(
        args.provider_metadata_json,
        "provider-metadata-json",
    )
    if provider_metadata:
        metadata["provider"] = provider_metadata
    docker: dict[str, object] = {}
    if args.docker_command is not None:
        docker["command"] = args.docker_command
    hardware = AssetHardware.from_dict(
        _json_option_object(args.hardware_json, "hardware-json")
    )
    asset = EndpointAsset(
        asset_id=args.asset_id,
        substrate=args.substrate,
        status="available",
        supported_profiles=profiles,
        ssh=AssetSSHInfo(
            host=args.ssh_host,
            user=args.ssh_user,
            port=args.ssh_port,
            identity_file=args.identity_file,
            known_hosts_file=args.known_hosts_file,
        ),
        docker=docker,
        hardware=hardware,
        metadata=metadata,
    )
    written_path = write_endpoint_asset(asset)
    return {
        "kind": "endpoint-asset-register",
        "registered": True,
        "asset_id": asset.asset_id,
        "asset_path": str(written_path),
        "asset": asset.to_dict(),
    }


def _asset_list_output() -> dict[str, object]:
    return {
        "kind": "endpoint-asset-list",
        "assets": [_asset_list_entry(asset) for asset in list_endpoint_assets()],
    }


def _asset_info_output(asset_id: str) -> dict[str, object]:
    asset = read_endpoint_asset(asset_id)
    return {
        "kind": "endpoint-asset-info",
        "asset_id": asset.asset_id,
        "asset_path": str(asset_record_path(asset.asset_id)),
        "asset": asset.to_dict(),
    }


def _asset_check_output(args: argparse.Namespace) -> dict[str, object]:
    return check_endpoint_asset(
        args.asset_id,
        args.profile,
        runner=run_command,
    )


def _asset_acquire_output(args: argparse.Namespace) -> dict[str, object]:
    ttl_seconds = _parse_duration_seconds(args.lease_ttl, "lease-ttl")
    metadata = _json_option_object(args.metadata_json, "metadata-json")
    return acquire_endpoint_asset_lease_by_profile(
        args.profile,
        ttl_seconds,
        owner=args.owner,
        metadata=metadata,
        wait=args.wait,
    )


def _asset_release_output(args: argparse.Namespace) -> dict[str, object]:
    return release_endpoint_asset_lease(args.lease_id)


def _asset_list_entry(asset: EndpointAsset) -> dict[str, object]:
    return {
        "asset_id": asset.asset_id,
        "substrate": asset.substrate,
        "status": asset.status,
        "supported_profiles": asset.supported_profiles,
        "lease_state": "leased" if asset.lease is not None else "unleased",
        "lease": None if asset.lease is None else asset.lease.to_dict(),
        "last_check_state": "unchecked" if asset.last_check is None else "checked",
        "last_check": asset.last_check,
    }


def _validated_asset_profiles(values: Sequence[str]) -> list[str]:
    profiles: list[str] = []
    for value in values:
        resolve_profile(value)
        profiles.append(value)
    return profiles


def _json_option_object(value: str | None, option_name: str) -> dict[str, object]:
    if value is None:
        return {}
    try:
        decoded = json.loads(value)
    except JSONDecodeError as exc:
        raise ValueError(f"{option_name} must be a JSON object: {exc.msg}") from exc
    return json_object(decoded, option_name)


def _parse_duration_seconds(value: str, option_name: str) -> int:
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{option_name} must be a duration")
    unit = value[-1].lower()
    multiplier = 1
    digits = value
    if unit in {"s", "m", "h"}:
        digits = value[:-1]
        multiplier = {"s": 1, "m": 60, "h": 3600}[unit]
    if digits == "" or not digits.isdecimal():
        raise ValueError(f"{option_name} must be integer seconds or use s, m, or h suffix")
    seconds = int(digits) * multiplier
    if seconds <= 0:
        raise ValueError(f"{option_name} must be positive")
    return seconds


def _emit_asset_output(
    args: argparse.Namespace,
    output: dict[str, object],
    *,
    default_label: str,
) -> int:
    if args.json:
        sys.stdout.write(dumps_json(output))
    else:
        _print_asset_output(output, default_label=default_label)
    return _asset_exit_code(output)


def _emit_asset_error(args: argparse.Namespace, error: str) -> int:
    output = {
        "kind": "endpoint-asset-error",
        "asset_id": getattr(args, "asset_id", None),
        "lease_id": getattr(args, "lease_id", None),
        "profile": getattr(args, "profile", None),
        "ok": False,
        "error": error,
    }
    if getattr(args, "json", False):
        sys.stdout.write(dumps_json(output))
    else:
        print(error, file=sys.stderr)
    return 1


def _asset_exit_code(output: dict[str, object]) -> int:
    ok = output.get("ok")
    if ok is False:
        exit_code = output.get("exit_code")
        return int(exit_code) if isinstance(exit_code, int) and exit_code != 0 else 1
    return 0


def _run_appliance(args: argparse.Namespace) -> int:
    subcommand = getattr(args, "appliance_command_name", None)
    if subcommand is None:
        print("endpoint appliance: missing appliance command", file=sys.stderr)
        return 2
    try:
        _normalize_appliance_target_args(args)
        if subcommand == "plan":
            output = _appliance_plan_output(args)
            return _emit_appliance_output(args, output, default_label="plan")
        if subcommand == "check":
            output = _appliance_check_output(args)
            return _emit_appliance_output(args, output, default_label="check")
        if subcommand == "deploy":
            output = _appliance_deploy_output(args)
            return _emit_appliance_output(args, output, default_label="deploy")
        if subcommand == "run":
            output = _appliance_run_output(args)
            return _emit_appliance_output(args, output, default_label="run")
        if subcommand == "collect":
            output = _appliance_collect_output(args)
            return _emit_appliance_output(args, output, default_label="collect")
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        return _emit_appliance_error(args, str(exc))
    print(f"endpoint appliance: unsupported appliance command {subcommand!r}", file=sys.stderr)
    return 2


def _normalize_appliance_target_args(args: argparse.Namespace) -> None:
    endpoint_id = getattr(args, "endpoint_id", None)
    profile = getattr(args, "profile", None)
    lease_id = getattr(args, "lease_id", None)

    if lease_id is not None:
        if profile is None:
            if endpoint_id is None:
                raise ValueError(
                    "endpoint appliance requires PROFILE when --lease is set"
                )
            profile = endpoint_id
            endpoint_id = None
        elif endpoint_id is not None:
            raise ValueError(
                "endpoint appliance --lease does not accept ENDPOINT_ID; "
                "use --lease LEASE_ID PROFILE"
            )
    elif isinstance(endpoint_id, str) and endpoint_id.startswith("lease:"):
        lease_id = endpoint_id.removeprefix("lease:")
        if lease_id == "":
            raise ValueError("endpoint appliance lease positional form requires lease:LEASE_ID")
        endpoint_id = None
        if profile is None:
            raise ValueError(
                "endpoint appliance lease positional form requires PROFILE after lease:LEASE_ID"
            )
    else:
        if endpoint_id is None or profile is None:
            raise ValueError(
                "endpoint appliance requires ENDPOINT_ID PROFILE or --lease LEASE_ID PROFILE"
            )

    if profile is None:
        raise ValueError("endpoint appliance requires PROFILE")

    args.endpoint_id = endpoint_id
    args.lease_id = lease_id
    args.profile = profile


def _appliance_target_context(args: argparse.Namespace) -> _ApplianceTargetContext:
    profile = resolve_profile(args.profile)
    lease_id = getattr(args, "lease_id", None)
    if lease_id is None:
        return _ApplianceTargetContext(
            target=read_endpoint_appliance_target(args.endpoint_id),
            profile=profile,
        )

    resolved = resolve_endpoint_asset_lease(lease_id, profile.name)
    artifact_root = asset_lease_artifact_root(resolved.asset.asset_id, resolved.lease_id)
    release_after_run = _lease_release_after_run_guidance(resolved.lease_id)
    return _ApplianceTargetContext(
        target=_asset_lease_appliance_target(
            resolved.asset,
            lease_id=resolved.lease_id,
            artifact_root=artifact_root,
            release_after_run=release_after_run,
        ),
        profile=profile,
        lease_id=resolved.lease_id,
        asset_id=resolved.asset.asset_id,
        lease_artifact_root=artifact_root,
        release_after_run=release_after_run,
        profile_environment=asset_profile_environment(resolved.asset, profile.name),
    )


def _asset_lease_appliance_target(
    asset: EndpointAsset,
    *,
    lease_id: str,
    artifact_root: Path,
    release_after_run: dict[str, object],
) -> EndpointApplianceTarget:
    ssh_target = asset_ssh_docker_target(asset)
    ssh_target_metadata = dict(ssh_target.metadata)
    ssh_target_metadata.update(
        {
            "asset_id": asset.asset_id,
            "lease_id": lease_id,
            "release_after_run": release_after_run,
        }
    )
    ssh_target = type(ssh_target).from_dict(
        {**ssh_target.to_dict(), "metadata": ssh_target_metadata}
    )
    if asset.lease is None:
        raise ValueError(f"endpoint asset {asset.asset_id!r} has no active lease")
    metadata = {
        "target_kind": "asset-lease",
        "endpoint_id": asset.asset_id,
        "asset_id": asset.asset_id,
        "asset_status": asset.status,
        "provider": "asset",
        "exposure": asset.substrate,
        "role": "lease",
        "artifact_dir": str(artifact_root),
        "asset_path": str(asset_record_path(asset.asset_id)),
        "supported_profiles": list(asset.supported_profiles),
        "lease_id": lease_id,
        "lease": asset.lease.to_dict(),
        "lease_expires_at": asset.lease.expires_at,
        "release_after_run": release_after_run,
        "asset_metadata": asset.metadata,
        "ssh_metadata": asset.ssh.metadata,
        "appliance": {
            "target_kind": "asset-lease",
            "asset_id": asset.asset_id,
            "lease_id": lease_id,
            "substrate": asset.substrate,
            "supported_profiles": list(asset.supported_profiles),
            "remote_work_root": ssh_target.remote_work_root,
            "remote_artifact_root": ssh_target.remote_artifact_root,
            "appliance_capable": True,
            "docker_execution_supported": True,
            "release_after_run": release_after_run,
        },
    }
    return EndpointApplianceTarget(
        endpoint_id=asset.asset_id,
        provider="asset",
        exposure=asset.substrate,
        role="lease",
        target=ssh_target,
        metadata=metadata,
    )


def _lease_release_after_run_guidance(lease_id: str) -> dict[str, object]:
    command = ["endpoint", "asset", "release", lease_id]
    command_string = shlex.join(command)
    return {
        "message": f"release lease after the appliance run: {command_string}",
        "command": command,
        "command_string": command_string,
    }


def _finalize_appliance_output(
    output: object,
    context: _ApplianceTargetContext,
) -> object:
    if context.lease_id is None:
        return output
    data = to_jsonable(output)
    if not isinstance(data, dict):
        return output
    data["lease_id"] = context.lease_id
    data["asset_id"] = context.asset_id
    data["lease_artifact_root"] = str(context.lease_artifact_root)
    if context.release_after_run is not None:
        data["release_after_run"] = context.release_after_run
        data["release_guidance"] = context.release_after_run["message"]
    data.setdefault("artifact_dir", _appliance_output_artifact_dir(data))
    metadata = data.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    metadata.update(
        {
            "lease_id": context.lease_id,
            "asset_id": context.asset_id,
            "lease_artifact_root": str(context.lease_artifact_root),
        }
    )
    if context.release_after_run is not None:
        metadata["release_after_run"] = context.release_after_run
    data["metadata"] = metadata
    return data


def _appliance_output_artifact_dir(data: dict[str, object]) -> str | None:
    for key in ("artifact_dir", "local_artifact_dir"):
        value = data.get(key)
        if isinstance(value, str):
            return value
    run = data.get("run")
    if isinstance(run, dict):
        for key in ("artifact_dir", "local_artifact_dir"):
            value = run.get(key)
            if isinstance(value, str):
                return value
    return None


def _appliance_plan_output(args: argparse.Namespace) -> dict[str, object]:
    context = _appliance_target_context(args)
    target = context.target
    profile = context.profile
    command = _appliance_command_parts(args.remote_command)
    deploy_plan = render_endpoint_appliance_deploy_plan(
        target,
        env=context.profile_environment,
        image_tag=profile.image,
    )
    sync_plan = None
    if args.work_dir is not None:
        sync_plan = render_endpoint_appliance_sync_plan(
            target,
            source_root=args.work_dir,
            artifact_dir=args.artifact_dir,
        )
    run_plan = render_endpoint_appliance_run_plan(
        target,
        profile,
        command,
        sync_context=sync_plan,
        artifact_dir=args.artifact_dir,
        env=context.profile_environment,
    )
    output = {
        "kind": "endpoint-appliance-plan",
        "endpoint_id": target.endpoint_id,
        "profile": profile.name,
        "dry_run": True,
        "executes": False,
        "deploy": deploy_plan,
        "sync": sync_plan,
        "run": run_plan,
    }
    return _finalize_appliance_output(output, context)  # type: ignore[return-value]


def _appliance_check_output(args: argparse.Namespace) -> dict[str, object]:
    context = _appliance_target_context(args)
    target = context.target
    profile = context.profile
    deploy_plan = render_endpoint_appliance_deploy_plan(
        target,
        env=context.profile_environment,
        image_tag=profile.image,
    )
    output: dict[str, object] = {
        "kind": "endpoint-appliance-check-plan",
        "endpoint_id": target.endpoint_id,
        "profile": profile.name,
        "dry_run": args.dry_run,
        "executes": False,
        "docker_check": deploy_plan.commands[0],
        "profile_checks": profile.checks,
        "host_requirements": profile.host_requirements,
    }
    return _finalize_appliance_output(output, context)  # type: ignore[return-value]


def _appliance_deploy_output(args: argparse.Namespace) -> object:
    context = _appliance_target_context(args)
    target = context.target
    profile = context.profile
    if args.dry_run:
        output = render_endpoint_appliance_deploy_plan(
            target,
            env=context.profile_environment,
            image_tag=profile.image,
        )
        return _finalize_appliance_output(output, context)
    output = deploy_endpoint_appliance_target(
        target,
        runner=run_command,
        artifact_dir=args.artifact_dir,
        env=context.profile_environment,
        image_tag=profile.image,
    )
    return _finalize_appliance_output(output, context)


def _appliance_run_output(args: argparse.Namespace) -> object:
    context = _appliance_target_context(args)
    target = context.target
    profile = context.profile
    command = _appliance_command_parts(args.remote_command)
    if args.dry_run:
        return _appliance_plan_output(args)

    sync_context = None
    if args.work_dir is not None:
        sync_context = sync_endpoint_appliance_workspace(
            target,
            runner=run_command,
            source_root=args.work_dir,
            artifact_dir=args.artifact_dir,
        )
        if not sync_context.ok:
            output = {
                "kind": "endpoint-appliance-run",
                "endpoint_id": target.endpoint_id,
                "profile": profile.name,
                "ok": False,
                "sync": sync_context,
                "error": "workspace sync failed",
            }
            return _finalize_appliance_output(output, context)
    output = run_endpoint_appliance_command(
        target,
        profile,
        command,
        runner=run_command,
        sync_context=sync_context,
        artifact_dir=args.artifact_dir,
        env=context.profile_environment,
    )
    return _finalize_appliance_output(output, context)


def _appliance_collect_output(args: argparse.Namespace) -> object:
    context = _appliance_target_context(args)
    target = context.target
    profile = context.profile
    command = _appliance_command_parts(args.remote_command, default=("true",))
    run_plan = render_endpoint_appliance_run_plan(
        target,
        profile,
        command,
        artifact_dir=args.artifact_dir,
        env=context.profile_environment,
    )
    if args.dry_run:
        output = {
            "kind": "endpoint-appliance-collect-plan",
            "endpoint_id": target.endpoint_id,
            "profile": profile.name,
            "dry_run": True,
            "executes": False,
            "run": run_plan,
            "remote_artifact_root": run_plan.remote_artifact_root,
            "artifact_dir": run_plan.local_artifact_dir,
        }
        return _finalize_appliance_output(output, context)
    output = collect_endpoint_appliance_run_artifacts(
        run_plan.to_dict(),
        runner=run_command,
        artifact_dir=args.artifact_dir,
    )
    return _finalize_appliance_output(output, context)


def _emit_appliance_output(
    args: argparse.Namespace,
    output: object,
    *,
    default_label: str,
) -> int:
    if args.json:
        sys.stdout.write(dumps_json(output))
    else:
        _print_appliance_output(output, default_label=default_label)
    return _appliance_exit_code(output)


def _emit_appliance_error(args: argparse.Namespace, error: str) -> int:
    output = {
        "kind": "endpoint-appliance-error",
        "endpoint_id": getattr(args, "endpoint_id", None),
        "lease_id": getattr(args, "lease_id", None),
        "profile": getattr(args, "profile", None),
        "ok": False,
        "error": error,
    }
    if getattr(args, "json", False):
        sys.stdout.write(dumps_json(output))
    else:
        print(error, file=sys.stderr)
    return 1


def _print_doctor_report(report: dict[str, object]) -> None:
    status = "ok" if bool(report["ok"]) else "failed"
    print(
        "endpoint doctor: "
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
        "endpoint create: "
        f"provider={manifest['provider']} exposure={manifest['exposure']} "
        f"endpoint_id={manifest['endpoint_id']} created={created}"
    )
    print(f"state: {manifest['manifest_path']}")
    print(f"artifacts: {manifest['artifact_dir']}")


def _print_destroy_endpoint_report(output: dict[str, object]) -> None:
    print(
        "endpoint destroy: "
        f"endpoint_id={output['endpoint_id']} status={output['status']} "
        f"destroyed={str(bool(output['destroyed'])).lower()}"
    )
    if output.get("manifest_path"):
        print(f"state: {output['manifest_path']}")
    if output.get("artifact_dir"):
        print(f"artifacts: {output['artifact_dir']}")


def _print_virtualbox_normalize_groups_report(output: dict[str, object]) -> None:
    print(
        "endpoint virtualbox normalize-groups: "
        f"dry_run={str(bool(output.get('dry_run'))).lower()} "
        f"candidates={output.get('candidate_count', 0)} "
        f"planned={output.get('planned_count', 0)} "
        f"changed={output.get('changed_count', 0)} "
        f"already_grouped={output.get('already_grouped_count', 0)} "
        f"missing={output.get('missing_count', 0)} "
        f"failed={output.get('failed_count', 0)}"
    )


def _print_ssh_info(output: dict[str, object]) -> None:
    print(
        "endpoint ssh-info: "
        f"endpoint_id={output['endpoint_id']} host={output.get('host')} "
        f"user={output.get('user')} port={output.get('port')}"
    )
    print(f"identity: {output['identity_file']}")
    print(f"known_hosts: {output['known_hosts_file']}")
    print(f"ssh: {output['ssh_command']}")


def _print_endpoint_list(output: dict[str, object]) -> None:
    endpoints = output["endpoints"]
    if not isinstance(endpoints, list) or not endpoints:
        print("endpoint list: no endpoints")
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


def _print_asset_output(output: dict[str, object], *, default_label: str) -> None:
    if default_label == "list":
        assets = output["assets"]
        if not isinstance(assets, list) or not assets:
            print("endpoint asset list: no assets")
            return
        for asset in assets:
            if not isinstance(asset, dict):
                continue
            print(
                f"{asset.get('asset_id')}\t"
                f"{asset.get('substrate')}\t"
                f"{asset.get('status')}\t"
                f"{asset.get('lease_state')}\t"
                f"{asset.get('last_check_state')}"
            )
        return
    asset_id = output.get("asset_id", "<unknown>")
    asset_path = output.get("asset_path")
    ok = output.get("ok")
    status = "" if ok is None else f" ok={str(bool(ok)).lower()}"
    print(f"endpoint asset {default_label}: asset_id={asset_id}{status}")
    if isinstance(asset_path, str):
        print(f"state: {asset_path}")


def _print_appliance_output(output: object, *, default_label: str) -> None:
    if isinstance(output, dict):
        endpoint_id = output.get("endpoint_id", "<unknown>")
        profile = output.get("profile")
        lease_id = output.get("lease_id")
        asset_id = output.get("asset_id")
        ok = output.get("ok")
        status = "" if ok is None else f" ok={str(bool(ok)).lower()}"
        profile_text = "" if profile is None else f" profile={profile}"
        lease_text = ""
        if isinstance(lease_id, str):
            lease_text = f" lease_id={lease_id}"
            if isinstance(asset_id, str):
                lease_text += f" asset_id={asset_id}"
        print(
            f"endpoint appliance {default_label}: "
            f"endpoint_id={endpoint_id}{profile_text}{lease_text}{status}"
        )
        artifact_dir = output.get("artifact_dir")
        if isinstance(artifact_dir, str):
            print(f"artifacts: {artifact_dir}")
        _print_appliance_release_guidance(output)
        return
    data = output.to_dict() if hasattr(output, "to_dict") else {}
    if isinstance(data, dict):
        endpoint_id = data.get("endpoint_id", "<unknown>")
        profile = data.get("profile")
        ok = data.get("ok")
        status = "" if ok is None else f" ok={str(bool(ok)).lower()}"
        profile_text = "" if profile is None else f" profile={profile}"
        print(f"endpoint appliance {default_label}: endpoint_id={endpoint_id}{profile_text}{status}")
        artifact_dir = data.get("artifact_dir") or data.get("local_artifact_dir")
        if isinstance(artifact_dir, str):
            print(f"artifacts: {artifact_dir}")
        _print_appliance_release_guidance(data)
        return
    print(f"endpoint appliance {default_label}")


def _print_appliance_release_guidance(output: dict[str, object]) -> None:
    release = output.get("release_after_run")
    if not isinstance(release, dict):
        return
    command = release.get("command_string")
    if isinstance(command, str):
        print(f"release: {command}")


def _appliance_exit_code(output: object) -> int:
    if hasattr(output, "to_dict"):
        data = output.to_dict()
    else:
        data = output
    if not isinstance(data, dict):
        return 0
    ok = data.get("ok")
    if ok is False:
        exit_code = data.get("exit_code")
        return int(exit_code) if isinstance(exit_code, int) and exit_code != 0 else 1
    return 0


def _remote_command_parts(remote_command: Sequence[str]) -> list[str]:
    command = list(remote_command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise ValueError("endpoint exec requires COMMAND after ENDPOINT_ID --")
    return command


def _appliance_command_parts(
    remote_command: Sequence[str],
    *,
    default: Sequence[str] = (),
) -> list[str]:
    command = list(remote_command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        command = list(default)
    if not command:
        raise ValueError("endpoint appliance command requires COMMAND after PROFILE --")
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


def _split_appliance_argv(argv: Sequence[str]) -> tuple[list[str], list[str] | None]:
    parts = list(argv)
    if len(parts) < 2 or parts[0] != "appliance":
        return parts, None
    if parts[1] not in {"plan", "check", "deploy", "run", "collect"}:
        return parts, None
    try:
        separator = parts.index("--", 2)
    except ValueError:
        return parts, None
    return parts[:separator], parts[separator + 1 :]


def main(argv: Sequence[str] | None = None) -> int:
    """Run the endpoint command-line interface."""
    parser = build_parser()
    raw_argv = sys.argv[1:] if argv is None else list(argv)
    parse_argv, appliance_remote_command = _split_appliance_argv(raw_argv)
    args = parser.parse_args(parse_argv)
    if appliance_remote_command is not None:
        args.remote_command = appliance_remote_command
    if getattr(args, "command", None) is None:
        parser.print_help(sys.stdout)
        return 0
    if args.command_name == "appliance":
        return _run_appliance(args)
    if args.command_name == "asset":
        return _run_asset(args)
    if args.command_name == "doctor":
        return _run_doctor(args)
    if args.command_name == "create":
        return _run_create_endpoint(args)
    if args.command_name == "destroy":
        return _run_destroy_endpoint(args)
    if args.command_name == "virtualbox":
        return _run_virtualbox(args)
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
    if args.command_name == "list":
        return _run_list_endpoints(args)
    parser.error(f"{args.command_name!r} is not implemented yet")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
