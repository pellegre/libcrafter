"""Command-line interface scaffold for tools/lab."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from . import session as lab_session_state
from . import endpoint_client
from .model import JSONObject, LabRequest, LabRole, LabSession
from .providers import UnknownLabProviderError, registered_providers, resolve_lab_provider


COMMANDS = (
    "providers",
    "plan",
    "doctor",
    "create",
    "destroy",
    "list-sessions",
    "session-info",
)

DEFAULT_LAB_ROLE_SPECS = ("stimulus", "target")
BGP_SMOKE_PROFILE = "bgp-smoke"
BGP_STIMULUS_ROLE = "stimulus"
BGP_TARGET_ROLE = "target"


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
    create.add_argument("--dry-run", action="store_true", help="plan without making changes")
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
        metavar="ROLE",
        help=(
            "role to include in the lab session, optionally ROLE=IPV4; may be repeated "
            "(default: stimulus and target)"
        ),
    )
    parser.add_argument(
        "--role-address",
        "--role-private-ip",
        dest="role_addresses",
        action="append",
        default=[],
        metavar="ROLE=IPV4",
        help="role IPv4 address override; may be repeated",
    )
    parser.add_argument(
        "--workload-label",
        "--workload",
        dest="workload_label",
        help="workload label used for deterministic session and resource names",
    )
    parser.add_argument(
        "--remote-dir",
        help="absolute remote repository directory planned for lab bootstrap",
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


def _run_providers(args: argparse.Namespace) -> int:
    output = {
        "ok": True,
        "providers": [_provider_metadata(provider) for provider in registered_providers()],
    }
    if getattr(args, "json", False):
        sys.stdout.write(json.dumps(output, indent=2, sort_keys=True))
        sys.stdout.write("\n")
    else:
        for provider in output["providers"]:
            if not isinstance(provider, dict):
                continue
            print(
                f"{provider['name']}\t"
                f"wire={provider['wire_provider']}/{provider['wire_exposure']}"
            )
    return 0


def _run_doctor(args: argparse.Namespace) -> int:
    try:
        adapter = resolve_lab_provider(args.provider)
        dry_run = True
        endpoint = endpoint_client.EndpointClient()
        response = endpoint.doctor(
            provider=adapter.wire_provider,
            exposure=adapter.wire_exposure,
            dry_run=dry_run,
        )
        wire_doctor = response.json_data or {}
        wire_ok = bool(wire_doctor.get("ok", response.ok))
        output: JSONObject = {
            "ok": wire_ok,
            "command": args.command_name,
            "provider": adapter.name,
            "wire_provider": adapter.wire_provider,
            "wire_exposure": adapter.wire_exposure,
            "dry_run": dry_run,
            "requested_dry_run": bool(getattr(args, "dry_run", False)),
            "metadata": _provider_metadata(adapter),
            "wire_doctor": wire_doctor,
            "command_records": [
                response.command_plan(
                    purpose=f"check-{adapter.name}-{adapter.wire_exposure}-wire",
                ).to_dict()
            ],
        }
        exit_code = 0 if dry_run else (0 if wire_ok else 1)
        return _write_output(
            output,
            args,
            text=(
                f"lab doctor: provider={adapter.name} "
                f"wire={adapter.wire_provider}/{adapter.wire_exposure} "
                f"dry_run={str(dry_run).lower()} "
                f"status={'ok' if wire_ok else 'failed'}"
            ),
            exit_code=exit_code,
        )
    except (UnknownLabProviderError, endpoint_client.EndpointClientError, ValueError) as exc:
        return _write_output(
            _error_output(args, exc),
            args,
            text=str(exc),
            exit_code=2,
        )


def _run_plan(args: argparse.Namespace) -> int:
    if not args.dry_run:
        output = {
            "ok": False,
            "command": args.command_name,
            "error": "confirm_live_run_required",
            "message": "lab plan currently supports dry-run planning only",
        }
        return _write_output(output, args, text="lab plan requires --dry-run", exit_code=2)

    try:
        adapter = resolve_lab_provider(args.provider)
        request = LabRequest(
            provider=adapter.name,
            profile=args.profile,
            seed=args.seed,
            roles=_lab_roles_from_args(
                provider=adapter.name,
                profile=args.profile,
                role_specs=args.roles,
                address_specs=args.role_addresses,
            ),
            dry_run=True,
            confirm_live_run=False,
            remote_dir=args.remote_dir,
            workload_label=args.workload_label,
        )
        session = adapter.plan_session(request)
        return _write_output(session.to_dict(), args, text=session.session_id)
    except (
        PermissionError,
        UnknownLabProviderError,
        ValueError,
        endpoint_client.EndpointClientError,
    ) as exc:
        return _write_output(
            _error_output(args, exc),
            args,
            text=str(exc),
            exit_code=2,
        )


def _run_create(args: argparse.Namespace) -> int:
    dry_run = bool(getattr(args, "dry_run", False))
    if not dry_run and not args.confirm_live_run:
        output = {
            "ok": False,
            "command": args.command_name,
            "error": "confirm_live_run_required",
            "message": "lab create requires --confirm-live-run for non-dry-run execution",
        }
        return _write_output(
            output,
            args,
            text="lab create requires --confirm-live-run",
            exit_code=2,
        )

    try:
        adapter = resolve_lab_provider(args.provider)
        request = LabRequest(
            provider=adapter.name,
            profile=args.profile,
            seed=args.seed,
            roles=_lab_roles_from_args(
                provider=adapter.name,
                profile=args.profile,
                role_specs=args.roles,
                address_specs=args.role_addresses,
            ),
            dry_run=dry_run,
            confirm_live_run=bool(args.confirm_live_run) and not dry_run,
            remote_dir=args.remote_dir,
            workload_label=args.workload_label,
        )
        if dry_run:
            lab_session = adapter.plan_session(request)
        else:
            lab_session = lab_session_state.create_session(adapter, request)
        return _write_output(
            lab_session.to_dict(),
            args,
            text=f"lab create: session={lab_session.session_id}",
        )
    except (
        PermissionError,
        UnknownLabProviderError,
        ValueError,
        endpoint_client.EndpointClientError,
    ) as exc:
        return _write_output(
            _error_output(args, exc),
            args,
            text=str(exc),
            exit_code=2,
        )


def _run_destroy(args: argparse.Namespace) -> int:
    try:
        lab_session = lab_session_state.destroy_session(args.session)
        cleanup_status = str(lab_session.cleanup_state.get("status", "unknown"))
        exit_code = 0 if cleanup_status in {"completed", "no_endpoints"} else 1
        return _write_output(
            lab_session.to_dict(),
            args,
            text=f"lab destroy: session={lab_session.session_id} status={cleanup_status}",
            exit_code=exit_code,
        )
    except (FileNotFoundError, ValueError, endpoint_client.EndpointClientError) as exc:
        return _write_output(
            _error_output(args, exc),
            args,
            text=str(exc),
            exit_code=1,
        )


def _run_list_sessions(args: argparse.Namespace) -> int:
    try:
        sessions = lab_session_state.list_session_manifests()
    except (FileNotFoundError, ValueError) as exc:
        return _write_output(
            _error_output(args, exc),
            args,
            text=str(exc),
            exit_code=1,
        )

    output: JSONObject = {
        "ok": True,
        "sessions": [_session_summary(session) for session in sessions],
    }
    return _write_output(
        output,
        args,
        text="\n".join(
            f"{session.session_id}\t{session.provider}\t{_cleanup_status(session)}"
            for session in sessions
        ),
    )


def _run_session_info(args: argparse.Namespace) -> int:
    try:
        lab_session = lab_session_state.read_session_manifest(args.session_id)
    except (FileNotFoundError, ValueError) as exc:
        return _write_output(
            _error_output(args, exc),
            args,
            text=str(exc),
            exit_code=1,
        )
    return _write_output(
        lab_session.to_dict(),
        args,
        text=f"lab session-info: session={lab_session.session_id}",
    )


def _provider_metadata(provider: object) -> JSONObject:
    return {
        "name": provider.name,
        "wire_provider": provider.wire_provider,
        "wire_exposure": provider.wire_exposure,
        "credential_label": provider.credential_label,
        "credentials_available": provider.credentials_available(),
        "missing_credential_reason": provider.missing_credential_reason,
        "capabilities": provider.default_provider_capabilities(dry_run=True),
    }


def _session_summary(session: LabSession) -> JSONObject:
    return {
        "session_id": session.session_id,
        "provider": session.provider,
        "wire_provider": session.wire_provider,
        "wire_exposure": session.wire_exposure,
        "roles": [role.name for role in session.roles],
        "endpoint_ids": [endpoint.endpoint_id for endpoint in session.endpoints],
        "created_endpoint_ids": list(session.created_endpoint_ids),
        "dry_run": session.dry_run,
        "remote_dir": session.remote_dir,
        "remote_artifact_root": session.remote_artifact_root,
        "cleanup_state": dict(session.cleanup_state),
    }


def _cleanup_status(session: LabSession) -> str:
    status = session.cleanup_state.get("status")
    return status if isinstance(status, str) else "unknown"


def _lab_roles_from_args(
    *,
    provider: str,
    profile: str,
    role_specs: Sequence[str] | None,
    address_specs: Sequence[str],
) -> list[LabRole]:
    role_names: list[str] = []
    addresses: dict[str, str] = {}

    for spec in role_specs or DEFAULT_LAB_ROLE_SPECS:
        role_name, address = _parse_role_spec(spec)
        role_names.append(role_name)
        if address is not None:
            _set_role_address(addresses, role_name, address)

    known_roles = set(role_names)
    for spec in address_specs:
        role_name, address = _parse_role_address_spec(spec)
        if role_name not in known_roles:
            raise ValueError(f"role address override references unknown role: {role_name}")
        _set_role_address(addresses, role_name, address)

    roles: list[LabRole] = []
    for role_name in role_names:
        address = addresses.get(role_name)
        role_kwargs = _profile_role_metadata(profile=profile, role_name=role_name)
        if provider == "virtualbox":
            roles.append(LabRole(name=role_name, planned_ipv4=address, **role_kwargs))
        else:
            roles.append(
                LabRole(name=role_name, requested_private_ipv4=address, **role_kwargs)
            )
    return roles


def _profile_role_metadata(*, profile: str, role_name: str) -> dict[str, object]:
    if profile != BGP_SMOKE_PROFILE:
        return {}
    if role_name == BGP_STIMULUS_ROLE:
        return {
            "capabilities": [
                "bgp_session_driver",
                "tcp_client",
                "artifact_output",
            ],
            "bootstrap_metadata": {
                "cargo_example": "bgp_session",
                "driver_source": "crafter/examples/bgp_session.rs",
            },
            "workload_metadata": {
                "workload": "bgp-live",
                "role": BGP_STIMULUS_ROLE,
                "driver": "bgp_session",
                "driver_source": "crafter/examples/bgp_session.rs",
                "peer_role": BGP_TARGET_ROLE,
                "artifact_subdir": "bgp",
            },
        }
    if role_name == BGP_TARGET_ROLE:
        return {
            "capabilities": [
                "frr_bgp_peer",
                "controlled_service",
                "rib_inspection",
            ],
            "bootstrap_metadata": {
                "service": "frr",
                "provision_script": "tools/lab/workloads/bgp/provision-peer.sh",
                "frr_template": "tools/lab/workloads/bgp/frr.conf.template",
            },
            "workload_metadata": {
                "workload": "bgp-live",
                "role": BGP_TARGET_ROLE,
                "peer": "frr",
                "provision_script": "tools/lab/workloads/bgp/provision-peer.sh",
                "frr_template": "tools/lab/workloads/bgp/frr.conf.template",
                "peer_role": BGP_STIMULUS_ROLE,
                "rib_command": "vtysh -c 'show bgp ipv4 unicast'",
            },
        }
    return {}


def _parse_role_spec(value: str) -> tuple[str, str | None]:
    if "=" in value:
        role, address = value.split("=", 1)
        return _non_empty(role, "role name"), _non_empty(address, "role address")
    return _non_empty(value, "role name"), None


def _parse_role_address_spec(value: str) -> tuple[str, str]:
    if "=" in value:
        role, address = value.split("=", 1)
    elif ":" in value:
        role, address = value.split(":", 1)
    else:
        raise ValueError(f"role address override must be ROLE=IPV4: {value!r}")
    return _non_empty(role, "role name"), _non_empty(address, "role address")


def _set_role_address(addresses: dict[str, str], role: str, address: str) -> None:
    existing = addresses.get(role)
    if existing is not None and existing != address:
        raise ValueError(
            f"role {role!r} has conflicting address overrides: {existing}, {address}"
        )
    addresses[role] = address


def _non_empty(value: str, label: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"{label} must be non-empty")
    return stripped


def _error_output(args: argparse.Namespace, exc: Exception) -> JSONObject:
    return {
        "ok": False,
        "command": args.command_name,
        "error": type(exc).__name__,
        "message": str(exc),
    }


def _write_output(
    output: dict[str, object],
    args: argparse.Namespace,
    *,
    text: str,
    exit_code: int = 0,
) -> int:
    if getattr(args, "json", False):
        sys.stdout.write(json.dumps(output, indent=2, sort_keys=True))
        sys.stdout.write("\n")
    else:
        stream = sys.stdout if exit_code == 0 else sys.stderr
        print(text, file=stream)
    return exit_code


def main(argv: Sequence[str] | None = None) -> int:
    """Run the lab command-line interface."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "command", None) is None:
        parser.print_help(sys.stdout)
        return 0
    if args.command_name == "providers":
        return _run_providers(args)
    if args.command_name == "doctor":
        return _run_doctor(args)
    if args.command_name == "plan":
        return _run_plan(args)
    if args.command_name == "create":
        return _run_create(args)
    if args.command_name == "destroy":
        return _run_destroy(args)
    if args.command_name == "list-sessions":
        return _run_list_sessions(args)
    if args.command_name == "session-info":
        return _run_session_info(args)
    if args.command_name in COMMANDS:
        return _run_not_implemented(args)
    parser.error(f"{args.command_name!r} is not implemented yet")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
