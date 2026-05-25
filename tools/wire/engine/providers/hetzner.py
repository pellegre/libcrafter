"""Hetzner provider checks and lifecycle operations for wire endpoints."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import time
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from ..model import (
    EndpointManifest,
    EndpointSSHInfo,
    NetworkInterface,
    ProviderResource,
    ProviderResources,
)
from ..process import CommandResult, run_command
from ..registry import validate_request
from ..ssh import create_key_pair, ensure_known_hosts_file, run_ssh_command, wait_for_ssh
from ..state import (
    DEFAULT_PRIVATE_CIDR,
    endpoint_layout,
    ensure_endpoint_dirs,
    planned_private_group_record,
    read_private_group_record,
    remove_private_group_allocation,
    update_private_group_allocation,
    write_endpoint_manifest,
)


TOKEN_ENV = "HETZNER_API_TOKEN"
HCLOUD_TOKEN_ENV = "HCLOUD_TOKEN"
HCLOUD_COMMAND = "hcloud"
PLANNED_CREATED_AT = "planned"
CONFIRMATION_ERROR = (
    "protected provider execution requires --confirm-live-run; no Hetzner resources were created"
)
DEFAULT_SERVER_TYPE = "cx22"
DEFAULT_IMAGE = "ubuntu-24.04"
DEFAULT_LOCATION = "hel1"
DEFAULT_PRIVATE_NETWORK_ZONE = "eu-central"
DEFAULT_SERVER_RUNNING_TIMEOUT = 300
DEFAULT_SERVER_RUNNING_INTERVAL = 5
INTERFACE_DISCOVERY_COMMAND = "\n".join(
    [
        "set -eu",
        "printf '%s\\n' __WIRE_IP_ADDR__",
        "ip -j address show scope global",
        "printf '%s\\n' __WIRE_IP_LINK__",
        "ip -j link show",
        "printf '%s\\n' __WIRE_IP_ROUTE__",
        "ip -j route get 1.1.1.1 || true",
    ]
)
HcloudRunner = Callable[..., CommandResult]


def doctor(
    *,
    provider: str,
    exposure: str,
    dry_run: bool = False,
    env: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Return non-mutating Hetzner provider prerequisite checks."""

    validate_request(provider, exposure)

    environ = os.environ if env is None else env
    hcloud_path = shutil.which(HCLOUD_COMMAND)
    token_configured = bool(_hetzner_token(environ))
    credential_required = not dry_run

    checks: list[dict[str, object]] = [
        {
            "name": "provider_exposure",
            "ok": True,
            "message": f"{provider}/{exposure} is supported",
        },
        {
            "name": "hcloud_installed",
            "ok": hcloud_path is not None,
            "message": (
                f"{HCLOUD_COMMAND} found at {hcloud_path}"
                if hcloud_path is not None
                else f"{HCLOUD_COMMAND} was not found on PATH"
            ),
        },
        {
            "name": "hetzner_api_token",
            "ok": token_configured or dry_run,
            "message": (
                f"{TOKEN_ENV} or {HCLOUD_TOKEN_ENV} is configured"
                if token_configured
                else f"{TOKEN_ENV} or {HCLOUD_TOKEN_ENV} is not configured"
            ),
        },
    ]

    return {
        "provider": provider,
        "exposure": exposure,
        "dry_run": dry_run,
        "ok": all(bool(check["ok"]) for check in checks),
        "checks": checks,
        "hcloud": {
            "command": HCLOUD_COMMAND,
            "installed": hcloud_path is not None,
            "path": hcloud_path,
        },
        "credentials": {
            "env": TOKEN_ENV,
            "accepted_env": [TOKEN_ENV, HCLOUD_TOKEN_ENV],
            "configured": token_configured,
            "required": credential_required,
        },
    }


def create_endpoint(
    *,
    provider: str,
    exposure: str,
    role: str,
    private_group: str | None = None,
    private_ip: str | None = None,
    dry_run: bool = False,
    confirm_live_run: bool = False,
    env: Mapping[str, str] | None = None,
    command_runner: HcloudRunner = run_command,
) -> dict[str, object]:
    """Create or plan one Hetzner endpoint."""

    validate_request(provider, exposure)
    _validate_create_request(exposure, role, private_group, private_ip)

    if dry_run:
        return _planned_endpoint_manifest(
            provider=provider,
            exposure=exposure,
            role=role,
            private_group=private_group,
            private_ip=private_ip,
        )

    if not confirm_live_run:
        raise PermissionError(CONFIRMATION_ERROR)

    if exposure == "wan":
        return _create_wan_endpoint(
            provider=provider,
            exposure=exposure,
            role=role,
            env=env,
            command_runner=command_runner,
        )
    if exposure == "private":
        return _create_private_endpoint(
            provider=provider,
            exposure=exposure,
            role=role,
            private_group=private_group,
            private_ip=private_ip,
            env=env,
            command_runner=command_runner,
        )
    raise NotImplementedError(f"real hetzner create-endpoint is not implemented for {exposure}")


def destroy_endpoint(
    manifest: EndpointManifest,
    *,
    env: Mapping[str, str] | None = None,
    command_runner: HcloudRunner = run_command,
) -> dict[str, object]:
    """Destroy Hetzner resources recorded in one endpoint manifest."""

    if manifest.provider != "hetzner":
        raise ValueError(f"endpoint provider is not hetzner: {manifest.provider}")

    private_destroy = _private_destroy_context(manifest)
    resources = _cleanup_resources(manifest)
    if manifest.status == "destroyed":
        output = _destroy_output(
            manifest=manifest,
            actions=[],
            skipped=[
                _destroy_action(resource, action="skip", reason="endpoint already destroyed")
                for resource in resources
            ],
            destroyed=False,
            already_destroyed=True,
        )
        return output

    actions: list[dict[str, object]] = []
    skipped: list[dict[str, object]] = []
    real_resources = [
        resource for resource in resources if _destroy_command(resource) is not None
    ]
    needs_private_hcloud = (
        private_destroy is not None
        and (
            private_destroy.get("server_resource") is not None
            or private_destroy.get("network_resource") is not None
        )
    )
    hcloud_env: Mapping[str, str] = {}
    if real_resources or needs_private_hcloud:
        environ = os.environ if env is None else env
        token = _hetzner_token(environ)
        if command_runner is run_command and not token:
            raise RuntimeError(f"{TOKEN_ENV} or {HCLOUD_TOKEN_ENV} must be configured")
        if command_runner is run_command and shutil.which(HCLOUD_COMMAND) is None:
            raise RuntimeError(f"{HCLOUD_COMMAND} was not found on PATH")
        hcloud_env = {HCLOUD_TOKEN_ENV: token} if token else {}

    if private_destroy is not None:
        detach_action = _detach_private_endpoint_from_network(
            private_destroy,
            env=hcloud_env,
            command_runner=command_runner,
        )
        if detach_action is not None:
            actions.append(detach_action)

    for resource in resources:
        argv = _destroy_command(resource)
        if argv is None:
            skipped.append(
                _destroy_action(
                    resource,
                    action="skip",
                    reason=f"resource kind {resource.kind!r} is not destroyed by hetzner provider",
                )
            )
            continue

        result = command_runner(argv, env=hcloud_env, timeout=120)
        if result.ok:
            actions.append(_destroy_action(resource, action="delete", result=result))
            continue
        if _is_missing_resource_result(result):
            actions.append(
                _destroy_action(
                    resource,
                    action="already-missing",
                    result=result,
                    reason="provider resource was already missing",
                )
            )
            continue
        raise RuntimeError(_command_error("hcloud destroy command failed", result))

    private_group_update: dict[str, object] | None = None
    if private_destroy is not None:
        private_group_update = _remove_private_endpoint_from_group(
            manifest,
            private_destroy,
        )
        actions.extend(
            _delete_private_network_if_unused(
                private_destroy,
                private_group_update=private_group_update,
                env=hcloud_env,
                command_runner=command_runner,
            )
        )

    destroyed_at = _utc_now()
    destroyed_manifest = replace(
        manifest,
        status="destroyed",
        metadata={
            **manifest.metadata,
            "destroyed_at": destroyed_at,
            "destroy": {
                "provider": "hetzner",
                "actions": actions,
                "skipped": skipped,
            },
            **(
                {"private_group_destroy": private_group_update}
                if private_group_update is not None
                else {}
            ),
        },
    )
    manifest_path = write_endpoint_manifest(destroyed_manifest)
    output = _destroy_output(
        manifest=destroyed_manifest,
        actions=actions,
        skipped=skipped,
        destroyed=True,
        already_destroyed=False,
    )
    output["manifest_path"] = str(manifest_path)
    output["state_dir"] = str(manifest_path.parent)
    return output


def cli_output_manifest(manifest: Mapping[str, object]) -> dict[str, object]:
    """Return a CLI-compatible manifest view without changing stored schema."""

    output = dict(manifest)
    provider_resources = output.get("provider_resources")
    if isinstance(provider_resources, Mapping):
        resources = provider_resources.get("resources")
        if isinstance(resources, list):
            output["provider_resources"] = [
                _compat_provider_resource(resource) for resource in resources
            ]
    return output


def _create_wan_endpoint(
    *,
    provider: str,
    exposure: str,
    role: str,
    env: Mapping[str, str] | None,
    command_runner: HcloudRunner = run_command,
) -> dict[str, object]:
    environ = os.environ if env is None else env
    token = _hetzner_token(environ)
    if not token:
        raise RuntimeError(f"{TOKEN_ENV} or {HCLOUD_TOKEN_ENV} must be configured")
    if command_runner is run_command and shutil.which(HCLOUD_COMMAND) is None:
        raise RuntimeError(f"{HCLOUD_COMMAND} was not found on PATH")

    created_at = _utc_now()
    endpoint_id = _real_endpoint_id(provider=provider, exposure=exposure, role=role)
    layout = ensure_endpoint_dirs(endpoint_id)
    ensure_known_hosts_file(layout.known_hosts_path)
    _ensure_endpoint_key(layout.private_key_path, endpoint_id)

    server_id: str | None = None
    ssh_key_id: str | None = None
    public_ipv4: str | None = None
    public_ipv6: str | None = None
    ssh_host: str | None = None
    server_name = _server_name(endpoint_id)
    ssh_key_name = f"{server_name}-key"
    hcloud_env = {HCLOUD_TOKEN_ENV: token}

    try:
        ssh_key = _hcloud_json(
            [
                HCLOUD_COMMAND,
                "ssh-key",
                "create",
                "--name",
                ssh_key_name,
                "--public-key-from-file",
                str(_public_key_path(layout.private_key_path)),
                "-o",
                "json",
            ],
            env=hcloud_env,
            command_runner=command_runner,
        )
        ssh_key_id = _object_id(_json_object(ssh_key.get("ssh_key", ssh_key), "ssh_key"))

        server = _hcloud_json(
            [
                HCLOUD_COMMAND,
                "server",
                "create",
                "--name",
                server_name,
                "--type",
                _env_or_default(environ, "HETZNER_SERVER_TYPE", DEFAULT_SERVER_TYPE),
                "--image",
                _env_or_default(environ, "HETZNER_IMAGE", DEFAULT_IMAGE),
                "--location",
                _env_or_default(environ, "HETZNER_LOCATION", DEFAULT_LOCATION),
                "--ssh-key",
                ssh_key_name,
                "--label",
                "libcrafter-wire=true",
                "--label",
                f"libcrafter-wire-endpoint-id={_label_value(endpoint_id)}",
                "--label",
                f"libcrafter-wire-role={_label_value(role)}",
                "--label",
                "libcrafter-wire-exposure=wan",
                "-o",
                "json",
            ],
            env=hcloud_env,
            command_runner=command_runner,
        )
        server_object = _json_object(server.get("server", server), "server")
        server_id = _object_id(server_object)
        public_net = _json_object(server_object.get("public_net", {}), "server.public_net")
        public_ipv4 = _ip_address(public_net.get("ipv4"))
        public_ipv6 = _ip_address(public_net.get("ipv6"))
        ssh_host = public_ipv4 or public_ipv6
        if ssh_host is None:
            raise RuntimeError("hcloud server create did not return a public IPv4 or IPv6 address")

        provider_resources = _wan_provider_resources(
            provider=provider,
            server_id=server_id,
            server_name=server_name,
            ssh_key_id=ssh_key_id,
            ssh_key_name=ssh_key_name,
            public_ipv4=public_ipv4,
            public_ipv6=public_ipv6,
        )
        initial_interfaces = [
            NetworkInterface(
                name="public",
                exposure=exposure,
                ipv4=public_ipv4,
                ipv6=public_ipv6,
                metadata={
                    "source": "hcloud",
                    "server_id": server_id,
                    "server_name": server_name,
                },
            )
        ]
        base_metadata = _wan_manifest_metadata(
            created=True,
            dry_run=False,
            layout=layout,
            server_id=server_id,
            server_name=server_name,
            ssh_key_id=ssh_key_id,
            ssh_key_name=ssh_key_name,
        )

        write_endpoint_manifest(
            EndpointManifest(
                endpoint_id=endpoint_id,
                provider=provider,
                exposure=exposure,
                status="creating",
                role=role,
                created_at=created_at,
                ssh=EndpointSSHInfo(
                    host=ssh_host,
                    user="root",
                    identity_file=str(layout.private_key_path),
                    known_hosts_file=str(layout.known_hosts_path),
                    metadata={
                        "created_by": "tools/wire",
                        "server_name": server_name,
                    },
                ),
                interfaces=initial_interfaces,
                provider_resources=provider_resources,
                artifact_dir=str(layout.artifact_dir),
                metadata={
                    **base_metadata,
                    "discovery": {
                        "server_running": False,
                        "ssh_ready": False,
                        "interfaces": False,
                    },
                },
            )
        )

        running_server = wait_for_server_running(
            server_id=server_id,
            env=hcloud_env,
            command_runner=command_runner,
        )
        try:
            wait_for_ssh(
                host=ssh_host,
                user="root",
                identity_file=layout.private_key_path,
                known_hosts=layout.known_hosts_path,
            )
        except TimeoutError as exc:
            raise RuntimeError(str(exc)) from exc
        discovered_interfaces = discover_endpoint_interfaces(
            host=ssh_host,
            user="root",
            identity_file=layout.private_key_path,
            known_hosts=layout.known_hosts_path,
            exposure=exposure,
            public_ipv4=public_ipv4,
            public_ipv6=public_ipv6,
        )

        manifest = EndpointManifest(
            endpoint_id=endpoint_id,
            provider=provider,
            exposure=exposure,
            status="active",
            role=role,
            created_at=created_at,
            ssh=EndpointSSHInfo(
                host=ssh_host,
                user="root",
                identity_file=str(layout.private_key_path),
                known_hosts_file=str(layout.known_hosts_path),
                metadata={
                    "created_by": "tools/wire",
                    "server_name": server_name,
                },
            ),
            interfaces=discovered_interfaces or initial_interfaces,
            provider_resources=provider_resources,
            artifact_dir=str(layout.artifact_dir),
            metadata={
                **base_metadata,
                "discovery": {
                    "server_running": running_server.get("status") == "running",
                    "ssh_ready": True,
                    "interfaces": bool(discovered_interfaces),
                },
            },
        )
        manifest_path = write_endpoint_manifest(manifest)
        output = manifest.to_dict()
        output["created"] = True
        output["dry_run"] = False
        output["state_dir"] = str(manifest_path.parent)
        output["manifest_path"] = str(manifest_path)
        return output
    except Exception as exc:
        if server_id is not None or ssh_key_id is not None:
            _write_failed_wan_manifest(
                endpoint_id=endpoint_id,
                provider=provider,
                exposure=exposure,
                role=role,
                created_at=created_at,
                layout=layout,
                server_id=server_id,
                server_name=server_name,
                ssh_key_id=ssh_key_id,
                ssh_key_name=ssh_key_name,
                public_ipv4=public_ipv4,
                public_ipv6=public_ipv6,
                ssh_host=ssh_host,
                error=str(exc),
            )
        _cleanup_partial_wan(server_id=server_id, ssh_key_id=ssh_key_id, env=hcloud_env)
        raise


def _create_private_endpoint(
    *,
    provider: str,
    exposure: str,
    role: str,
    private_group: str | None,
    private_ip: str | None,
    env: Mapping[str, str] | None,
    command_runner: HcloudRunner = run_command,
) -> dict[str, object]:
    if private_group is None:
        raise ValueError("--private-group is required for real private Hetzner endpoints")

    environ = os.environ if env is None else env
    token = _hetzner_token(environ)
    if not token:
        raise RuntimeError(f"{TOKEN_ENV} or {HCLOUD_TOKEN_ENV} must be configured")
    if command_runner is run_command and shutil.which(HCLOUD_COMMAND) is None:
        raise RuntimeError(f"{HCLOUD_COMMAND} was not found on PATH")

    created_at = _utc_now()
    endpoint_id = _real_endpoint_id(provider=provider, exposure=exposure, role=role)
    layout = ensure_endpoint_dirs(endpoint_id)
    ensure_known_hosts_file(layout.known_hosts_path)
    _ensure_endpoint_key(layout.private_key_path, endpoint_id)

    hcloud_env = {HCLOUD_TOKEN_ENV: token}
    private_cidr = _env_or_default(environ, "HETZNER_PRIVATE_CIDR", DEFAULT_PRIVATE_CIDR)
    network_zone = _env_or_default(
        environ,
        "HETZNER_NETWORK_ZONE",
        DEFAULT_PRIVATE_NETWORK_ZONE,
    )

    network_created = False
    server_id: str | None = None
    ssh_key_id: str | None = None
    public_ipv4: str | None = None
    public_ipv6: str | None = None
    ssh_host: str | None = None
    private_ipv4: str | None = private_ip
    network_resource: dict[str, object] = {}
    group_record_written = False
    server_name = _server_name(endpoint_id)
    ssh_key_name = f"{server_name}-key"

    try:
        private_network = _ensure_private_network(
            provider=provider,
            private_group=private_group,
            private_cidr=private_cidr,
            network_zone=network_zone,
            env=hcloud_env,
            command_runner=command_runner,
        )
        network_created = bool(private_network["created"])
        network_resource = _json_object(private_network["resource"], "private network resource")
        private_ipv4 = _allocate_private_ipv4(
            provider=provider,
            private_group=private_group,
            private_cidr=private_cidr,
            requested_private_ip=private_ip,
        )

        ssh_key = _hcloud_json(
            [
                HCLOUD_COMMAND,
                "ssh-key",
                "create",
                "--name",
                ssh_key_name,
                "--public-key-from-file",
                str(_public_key_path(layout.private_key_path)),
                "-o",
                "json",
            ],
            env=hcloud_env,
            command_runner=command_runner,
        )
        ssh_key_id = _object_id(_json_object(ssh_key.get("ssh_key", ssh_key), "ssh_key"))

        server = _hcloud_json(
            [
                HCLOUD_COMMAND,
                "server",
                "create",
                "--name",
                server_name,
                "--type",
                _env_or_default(environ, "HETZNER_SERVER_TYPE", DEFAULT_SERVER_TYPE),
                "--image",
                _env_or_default(environ, "HETZNER_IMAGE", DEFAULT_IMAGE),
                "--location",
                _env_or_default(environ, "HETZNER_LOCATION", DEFAULT_LOCATION),
                "--ssh-key",
                ssh_key_name,
                "--label",
                "libcrafter-wire=true",
                "--label",
                f"libcrafter-wire-endpoint-id={_label_value(endpoint_id)}",
                "--label",
                f"libcrafter-wire-role={_label_value(role)}",
                "--label",
                "libcrafter-wire-exposure=private",
                "--label",
                f"libcrafter-wire-private-group={_label_value(private_group)}",
                "-o",
                "json",
            ],
            env=hcloud_env,
            command_runner=command_runner,
        )
        server_object = _json_object(server.get("server", server), "server")
        server_id = _object_id(server_object)
        public_net = _json_object(server_object.get("public_net", {}), "server.public_net")
        public_ipv4 = _ip_address(public_net.get("ipv4"))
        public_ipv6 = _ip_address(public_net.get("ipv6"))
        ssh_host = public_ipv4 or public_ipv6
        if ssh_host is None:
            raise RuntimeError("hcloud server create did not return a public IPv4 or IPv6 address")

        private_interface = _private_network_interface(
            exposure=exposure,
            private_group=private_group,
            private_ipv4=private_ipv4,
            network_resource=network_resource,
            server_id=server_id,
            server_name=server_name,
        )
        base_metadata = _private_manifest_metadata(
            created=True,
            dry_run=False,
            layout=layout,
            private_group=private_group,
            private_ipv4=private_ipv4,
            network_resource=network_resource,
            network_created=network_created,
            server_id=server_id,
            server_name=server_name,
            ssh_key_id=ssh_key_id,
            ssh_key_name=ssh_key_name,
        )

        write_endpoint_manifest(
            EndpointManifest(
                endpoint_id=endpoint_id,
                provider=provider,
                exposure=exposure,
                status="creating",
                role=role,
                created_at=created_at,
                ssh=EndpointSSHInfo(
                    host=ssh_host,
                    user="root",
                    identity_file=str(layout.private_key_path),
                    known_hosts_file=str(layout.known_hosts_path),
                    metadata={
                        "created_by": "tools/wire",
                        "server_name": server_name,
                        "control_plane": "public",
                    },
                ),
                interfaces=[private_interface],
                provider_resources=_private_endpoint_provider_resources(
                    provider=provider,
                    server_id=server_id,
                    server_name=server_name,
                    ssh_key_id=ssh_key_id,
                    ssh_key_name=ssh_key_name,
                    public_ipv4=public_ipv4,
                    public_ipv6=public_ipv6,
                ),
                artifact_dir=str(layout.artifact_dir),
                metadata={
                    **base_metadata,
                    "discovery": {
                        "server_running": False,
                        "ssh_ready": False,
                        "interfaces": False,
                    },
                },
            )
        )

        _attach_server_to_private_network(
            server_id=server_id,
            network_resource=network_resource,
            private_ipv4=private_ipv4,
            env=hcloud_env,
            command_runner=command_runner,
        )
        running_server = wait_for_server_running(
            server_id=server_id,
            env=hcloud_env,
            command_runner=command_runner,
        )
        try:
            wait_for_ssh(
                host=ssh_host,
                user="root",
                identity_file=layout.private_key_path,
                known_hosts=layout.known_hosts_path,
            )
        except TimeoutError as exc:
            raise RuntimeError(str(exc)) from exc

        private_group_record = update_private_group_allocation(
            provider=provider,
            group=private_group,
            endpoint_id=endpoint_id,
            private_ipv4=private_ipv4,
            private_cidr=private_cidr,
            network_resource=network_resource,
        )
        group_record_written = True

        manifest = EndpointManifest(
            endpoint_id=endpoint_id,
            provider=provider,
            exposure=exposure,
            status="active",
            role=role,
            created_at=created_at,
            ssh=EndpointSSHInfo(
                host=ssh_host,
                user="root",
                identity_file=str(layout.private_key_path),
                known_hosts_file=str(layout.known_hosts_path),
                metadata={
                    "created_by": "tools/wire",
                    "server_name": server_name,
                    "control_plane": "public",
                },
            ),
            interfaces=[private_interface],
            provider_resources=_private_endpoint_provider_resources(
                provider=provider,
                server_id=server_id,
                server_name=server_name,
                ssh_key_id=ssh_key_id,
                ssh_key_name=ssh_key_name,
                public_ipv4=public_ipv4,
                public_ipv6=public_ipv6,
            ),
            artifact_dir=str(layout.artifact_dir),
            metadata={
                **base_metadata,
                "private_group_record": private_group_record.to_dict(),
                "discovery": {
                    "server_running": running_server.get("status") == "running",
                    "ssh_ready": True,
                    "interfaces": True,
                },
            },
        )
        manifest_path = write_endpoint_manifest(manifest)
        output = manifest.to_dict()
        output["created"] = True
        output["dry_run"] = False
        output["state_dir"] = str(manifest_path.parent)
        output["manifest_path"] = str(manifest_path)
        return output
    except Exception as exc:
        if server_id is not None or ssh_key_id is not None:
            _write_failed_private_manifest(
                endpoint_id=endpoint_id,
                provider=provider,
                exposure=exposure,
                role=role,
                created_at=created_at,
                layout=layout,
                private_group=private_group,
                private_ipv4=private_ipv4,
                network_resource=network_resource,
                server_id=server_id,
                server_name=server_name,
                ssh_key_id=ssh_key_id,
                ssh_key_name=ssh_key_name,
                public_ipv4=public_ipv4,
                public_ipv6=public_ipv6,
                ssh_host=ssh_host,
                error=str(exc),
            )
        _cleanup_partial_wan(server_id=server_id, ssh_key_id=ssh_key_id, env=hcloud_env)
        if network_created and not group_record_written:
            network_id = _network_resource_id(network_resource)
            if network_id is not None:
                _hcloud_cleanup([HCLOUD_COMMAND, "network", "delete", network_id], env=hcloud_env)
        raise


def wait_for_server_running(
    *,
    server_id: str,
    env: Mapping[str, str],
    timeout: float = DEFAULT_SERVER_RUNNING_TIMEOUT,
    interval: float = DEFAULT_SERVER_RUNNING_INTERVAL,
    command_runner: HcloudRunner = run_command,
) -> dict[str, object]:
    """Wait for a Hetzner server to report the running state."""

    deadline = time.monotonic() + _positive_float(timeout, "timeout")
    sleep_interval = _positive_float(interval, "interval")
    last_status = "unknown"

    while True:
        server = _hcloud_json(
            [HCLOUD_COMMAND, "server", "describe", server_id, "-o", "json"],
            env=env,
            command_runner=command_runner,
        )
        server_object = _json_object(server.get("server", server), "server")
        status = server_object.get("status")
        if isinstance(status, str) and status:
            last_status = status
        if last_status == "running":
            return server_object

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(
                f"server running wait timed out for Hetzner server {server_id}: "
                f"last status={last_status}"
            )
        time.sleep(min(sleep_interval, remaining))


def discover_endpoint_interfaces(
    *,
    host: str,
    user: str,
    identity_file: str | Path,
    known_hosts: str | Path,
    exposure: str,
    public_ipv4: str | None = None,
    public_ipv6: str | None = None,
) -> list[NetworkInterface]:
    """Discover endpoint interfaces with Linux ip commands over SSH."""

    result = run_ssh_command(
        host=host,
        user=user,
        identity_file=identity_file,
        known_hosts=known_hosts,
        command=INTERFACE_DISCOVERY_COMMAND,
        timeout=30,
    )
    if not result.ok:
        raise RuntimeError(_command_error("interface discovery over ssh failed", result))
    return parse_ip_interface_discovery(
        result.stdout,
        exposure=exposure,
        public_ipv4=public_ipv4,
        public_ipv6=public_ipv6,
    )


def parse_ip_interface_discovery(
    output: str,
    *,
    exposure: str,
    public_ipv4: str | None = None,
    public_ipv6: str | None = None,
) -> list[NetworkInterface]:
    """Parse JSON emitted by the endpoint interface discovery command."""

    sections = _interface_discovery_sections(output)
    addresses = _json_list(sections["addr"], "ip address output")
    links = _json_list(sections["link"], "ip link output")
    routes = _json_list(sections["route"], "ip route output") if sections["route"] else []
    link_by_name = {
        item.get("ifname"): item for item in links if isinstance(item.get("ifname"), str)
    }
    route_dev = _route_dev(routes)

    discovered: list[NetworkInterface] = []
    for item in addresses:
        ifname = item.get("ifname")
        if not isinstance(ifname, str) or ifname == "":
            continue
        addr_info = item.get("addr_info")
        if not isinstance(addr_info, list):
            continue

        ipv4 = _interface_address(addr_info, family="inet")
        ipv6 = _interface_address(addr_info, family="inet6")
        if ipv4 is None and ipv6 is None:
            continue

        link = link_by_name.get(ifname, {})
        mac = _optional_mapping_string(link, "address") or _optional_mapping_string(item, "address")
        matched_public = (
            (public_ipv4 is not None and ipv4 == public_ipv4)
            or (public_ipv6 is not None and ipv6 == public_ipv6)
        )
        default_route = route_dev == ifname
        discovered.append(
            NetworkInterface(
                name=ifname,
                exposure=exposure,
                ipv4=ipv4,
                ipv6=ipv6,
                mac=mac,
                metadata={
                    "source": "ip-ssh-discovery",
                    "ifindex": _optional_mapping_int(item, "ifindex"),
                    "operstate": _optional_mapping_string(link, "operstate")
                    or _optional_mapping_string(item, "operstate"),
                    "mtu": _optional_mapping_int(link, "mtu")
                    or _optional_mapping_int(item, "mtu"),
                    "matched_public_address": matched_public,
                    "default_route": default_route,
                    "hcloud_public_ipv4": public_ipv4,
                    "hcloud_public_ipv6": public_ipv6,
                },
            )
        )

    if public_ipv4 is not None or public_ipv6 is not None:
        public_matches = [
            interface
            for interface in discovered
            if bool(interface.metadata.get("matched_public_address"))
        ]
        if public_matches:
            return public_matches
    route_matches = [
        interface for interface in discovered if bool(interface.metadata.get("default_route"))
    ]
    return route_matches or discovered


def _planned_endpoint_manifest(
    *,
    provider: str,
    exposure: str,
    role: str,
    private_group: str | None,
    private_ip: str | None,
) -> dict[str, object]:
    endpoint_id = _planned_endpoint_id(
        provider=provider,
        exposure=exposure,
        role=role,
        private_group=private_group,
    )
    layout = endpoint_layout(endpoint_id)
    metadata: dict[str, object] = {
        "created": False,
        "dry_run": True,
        "state_dir": str(layout.state_dir),
        "manifest_path": str(layout.manifest_path),
    }
    interfaces = [
        NetworkInterface(
            name="public" if exposure == "wan" else "private",
            exposure=exposure,
            ipv4=private_ip if exposure == "private" else None,
            provider_network_id=(
                _planned_private_network_id(private_group)
                if exposure == "private" and private_group is not None
                else None
            ),
            metadata=_private_interface_metadata(private_group)
            if exposure == "private"
            else {"planned": True},
        )
    ]

    if exposure == "private":
        private_metadata = _planned_private_metadata(private_group, private_ip)
        metadata["private"] = private_metadata
        metadata["private_network"] = private_metadata
        if private_group is not None:
            metadata["private_group"] = private_group
            metadata["private_group_record"] = planned_private_group_record(
                provider=provider,
                group=private_group,
                network_resource=private_metadata,
            ).to_dict()

    manifest = EndpointManifest(
        endpoint_id=endpoint_id,
        provider=provider,
        exposure=exposure,
        status="planned",
        role=role,
        created_at=PLANNED_CREATED_AT,
        ssh=EndpointSSHInfo(
            host="planned",
            user="root",
            identity_file=str(layout.private_key_path),
            known_hosts_file=str(layout.known_hosts_path),
            metadata={"planned": True},
        ),
        interfaces=interfaces,
        provider_resources=ProviderResources(
            resources=[
                ProviderResource(
                    kind="planned-server",
                    provider_id=f"{endpoint_id}-server",
                    name=_server_name(endpoint_id),
                    cleanup=True,
                    metadata={"planned": True, "type": "planned-server"},
                )
            ],
            cleanup_order=["server"],
            metadata={"planned": True},
        ),
        artifact_dir=str(layout.artifact_dir),
        metadata=metadata,
    ).to_dict()

    manifest["created"] = False
    manifest["dry_run"] = True
    manifest["state_dir"] = str(layout.state_dir)
    manifest["manifest_path"] = str(layout.manifest_path)
    return manifest


def _validate_create_request(
    exposure: str,
    role: str,
    private_group: str | None,
    private_ip: str | None,
) -> None:
    if role == "":
        raise ValueError("role must be a non-empty string")
    if private_group == "":
        raise ValueError("private_group must be a non-empty string when supplied")
    if private_ip == "":
        raise ValueError("private_ip must be a non-empty string when supplied")
    if exposure != "private" and private_group is not None:
        raise ValueError("--private-group is only valid with --exposure private")
    if exposure != "private" and private_ip is not None:
        raise ValueError("--private-ip is only valid with --exposure private")


def _planned_endpoint_id(
    *,
    provider: str,
    exposure: str,
    role: str,
    private_group: str | None,
) -> str:
    parts = ["planned", provider, exposure, role]
    if private_group is not None:
        parts.append(private_group)
    return "-".join(_path_component(part) for part in parts)


def _path_component(value: str) -> str:
    output = "".join(character if character.isalnum() else "-" for character in value.lower())
    output = "-".join(part for part in output.split("-") if part)
    return output or "value"


def _planned_private_network_id(private_group: str | None) -> str:
    suffix = _path_component(private_group) if private_group is not None else "ungrouped"
    return f"planned-private-network-{suffix}"


def _private_interface_metadata(private_group: str | None) -> dict[str, object]:
    metadata: dict[str, object] = {
        "planned": True,
        "network": _planned_private_metadata(private_group, private_ip=None),
    }
    if private_group is not None:
        metadata["private_group"] = private_group
    return metadata


def _planned_private_metadata(
    private_group: str | None,
    private_ip: str | None,
) -> dict[str, object]:
    metadata: dict[str, object] = {
        "planned": True,
        "network_id": _planned_private_network_id(private_group),
    }
    if private_group is not None:
        metadata["private_group"] = private_group
        metadata["network_name"] = f"wire-{_path_component(private_group)}"
    if private_ip is not None:
        metadata["ipv4"] = private_ip
    return metadata


def _ensure_private_network(
    *,
    provider: str,
    private_group: str,
    private_cidr: str,
    network_zone: str,
    env: Mapping[str, str],
    command_runner: HcloudRunner,
) -> dict[str, object]:
    network_name = _private_network_name(private_group)
    created = False

    network_object: dict[str, object] | None = None
    try:
        record = read_private_group_record(provider, private_group)
    except FileNotFoundError:
        record = None

    if record is not None:
        network_id = _network_resource_id(record.network_resource)
        if network_id is not None:
            network_object = _hcloud_json_optional(
                [HCLOUD_COMMAND, "network", "describe", network_id, "-o", "json"],
                env=env,
                command_runner=command_runner,
            )

    if network_object is None:
        network_object = _hcloud_json_optional(
            [HCLOUD_COMMAND, "network", "describe", network_name, "-o", "json"],
            env=env,
            command_runner=command_runner,
        )

    if network_object is None:
        created = True
        network_created = _hcloud_json(
            [
                HCLOUD_COMMAND,
                "network",
                "create",
                "--name",
                network_name,
                "--ip-range",
                private_cidr,
                "--label",
                "libcrafter-wire=true",
                "--label",
                f"libcrafter-wire-private-group={_label_value(private_group)}",
                "-o",
                "json",
            ],
            env=env,
            command_runner=command_runner,
        )
        network_object = _json_object(network_created.get("network", network_created), "network")
    else:
        network_object = _json_object(network_object.get("network", network_object), "network")

    if not _network_has_subnet(
        network_object,
        private_cidr=private_cidr,
        network_zone=network_zone,
    ):
        _hcloud_ok(
            [
                HCLOUD_COMMAND,
                "network",
                "add-subnet",
                _object_id(network_object),
                "--type",
                "server",
                "--network-zone",
                network_zone,
                "--ip-range",
                private_cidr,
                "-o",
                "json",
            ],
            env=env,
            command_runner=command_runner,
        )
        described = _hcloud_json(
            [HCLOUD_COMMAND, "network", "describe", _object_id(network_object), "-o", "json"],
            env=env,
            command_runner=command_runner,
        )
        network_object = _json_object(described.get("network", described), "network")

    return {
        "created": created,
        "resource": _private_network_resource(
            network_object,
            private_group=private_group,
            private_cidr=private_cidr,
            network_zone=network_zone,
        ),
    }


def _attach_server_to_private_network(
    *,
    server_id: str,
    network_resource: Mapping[str, object],
    private_ipv4: str,
    env: Mapping[str, str],
    command_runner: HcloudRunner,
) -> dict[str, object]:
    network_id = _network_resource_id(network_resource)
    if network_id is None:
        raise RuntimeError("private network resource did not include a network id")
    result = _hcloud_ok(
        [
            HCLOUD_COMMAND,
            "server",
            "attach-to-network",
            server_id,
            "--network",
            network_id,
            "--ip",
            private_ipv4,
            "-o",
            "json",
        ],
        env=env,
        command_runner=command_runner,
    )
    if result.stdout.strip():
        return _parse_hcloud_json(result)
    return {}


def _allocate_private_ipv4(
    *,
    provider: str,
    private_group: str,
    private_cidr: str,
    requested_private_ip: str | None,
) -> str:
    network = _ipv4_network(private_cidr)
    try:
        record = read_private_group_record(provider, private_group)
        allocated = set(record.allocated_private_ipv4s)
    except FileNotFoundError:
        allocated = set()

    if requested_private_ip is not None:
        address = _ipv4_address(requested_private_ip, "private_ip")
        if address not in network:
            raise ValueError(f"private_ip {requested_private_ip} is outside {private_cidr}")
        if requested_private_ip in allocated:
            raise ValueError(f"private_ip {requested_private_ip} is already allocated")
        return requested_private_ip

    for address in network.hosts():
        private_ipv4 = str(address)
        if private_ipv4.endswith(".1"):
            continue
        if private_ipv4 not in allocated:
            return private_ipv4
    raise RuntimeError(f"no private IPv4 addresses are available in {private_cidr}")


def _private_network_interface(
    *,
    exposure: str,
    private_group: str,
    private_ipv4: str,
    network_resource: Mapping[str, object],
    server_id: str,
    server_name: str,
) -> NetworkInterface:
    return NetworkInterface(
        name="private",
        exposure=exposure,
        ipv4=private_ipv4,
        provider_network_id=_network_resource_id(network_resource),
        metadata={
            "source": "hcloud",
            "private_group": private_group,
            "private_ip": private_ipv4,
            "server_id": server_id,
            "server_name": server_name,
            "network": dict(network_resource),
        },
    )


def _private_network_name(private_group: str) -> str:
    return f"wire-{_path_component(private_group)}"


def _network_has_subnet(
    network_object: Mapping[str, object],
    *,
    private_cidr: str,
    network_zone: str,
) -> bool:
    subnets = network_object.get("subnets")
    if not isinstance(subnets, list):
        return False
    for item in subnets:
        if not isinstance(item, Mapping):
            continue
        if item.get("type") != "server":
            continue
        if item.get("ip_range") != private_cidr:
            continue
        return True
    return False


def _private_network_resource(
    network_object: Mapping[str, object],
    *,
    private_group: str,
    private_cidr: str,
    network_zone: str,
) -> dict[str, object]:
    raw_subnets = network_object.get("subnets", [])
    if not isinstance(raw_subnets, list):
        raw_subnets = []
    subnets = [
        dict(item)
        for item in raw_subnets
        if isinstance(item, Mapping)
        and item.get("type") == "server"
        and item.get("ip_range") == private_cidr
    ]
    name = network_object.get("name")
    return {
        "type": "network",
        "provider": "hetzner",
        "network_id": _object_id(network_object),
        "network_name": name if isinstance(name, str) and name else _private_network_name(private_group),
        "private_group": private_group,
        "ip_range": _optional_mapping_string(network_object, "ip_range") or private_cidr,
        "subnet": subnets[0] if subnets else {
            "type": "server",
            "network_zone": network_zone,
            "ip_range": private_cidr,
        },
    }


def _network_resource_id(network_resource: Mapping[str, object]) -> str | None:
    for key in ("network_id", "provider_id", "id"):
        value = network_resource.get(key)
        if isinstance(value, int):
            return str(value)
        if isinstance(value, str) and value:
            return value
    return None


def _private_endpoint_provider_resources(
    *,
    provider: str,
    server_id: str | None,
    server_name: str,
    ssh_key_id: str | None,
    ssh_key_name: str,
    public_ipv4: str | None,
    public_ipv6: str | None,
) -> ProviderResources:
    resources = _wan_provider_resources(
        provider=provider,
        server_id=server_id,
        server_name=server_name,
        ssh_key_id=ssh_key_id,
        ssh_key_name=ssh_key_name,
        public_ipv4=public_ipv4,
        public_ipv6=public_ipv6,
    )
    return ProviderResources(
        resources=resources.resources,
        cleanup_order=["server", "ssh-key"],
        metadata={
            **resources.metadata,
            "exposure": "private",
            "private_network_cleanup": "private-group-owned",
        },
    )


def _wan_provider_resources(
    *,
    provider: str,
    server_id: str | None,
    server_name: str,
    ssh_key_id: str | None,
    ssh_key_name: str,
    public_ipv4: str | None,
    public_ipv6: str | None,
) -> ProviderResources:
    resources: list[ProviderResource] = []
    if server_id is not None:
        resources.append(
            ProviderResource(
                kind="server",
                provider_id=server_id,
                name=server_name,
                cleanup=True,
                metadata={
                    "type": "server",
                    "public_ipv4": public_ipv4,
                    "public_ipv6": public_ipv6,
                },
            )
        )
    if ssh_key_id is not None:
        resources.append(
            ProviderResource(
                kind="ssh-key",
                provider_id=ssh_key_id,
                name=ssh_key_name,
                cleanup=True,
                metadata={"type": "ssh-key"},
            )
        )
    return ProviderResources(
        resources=resources,
        cleanup_order=["server", "ssh-key"],
        metadata={"created_by": "tools/wire", "provider": provider},
    )


def _write_failed_wan_manifest(
    *,
    endpoint_id: str,
    provider: str,
    exposure: str,
    role: str,
    created_at: str,
    layout: object,
    server_id: str | None,
    server_name: str,
    ssh_key_id: str | None,
    ssh_key_name: str,
    public_ipv4: str | None,
    public_ipv6: str | None,
    ssh_host: str | None,
    error: str,
) -> None:
    try:
        write_endpoint_manifest(
            EndpointManifest(
                endpoint_id=endpoint_id,
                provider=provider,
                exposure=exposure,
                status="failed",
                role=role,
                created_at=created_at,
                ssh=EndpointSSHInfo(
                    host=ssh_host or "pending",
                    user="root",
                    identity_file=str(getattr(layout, "private_key_path")),
                    known_hosts_file=str(getattr(layout, "known_hosts_path")),
                    metadata={
                        "created_by": "tools/wire",
                        "server_name": server_name,
                    },
                ),
                interfaces=[
                    NetworkInterface(
                        name="public",
                        exposure=exposure,
                        ipv4=public_ipv4,
                        ipv6=public_ipv6,
                        metadata={
                            "source": "hcloud-partial",
                            "server_id": server_id,
                            "server_name": server_name,
                        },
                    )
                ],
                provider_resources=_wan_provider_resources(
                    provider=provider,
                    server_id=server_id,
                    server_name=server_name,
                    ssh_key_id=ssh_key_id,
                    ssh_key_name=ssh_key_name,
                    public_ipv4=public_ipv4,
                    public_ipv6=public_ipv6,
                ),
                artifact_dir=str(getattr(layout, "artifact_dir")),
                metadata={
                    **_wan_manifest_metadata(
                        created=True,
                        dry_run=False,
                        layout=layout,
                        server_id=server_id,
                        server_name=server_name,
                        ssh_key_id=ssh_key_id,
                        ssh_key_name=ssh_key_name,
                    ),
                    "error": error,
                },
            )
        )
    except Exception:
        return


def _write_failed_private_manifest(
    *,
    endpoint_id: str,
    provider: str,
    exposure: str,
    role: str,
    created_at: str,
    layout: object,
    private_group: str,
    private_ipv4: str | None,
    network_resource: Mapping[str, object],
    server_id: str | None,
    server_name: str,
    ssh_key_id: str | None,
    ssh_key_name: str,
    public_ipv4: str | None,
    public_ipv6: str | None,
    ssh_host: str | None,
    error: str,
) -> None:
    try:
        write_endpoint_manifest(
            EndpointManifest(
                endpoint_id=endpoint_id,
                provider=provider,
                exposure=exposure,
                status="failed",
                role=role,
                created_at=created_at,
                ssh=EndpointSSHInfo(
                    host=ssh_host or "pending",
                    user="root",
                    identity_file=str(getattr(layout, "private_key_path")),
                    known_hosts_file=str(getattr(layout, "known_hosts_path")),
                    metadata={
                        "created_by": "tools/wire",
                        "server_name": server_name,
                        "control_plane": "public",
                    },
                ),
                interfaces=[
                    NetworkInterface(
                        name="private",
                        exposure=exposure,
                        ipv4=private_ipv4,
                        provider_network_id=_network_resource_id(network_resource),
                        metadata={
                            "source": "hcloud-partial",
                            "private_group": private_group,
                            "private_ip": private_ipv4,
                            "server_id": server_id,
                            "server_name": server_name,
                            "network": dict(network_resource),
                        },
                    )
                ],
                provider_resources=_private_endpoint_provider_resources(
                    provider=provider,
                    server_id=server_id,
                    server_name=server_name,
                    ssh_key_id=ssh_key_id,
                    ssh_key_name=ssh_key_name,
                    public_ipv4=public_ipv4,
                    public_ipv6=public_ipv6,
                ),
                artifact_dir=str(getattr(layout, "artifact_dir")),
                metadata={
                    **_private_manifest_metadata(
                        created=True,
                        dry_run=False,
                        layout=layout,
                        private_group=private_group,
                        private_ipv4=private_ipv4,
                        network_resource=network_resource,
                        network_created=False,
                        server_id=server_id,
                        server_name=server_name,
                        ssh_key_id=ssh_key_id,
                        ssh_key_name=ssh_key_name,
                    ),
                    "error": error,
                },
            )
        )
    except Exception:
        return


def _wan_manifest_metadata(
    *,
    created: bool,
    dry_run: bool,
    layout: object,
    server_id: str | None,
    server_name: str,
    ssh_key_id: str | None,
    ssh_key_name: str,
) -> dict[str, object]:
    state_dir = getattr(layout, "state_dir")
    manifest_path = getattr(layout, "manifest_path")
    return {
        "created": created,
        "dry_run": dry_run,
        "state_dir": str(state_dir),
        "manifest_path": str(manifest_path),
        "cleanup": {
            "server_id": server_id,
            "ssh_key_id": ssh_key_id,
            "server_name": server_name,
            "ssh_key_name": ssh_key_name,
        },
    }


def _private_manifest_metadata(
    *,
    created: bool,
    dry_run: bool,
    layout: object,
    private_group: str,
    private_ipv4: str | None,
    network_resource: Mapping[str, object],
    network_created: bool,
    server_id: str | None,
    server_name: str,
    ssh_key_id: str | None,
    ssh_key_name: str,
) -> dict[str, object]:
    metadata = _wan_manifest_metadata(
        created=created,
        dry_run=dry_run,
        layout=layout,
        server_id=server_id,
        server_name=server_name,
        ssh_key_id=ssh_key_id,
        ssh_key_name=ssh_key_name,
    )
    metadata.update(
        {
            "private_group": private_group,
            "private_ip": private_ipv4,
            "private_network": dict(network_resource),
            "private": {
                "private_group": private_group,
                "private_ip": private_ipv4,
                "network": dict(network_resource),
                "network_created": network_created,
            },
        }
    )
    return metadata


def _interface_discovery_sections(output: str) -> dict[str, str]:
    lines = output.splitlines()
    markers = {
        "addr": "__WIRE_IP_ADDR__",
        "link": "__WIRE_IP_LINK__",
        "route": "__WIRE_IP_ROUTE__",
    }
    positions: dict[str, int] = {}
    for name, marker in markers.items():
        try:
            positions[name] = lines.index(marker)
        except ValueError as exc:
            raise RuntimeError(f"interface discovery output missing marker {marker}") from exc

    return {
        "addr": "\n".join(lines[positions["addr"] + 1 : positions["link"]]).strip(),
        "link": "\n".join(lines[positions["link"] + 1 : positions["route"]]).strip(),
        "route": "\n".join(lines[positions["route"] + 1 :]).strip(),
    }


def _json_list(value: str, name: str) -> list[dict[str, object]]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{name} was not valid JSON") from exc
    if not isinstance(parsed, list):
        raise RuntimeError(f"{name} must be a JSON list")
    output: list[dict[str, object]] = []
    for item in parsed:
        if isinstance(item, Mapping):
            output.append(dict(item))
    return output


def _route_dev(routes: list[dict[str, object]]) -> str | None:
    for route in routes:
        dev = route.get("dev")
        if isinstance(dev, str) and dev:
            return dev
    return None


def _interface_address(addr_info: list[object], *, family: str) -> str | None:
    for address in addr_info:
        if not isinstance(address, Mapping):
            continue
        if address.get("family") != family:
            continue
        local = address.get("local")
        if isinstance(local, str) and local:
            return local
    return None


def _optional_mapping_string(value: Mapping[str, object], key: str) -> str | None:
    item = value.get(key)
    return item if isinstance(item, str) and item else None


def _optional_mapping_int(value: Mapping[str, object], key: str) -> int | None:
    item = value.get(key)
    if isinstance(item, bool):
        return None
    if isinstance(item, int):
        return item
    return None


def _compat_provider_resource(resource: object) -> dict[str, object]:
    if not isinstance(resource, Mapping):
        return {"type": "unknown", "value": str(resource)}
    output = dict(resource)
    metadata = output.get("metadata")
    resource_type = None
    if isinstance(metadata, Mapping):
        resource_type = metadata.get("type")
    if not isinstance(resource_type, str) or resource_type == "":
        kind = output.get("kind")
        resource_type = kind if isinstance(kind, str) and kind else "resource"
    output["type"] = resource_type
    return output


def _hetzner_token(environ: Mapping[str, str]) -> str | None:
    return environ.get(TOKEN_ENV) or environ.get(HCLOUD_TOKEN_ENV) or None


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _real_endpoint_id(*, provider: str, exposure: str, role: str) -> str:
    timestamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    suffix = secrets.token_hex(3)
    return "-".join(
        _path_component(part) for part in (provider, exposure, role, timestamp, suffix)
    )


def _server_name(endpoint_id: str) -> str:
    name = f"wire-{endpoint_id}"
    if len(name) <= 63:
        return name
    return name[:63].rstrip("-") or "wire-endpoint"


def _label_value(value: str) -> str:
    output = "".join(character if character.isalnum() else "-" for character in value.lower())
    output = "-".join(part for part in output.split("-") if part)
    return (output or "value")[:63].rstrip("-") or "value"


def _env_or_default(environ: Mapping[str, str], name: str, default: str) -> str:
    value = environ.get(name)
    if value is None or value == "":
        return default
    return value


def _ensure_endpoint_key(private_key_path: Path, endpoint_id: str) -> None:
    public_key_path = _public_key_path(private_key_path)
    if private_key_path.exists() and public_key_path.exists():
        return
    if private_key_path.exists() != public_key_path.exists():
        raise FileExistsError(
            f"endpoint SSH key is incomplete: {private_key_path} and {public_key_path}"
        )
    result = create_key_pair(private_key_path, comment=f"libcrafter-wire {endpoint_id}", timeout=30)
    if not result.ok:
        raise RuntimeError(_command_error("ssh-keygen failed", result))


def _public_key_path(private_key_path: Path) -> Path:
    return private_key_path.with_name(f"{private_key_path.name}.pub")


def _hcloud_json(
    argv: list[str],
    *,
    env: Mapping[str, str],
    command_runner: HcloudRunner = run_command,
) -> dict[str, object]:
    result = command_runner(argv, env=env, timeout=180)
    if not result.ok:
        raise RuntimeError(_command_error("hcloud command failed", result))
    return _parse_hcloud_json(result)


def _hcloud_json_optional(
    argv: list[str],
    *,
    env: Mapping[str, str],
    command_runner: HcloudRunner,
) -> dict[str, object] | None:
    result = command_runner(argv, env=env, timeout=180)
    if not result.ok:
        if _is_missing_resource_result(result):
            return None
        raise RuntimeError(_command_error("hcloud command failed", result))
    return _parse_hcloud_json(result)


def _hcloud_ok(
    argv: list[str],
    *,
    env: Mapping[str, str],
    command_runner: HcloudRunner,
) -> CommandResult:
    result = command_runner(argv, env=env, timeout=180)
    if not result.ok:
        raise RuntimeError(_command_error("hcloud command failed", result))
    return result


def _parse_hcloud_json(result: CommandResult) -> dict[str, object]:
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"hcloud command did not emit valid JSON: {result.command}") from exc
    return _json_object(value, "hcloud output")


def _cleanup_partial_wan(
    *,
    server_id: str | None,
    ssh_key_id: str | None,
    env: Mapping[str, str],
) -> None:
    if server_id is not None:
        _hcloud_cleanup([HCLOUD_COMMAND, "server", "delete", server_id], env=env)
    if ssh_key_id is not None:
        _hcloud_cleanup([HCLOUD_COMMAND, "ssh-key", "delete", ssh_key_id], env=env)


def _cleanup_resources(manifest: EndpointManifest) -> list[ProviderResource]:
    resources = [
        resource for resource in manifest.provider_resources.resources if resource.cleanup
    ]
    cleanup_order = manifest.provider_resources.cleanup_order
    if not cleanup_order:
        return resources

    order = {_normalized_resource_kind(kind): index for index, kind in enumerate(cleanup_order)}
    return sorted(
        resources,
        key=lambda resource: (order.get(_normalized_resource_kind(resource.kind), len(order)),),
    )


def _private_destroy_context(manifest: EndpointManifest) -> dict[str, object] | None:
    if manifest.exposure != "private":
        return None
    private_group = _private_group_from_manifest(manifest)
    if private_group is None:
        return None

    record = None
    try:
        record = read_private_group_record(manifest.provider, private_group)
        network_resource = dict(record.network_resource)
    except FileNotFoundError:
        network_resource = {}

    return {
        "private_group": private_group,
        "private_ipv4": _private_ipv4_from_manifest(manifest),
        "group_record": record,
        "network_resource": network_resource,
        "server_resource": _resource_by_kind(manifest, "server"),
    }


def _detach_private_endpoint_from_network(
    private_destroy: Mapping[str, object],
    *,
    env: Mapping[str, str],
    command_runner: HcloudRunner,
) -> dict[str, object] | None:
    server_resource = private_destroy.get("server_resource")
    network_resource = private_destroy.get("network_resource")
    if not isinstance(server_resource, ProviderResource) or not isinstance(
        network_resource, Mapping
    ):
        return None

    network_id = _network_resource_id(network_resource)
    if network_id is None:
        return None

    result = command_runner(
        [
            HCLOUD_COMMAND,
            "server",
            "detach-from-network",
            server_resource.provider_id,
            "--network",
            network_id,
        ],
        env=env,
        timeout=120,
    )
    action = _destroy_action(
        server_resource,
        action="detach",
        result=result,
        reason=f"detach private endpoint from network {network_id}",
    )
    action["network_id"] = network_id
    if result.ok or _is_missing_resource_result(result):
        if not result.ok:
            action["action"] = "already-missing"
            action["reason"] = "private network attachment was already missing"
        return action
    raise RuntimeError(_command_error("hcloud private network detach command failed", result))


def _remove_private_endpoint_from_group(
    manifest: EndpointManifest,
    private_destroy: Mapping[str, object],
) -> dict[str, object]:
    private_group = private_destroy.get("private_group")
    if not isinstance(private_group, str):
        raise RuntimeError("private endpoint destroy requires a private group")
    private_ipv4 = private_destroy.get("private_ipv4")
    if not isinstance(private_ipv4, str):
        private_ipv4 = None

    try:
        updated = remove_private_group_allocation(
            provider=manifest.provider,
            group=private_group,
            endpoint_id=manifest.endpoint_id,
            private_ipv4=private_ipv4,
        )
    except FileNotFoundError:
        return {
            "private_group": private_group,
            "record_found": False,
            "remaining_endpoints": [],
            "network_deleted": False,
        }

    return {
        "private_group": private_group,
        "record_found": True,
        "remaining_endpoints": updated.allocated_endpoint_ids,
        "network_deleted": False,
        "private_group_record": updated.to_dict(),
    }


def _delete_private_network_if_unused(
    private_destroy: Mapping[str, object],
    *,
    private_group_update: Mapping[str, object],
    env: Mapping[str, str],
    command_runner: HcloudRunner,
) -> list[dict[str, object]]:
    remaining_endpoints = private_group_update.get("remaining_endpoints")
    if remaining_endpoints:
        return []

    network_resource = private_destroy.get("network_resource")
    if not isinstance(network_resource, Mapping):
        return []
    network_id = _network_resource_id(network_resource)
    if network_id is None:
        return []

    network = ProviderResource(
        kind="network",
        provider_id=network_id,
        name=_optional_mapping_string(network_resource, "network_name"),
        metadata={
            "type": "network",
            "private_group": str(private_destroy.get("private_group", "")),
        },
    )
    result = command_runner(_destroy_command(network) or [], env=env, timeout=120)
    if result.ok:
        if isinstance(private_group_update, dict):
            private_group_update["network_deleted"] = True
        return [_destroy_action(network, action="delete", result=result)]
    if _is_missing_resource_result(result):
        if isinstance(private_group_update, dict):
            private_group_update["network_deleted"] = True
        return [
            _destroy_action(
                network,
                action="already-missing",
                result=result,
                reason="private group network was already missing",
            )
        ]
    raise RuntimeError(_command_error("hcloud private network delete command failed", result))


def _resource_by_kind(
    manifest: EndpointManifest,
    kind: str,
) -> ProviderResource | None:
    normalized_kind = _normalized_resource_kind(kind)
    for resource in manifest.provider_resources.resources:
        if resource.cleanup and _normalized_resource_kind(resource.kind) == normalized_kind:
            return resource
    return None


def _private_group_from_manifest(manifest: EndpointManifest) -> str | None:
    metadata_group = manifest.metadata.get("private_group")
    if isinstance(metadata_group, str) and metadata_group:
        return metadata_group
    private_metadata = manifest.metadata.get("private")
    if isinstance(private_metadata, Mapping):
        private_group = private_metadata.get("private_group")
        if isinstance(private_group, str) and private_group:
            return private_group
    for interface in manifest.interfaces:
        private_group = interface.metadata.get("private_group")
        if isinstance(private_group, str) and private_group:
            return private_group
    return None


def _private_ipv4_from_manifest(manifest: EndpointManifest) -> str | None:
    metadata_ip = manifest.metadata.get("private_ip")
    if isinstance(metadata_ip, str) and metadata_ip:
        return metadata_ip
    private_metadata = manifest.metadata.get("private")
    if isinstance(private_metadata, Mapping):
        private_ip = private_metadata.get("private_ip")
        if isinstance(private_ip, str) and private_ip:
            return private_ip
    for interface in manifest.interfaces:
        if interface.exposure == "private" and interface.ipv4 is not None:
            return interface.ipv4
    return None


def _destroy_command(resource: ProviderResource) -> list[str] | None:
    kind = _normalized_resource_kind(resource.kind)
    if kind == "server":
        return [HCLOUD_COMMAND, "server", "delete", resource.provider_id]
    if kind == "ssh-key":
        return [HCLOUD_COMMAND, "ssh-key", "delete", resource.provider_id]
    if kind == "network":
        return [HCLOUD_COMMAND, "network", "delete", resource.provider_id]
    return None


def _normalized_resource_kind(kind: str) -> str:
    return kind.replace("_", "-")


def _destroy_action(
    resource: ProviderResource,
    *,
    action: str,
    result: CommandResult | None = None,
    reason: str | None = None,
) -> dict[str, object]:
    output: dict[str, object] = {
        "action": action,
        "kind": resource.kind,
        "provider_id": resource.provider_id,
        "name": resource.name,
    }
    if reason is not None:
        output["reason"] = reason
    if result is not None:
        output["command"] = result.command
        output["exit_code"] = result.exit_code
    return output


def _destroy_output(
    *,
    manifest: EndpointManifest,
    actions: list[dict[str, object]],
    skipped: list[dict[str, object]],
    destroyed: bool,
    already_destroyed: bool,
) -> dict[str, object]:
    return {
        "ok": True,
        "endpoint_id": manifest.endpoint_id,
        "provider": manifest.provider,
        "exposure": manifest.exposure,
        "status": manifest.status,
        "destroyed": destroyed,
        "already_destroyed": already_destroyed,
        "artifact_dir": manifest.artifact_dir,
        "actions": actions,
        "skipped": skipped,
    }


def _is_missing_resource_result(result: CommandResult) -> bool:
    text = " ".join(
        part.strip().lower() for part in (result.stderr, result.stdout, result.error or "")
    )
    missing_markers = (
        "not found",
        "not_found",
        "404",
        "does not exist",
        "no such",
        "could not find",
        "was not found",
        "already deleted",
        "not attached",
        "already detached",
    )
    return any(marker in text for marker in missing_markers)


def _hcloud_cleanup(argv: list[str], *, env: Mapping[str, str]) -> None:
    run_command(argv, env=env, timeout=120)


def _command_error(message: str, result: CommandResult) -> str:
    details = result.stderr.strip() or result.stdout.strip() or result.error or "no output"
    return f"{message}: {result.command}: {details}"


def _json_object(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise RuntimeError(f"{name} must be a JSON object")
    return dict(value)


def _object_id(value: Mapping[str, object]) -> str:
    provider_id = value.get("id")
    if isinstance(provider_id, int):
        return str(provider_id)
    if isinstance(provider_id, str) and provider_id:
        return provider_id
    raise RuntimeError("hcloud output did not include an object id")


def _ip_address(value: object) -> str | None:
    if isinstance(value, Mapping):
        ip = value.get("ip")
        return ip if isinstance(ip, str) and ip else None
    return None


def _ipv4_network(value: str) -> IPv4Network:
    try:
        network = ip_network(value)
    except ValueError as exc:
        raise ValueError(f"private_cidr must be a valid IPv4 CIDR: {value}") from exc
    if not isinstance(network, IPv4Network):
        raise ValueError(f"private_cidr must be an IPv4 CIDR: {value}")
    return network


def _ipv4_address(value: str, name: str) -> IPv4Address:
    try:
        address = ip_address(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a valid IPv4 address: {value}") from exc
    if not isinstance(address, IPv4Address):
        raise ValueError(f"{name} must be an IPv4 address: {value}")
    return address


def _positive_float(value: float, name: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a positive number")
    output = float(value)
    if output <= 0:
        raise ValueError(f"{name} must be a positive number")
    return output
