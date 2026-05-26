"""Hetzner endpoint creation operations."""

from __future__ import annotations

import os
import shutil
from collections.abc import Mapping

from ...model import EndpointManifest, EndpointSSHInfo, NetworkInterface
from ...process import run_command
from ...registry import validate_request
from ...ssh import ensure_known_hosts_file, wait_for_ssh
from ...state import DEFAULT_PRIVATE_CIDR, ensure_endpoint_dirs, update_private_group_allocation, write_endpoint_manifest
from .constants import (
    CONFIRMATION_ERROR,
    DEFAULT_IMAGE,
    DEFAULT_LOCATION,
    DEFAULT_PRIVATE_NETWORK_ZONE,
    DEFAULT_SERVER_TYPE,
    HCLOUD_COMMAND,
    HCLOUD_TOKEN_ENV,
    HcloudRunner,
    TOKEN_ENV,
)
from .destroy import _cleanup_partial_wan
from .discovery import discover_endpoint_interfaces, wait_for_server_running
from .hcloud import _hcloud_cleanup, _hcloud_json
from .manifest import (
    _planned_endpoint_manifest,
    _private_manifest_metadata,
    _validate_create_request,
    _wan_manifest_metadata,
    _write_failed_private_manifest,
    _write_failed_wan_manifest,
)
from .network import (
    _allocate_private_ipv4,
    _attach_server_to_private_network,
    _ensure_private_network,
    _private_network_interface,
)
from .resources import _private_endpoint_provider_resources, _wan_provider_resources
from .utils import (
    _env_or_default,
    _ensure_endpoint_key,
    _hetzner_token,
    _ip_address,
    _json_object,
    _label_value,
    _network_resource_id,
    _object_id,
    _public_key_path,
    _real_endpoint_id,
    _server_name,
    _utc_now,
)



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
