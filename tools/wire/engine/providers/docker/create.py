"""Docker endpoint creation and planning operations."""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import replace
from hashlib import sha256
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from ...model import (
    ArtifactPath,
    EndpointManifest,
    EndpointSSHInfo,
    NetworkInterface,
    ProviderResource,
    write_json,
)
from ...process import CommandResult, run_command
from ...registry import validate_request
from ...ssh import ensure_known_hosts_file, wait_for_ssh
from ...state import (
    endpoint_layout,
    ensure_endpoint_dirs,
    planned_private_group_record,
    private_group_path,
    read_private_group_record,
    update_private_group_allocation,
    write_endpoint_manifest,
)
from ..vm import (
    command_error,
    discover_linux_endpoint_interfaces,
    ensure_endpoint_ssh_key,
    public_key_path,
    utc_now,
)
from .constants import (
    CONFIRMATION_ERROR,
    DOCKER_DEFAULT_LAN_NETWORK,
    DOCKER_DEFAULT_WAN_NETWORK,
    DOCKER_LAN_NETWORK_ENV,
    DOCKER_SSH_GUEST_PORT,
    DOCKER_SSH_HOST,
    DOCKER_SSH_USER,
    DOCKER_WAN_NETWORK_ENV,
    EXPOSURE_LAN,
    EXPOSURE_PRIVATE,
    EXPOSURE_WAN,
    NAT_L3_CAPABILITIES,
    PLANNED_CREATED_AT,
    PRIVATE_CAPABILITIES,
    PROVIDER_NAME,
    DockerRunner,
)
from .resources import (
    DOCKER_LABEL_EXPOSURE,
    DOCKER_LABEL_MANAGED,
    DOCKER_LABEL_PRIVATE_GROUP,
    DOCKER_LABEL_PROVIDER,
    DOCKER_MANAGED_LABEL_VALUE,
    allocate_private_ipv4,
    deterministic_private_mac,
    docker_argv,
    docker_container_name,
    docker_container_resource,
    docker_endpoint_id,
    docker_image_resource,
    docker_inspect_id,
    docker_inspect_labels,
    docker_inspect_name,
    docker_label_args,
    docker_labels,
    docker_local_file_resource,
    docker_network_resource,
    docker_private_network_name,
    docker_provider_resources,
    docker_publish_arg,
    ensure_docker_image,
    free_localhost_tcp_port,
    parse_private_cidr,
    parse_single_docker_inspect_output,
    plan_docker_image,
    planned_docker_endpoint_id,
    private_gateway_ipv4,
    requested_docker_command,
    requested_docker_image,
    requested_private_cidr,
    render_docker_argv,
    validate_requested_private_ipv4,
)


AUTHORIZED_KEY_TARGET = "/run/libcrafter/authorized_key.pub"
DEFAULT_PRIVATE_GROUP = "default"
DOCKER_PRIVATE_INTERFACE = "eth0"
DOCKER_LAN_INTERFACE = "eth0"
DOCKER_WAN_INTERFACE = "eth0"
DOCKER_SSH_WAIT_TIMEOUT = 300
DOCKER_SSH_WAIT_INTERVAL = 5
DOCKER_CONTAINER_COMMAND_LOG_NAME = "docker-container-commands.json"
DOCKER_CONTAINER_CREATE_TIMEOUT = 120
DOCKER_NETWORK_INSPECT_TIMEOUT = 30
DOCKER_NETWORK_CREATE_TIMEOUT = 60


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
    command_runner: DockerRunner = run_command,
) -> dict[str, object]:
    """Create or plan one Docker endpoint."""

    validate_request(provider, exposure)
    _validate_create_request(exposure, role, private_group, private_ip)
    environ = os.environ if env is None else env

    if dry_run:
        if exposure == EXPOSURE_PRIVATE:
            return _planned_private_endpoint_manifest(
                provider=provider,
                exposure=exposure,
                role=role,
                private_group=_effective_private_group(private_group),
                private_group_source=_private_group_source(private_group),
                private_ip=private_ip,
                env=environ,
            )
        if exposure == EXPOSURE_LAN:
            return _planned_lan_endpoint_manifest(
                provider=provider,
                exposure=exposure,
                role=role,
                env=environ,
            )
        if exposure == EXPOSURE_WAN:
            return _planned_wan_endpoint_manifest(
                provider=provider,
                exposure=exposure,
                role=role,
                env=environ,
            )
        raise NotImplementedError(
            f"docker dry-run create-endpoint is not implemented for {exposure}"
        )

    if not confirm_live_run:
        raise PermissionError(CONFIRMATION_ERROR)
    if exposure == EXPOSURE_PRIVATE:
        return _create_live_private_endpoint(
            provider=provider,
            exposure=exposure,
            role=role,
            private_group=private_group,
            private_ip=private_ip,
            env=environ,
            command_runner=command_runner,
        )
    if exposure == EXPOSURE_LAN:
        return _create_live_lan_endpoint(
            provider=provider,
            exposure=exposure,
            role=role,
            env=environ,
            command_runner=command_runner,
        )
    if exposure == EXPOSURE_WAN:
        return _create_live_wan_endpoint(
            provider=provider,
            exposure=exposure,
            role=role,
            env=environ,
            command_runner=command_runner,
        )
    raise NotImplementedError(
        f"real docker create-endpoint is not implemented for {exposure}"
    )


def _create_live_private_endpoint(
    *,
    provider: str,
    exposure: str,
    role: str,
    private_group: str | None,
    private_ip: str | None,
    env: Mapping[str, str],
    command_runner: DockerRunner,
) -> dict[str, object]:
    if private_group is None:
        raise ValueError("--private-group is required for live docker/private endpoints")

    endpoint_id = docker_endpoint_id(
        provider=provider,
        exposure=exposure,
        role=role,
    )
    created_at = utc_now()
    docker_command = requested_docker_command(env)
    private_plan = _prepare_live_private_network(
        provider=provider,
        exposure=exposure,
        role=role,
        private_group=private_group,
        endpoint_id=endpoint_id,
        private_cidr=requested_private_cidr(env),
        requested_private_ip=private_ip,
        env=env,
        docker_command=docker_command,
        command_runner=command_runner,
        created_at=created_at,
    )
    manifest = _create_live_container_endpoint(
        provider=provider,
        exposure=exposure,
        role=role,
        env=env,
        command_runner=command_runner,
        network_name=str(private_plan["network_name"]),
        network_args=_object_sequence(private_plan["network_args"], "private.network_args"),
        network_resources=_provider_resource_sequence(
            private_plan["network_resources"],
            "private.network_resources",
        ),
        security=_docker_private_security_flags(),
        capabilities=_private_capabilities_metadata(
            provider=provider,
            exposure=exposure,
            dry_run=False,
        ),
        planned_interfaces=_network_interface_sequence(
            private_plan["planned_interfaces"],
            "private.planned_interfaces",
        ),
        private_group=private_group,
        endpoint_id=endpoint_id,
        created_at=created_at,
        extra_metadata=_metadata_mapping(private_plan.get("extra_metadata")),
        discovery_prefer_public_or_default=False,
    )
    return _docker_live_output(manifest)


def _create_live_lan_endpoint(
    *,
    provider: str,
    exposure: str,
    role: str,
    env: Mapping[str, str],
    command_runner: DockerRunner,
) -> dict[str, object]:
    endpoint_id = docker_endpoint_id(
        provider=provider,
        exposure=exposure,
        role=role,
    )
    created_at = utc_now()
    docker_command = requested_docker_command(env)
    lan_network_name, lan_network_source = _requested_lan_network(env)
    lan_network = _live_configured_nat_l3_network_metadata(
        _lan_network_metadata(
            network_name=lan_network_name,
            network_source=lan_network_source,
            docker_command=docker_command,
        )
    )
    network_resource = docker_network_resource(
        None,
        name=lan_network_name,
        cleanup=False,
        metadata=lan_network,
    )
    capabilities = _nat_l3_capabilities_metadata(
        provider=provider,
        exposure=exposure,
        dry_run=False,
    )
    security = _docker_nat_l3_security_flags(
        exposure=exposure,
        network_name=lan_network_name,
    )
    manifest = _create_live_container_endpoint(
        provider=provider,
        exposure=exposure,
        role=role,
        env=env,
        command_runner=command_runner,
        network_name=lan_network_name,
        network_args=["--network", lan_network_name],
        network_resources=[network_resource],
        security=security,
        capabilities=capabilities,
        planned_interfaces=[_lan_interface(lan_network=lan_network)],
        endpoint_id=endpoint_id,
        created_at=created_at,
        extra_metadata={
            "lan": lan_network,
            "lan_network": lan_network,
            "docker_network": lan_network_name,
            "docker_network_source": lan_network_source,
            "nat_backed_l3_lan": True,
            "true_lan_l2": False,
            "docker": {
                "network": lan_network,
                "lan_network": lan_network,
            },
        },
        require_discovered_ipv4=True,
    )
    return _docker_live_output(manifest)


def _create_live_wan_endpoint(
    *,
    provider: str,
    exposure: str,
    role: str,
    env: Mapping[str, str],
    command_runner: DockerRunner,
) -> dict[str, object]:
    endpoint_id = docker_endpoint_id(
        provider=provider,
        exposure=exposure,
        role=role,
    )
    created_at = utc_now()
    docker_command = requested_docker_command(env)
    wan_network_name, wan_network_source = _requested_wan_network(env)
    wan_network = _live_configured_nat_l3_network_metadata(
        _wan_network_metadata(
            network_name=wan_network_name,
            network_source=wan_network_source,
            docker_command=docker_command,
        )
    )
    network_resource = docker_network_resource(
        None,
        name=wan_network_name,
        cleanup=False,
        metadata=wan_network,
    )
    capabilities = _nat_l3_capabilities_metadata(
        provider=provider,
        exposure=exposure,
        dry_run=False,
    )
    security = _docker_nat_l3_security_flags(
        exposure=exposure,
        network_name=wan_network_name,
    )
    manifest = _create_live_container_endpoint(
        provider=provider,
        exposure=exposure,
        role=role,
        env=env,
        command_runner=command_runner,
        network_name=wan_network_name,
        network_args=["--network", wan_network_name],
        network_resources=[network_resource],
        security=security,
        capabilities=capabilities,
        planned_interfaces=[_wan_interface(wan_network=wan_network)],
        endpoint_id=endpoint_id,
        created_at=created_at,
        extra_metadata={
            "wan": wan_network,
            "wan_network": wan_network,
            "docker_network": wan_network_name,
            "docker_network_source": wan_network_source,
            "nat_backed_l3_egress": True,
            "public_inbound": False,
            "public_inbound_reachability": False,
            "wan_l2": False,
            "link_layer_fidelity": False,
            "broadcast": False,
            "docker": {
                "network": wan_network,
                "wan_network": wan_network,
            },
        },
        require_discovered_ipv4=True,
    )
    return _docker_live_output(manifest)


def _planned_private_endpoint_manifest(
    *,
    provider: str,
    exposure: str,
    role: str,
    private_group: str,
    private_group_source: str,
    private_ip: str | None,
    env: Mapping[str, str],
) -> dict[str, object]:
    endpoint_id = planned_docker_endpoint_id(
        provider=provider,
        exposure=exposure,
        role=role,
        private_group=private_group,
    )
    layout = endpoint_layout(endpoint_id)
    endpoint_public_key_path = public_key_path(layout.private_key_path)
    ssh_port = free_localhost_tcp_port()
    docker_command = requested_docker_command(env)
    image = plan_docker_image(
        env,
        artifact_dir=layout.artifact_dir,
        docker_command=docker_command,
    )["docker_image"]
    image_tag = requested_docker_image(env)
    private_cidr = requested_private_cidr(env)
    private_network = _private_network_metadata(
        provider=provider,
        exposure=exposure,
        role=role,
        private_group=private_group,
        private_cidr=private_cidr,
        docker_command=docker_command,
    )
    private_ipv4, ipv4_source = _planned_private_ipv4(
        endpoint_id=endpoint_id,
        private_group=private_group,
        private_cidr=private_cidr,
        requested_private_ip=private_ip,
    )
    private_mac = deterministic_private_mac(
        private_group=private_group,
        endpoint_id=endpoint_id,
    )
    security = _docker_private_security_flags()
    labels = docker_labels(
        endpoint_id=endpoint_id,
        exposure=exposure,
        role=role,
        private_group=private_group,
        created_at=PLANNED_CREATED_AT,
        provider=provider,
    )
    container_name = docker_container_name(endpoint_id)
    container = _container_metadata(
        container_name=container_name,
        endpoint_id=endpoint_id,
        image_tag=image_tag,
        network_name=str(private_network["network_name"]),
        private_ipv4=private_ipv4,
        private_mac=private_mac,
        ssh_port=ssh_port,
        labels=labels,
        security=security,
        docker_command=docker_command,
        authorized_key_source=endpoint_public_key_path,
    )
    capabilities = _private_capabilities_metadata(
        provider=provider,
        exposure=exposure,
        dry_run=True,
    )
    group_record = _private_group_record_metadata(
        provider=provider,
        private_group=private_group,
        private_cidr=private_cidr,
        private_network=private_network,
        endpoint_id=endpoint_id,
        private_ipv4=private_ipv4,
        private_mac=private_mac,
    )

    manifest = EndpointManifest(
        endpoint_id=endpoint_id,
        provider=provider,
        exposure=exposure,
        status="planned",
        role=role,
        created_at=PLANNED_CREATED_AT,
        ssh=EndpointSSHInfo(
            host=DOCKER_SSH_HOST,
            user=DOCKER_SSH_USER,
            port=ssh_port,
            identity_file=str(layout.private_key_path),
            known_hosts_file=str(layout.known_hosts_path),
            metadata={
                "planned": True,
                "transport": "docker-localhost-port-forward",
                "host": DOCKER_SSH_HOST,
                "host_port": ssh_port,
                "guest_port": DOCKER_SSH_GUEST_PORT,
                "container_name": container_name,
                "endpoint_key_paths": {
                    "private_key": str(layout.private_key_path),
                    "public_key": str(endpoint_public_key_path),
                    "known_hosts": str(layout.known_hosts_path),
                },
            },
        ),
        interfaces=[
            _private_interface(
                network_name=str(private_network["network_name"]),
                private_group=private_group,
                private_cidr=private_cidr,
                private_ipv4=private_ipv4,
                private_mac=private_mac,
                ipv4_source=ipv4_source,
                requested_private_ip=private_ip,
            )
        ],
        provider_resources=docker_provider_resources(
            [
                docker_container_resource(
                    None,
                    name=container_name,
                    endpoint_id=endpoint_id,
                    metadata={
                        "planned": True,
                        "exposure": exposure,
                        "role": role,
                        "private_group": private_group,
                        "image": image_tag,
                        "ssh_host": DOCKER_SSH_HOST,
                        "ssh_host_port": ssh_port,
                        "ssh_guest_port": DOCKER_SSH_GUEST_PORT,
                        "security": security,
                    },
                ),
                docker_network_resource(
                    None,
                    name=str(private_network["network_name"]),
                    private_group=private_group,
                    cidr=private_cidr,
                    metadata=private_network,
                ),
                docker_image_resource(
                    image_tag,
                    cleanup=False,
                    metadata={"planned": True, **image},
                ),
                docker_local_file_resource(
                    layout.private_key_path,
                    name="ssh-private-key",
                    metadata={"planned": True, "role": "ssh-private-key"},
                ),
                docker_local_file_resource(
                    endpoint_public_key_path,
                    name="ssh-public-key",
                    metadata={"planned": True, "role": "ssh-public-key"},
                ),
                docker_local_file_resource(
                    layout.known_hosts_path,
                    name="ssh-known-hosts",
                    metadata={"planned": True, "role": "ssh-known-hosts"},
                ),
                docker_local_file_resource(
                    layout.state_dir,
                    name="endpoint-state-dir",
                    metadata={"planned": True, "role": "endpoint-state"},
                ),
                docker_local_file_resource(
                    layout.manifest_path,
                    name="endpoint-manifest",
                    metadata={"planned": True, "role": "endpoint-manifest"},
                ),
                docker_local_file_resource(
                    layout.artifact_dir,
                    name="endpoint-artifact-dir",
                    cleanup=False,
                    metadata={"planned": True, "role": "endpoint-artifacts"},
                ),
            ],
            metadata={
                "provider": provider,
                "exposure": exposure,
                "planned": True,
                "private_group": private_group,
            },
        ),
        artifact_dir=str(layout.artifact_dir),
        metadata={
            "created": False,
            "dry_run": True,
            "state_dir": str(layout.state_dir),
            "manifest_path": str(layout.manifest_path),
            "docker": {
                "command": docker_command,
                "container": container,
                "private_network": private_network,
                "image": image,
                "security": security,
                "capabilities": capabilities,
            },
            "private": private_network,
            "private_network": private_network,
            "private_group": private_group,
            "private_group_source": private_group_source,
            "private_group_record": group_record,
            "private_ip": private_ipv4,
            "private_ip_source": ipv4_source,
            "private_mac": private_mac,
            "capabilities": capabilities,
            "docker_image": image,
        },
    )
    output = manifest.to_dict()
    output["metadata"]["artifact_paths"] = manifest.artifact_paths(  # type: ignore[index]
        _artifact_paths(
            layout=layout,
            public_key=endpoint_public_key_path,
            docker_image=image,
        )
    ).to_dict()
    output["created"] = False
    output["dry_run"] = True
    output["state_dir"] = str(layout.state_dir)
    output["manifest_path"] = str(layout.manifest_path)
    return output


def _planned_lan_endpoint_manifest(
    *,
    provider: str,
    exposure: str,
    role: str,
    env: Mapping[str, str],
) -> dict[str, object]:
    endpoint_id = planned_docker_endpoint_id(
        provider=provider,
        exposure=exposure,
        role=role,
    )
    layout = endpoint_layout(endpoint_id)
    endpoint_public_key_path = public_key_path(layout.private_key_path)
    ssh_port = free_localhost_tcp_port()
    docker_command = requested_docker_command(env)
    image = plan_docker_image(
        env,
        artifact_dir=layout.artifact_dir,
        docker_command=docker_command,
    )["docker_image"]
    image_tag = requested_docker_image(env)
    lan_network_name, lan_network_source = _requested_lan_network(env)
    lan_network = _lan_network_metadata(
        network_name=lan_network_name,
        network_source=lan_network_source,
        docker_command=docker_command,
    )
    security = _docker_nat_l3_security_flags(
        exposure=exposure,
        network_name=lan_network_name,
    )
    labels = docker_labels(
        endpoint_id=endpoint_id,
        exposure=exposure,
        role=role,
        created_at=PLANNED_CREATED_AT,
        provider=provider,
    )
    container_name = docker_container_name(endpoint_id)
    container = _nat_l3_container_metadata(
        container_name=container_name,
        endpoint_id=endpoint_id,
        image_tag=image_tag,
        exposure=exposure,
        network_name=lan_network_name,
        ssh_port=ssh_port,
        labels=labels,
        security=security,
        docker_command=docker_command,
        authorized_key_source=endpoint_public_key_path,
    )
    capabilities = _nat_l3_capabilities_metadata(
        provider=provider,
        exposure=exposure,
        dry_run=True,
    )

    manifest = EndpointManifest(
        endpoint_id=endpoint_id,
        provider=provider,
        exposure=exposure,
        status="planned",
        role=role,
        created_at=PLANNED_CREATED_AT,
        ssh=EndpointSSHInfo(
            host=DOCKER_SSH_HOST,
            user=DOCKER_SSH_USER,
            port=ssh_port,
            identity_file=str(layout.private_key_path),
            known_hosts_file=str(layout.known_hosts_path),
            metadata={
                "planned": True,
                "transport": "docker-localhost-port-forward",
                "host": DOCKER_SSH_HOST,
                "host_port": ssh_port,
                "guest_port": DOCKER_SSH_GUEST_PORT,
                "container_name": container_name,
                "public_inbound_reachability": False,
                "endpoint_key_paths": {
                    "private_key": str(layout.private_key_path),
                    "public_key": str(endpoint_public_key_path),
                    "known_hosts": str(layout.known_hosts_path),
                },
            },
        ),
        interfaces=[_lan_interface(lan_network=lan_network)],
        provider_resources=docker_provider_resources(
            [
                docker_container_resource(
                    None,
                    name=container_name,
                    endpoint_id=endpoint_id,
                    metadata={
                        "planned": True,
                        "exposure": exposure,
                        "role": role,
                        "image": image_tag,
                        "docker_network": lan_network_name,
                        "ssh_host": DOCKER_SSH_HOST,
                        "ssh_host_port": ssh_port,
                        "ssh_guest_port": DOCKER_SSH_GUEST_PORT,
                        "security": security,
                    },
                ),
                docker_network_resource(
                    None,
                    name=lan_network_name,
                    cleanup=False,
                    metadata=lan_network,
                ),
                docker_image_resource(
                    image_tag,
                    cleanup=False,
                    metadata={"planned": True, **image},
                ),
                docker_local_file_resource(
                    layout.private_key_path,
                    name="ssh-private-key",
                    metadata={"planned": True, "role": "ssh-private-key"},
                ),
                docker_local_file_resource(
                    endpoint_public_key_path,
                    name="ssh-public-key",
                    metadata={"planned": True, "role": "ssh-public-key"},
                ),
                docker_local_file_resource(
                    layout.known_hosts_path,
                    name="ssh-known-hosts",
                    metadata={"planned": True, "role": "ssh-known-hosts"},
                ),
                docker_local_file_resource(
                    layout.state_dir,
                    name="endpoint-state-dir",
                    metadata={"planned": True, "role": "endpoint-state"},
                ),
                docker_local_file_resource(
                    layout.manifest_path,
                    name="endpoint-manifest",
                    metadata={"planned": True, "role": "endpoint-manifest"},
                ),
                docker_local_file_resource(
                    layout.artifact_dir,
                    name="endpoint-artifact-dir",
                    cleanup=False,
                    metadata={"planned": True, "role": "endpoint-artifacts"},
                ),
            ],
            metadata={
                "provider": provider,
                "exposure": exposure,
                "planned": True,
                "mode": "nat-backed-l3-lan",
                "docker_network": lan_network_name,
            },
        ),
        artifact_dir=str(layout.artifact_dir),
        metadata={
            "created": False,
            "dry_run": True,
            "state_dir": str(layout.state_dir),
            "manifest_path": str(layout.manifest_path),
            "docker": {
                "command": docker_command,
                "container": container,
                "network": lan_network,
                "lan_network": lan_network,
                "image": image,
                "security": security,
                "capabilities": capabilities,
            },
            "lan": lan_network,
            "lan_network": lan_network,
            "docker_network": lan_network_name,
            "docker_network_source": lan_network_source,
            "capabilities": capabilities,
            "docker_image": image,
        },
    )
    output = manifest.to_dict()
    output["metadata"]["artifact_paths"] = manifest.artifact_paths(  # type: ignore[index]
        _artifact_paths(
            layout=layout,
            public_key=endpoint_public_key_path,
            docker_image=image,
        )
    ).to_dict()
    output["created"] = False
    output["dry_run"] = True
    output["state_dir"] = str(layout.state_dir)
    output["manifest_path"] = str(layout.manifest_path)
    return output


def _planned_wan_endpoint_manifest(
    *,
    provider: str,
    exposure: str,
    role: str,
    env: Mapping[str, str],
) -> dict[str, object]:
    endpoint_id = planned_docker_endpoint_id(
        provider=provider,
        exposure=exposure,
        role=role,
    )
    layout = endpoint_layout(endpoint_id)
    endpoint_public_key_path = public_key_path(layout.private_key_path)
    ssh_port = free_localhost_tcp_port()
    docker_command = requested_docker_command(env)
    image = plan_docker_image(
        env,
        artifact_dir=layout.artifact_dir,
        docker_command=docker_command,
    )["docker_image"]
    image_tag = requested_docker_image(env)
    wan_network_name, wan_network_source = _requested_wan_network(env)
    wan_network = _wan_network_metadata(
        network_name=wan_network_name,
        network_source=wan_network_source,
        docker_command=docker_command,
    )
    security = _docker_nat_l3_security_flags(
        exposure=exposure,
        network_name=wan_network_name,
    )
    labels = docker_labels(
        endpoint_id=endpoint_id,
        exposure=exposure,
        role=role,
        created_at=PLANNED_CREATED_AT,
        provider=provider,
    )
    container_name = docker_container_name(endpoint_id)
    container = _nat_l3_container_metadata(
        container_name=container_name,
        endpoint_id=endpoint_id,
        image_tag=image_tag,
        exposure=exposure,
        network_name=wan_network_name,
        ssh_port=ssh_port,
        labels=labels,
        security=security,
        docker_command=docker_command,
        authorized_key_source=endpoint_public_key_path,
    )
    capabilities = _nat_l3_capabilities_metadata(
        provider=provider,
        exposure=exposure,
        dry_run=True,
    )

    manifest = EndpointManifest(
        endpoint_id=endpoint_id,
        provider=provider,
        exposure=exposure,
        status="planned",
        role=role,
        created_at=PLANNED_CREATED_AT,
        ssh=EndpointSSHInfo(
            host=DOCKER_SSH_HOST,
            user=DOCKER_SSH_USER,
            port=ssh_port,
            identity_file=str(layout.private_key_path),
            known_hosts_file=str(layout.known_hosts_path),
            metadata={
                "planned": True,
                "transport": "docker-localhost-port-forward",
                "host": DOCKER_SSH_HOST,
                "host_port": ssh_port,
                "guest_port": DOCKER_SSH_GUEST_PORT,
                "container_name": container_name,
                "public_inbound_reachability": False,
                "endpoint_key_paths": {
                    "private_key": str(layout.private_key_path),
                    "public_key": str(endpoint_public_key_path),
                    "known_hosts": str(layout.known_hosts_path),
                },
            },
        ),
        interfaces=[_wan_interface(wan_network=wan_network)],
        provider_resources=docker_provider_resources(
            [
                docker_container_resource(
                    None,
                    name=container_name,
                    endpoint_id=endpoint_id,
                    metadata={
                        "planned": True,
                        "exposure": exposure,
                        "role": role,
                        "image": image_tag,
                        "docker_network": wan_network_name,
                        "ssh_host": DOCKER_SSH_HOST,
                        "ssh_host_port": ssh_port,
                        "ssh_guest_port": DOCKER_SSH_GUEST_PORT,
                        "security": security,
                    },
                ),
                docker_network_resource(
                    None,
                    name=wan_network_name,
                    cleanup=False,
                    metadata=wan_network,
                ),
                docker_image_resource(
                    image_tag,
                    cleanup=False,
                    metadata={"planned": True, **image},
                ),
                docker_local_file_resource(
                    layout.private_key_path,
                    name="ssh-private-key",
                    metadata={"planned": True, "role": "ssh-private-key"},
                ),
                docker_local_file_resource(
                    endpoint_public_key_path,
                    name="ssh-public-key",
                    metadata={"planned": True, "role": "ssh-public-key"},
                ),
                docker_local_file_resource(
                    layout.known_hosts_path,
                    name="ssh-known-hosts",
                    metadata={"planned": True, "role": "ssh-known-hosts"},
                ),
                docker_local_file_resource(
                    layout.state_dir,
                    name="endpoint-state-dir",
                    metadata={"planned": True, "role": "endpoint-state"},
                ),
                docker_local_file_resource(
                    layout.manifest_path,
                    name="endpoint-manifest",
                    metadata={"planned": True, "role": "endpoint-manifest"},
                ),
                docker_local_file_resource(
                    layout.artifact_dir,
                    name="endpoint-artifact-dir",
                    cleanup=False,
                    metadata={"planned": True, "role": "endpoint-artifacts"},
                ),
            ],
            metadata={
                "provider": provider,
                "exposure": exposure,
                "planned": True,
                "mode": "nat-backed-l3-wan-egress",
                "docker_network": wan_network_name,
            },
        ),
        artifact_dir=str(layout.artifact_dir),
        metadata={
            "created": False,
            "dry_run": True,
            "state_dir": str(layout.state_dir),
            "manifest_path": str(layout.manifest_path),
            "docker": {
                "command": docker_command,
                "container": container,
                "network": wan_network,
                "wan_network": wan_network,
                "image": image,
                "security": security,
                "capabilities": capabilities,
            },
            "wan": wan_network,
            "wan_network": wan_network,
            "docker_network": wan_network_name,
            "docker_network_source": wan_network_source,
            "capabilities": capabilities,
            "docker_image": image,
        },
    )
    output = manifest.to_dict()
    output["metadata"]["artifact_paths"] = manifest.artifact_paths(  # type: ignore[index]
        _artifact_paths(
            layout=layout,
            public_key=endpoint_public_key_path,
            docker_image=image,
        )
    ).to_dict()
    output["created"] = False
    output["dry_run"] = True
    output["state_dir"] = str(layout.state_dir)
    output["manifest_path"] = str(layout.manifest_path)
    return output


def _ensure_docker_ssh_material(
    *,
    endpoint_id: str,
    private_key_path: str | Path,
    known_hosts_path: str | Path,
    command_runner: DockerRunner = run_command,
) -> tuple[Path, Path, Path]:
    """Ensure Docker endpoint SSH files exist and return their paths."""

    private_key, public_key = ensure_endpoint_ssh_key(
        private_key_path,
        endpoint_id,
        runner=command_runner,
    )
    known_hosts = ensure_known_hosts_file(known_hosts_path)
    return private_key, public_key, known_hosts


def _wait_for_docker_ssh(
    *,
    private_key_path: str | Path,
    known_hosts_path: str | Path,
    ssh_port: int,
    command_runner: DockerRunner = run_command,
    wait_timeout: float = DOCKER_SSH_WAIT_TIMEOUT,
    interval: float = DOCKER_SSH_WAIT_INTERVAL,
) -> CommandResult:
    """Wait for the Docker endpoint SSH server on the forwarded localhost port."""

    known_hosts = ensure_known_hosts_file(known_hosts_path)
    try:
        return wait_for_ssh(
            host=DOCKER_SSH_HOST,
            user=DOCKER_SSH_USER,
            identity_file=private_key_path,
            known_hosts=known_hosts,
            port=ssh_port,
            wait_timeout=wait_timeout,
            interval=interval,
            runner=command_runner,
        )
    except TimeoutError as exc:
        raise RuntimeError(str(exc)) from exc


def _create_live_container_endpoint(
    *,
    provider: str,
    exposure: str,
    role: str,
    env: Mapping[str, str],
    command_runner: DockerRunner,
    network_name: str,
    network_args: Sequence[object],
    network_resources: Sequence[ProviderResource],
    security: Mapping[str, object],
    capabilities: Mapping[str, object],
    planned_interfaces: Sequence[NetworkInterface],
    private_group: str | None = None,
    endpoint_id: str | None = None,
    created_at: str | None = None,
    extra_labels: Mapping[str, object] | None = None,
    extra_metadata: Mapping[str, object] | None = None,
    ssh_wait_timeout: float = DOCKER_SSH_WAIT_TIMEOUT,
    ssh_wait_interval: float = DOCKER_SSH_WAIT_INTERVAL,
    discovery_prefer_public_or_default: bool = True,
    require_discovered_ipv4: bool = False,
) -> EndpointManifest:
    """Create one live Docker container after exposure-specific networking is ready."""

    endpoint_id = endpoint_id or docker_endpoint_id(
        provider=provider,
        exposure=exposure,
        role=role,
    )
    created_at = created_at or utc_now()
    layout = ensure_endpoint_dirs(endpoint_id)
    docker_command = requested_docker_command(env)
    command_log_path = layout.artifact_dir / DOCKER_CONTAINER_COMMAND_LOG_NAME
    recorder = _DockerContainerCommandRecorder(command_runner, command_log_path)
    image = ensure_docker_image(
        env=env,
        artifact_dir=layout.artifact_dir,
        docker_command=docker_command,
        command_runner=command_runner,
    )["docker_image"]
    image_tag = requested_docker_image(env)
    ssh_port = free_localhost_tcp_port()
    container_name = docker_container_name(endpoint_id)

    _, public_key, known_hosts = _ensure_docker_ssh_material(
        endpoint_id=endpoint_id,
        private_key_path=layout.private_key_path,
        known_hosts_path=layout.known_hosts_path,
        command_runner=recorder,
    )
    labels = docker_labels(
        endpoint_id=endpoint_id,
        exposure=exposure,
        role=role,
        private_group=private_group,
        created_at=created_at,
        provider=provider,
        extra=extra_labels,
    )
    run_network_args = tuple(network_args) if network_args else ("--network", network_name)
    run_argv = _docker_live_run_argv(
        container_name=container_name,
        endpoint_id=endpoint_id,
        image_tag=image_tag,
        ssh_port=ssh_port,
        network_args=run_network_args,
        labels=labels,
        security=security,
        docker_command=docker_command,
        authorized_key_source=public_key,
    )
    container = _live_container_metadata(
        container_id=None,
        container_name=container_name,
        endpoint_id=endpoint_id,
        image_tag=image_tag,
        exposure=exposure,
        network_name=network_name,
        ssh_port=ssh_port,
        labels=labels,
        security=security,
        docker_command=docker_command,
        authorized_key_source=public_key,
        run_argv=run_argv,
        created=False,
    )
    provider_resources = _live_container_provider_resources(
        container_id=None,
        container_name=container_name,
        endpoint_id=endpoint_id,
        exposure=exposure,
        role=role,
        image_tag=image_tag,
        image=image,
        network_name=network_name,
        network_resources=network_resources,
        layout=layout,
        public_key=public_key,
        command_log_path=command_log_path,
        security=security,
        created=False,
    )
    write_endpoint_manifest(
        EndpointManifest(
            endpoint_id=endpoint_id,
            provider=provider,
            exposure=exposure,
            status="creating",
            role=role,
            created_at=created_at,
            ssh=_docker_live_ssh_info(
                layout=layout,
                container_name=container_name,
                ssh_port=ssh_port,
                control_interface=_first_planned_interface_name(planned_interfaces),
            ),
            interfaces=list(planned_interfaces),
            provider_resources=provider_resources,
            artifact_dir=str(layout.artifact_dir),
            metadata=_docker_live_manifest_metadata(
                created=False,
                layout=layout,
                docker_command=docker_command,
                container=container,
                network_name=network_name,
                network_resources=network_resources,
                image=image,
                security=security,
                capabilities=capabilities,
                command_log_path=command_log_path,
                extra_metadata=extra_metadata,
                discovery={
                    "ssh_ready": False,
                    "interfaces": False,
                },
            ),
        )
    )

    run_result = _run_docker(
        run_argv,
        runner=recorder,
        env=env,
        timeout=DOCKER_CONTAINER_CREATE_TIMEOUT,
    )
    container_id = _docker_container_id_from_run(run_result, fallback=container_name)
    container = _live_container_metadata(
        container_id=container_id,
        container_name=container_name,
        endpoint_id=endpoint_id,
        image_tag=image_tag,
        exposure=exposure,
        network_name=network_name,
        ssh_port=ssh_port,
        labels=labels,
        security=security,
        docker_command=docker_command,
        authorized_key_source=public_key,
        run_argv=run_argv,
        created=True,
    )
    provider_resources = _live_container_provider_resources(
        container_id=container_id,
        container_name=container_name,
        endpoint_id=endpoint_id,
        exposure=exposure,
        role=role,
        image_tag=image_tag,
        image=image,
        network_name=network_name,
        network_resources=network_resources,
        layout=layout,
        public_key=public_key,
        command_log_path=command_log_path,
        security=security,
        created=True,
    )
    write_endpoint_manifest(
        EndpointManifest(
            endpoint_id=endpoint_id,
            provider=provider,
            exposure=exposure,
            status="creating",
            role=role,
            created_at=created_at,
            ssh=_docker_live_ssh_info(
                layout=layout,
                container_name=container_name,
                ssh_port=ssh_port,
                control_interface=_first_planned_interface_name(planned_interfaces),
            ),
            interfaces=list(planned_interfaces),
            provider_resources=provider_resources,
            artifact_dir=str(layout.artifact_dir),
            metadata=_docker_live_manifest_metadata(
                created=True,
                layout=layout,
                docker_command=docker_command,
                container=container,
                network_name=network_name,
                network_resources=network_resources,
                image=image,
                security=security,
                capabilities=capabilities,
                command_log_path=command_log_path,
                extra_metadata=extra_metadata,
                discovery={
                    "ssh_ready": False,
                    "interfaces": False,
                },
            ),
        )
    )

    _wait_for_docker_ssh(
        private_key_path=layout.private_key_path,
        known_hosts_path=known_hosts,
        ssh_port=ssh_port,
        command_runner=recorder,
        wait_timeout=ssh_wait_timeout,
        interval=ssh_wait_interval,
    )
    discovered_interfaces = discover_linux_endpoint_interfaces(
        host=DOCKER_SSH_HOST,
        user=DOCKER_SSH_USER,
        identity_file=layout.private_key_path,
        known_hosts=known_hosts,
        exposure=exposure,
        port=ssh_port,
        runner=recorder,
        source="docker-ssh-discovery",
        metadata={
            "container_id": container_id,
            "container_name": container_name,
            "docker_network": network_name,
        },
        prefer_public_or_default=discovery_prefer_public_or_default,
    )
    active_interfaces = _docker_active_interfaces(
        planned_interfaces=planned_interfaces,
        discovered_interfaces=discovered_interfaces,
        network_name=network_name,
        container=container,
    )
    if not active_interfaces:
        raise RuntimeError("Docker interface discovery did not find any interfaces")
    if require_discovered_ipv4 and not any(
        interface.ipv4 is not None for interface in active_interfaces
    ):
        raise RuntimeError("Docker interface discovery did not find an IPv4 address")

    manifest = EndpointManifest(
        endpoint_id=endpoint_id,
        provider=provider,
        exposure=exposure,
        status="active",
        role=role,
        created_at=created_at,
        ssh=_docker_live_ssh_info(
            layout=layout,
            container_name=container_name,
            ssh_port=ssh_port,
            control_interface=active_interfaces[0].name,
        ),
        interfaces=active_interfaces,
        provider_resources=provider_resources,
        artifact_dir=str(layout.artifact_dir),
        metadata=_docker_live_manifest_metadata(
            created=True,
            layout=layout,
            docker_command=docker_command,
            container=container,
            network_name=network_name,
            network_resources=network_resources,
            image=image,
            security=security,
            capabilities=capabilities,
            command_log_path=command_log_path,
            extra_metadata=extra_metadata,
            discovery={
                "ssh_ready": True,
                "interfaces": True,
                "interface_count": len(discovered_interfaces),
                "ipv4": any(interface.ipv4 is not None for interface in active_interfaces),
            },
        ),
    )
    write_endpoint_manifest(manifest)
    return manifest


def _docker_live_output(manifest: EndpointManifest) -> dict[str, object]:
    layout = endpoint_layout(manifest.endpoint_id)
    output = manifest.to_dict()
    output["created"] = True
    output["dry_run"] = False
    output["state_dir"] = str(manifest.metadata.get("state_dir", layout.state_dir))
    output["manifest_path"] = str(
        manifest.metadata.get("manifest_path", layout.manifest_path)
    )
    output["metadata"]["artifact_paths"] = manifest.artifact_paths(  # type: ignore[index]
        _artifact_paths(
            layout=layout,
            public_key=public_key_path(layout.private_key_path),
            docker_image=_metadata_mapping(manifest.metadata.get("docker_image")),
        )
    ).to_dict()
    return output


def _docker_live_run_argv(
    *,
    container_name: str,
    endpoint_id: str,
    image_tag: str,
    ssh_port: int,
    network_args: Sequence[object],
    labels: Mapping[str, object],
    security: Mapping[str, object],
    docker_command: str,
    authorized_key_source: str | Path,
) -> list[str]:
    return docker_argv(
        "run",
        "--detach",
        "--name",
        container_name,
        "--hostname",
        endpoint_id,
        *network_args,
        "--publish",
        docker_publish_arg(host_port=ssh_port, guest_port=DOCKER_SSH_GUEST_PORT),
        *_docker_security_argv(security),
        "--mount",
        _authorized_key_mount_spec(authorized_key_source),
        *docker_label_args(labels),
        image_tag,
        docker_command=docker_command,
    )


def _docker_security_argv(security: Mapping[str, object]) -> list[str]:
    _validate_docker_security(security)
    args: list[str] = []
    for capability in _string_sequence(security.get("cap_drop", ()), "security.cap_drop"):
        args.extend(["--cap-drop", capability])
    for capability in _string_sequence(security.get("cap_add", ()), "security.cap_add"):
        args.extend(["--cap-add", capability])
    for option in _string_sequence(security.get("security_opt", ()), "security.security_opt"):
        args.extend(["--security-opt", option])
    return args


def _validate_docker_security(security: Mapping[str, object]) -> None:
    if bool(security.get("docker_socket_mounted")):
        raise ValueError("Docker endpoint containers must not mount the Docker socket")
    if bool(security.get("privileged")):
        raise ValueError("Docker endpoint containers must not use --privileged")
    if bool(security.get("host_network")):
        raise ValueError("Docker endpoint containers must not use host networking")
    if bool(security.get("host_pid")):
        raise ValueError("Docker endpoint containers must not use host PID mode")
    if bool(security.get("broad_host_filesystem_mounts")):
        raise ValueError("Docker endpoint containers must not use broad host mounts")
    cap_drop = _string_sequence(security.get("cap_drop", ()), "security.cap_drop")
    security_opt = _string_sequence(
        security.get("security_opt", ()),
        "security.security_opt",
    )
    if "ALL" not in cap_drop:
        raise ValueError("Docker endpoint containers must use --cap-drop ALL")
    if "no-new-privileges" not in security_opt:
        raise ValueError(
            "Docker endpoint containers must use --security-opt no-new-privileges"
        )


def _live_container_metadata(
    *,
    container_id: str | None,
    container_name: str,
    endpoint_id: str,
    image_tag: str,
    exposure: str,
    network_name: str,
    ssh_port: int,
    labels: Mapping[str, object],
    security: Mapping[str, object],
    docker_command: str,
    authorized_key_source: Path,
    run_argv: Sequence[object],
    created: bool,
) -> dict[str, object]:
    return {
        "planned": False,
        "created": created,
        "type": "docker-container",
        "container_id": container_id,
        "container_name": container_name,
        "endpoint_id": endpoint_id,
        "image": image_tag,
        "exposure": exposure,
        "network": network_name,
        "docker_network": network_name,
        "ssh": {
            "host": DOCKER_SSH_HOST,
            "host_port": ssh_port,
            "guest_port": DOCKER_SSH_GUEST_PORT,
            "publish": docker_publish_arg(
                host_port=ssh_port,
                guest_port=DOCKER_SSH_GUEST_PORT,
            ),
            "public_inbound_reachability": False,
        },
        "authorized_key": {
            "source": str(authorized_key_source),
            "target": AUTHORIZED_KEY_TARGET,
            "readonly": True,
        },
        "labels": dict(labels),
        "security": dict(security),
        "docker_command": docker_command,
        "run_argv": list(run_argv),
        "run_command": render_docker_argv(run_argv),
    }


def _live_container_provider_resources(
    *,
    container_id: str | None,
    container_name: str,
    endpoint_id: str,
    exposure: str,
    role: str,
    image_tag: str,
    image: Mapping[str, object],
    network_name: str,
    network_resources: Sequence[ProviderResource],
    layout: object,
    public_key: Path,
    command_log_path: Path,
    security: Mapping[str, object],
    created: bool,
):
    return docker_provider_resources(
        [
            docker_container_resource(
                container_id,
                name=container_name,
                endpoint_id=endpoint_id,
                metadata={
                    "created": created,
                    "exposure": exposure,
                    "role": role,
                    "image": image_tag,
                    "docker_network": network_name,
                    "ssh_host": DOCKER_SSH_HOST,
                    "ssh_guest_port": DOCKER_SSH_GUEST_PORT,
                    "security": security,
                },
            ),
            *network_resources,
            docker_image_resource(
                image_tag,
                cleanup=False,
                metadata={"planned": False, **dict(image)},
            ),
            docker_local_file_resource(
                getattr(layout, "private_key_path"),
                name="ssh-private-key",
                metadata={"role": "ssh-private-key"},
            ),
            docker_local_file_resource(
                public_key,
                name="ssh-public-key",
                metadata={"role": "ssh-public-key"},
            ),
            docker_local_file_resource(
                getattr(layout, "known_hosts_path"),
                name="ssh-known-hosts",
                metadata={"role": "ssh-known-hosts"},
            ),
            docker_local_file_resource(
                getattr(layout, "state_dir"),
                name="endpoint-state-dir",
                metadata={"role": "endpoint-state"},
            ),
            docker_local_file_resource(
                getattr(layout, "manifest_path"),
                name="endpoint-manifest",
                metadata={"role": "endpoint-manifest"},
            ),
            docker_local_file_resource(
                getattr(layout, "artifact_dir"),
                name="endpoint-artifact-dir",
                cleanup=False,
                metadata={"role": "endpoint-artifacts"},
            ),
            docker_local_file_resource(
                command_log_path,
                name="docker-container-command-log",
                cleanup=False,
                metadata={"role": "docker-container-command-log"},
            ),
        ],
        metadata={
            "provider": PROVIDER_NAME,
            "exposure": exposure,
            "docker_network": network_name,
            "created": created,
        },
    )


def _docker_live_manifest_metadata(
    *,
    created: bool,
    layout: object,
    docker_command: str,
    container: Mapping[str, object],
    network_name: str,
    network_resources: Sequence[ProviderResource],
    image: Mapping[str, object],
    security: Mapping[str, object],
    capabilities: Mapping[str, object],
    command_log_path: Path,
    extra_metadata: Mapping[str, object] | None,
    discovery: Mapping[str, object],
) -> dict[str, object]:
    metadata = dict(extra_metadata or {})
    docker_metadata = _metadata_mapping(metadata.get("docker"))
    docker_metadata.update(
        {
            "command": docker_command,
            "container": dict(container),
            "network_name": network_name,
            "network_resources": [resource.to_dict() for resource in network_resources],
            "image": dict(image),
            "security": dict(security),
            "capabilities": dict(capabilities),
            "command_log_path": str(command_log_path),
        }
    )
    metadata.update(
        {
            "created": created,
            "dry_run": False,
            "state_dir": str(getattr(layout, "state_dir")),
            "manifest_path": str(getattr(layout, "manifest_path")),
            "docker": docker_metadata,
            "docker_network": network_name,
            "docker_image": dict(image),
            "capabilities": dict(capabilities),
            "command_artifacts": {
                "container": str(command_log_path),
                "image": image.get("command_log_path"),
            },
            "discovery": dict(discovery),
        }
    )
    return metadata


def _docker_live_ssh_info(
    *,
    layout: object,
    container_name: str,
    ssh_port: int,
    control_interface: str,
) -> EndpointSSHInfo:
    return EndpointSSHInfo(
        host=DOCKER_SSH_HOST,
        user=DOCKER_SSH_USER,
        port=ssh_port,
        identity_file=str(getattr(layout, "private_key_path")),
        known_hosts_file=str(getattr(layout, "known_hosts_path")),
        metadata={
            "created_by": "tools/wire",
            "transport": "docker-localhost-port-forward",
            "container_name": container_name,
            "control_interface": control_interface,
            "host": DOCKER_SSH_HOST,
            "host_port": ssh_port,
            "guest_port": DOCKER_SSH_GUEST_PORT,
        },
    )


def _docker_active_interfaces(
    *,
    planned_interfaces: Sequence[NetworkInterface],
    discovered_interfaces: Sequence[NetworkInterface],
    network_name: str,
    container: Mapping[str, object],
) -> list[NetworkInterface]:
    if not discovered_interfaces:
        return []
    if not planned_interfaces:
        return [
            replace(
                interface,
                provider_network_id=interface.provider_network_id or network_name,
                metadata={
                    **interface.metadata,
                    "planned": False,
                    "discovered": True,
                    "docker_network": network_name,
                    "container": dict(container),
                },
            )
            for interface in discovered_interfaces
        ]

    active: list[NetworkInterface] = []
    for planned in planned_interfaces:
        selected = _select_docker_discovered_interface(
            planned,
            discovered_interfaces,
        )
        if selected is None:
            raise RuntimeError(
                f"Docker interface discovery did not find interface {planned.name}"
            )
        active.append(
            replace(
                selected,
                exposure=planned.exposure,
                ipv4=planned.ipv4 or selected.ipv4,
                ipv6=planned.ipv6 or selected.ipv6,
                mac=planned.mac or selected.mac,
                provider_network_id=planned.provider_network_id
                or selected.provider_network_id
                or network_name,
                metadata={
                    **planned.metadata,
                    **selected.metadata,
                    "planned": False,
                    "discovered": True,
                    "docker_network": network_name,
                    "container": dict(container),
                },
            )
        )
    return active


def _select_docker_discovered_interface(
    planned: NetworkInterface,
    discovered_interfaces: Sequence[NetworkInterface],
) -> NetworkInterface | None:
    planned_mac = (planned.mac or "").lower()
    for interface in discovered_interfaces:
        if planned.ipv4 is not None and interface.ipv4 == planned.ipv4:
            return interface
    for interface in discovered_interfaces:
        if planned_mac and (interface.mac or "").lower() == planned_mac:
            return interface
    for interface in discovered_interfaces:
        if interface.name == planned.name:
            return interface
    for interface in discovered_interfaces:
        if bool(interface.metadata.get("default_route")):
            return interface
    return discovered_interfaces[0] if discovered_interfaces else None


def _first_planned_interface_name(interfaces: Sequence[NetworkInterface]) -> str:
    if interfaces:
        return interfaces[0].name
    return "eth0"


def _run_docker(
    argv: Sequence[object],
    *,
    runner: DockerRunner,
    env: Mapping[str, str],
    timeout: float | None,
) -> CommandResult:
    result = runner(argv, env=env, timeout=timeout)
    if not result.ok:
        raise RuntimeError(command_error("Docker command failed", result))
    return result


def _docker_container_id_from_run(result: CommandResult, *, fallback: str) -> str:
    for line in result.stdout.splitlines():
        container_id = line.strip()
        if container_id:
            return container_id
    return fallback


class _DockerContainerCommandRecorder:
    def __init__(self, runner: DockerRunner, log_path: Path) -> None:
        self._runner = runner
        self.path = log_path.resolve(strict=False)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._records: list[dict[str, object]] = []
        self._write()

    def __call__(self, argv: Sequence[object], **kwargs: object) -> CommandResult:
        result = self._runner(argv, **kwargs)
        self._records.append(_command_result_record(result))
        self._write()
        return result

    def _write(self) -> None:
        write_json(self.path, {"commands": self._records})


def _command_result_record(result: CommandResult) -> dict[str, object]:
    return {
        "argv": list(result.redacted_argv),
        "cwd": result.cwd,
        "exit_code": result.exit_code,
        "ok": result.ok,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "timed_out": result.timed_out,
        "timeout": result.timeout,
        "error": result.error,
    }


def _metadata_mapping(value: object) -> dict[str, object]:
    return dict(value) if isinstance(value, Mapping) else {}


def _string_sequence(value: object, name: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        values: Sequence[object] = (value,)
    elif isinstance(value, Sequence):
        values = value
    else:
        raise ValueError(f"{name} must be a string sequence")
    output: list[str] = []
    for item in values:
        if not isinstance(item, str) or item == "":
            raise ValueError(f"{name} must contain non-empty strings")
        output.append(item)
    return output


def _string_list(value: object) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    return [item for item in value if isinstance(item, str)]


def _object_sequence(value: object, name: str) -> list[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"{name} must be a sequence")
    return list(value)


def _provider_resource_sequence(value: object, name: str) -> list[ProviderResource]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"{name} must be a provider resource sequence")
    resources: list[ProviderResource] = []
    for item in value:
        if not isinstance(item, ProviderResource):
            raise ValueError(f"{name} must contain provider resources")
        resources.append(item)
    return resources


def _network_interface_sequence(value: object, name: str) -> list[NetworkInterface]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"{name} must be a network interface sequence")
    interfaces: list[NetworkInterface] = []
    for item in value:
        if not isinstance(item, NetworkInterface):
            raise ValueError(f"{name} must contain network interfaces")
        interfaces.append(item)
    return interfaces


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
    if exposure != EXPOSURE_PRIVATE and private_group is not None:
        raise ValueError("--private-group is only valid with --exposure private")
    if exposure != EXPOSURE_PRIVATE and private_ip is not None:
        raise ValueError("--private-ip is only valid with --exposure private")


def _effective_private_group(private_group: str | None) -> str:
    return DEFAULT_PRIVATE_GROUP if private_group is None else private_group


def _private_group_source(private_group: str | None) -> str:
    return "default" if private_group is None else "requested"


def _private_network_metadata(
    *,
    provider: str,
    exposure: str,
    role: str,
    private_group: str,
    private_cidr: str,
    docker_command: str,
) -> dict[str, object]:
    network = parse_private_cidr(private_cidr)
    network_name = docker_private_network_name(private_group)
    labels = _private_network_labels(
        provider=provider,
        private_group=private_group,
        created_at=PLANNED_CREATED_AT,
    )
    create_argv = docker_argv(
        "network",
        "create",
        "--driver",
        "bridge",
        "--internal",
        "--subnet",
        private_cidr,
        *docker_label_args(labels),
        network_name,
        docker_command=docker_command,
    )
    _ = (exposure, role)
    return {
        "planned": True,
        "type": "docker-private-network",
        "driver": "bridge",
        "internal": True,
        "network_id": network_name,
        "network_name": network_name,
        "private_group": private_group,
        "cidr": private_cidr,
        "gateway_ipv4": str(private_gateway_ipv4(network)),
        "same_segment": True,
        "l2_segment": True,
        "controlled_router": False,
        "labels": labels,
        "create_argv": create_argv,
    }


def _prepare_live_private_network(
    *,
    provider: str,
    exposure: str,
    role: str,
    private_group: str,
    endpoint_id: str,
    private_cidr: str,
    requested_private_ip: str | None,
    env: Mapping[str, str],
    docker_command: str,
    command_runner: DockerRunner,
    created_at: str,
) -> dict[str, object]:
    """Create/reuse a private bridge and reserve this endpoint's private address."""

    if exposure != EXPOSURE_PRIVATE:
        raise ValueError("live private network setup is only valid for private exposure")
    private_cidr = str(parse_private_cidr(private_cidr))
    private_network = _ensure_live_private_network(
        provider=provider,
        private_group=private_group,
        private_cidr=private_cidr,
        env=env,
        docker_command=docker_command,
        command_runner=command_runner,
        created_at=created_at,
    )
    private_ipv4, ipv4_source = _allocate_live_private_ipv4(
        provider=provider,
        private_group=private_group,
        private_cidr=private_cidr,
        requested_private_ip=requested_private_ip,
    )
    private_mac = deterministic_private_mac(
        private_group=private_group,
        endpoint_id=endpoint_id,
    )
    private_group_record = update_private_group_allocation(
        provider=provider,
        group=private_group,
        endpoint_id=endpoint_id,
        private_ipv4=private_ipv4,
        private_cidr=private_cidr,
        network_resource=private_network,
    )
    allocation_state = _private_allocation_state(
        provider=provider,
        private_group=private_group,
        endpoint_id=endpoint_id,
        private_ipv4=private_ipv4,
        private_mac=private_mac,
        private_cidr=private_cidr,
        private_group_record=private_group_record.to_dict(),
        ipv4_source=ipv4_source,
    )
    private_network = {
        **private_network,
        "allocation_state": allocation_state,
        "allocation": allocation_state,
    }
    network_name = str(private_network["network_name"])
    network_id = str(private_network["network_id"])
    network_resource = docker_network_resource(
        network_id,
        name=network_name,
        private_group=private_group,
        cidr=private_cidr,
        metadata=private_network,
    )
    network_args = [
        "--network",
        network_name,
        "--ip",
        private_ipv4,
        "--mac-address",
        private_mac,
    ]
    planned_interface = _private_interface(
        network_name=network_name,
        private_group=private_group,
        private_cidr=private_cidr,
        private_ipv4=private_ipv4,
        private_mac=private_mac,
        ipv4_source=ipv4_source,
        requested_private_ip=requested_private_ip,
    )
    extra_metadata = {
        "private": private_network,
        "private_network": private_network,
        "private_group": private_group,
        "private_group_record": private_group_record.to_dict(),
        "private_ip": private_ipv4,
        "private_ip_source": ipv4_source,
        "private_mac": private_mac,
        "allocation_state": allocation_state,
        "docker": {
            "private_network": private_network,
            "private_allocation": allocation_state,
        },
    }
    _ = role
    return {
        "network_name": network_name,
        "network_id": network_id,
        "network_args": network_args,
        "network_resources": [network_resource],
        "planned_interfaces": [planned_interface],
        "private_network": private_network,
        "private_group_record": private_group_record.to_dict(),
        "allocation_state": allocation_state,
        "private_ipv4": private_ipv4,
        "private_mac": private_mac,
        "extra_metadata": extra_metadata,
    }


def _ensure_live_private_network(
    *,
    provider: str,
    private_group: str,
    private_cidr: str,
    env: Mapping[str, str],
    docker_command: str,
    command_runner: DockerRunner,
    created_at: str,
) -> dict[str, object]:
    """Create or reuse the internal Docker bridge for one private group."""

    private_cidr = str(parse_private_cidr(private_cidr))
    _validate_private_group_record(
        provider=provider,
        private_group=private_group,
        private_cidr=private_cidr,
    )
    network_name = docker_private_network_name(private_group)
    labels = _private_network_labels(
        provider=provider,
        private_group=private_group,
        created_at=created_at,
    )
    inspect_argv = docker_argv(
        "network",
        "inspect",
        network_name,
        docker_command=docker_command,
    )
    create_argv = docker_argv(
        "network",
        "create",
        "--driver",
        "bridge",
        "--internal",
        "--subnet",
        private_cidr,
        *docker_label_args(labels),
        network_name,
        docker_command=docker_command,
    )

    inspect_result = command_runner(
        inspect_argv,
        env=env,
        timeout=DOCKER_NETWORK_INSPECT_TIMEOUT,
    )
    created = False
    if not inspect_result.ok:
        _run_docker(
            create_argv,
            runner=command_runner,
            env=env,
            timeout=DOCKER_NETWORK_CREATE_TIMEOUT,
        )
        created = True
        inspect_result = _run_docker(
            inspect_argv,
            runner=command_runner,
            env=env,
            timeout=DOCKER_NETWORK_INSPECT_TIMEOUT,
        )

    network_record = parse_single_docker_inspect_output(
        inspect_result,
        context=f"Docker network inspect {network_name!r}",
    )
    _validate_live_private_network(
        network_record,
        provider=provider,
        private_group=private_group,
        private_cidr=private_cidr,
        network_name=network_name,
    )
    return _live_private_network_metadata(
        network_record,
        provider=provider,
        private_group=private_group,
        private_cidr=private_cidr,
        network_name=network_name,
        labels=labels,
        created=created,
        inspect_argv=inspect_argv,
        create_argv=create_argv,
    )


def _private_network_labels(
    *,
    provider: str,
    private_group: str,
    created_at: str,
) -> dict[str, str]:
    return docker_labels(
        exposure=EXPOSURE_PRIVATE,
        private_group=private_group,
        created_at=created_at,
        provider=provider,
    )


def _validate_private_group_record(
    *,
    provider: str,
    private_group: str,
    private_cidr: str,
) -> None:
    try:
        record = read_private_group_record(provider, private_group)
    except FileNotFoundError:
        return
    recorded_cidr = str(parse_private_cidr(record.private_cidr))
    if recorded_cidr != private_cidr:
        raise ValueError(
            f"private group {private_group!r} is already recorded with CIDR "
            f"{recorded_cidr}, not {private_cidr}"
        )


def _allocate_live_private_ipv4(
    *,
    provider: str,
    private_group: str,
    private_cidr: str,
    requested_private_ip: str | None,
) -> tuple[str, str]:
    try:
        record = read_private_group_record(provider, private_group)
        allocated_private_ipv4s = record.allocated_private_ipv4s
    except FileNotFoundError:
        allocated_private_ipv4s = []
    private_ipv4 = allocate_private_ipv4(
        private_cidr,
        allocated_private_ipv4s=allocated_private_ipv4s,
        requested_private_ip=requested_private_ip,
    )
    return private_ipv4, "requested" if requested_private_ip is not None else "allocated"


def _validate_live_private_network(
    network_record: Mapping[str, object],
    *,
    provider: str,
    private_group: str,
    private_cidr: str,
    network_name: str,
) -> None:
    actual_name = docker_inspect_name(network_record)
    if actual_name is not None and actual_name != network_name:
        raise RuntimeError(
            f"Docker private network {network_name!r} resolved to unexpected "
            f"network {actual_name!r}"
        )
    driver = network_record.get("Driver")
    if driver != "bridge":
        raise RuntimeError(
            f"Docker private network {network_name!r} must use bridge driver, got {driver!r}"
        )
    if network_record.get("Internal") is not True:
        raise RuntimeError(f"Docker private network {network_name!r} must be internal")

    actual_labels = docker_inspect_labels(network_record)
    required_labels = {
        DOCKER_LABEL_PROVIDER: provider,
        DOCKER_LABEL_MANAGED: DOCKER_MANAGED_LABEL_VALUE,
        DOCKER_LABEL_PRIVATE_GROUP: private_group,
        DOCKER_LABEL_EXPOSURE: EXPOSURE_PRIVATE,
    }
    for key, expected in required_labels.items():
        actual = actual_labels.get(key)
        if actual != expected:
            raise RuntimeError(
                f"Docker private network {network_name!r} has incompatible label "
                f"{key}={actual!r}; expected {expected!r}"
            )

    expected_cidr = str(parse_private_cidr(private_cidr))
    actual_cidrs = _docker_network_subnets(network_record)
    if expected_cidr not in actual_cidrs:
        raise RuntimeError(
            f"Docker private network {network_name!r} has CIDRs {actual_cidrs}, "
            f"not {expected_cidr}"
        )


def _live_private_network_metadata(
    network_record: Mapping[str, object],
    *,
    provider: str,
    private_group: str,
    private_cidr: str,
    network_name: str,
    labels: Mapping[str, object],
    created: bool,
    inspect_argv: Sequence[object],
    create_argv: Sequence[object],
) -> dict[str, object]:
    network_id = docker_inspect_id(network_record) or network_name
    ipam_config = _docker_network_ipam_config(network_record)
    return {
        "planned": False,
        "type": "docker-private-network",
        "provider": provider,
        "driver": "bridge",
        "internal": True,
        "isolation": "internal-bridge",
        "isolated": True,
        "owned_by_provider": True,
        "cleanup": True,
        "shared_private_group": True,
        "remove_when_unallocated": True,
        "created": created,
        "reused": not created,
        "network_id": network_id,
        "network_name": network_name,
        "private_group": private_group,
        "cidr": private_cidr,
        "private_cidr": private_cidr,
        "gateway_ipv4": _docker_network_gateway(network_record, private_cidr),
        "same_segment": True,
        "l2_segment": True,
        "controlled_router": False,
        "labels": dict(labels),
        "inspect_labels": docker_inspect_labels(network_record),
        "ipam": {"config": ipam_config},
        "subnets": _docker_network_subnets(network_record),
        "inspect_argv": list(inspect_argv),
        "create_argv": list(create_argv),
    }


def _private_allocation_state(
    *,
    provider: str,
    private_group: str,
    endpoint_id: str,
    private_ipv4: str,
    private_mac: str,
    private_cidr: str,
    private_group_record: Mapping[str, object],
    ipv4_source: str,
) -> dict[str, object]:
    return {
        "provider": provider,
        "private_group": private_group,
        "private_cidr": private_cidr,
        "endpoint_id": endpoint_id,
        "private_ipv4": private_ipv4,
        "private_mac": private_mac,
        "private_ipv4_source": ipv4_source,
        "record_path": str(private_group_path(provider, private_group)),
        "record": dict(private_group_record),
        "allocated_endpoint_ids": list(
            _string_list(private_group_record.get("allocated_endpoint_ids", []))
        ),
        "allocated_private_ipv4s": list(
            _string_list(private_group_record.get("allocated_private_ipv4s", []))
        ),
    }


def _docker_network_ipam_config(
    network_record: Mapping[str, object],
) -> list[dict[str, object]]:
    ipam = network_record.get("IPAM")
    if not isinstance(ipam, Mapping):
        return []
    config = ipam.get("Config")
    if not isinstance(config, Sequence) or isinstance(config, (str, bytes)):
        return []
    return [dict(item) for item in config if isinstance(item, Mapping)]


def _docker_network_subnets(network_record: Mapping[str, object]) -> list[str]:
    subnets: list[str] = []
    for item in _docker_network_ipam_config(network_record):
        subnet = item.get("Subnet")
        if not isinstance(subnet, str) or subnet == "":
            continue
        try:
            subnets.append(str(parse_private_cidr(subnet)))
        except ValueError:
            continue
    return subnets


def _docker_network_gateway(
    network_record: Mapping[str, object],
    private_cidr: str,
) -> str:
    expected_cidr = str(parse_private_cidr(private_cidr))
    for item in _docker_network_ipam_config(network_record):
        subnet = item.get("Subnet")
        if not isinstance(subnet, str):
            continue
        try:
            cidr = str(parse_private_cidr(subnet))
        except ValueError:
            continue
        if cidr != expected_cidr:
            continue
        gateway = item.get("Gateway")
        if isinstance(gateway, str) and gateway:
            return gateway
    return str(private_gateway_ipv4(private_cidr))


def _planned_private_ipv4(
    *,
    endpoint_id: str,
    private_group: str,
    private_cidr: str,
    requested_private_ip: str | None,
) -> tuple[str, str]:
    requested = validate_requested_private_ipv4(requested_private_ip, private_cidr)
    if requested is not None:
        return requested, "requested"
    return _deterministic_private_ipv4(
        endpoint_id=endpoint_id,
        private_group=private_group,
        private_cidr=parse_private_cidr(private_cidr),
    ), "deterministic"


def _deterministic_private_ipv4(
    *,
    endpoint_id: str,
    private_group: str,
    private_cidr: IPv4Network,
) -> str:
    first_host = int(private_cidr.network_address) + 1
    last_host = int(private_cidr.broadcast_address) - 1
    gateway = int(private_gateway_ipv4(private_cidr))
    host_slots = last_host - first_host + 1
    usable_slots = host_slots - 1
    if usable_slots <= 0:
        raise ValueError(f"private CIDR {private_cidr} has no endpoint IPv4 addresses")

    digest = sha256(f"{private_group}:{endpoint_id}".encode("utf-8")).digest()
    offset = int.from_bytes(digest[:8], "big") % usable_slots
    gateway_offset = gateway - first_host
    if offset >= gateway_offset:
        offset += 1
    return str(IPv4Address(first_host + offset))


def _private_interface(
    *,
    network_name: str,
    private_group: str,
    private_cidr: str,
    private_ipv4: str,
    private_mac: str,
    ipv4_source: str,
    requested_private_ip: str | None,
) -> NetworkInterface:
    return NetworkInterface(
        name=DOCKER_PRIVATE_INTERFACE,
        exposure=EXPOSURE_PRIVATE,
        ipv4=private_ipv4,
        mac=private_mac,
        provider_network_id=network_name,
        metadata={
            "planned": True,
            "type": "docker-private-bridge",
            "interface": DOCKER_PRIVATE_INTERFACE,
            "network_name": network_name,
            "private_group": private_group,
            "private_cidr": private_cidr,
            "gateway_ipv4": str(private_gateway_ipv4(private_cidr)),
            "same_segment": True,
            "l2_segment": True,
            "provider_mac_known": True,
            "ipv4_source": ipv4_source,
            "requested_private_ip": requested_private_ip,
            "mac_source": "deterministic",
        },
    )


def _requested_lan_network(env: Mapping[str, str]) -> tuple[str, str]:
    raw_value = env.get(DOCKER_LAN_NETWORK_ENV)
    if raw_value is not None and raw_value.strip():
        return raw_value.strip(), "env"
    return DOCKER_DEFAULT_LAN_NETWORK, "default"


def _requested_wan_network(env: Mapping[str, str]) -> tuple[str, str]:
    raw_value = env.get(DOCKER_WAN_NETWORK_ENV)
    if raw_value is not None and raw_value.strip():
        return raw_value.strip(), "env"
    return DOCKER_DEFAULT_WAN_NETWORK, "default"


def _live_configured_nat_l3_network_metadata(
    network_metadata: Mapping[str, object],
) -> dict[str, object]:
    metadata = dict(network_metadata)
    metadata.update(
        {
            "planned": False,
            "created": False,
            "reused": True,
            "owned_by_provider": False,
            "cleanup": False,
        }
    )
    return metadata


def _lan_network_metadata(
    *,
    network_name: str,
    network_source: str,
    docker_command: str,
) -> dict[str, object]:
    inspect_argv = docker_argv(
        "network",
        "inspect",
        network_name,
        docker_command=docker_command,
    )
    return {
        "planned": True,
        "type": "docker-nat-l3-lan-network",
        "mode": "lan",
        "network_id": network_name,
        "network_name": network_name,
        "configured_network": network_name,
        "env": DOCKER_LAN_NETWORK_ENV,
        "default": DOCKER_DEFAULT_LAN_NETWORK,
        "source": network_source,
        "owned_by_provider": False,
        "cleanup": False,
        "backend": "docker-bridge-routing",
        "reachability": "nat-backed-l3-lan",
        "nat": True,
        "nat_backed_l3": True,
        "nat_backed_l3_lan": True,
        "ipv4_unicast": True,
        "l3": True,
        "l2": False,
        "true_lan_l2": False,
        "same_segment": False,
        "same_segment_l2": False,
        "physical_lan_l2": False,
        "link_layer_fidelity": False,
        "arp_injection": False,
        "broadcast": False,
        "controlled_router": False,
        "public_inbound_reachability": False,
        "localhost_ssh_forwarding": True,
        "docker_capabilities": ["NET_RAW"],
        "inspect_argv": inspect_argv,
        "semantics": "NAT-backed L3 reachability from Docker bridge routing to LAN targets",
    }


def _wan_network_metadata(
    *,
    network_name: str,
    network_source: str,
    docker_command: str,
) -> dict[str, object]:
    inspect_argv = docker_argv(
        "network",
        "inspect",
        network_name,
        docker_command=docker_command,
    )
    return {
        "planned": True,
        "type": "docker-nat-l3-wan-network",
        "mode": "wan",
        "network_id": network_name,
        "network_name": network_name,
        "configured_network": network_name,
        "env": DOCKER_WAN_NETWORK_ENV,
        "default": DOCKER_DEFAULT_WAN_NETWORK,
        "source": network_source,
        "owned_by_provider": False,
        "cleanup": False,
        "backend": "docker-bridge-routing",
        "reachability": "nat-backed-l3-egress",
        "nat": True,
        "nat_backed_l3": True,
        "nat_backed_l3_egress": True,
        "internet_egress": True,
        "ipv4_unicast": True,
        "l3": True,
        "l2": False,
        "same_segment": False,
        "same_segment_l2": False,
        "wan_l2": False,
        "link_layer_fidelity": False,
        "broadcast": False,
        "controlled_router": False,
        "public_inbound_reachability": False,
        "localhost_ssh_forwarding": True,
        "docker_capabilities": ["NET_RAW"],
        "inspect_argv": inspect_argv,
        "semantics": "NAT-backed L3 egress from Docker bridge routing to internet targets",
    }


def _lan_interface(*, lan_network: Mapping[str, object]) -> NetworkInterface:
    network_name = str(lan_network["network_name"])
    return NetworkInterface(
        name=DOCKER_LAN_INTERFACE,
        exposure=EXPOSURE_LAN,
        provider_network_id=network_name,
        metadata={
            "planned": True,
            "type": "docker-nat-l3-lan",
            "interface": DOCKER_LAN_INTERFACE,
            "network_name": network_name,
            "network": dict(lan_network),
            "nat_backed_l3": True,
            "nat_backed_l3_lan": True,
            "ipv4_unicast": True,
            "link_layer_send": False,
            "link_layer_capture": False,
            "link_layer_fidelity": False,
            "provider_mac_known": False,
            "broadcast": False,
            "controlled_router": False,
            "public_inbound_reachability": False,
            "true_lan_l2": False,
            "physical_lan_l2": False,
            "arp_injection": False,
        },
    )


def _wan_interface(*, wan_network: Mapping[str, object]) -> NetworkInterface:
    network_name = str(wan_network["network_name"])
    return NetworkInterface(
        name=DOCKER_WAN_INTERFACE,
        exposure=EXPOSURE_WAN,
        provider_network_id=network_name,
        metadata={
            "planned": True,
            "type": "docker-nat-l3-wan",
            "interface": DOCKER_WAN_INTERFACE,
            "network_name": network_name,
            "network": dict(wan_network),
            "nat_backed_l3": True,
            "nat_backed_l3_egress": True,
            "internet_egress": True,
            "ipv4_unicast": True,
            "link_layer_send": False,
            "link_layer_capture": False,
            "link_layer_fidelity": False,
            "provider_mac_known": False,
            "broadcast": False,
            "controlled_router": False,
            "public_inbound_reachability": False,
            "wan_l2": False,
        },
    )


def _container_metadata(
    *,
    container_name: str,
    endpoint_id: str,
    image_tag: str,
    network_name: str,
    private_ipv4: str,
    private_mac: str,
    ssh_port: int,
    labels: Mapping[str, object],
    security: Mapping[str, object],
    docker_command: str,
    authorized_key_source: Path,
) -> dict[str, object]:
    run_argv = docker_argv(
        "run",
        "--detach",
        "--name",
        container_name,
        "--hostname",
        endpoint_id,
        "--network",
        network_name,
        "--ip",
        private_ipv4,
        "--mac-address",
        private_mac,
        "--publish",
        docker_publish_arg(host_port=ssh_port, guest_port=DOCKER_SSH_GUEST_PORT),
        "--cap-drop",
        "ALL",
        "--cap-add",
        "NET_RAW",
        "--cap-add",
        "NET_ADMIN",
        "--security-opt",
        "no-new-privileges",
        "--mount",
        _authorized_key_mount_spec(authorized_key_source),
        *docker_label_args(labels),
        image_tag,
        docker_command=docker_command,
    )
    return {
        "planned": True,
        "type": "docker-container",
        "container_id": None,
        "container_name": container_name,
        "endpoint_id": endpoint_id,
        "image": image_tag,
        "private_network": network_name,
        "private_ipv4": private_ipv4,
        "private_mac": private_mac,
        "ssh": {
            "host": DOCKER_SSH_HOST,
            "host_port": ssh_port,
            "guest_port": DOCKER_SSH_GUEST_PORT,
            "publish": docker_publish_arg(
                host_port=ssh_port,
                guest_port=DOCKER_SSH_GUEST_PORT,
            ),
        },
        "authorized_key": {
            "source": str(authorized_key_source),
            "target": AUTHORIZED_KEY_TARGET,
            "readonly": True,
        },
        "labels": dict(labels),
        "security": dict(security),
        "run_argv": run_argv,
    }


def _nat_l3_container_metadata(
    *,
    container_name: str,
    endpoint_id: str,
    image_tag: str,
    exposure: str,
    network_name: str,
    ssh_port: int,
    labels: Mapping[str, object],
    security: Mapping[str, object],
    docker_command: str,
    authorized_key_source: Path,
) -> dict[str, object]:
    run_argv = docker_argv(
        "run",
        "--detach",
        "--name",
        container_name,
        "--hostname",
        endpoint_id,
        "--network",
        network_name,
        "--publish",
        docker_publish_arg(host_port=ssh_port, guest_port=DOCKER_SSH_GUEST_PORT),
        "--cap-drop",
        "ALL",
        "--cap-add",
        "NET_RAW",
        "--security-opt",
        "no-new-privileges",
        "--mount",
        _authorized_key_mount_spec(authorized_key_source),
        *docker_label_args(labels),
        image_tag,
        docker_command=docker_command,
    )
    return {
        "planned": True,
        "type": "docker-container",
        "container_id": None,
        "container_name": container_name,
        "endpoint_id": endpoint_id,
        "image": image_tag,
        "exposure": exposure,
        "network": network_name,
        "docker_network": network_name,
        "ssh": {
            "host": DOCKER_SSH_HOST,
            "host_port": ssh_port,
            "guest_port": DOCKER_SSH_GUEST_PORT,
            "publish": docker_publish_arg(
                host_port=ssh_port,
                guest_port=DOCKER_SSH_GUEST_PORT,
            ),
            "public_inbound_reachability": False,
        },
        "authorized_key": {
            "source": str(authorized_key_source),
            "target": AUTHORIZED_KEY_TARGET,
            "readonly": True,
        },
        "labels": dict(labels),
        "security": dict(security),
        "run_argv": run_argv,
    }


def _authorized_key_mount_spec(
    authorized_key_source: str | Path,
    *,
    target: str = AUTHORIZED_KEY_TARGET,
) -> str:
    source = Path(authorized_key_source).expanduser().resolve(strict=False)
    if str(source) == "":
        raise ValueError("authorized_key_source must be a non-empty path")
    if not isinstance(target, str) or target == "":
        raise ValueError("target must be a non-empty string")
    return f"type=bind,source={source},target={target},readonly"


def _docker_private_security_flags() -> dict[str, object]:
    return {
        "docker_socket_mounted": False,
        "privileged": False,
        "host_network": False,
        "host_pid": False,
        "broad_host_filesystem_mounts": False,
        "network_mode": "provider-owned-bridge",
        "cap_drop": ["ALL"],
        "cap_add": ["NET_RAW", "NET_ADMIN"],
        "security_opt": ["no-new-privileges"],
        "no_new_privileges": True,
    }


def _docker_nat_l3_security_flags(
    *,
    exposure: str,
    network_name: str,
) -> dict[str, object]:
    return {
        "docker_socket_mounted": False,
        "privileged": False,
        "host_network": False,
        "host_pid": False,
        "broad_host_filesystem_mounts": False,
        "network_mode": "configured-docker-network",
        "network_name": network_name,
        "exposure": exposure,
        "cap_drop": ["ALL"],
        "cap_add": ["NET_RAW"],
        "net_raw_only": True,
        "net_admin": False,
        "security_opt": ["no-new-privileges"],
        "no_new_privileges": True,
        "link_layer_fidelity": False,
        "broadcast": False,
        "controlled_router": False,
        "public_inbound_reachability": False,
    }


def _private_capabilities_metadata(
    *,
    provider: str,
    exposure: str,
    dry_run: bool,
) -> dict[str, object]:
    return {
        "provider": provider,
        "exposure": exposure,
        "dry_run": dry_run,
        "capabilities": list(PRIVATE_CAPABILITIES),
        "ipv4_unicast": True,
        "ipv6_unicast": False,
        "link_layer_send": True,
        "link_layer_capture": True,
        "broadcast": True,
        "provider_mac_known": True,
        "controlled_services": True,
        "controlled_router": False,
        "same_segment_l2": True,
        "same_segment_l3": True,
        "l2": True,
        "l3": True,
        "semantics": "provider-owned Docker bridge with same-segment L2/L3 packet exchange",
    }


def _nat_l3_capabilities_metadata(
    *,
    provider: str,
    exposure: str,
    dry_run: bool,
) -> dict[str, object]:
    if exposure == EXPOSURE_WAN:
        semantics = "NAT-backed L3 egress from Docker bridge routing to internet targets"
        exposure_metadata: dict[str, object] = {
            "nat_backed_l3_egress": True,
            "internet_egress": True,
            "wan_l2": False,
        }
    else:
        semantics = "NAT-backed L3 reachability from Docker bridge routing to LAN targets"
        exposure_metadata = {
            "nat_backed_l3_lan": True,
            "true_lan_l2": False,
            "physical_lan_l2": False,
            "arp_injection": False,
        }
    return {
        "provider": provider,
        "exposure": exposure,
        "dry_run": dry_run,
        "capabilities": list(NAT_L3_CAPABILITIES),
        "ipv4_unicast": True,
        "ipv6_unicast": False,
        "link_layer_send": False,
        "link_layer_capture": False,
        "broadcast": False,
        "provider_mac_known": False,
        "controlled_services": False,
        "controlled_router": False,
        "same_segment_l2": False,
        "same_segment_l3": False,
        "l2": False,
        "l3": True,
        "nat_backed_l3": True,
        "link_layer_fidelity": False,
        "public_inbound_reachability": False,
        "docker_capabilities": ["NET_RAW"],
        "semantics": semantics,
        **exposure_metadata,
    }


def _private_group_record_metadata(
    *,
    provider: str,
    private_group: str,
    private_cidr: str,
    private_network: Mapping[str, object],
    endpoint_id: str,
    private_ipv4: str,
    private_mac: str,
) -> dict[str, object]:
    record = planned_private_group_record(
        provider=provider,
        group=private_group,
        private_cidr=private_cidr,
        network_resource=private_network,
    ).to_dict()
    record["record_path"] = str(private_group_path(provider, private_group))
    record["planned_allocation"] = {
        "endpoint_id": endpoint_id,
        "private_ipv4": private_ipv4,
        "private_mac": private_mac,
    }
    return record


def _artifact_paths(
    *,
    layout: object,
    public_key: Path,
    docker_image: Mapping[str, object],
) -> Sequence[ArtifactPath]:
    paths = [
        ArtifactPath(name="endpoint-state-dir", path=str(getattr(layout, "state_dir"))),
        ArtifactPath(name="endpoint-manifest", path=str(getattr(layout, "manifest_path"))),
        ArtifactPath(name="endpoint-artifact-dir", path=str(getattr(layout, "artifact_dir"))),
        ArtifactPath(name="ssh-private-key", path=str(getattr(layout, "private_key_path"))),
        ArtifactPath(name="ssh-public-key", path=str(public_key)),
        ArtifactPath(name="ssh-known-hosts", path=str(getattr(layout, "known_hosts_path"))),
    ]
    command_log_path = docker_image.get("command_log_path")
    if isinstance(command_log_path, str) and command_log_path:
        paths.append(ArtifactPath(name="docker-image-command-log", path=command_log_path))
    return paths


__all__ = ["create_endpoint"]
