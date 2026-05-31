"""Docker endpoint creation and planning operations."""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from hashlib import sha256
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from ...model import ArtifactPath, EndpointManifest, EndpointSSHInfo, NetworkInterface
from ...process import run_command
from ...registry import validate_request
from ...state import endpoint_layout, planned_private_group_record, private_group_path
from ..vm import public_key_path
from .constants import (
    CONFIRMATION_ERROR,
    DOCKER_DEFAULT_LAN_NETWORK,
    DOCKER_LAN_NETWORK_ENV,
    DOCKER_SSH_GUEST_PORT,
    DOCKER_SSH_HOST,
    DOCKER_SSH_USER,
    EXPOSURE_LAN,
    EXPOSURE_PRIVATE,
    NAT_L3_CAPABILITIES,
    PLANNED_CREATED_AT,
    PRIVATE_CAPABILITIES,
    DockerRunner,
)
from .resources import (
    deterministic_private_mac,
    docker_argv,
    docker_container_name,
    docker_container_resource,
    docker_image_resource,
    docker_label_args,
    docker_labels,
    docker_local_file_resource,
    docker_network_resource,
    docker_private_network_name,
    docker_provider_resources,
    docker_publish_arg,
    free_localhost_tcp_port,
    parse_private_cidr,
    plan_docker_image,
    planned_docker_endpoint_id,
    private_gateway_ipv4,
    requested_docker_command,
    requested_docker_image,
    requested_private_cidr,
    validate_requested_private_ipv4,
)


AUTHORIZED_KEY_TARGET = "/run/libcrafter/authorized_key.pub"
DEFAULT_PRIVATE_GROUP = "default"
DOCKER_PRIVATE_INTERFACE = "eth0"
DOCKER_LAN_INTERFACE = "eth0"


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
        raise NotImplementedError(
            f"docker dry-run create-endpoint is not implemented for {exposure}"
        )

    if not confirm_live_run:
        raise PermissionError(CONFIRMATION_ERROR)
    _ = command_runner
    raise NotImplementedError(
        f"real docker create-endpoint is not implemented for {exposure}"
    )


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
    labels = docker_labels(
        exposure=exposure,
        role=role,
        private_group=private_group,
        created_at=PLANNED_CREATED_AT,
        provider=provider,
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
        "ipv4_unicast": True,
        "l3": True,
        "l2": False,
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
            "ipv4_unicast": True,
            "link_layer_send": False,
            "link_layer_capture": False,
            "link_layer_fidelity": False,
            "provider_mac_known": False,
            "broadcast": False,
            "controlled_router": False,
            "public_inbound_reachability": False,
            "physical_lan_l2": False,
            "arp_injection": False,
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
        (
            "type=bind,"
            f"source={authorized_key_source},"
            f"target={AUTHORIZED_KEY_TARGET},readonly"
        ),
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
        (
            "type=bind,"
            f"source={authorized_key_source},"
            f"target={AUTHORIZED_KEY_TARGET},readonly"
        ),
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
        "physical_lan_l2": False,
        "link_layer_fidelity": False,
        "arp_injection": False,
        "public_inbound_reachability": False,
        "docker_capabilities": ["NET_RAW"],
        "semantics": "NAT-backed L3 reachability from Docker bridge routing to LAN targets",
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
