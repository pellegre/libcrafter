"""QEMU endpoint creation and planning operations."""

from __future__ import annotations

import os
from collections.abc import Mapping

from ...model import EndpointManifest, EndpointSSHInfo, NetworkInterface
from ...registry import validate_request
from ...state import endpoint_layout, planned_private_group_record
from ..vm import (
    file_resource,
    free_localhost_tcp_port,
    path_component,
    plan_guest_artifacts,
    provider_resources,
    short_provider_resource_name,
    vm_resource,
)
from .constants import (
    CONFIRMATION_ERROR,
    PLANNED_CREATED_AT,
    QEMU_ACCEL_ENV,
    QEMU_DEFAULT_ACCEL,
    QEMU_SSH_GUEST_PORT,
    QEMU_SSH_HOST,
    QEMU_SSH_USER,
    QEMU_SYSTEM_COMMAND,
    SUPPORTED_QEMU_ACCELS,
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
) -> dict[str, object]:
    """Create or plan one QEMU endpoint."""

    validate_request(provider, exposure)
    _validate_create_request(exposure, role, private_group, private_ip)

    if dry_run:
        return _planned_endpoint_manifest(
            provider=provider,
            exposure=exposure,
            role=role,
            private_group=private_group,
            private_ip=private_ip,
            env=os.environ if env is None else env,
        )

    if not confirm_live_run:
        raise PermissionError(CONFIRMATION_ERROR)
    raise NotImplementedError("real qemu create-endpoint is not implemented yet")


def _planned_endpoint_manifest(
    *,
    provider: str,
    exposure: str,
    role: str,
    private_group: str | None,
    private_ip: str | None,
    env: Mapping[str, str],
) -> dict[str, object]:
    endpoint_id = _planned_endpoint_id(
        provider=provider,
        exposure=exposure,
        role=role,
        private_group=private_group,
    )
    layout = endpoint_layout(endpoint_id)
    artifacts = plan_guest_artifacts(
        endpoint_id=endpoint_id,
        provider=provider,
        layout=layout,
        disk_format="qcow2",
        env=env,
        include_network_config=exposure == "private",
    )
    acceleration = _requested_acceleration(env)
    vm_name = short_provider_resource_name("wire", endpoint_id, max_length=63)
    ssh_port = free_localhost_tcp_port()
    interfaces = _planned_interfaces(
        exposure=exposure,
        ssh_port=ssh_port,
        private_group=private_group,
        private_ip=private_ip,
    )
    qemu_metadata = _qemu_metadata(
        exposure=exposure,
        vm_name=vm_name,
        ssh_port=ssh_port,
        acceleration=acceleration,
        private_group=private_group,
        private_ip=private_ip,
    )
    metadata: dict[str, object] = {
        "created": False,
        "dry_run": True,
        "state_dir": str(layout.state_dir),
        "manifest_path": str(layout.manifest_path),
        "qemu": qemu_metadata,
        **artifacts.to_manifest_metadata(),
    }
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
        if private_ip is not None:
            metadata["private_ip"] = private_ip

    manifest = EndpointManifest(
        endpoint_id=endpoint_id,
        provider=provider,
        exposure=exposure,
        status="planned",
        role=role,
        created_at=PLANNED_CREATED_AT,
        ssh=EndpointSSHInfo(
            host=QEMU_SSH_HOST,
            user=QEMU_SSH_USER,
            port=ssh_port,
            identity_file=str(layout.private_key_path),
            known_hosts_file=str(layout.known_hosts_path),
            metadata={
                "planned": True,
                "transport": "qemu-user-net-hostfwd",
                "control_interface": "user-control",
                "acceleration": acceleration,
            },
        ),
        interfaces=interfaces,
        provider_resources=provider_resources(
            [
                vm_resource(
                    vm_name,
                    kind="qemu-vm",
                    metadata={
                        "planned": True,
                        "provider": provider,
                        "exposure": exposure,
                        "acceleration": acceleration,
                    },
                ),
                *artifacts.file_resources(include_cache=True),
                file_resource(layout.private_key_path, name="ssh-private-key"),
                file_resource(layout.known_hosts_path, name="ssh-known-hosts"),
            ],
            cleanup_order=["qemu-vm", "process", "local-file"],
            metadata={
                "provider": provider,
                "exposure": exposure,
                "planned": True,
            },
        ),
        artifact_dir=str(layout.artifact_dir),
        metadata=metadata,
    )
    output = manifest.to_dict()
    output["metadata"]["artifact_paths"] = manifest.artifact_paths(  # type: ignore[index]
        artifacts.artifact_paths()
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
    return "-".join(path_component(part) for part in parts)


def _requested_acceleration(env: Mapping[str, str]) -> str:
    acceleration = (env.get(QEMU_ACCEL_ENV) or QEMU_DEFAULT_ACCEL).strip().lower()
    if not acceleration:
        acceleration = QEMU_DEFAULT_ACCEL
    if acceleration not in SUPPORTED_QEMU_ACCELS:
        raise ValueError(
            f"{QEMU_ACCEL_ENV}={acceleration!r} is unsupported; "
            f"supported values: {', '.join(sorted(SUPPORTED_QEMU_ACCELS))}"
        )
    return acceleration


def _planned_interfaces(
    *,
    exposure: str,
    ssh_port: int,
    private_group: str | None,
    private_ip: str | None,
) -> list[NetworkInterface]:
    control = NetworkInterface(
        name="user-control",
        exposure="control",
        metadata={
            "planned": True,
            "type": "qemu-user-net-control",
            "network": "user",
            "netdev": "control0",
            "host": QEMU_SSH_HOST,
            "host_port": ssh_port,
            "guest_port": QEMU_SSH_GUEST_PORT,
        },
    )
    if exposure == "wan":
        return [
            control,
            NetworkInterface(
                name="wan",
                exposure="wan",
                metadata={
                    "planned": True,
                    "type": "qemu-user-net",
                    "network": "user",
                    "netdev": "control0",
                    "outbound_nat": True,
                    "host_forwarded_ssh": True,
                },
            ),
        ]
    return [
        control,
        NetworkInterface(
            name="private",
            exposure="private",
            ipv4=private_ip,
            provider_network_id=_planned_private_network_id(private_group),
            metadata={
                "planned": True,
                "type": "qemu-private-net",
                "network": "isolated",
                "backend": "socket",
                "netdev": "private0",
                "private_group": private_group,
                "private_ip": private_ip,
            },
        ),
    ]


def _qemu_metadata(
    *,
    exposure: str,
    vm_name: str,
    ssh_port: int,
    acceleration: str,
    private_group: str | None,
    private_ip: str | None,
) -> dict[str, object]:
    metadata: dict[str, object] = {
        "command": QEMU_SYSTEM_COMMAND,
        "vm_name": vm_name,
        "acceleration": acceleration,
        "ssh_host": QEMU_SSH_HOST,
        "ssh_port": ssh_port,
        "control_netdev": "control0",
        "network": {
            "exposure": exposure,
            "control": {
                "type": "user",
                "host_forward": f"tcp:{QEMU_SSH_HOST}:{ssh_port}-:{QEMU_SSH_GUEST_PORT}",
            },
        },
    }
    if exposure == "private":
        metadata["private_group"] = private_group
        metadata["private_ip"] = private_ip
        network = metadata["network"]
        if isinstance(network, dict):
            network["private"] = _planned_private_metadata(private_group, private_ip)
    return metadata


def _planned_private_network_id(private_group: str | None) -> str:
    suffix = path_component(private_group) if private_group is not None else "ungrouped"
    return f"qemu-private-group-{suffix}"


def _planned_private_metadata(
    private_group: str | None,
    private_ip: str | None,
) -> dict[str, object]:
    metadata: dict[str, object] = {
        "planned": True,
        "provider": "qemu",
        "network_id": _planned_private_network_id(private_group),
        "backend": "socket",
        "netdev": "private0",
    }
    if private_group is not None:
        metadata["private_group"] = private_group
        metadata["network_name"] = f"wire-qemu-{path_component(private_group)}"
    if private_ip is not None:
        metadata["private_ip"] = private_ip
        metadata["ipv4"] = private_ip
    return metadata

