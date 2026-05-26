"""VirtualBox endpoint creation and planning operations."""

from __future__ import annotations

import os
from collections.abc import Mapping

from ...model import EndpointManifest, EndpointSSHInfo, NetworkInterface
from ...registry import validate_request
from ...state import endpoint_layout
from ..vm import (
    file_resource,
    free_localhost_tcp_port,
    path_component,
    plan_guest_artifacts,
    provider_resources,
    short_provider_resource_name,
    vm_resource,
)
from .bridge import planned_bridge_interface
from .constants import CONFIRMATION_ERROR, PLANNED_CREATED_AT, VBOXMANAGE_COMMAND


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
    """Create or plan one VirtualBox endpoint."""

    validate_request(provider, exposure)
    _validate_create_request(role, private_group, private_ip)

    if dry_run:
        return _planned_endpoint_manifest(
            provider=provider,
            exposure=exposure,
            role=role,
            env=os.environ if env is None else env,
        )

    if not confirm_live_run:
        raise PermissionError(CONFIRMATION_ERROR)
    raise NotImplementedError("real virtualbox create-endpoint is not implemented yet")


def _planned_endpoint_manifest(
    *,
    provider: str,
    exposure: str,
    role: str,
    env: Mapping[str, str],
) -> dict[str, object]:
    endpoint_id = _planned_endpoint_id(provider=provider, exposure=exposure, role=role)
    layout = endpoint_layout(endpoint_id)
    artifacts = plan_guest_artifacts(
        endpoint_id=endpoint_id,
        provider=provider,
        layout=layout,
        disk_format="vdi",
        env=env,
        include_network_config=True,
    )
    bridge = planned_bridge_interface(env)
    vm_name = short_provider_resource_name("wire", endpoint_id, max_length=80)
    ssh_port = free_localhost_tcp_port()
    manifest = EndpointManifest(
        endpoint_id=endpoint_id,
        provider=provider,
        exposure=exposure,
        status="planned",
        role=role,
        created_at=PLANNED_CREATED_AT,
        ssh=EndpointSSHInfo(
            host="127.0.0.1",
            user="root",
            port=ssh_port,
            identity_file=str(layout.private_key_path),
            known_hosts_file=str(layout.known_hosts_path),
            metadata={
                "planned": True,
                "transport": "virtualbox-nat-port-forward",
                "control_interface": "nat-control",
            },
        ),
        interfaces=[
            NetworkInterface(
                name="nat-control",
                exposure="control",
                metadata={
                    "planned": True,
                    "type": "nat-control",
                    "adapter": 1,
                    "network": "nat",
                    "host": "127.0.0.1",
                    "host_port": ssh_port,
                    "guest_port": 22,
                },
            ),
            NetworkInterface(
                name="lan",
                exposure="lan",
                metadata={
                    "planned": True,
                    "type": "bridged-lan",
                    "adapter": 2,
                    "bridge_interface": bridge["name"],
                    "bridge_selection": bridge["selection"],
                    "bridge_env": bridge["env"],
                    "bridge_validated": bridge["validated"],
                },
            ),
        ],
        provider_resources=provider_resources(
            [
                vm_resource(
                    vm_name,
                    kind="virtualbox-vm",
                    metadata={
                        "planned": True,
                        "provider": provider,
                        "exposure": exposure,
                    },
                ),
                *artifacts.file_resources(include_cache=True),
                file_resource(layout.private_key_path, name="ssh-private-key"),
                file_resource(layout.known_hosts_path, name="ssh-known-hosts"),
            ],
            cleanup_order=["virtualbox-vm", "local-file"],
            metadata={
                "provider": provider,
                "exposure": exposure,
                "planned": True,
            },
        ),
        artifact_dir=str(layout.artifact_dir),
        metadata={
            "created": False,
            "dry_run": True,
            "state_dir": str(layout.state_dir),
            "manifest_path": str(layout.manifest_path),
            "virtualbox": {
                "command": VBOXMANAGE_COMMAND,
                "vm_name": vm_name,
                "nat_adapter": 1,
                "lan_adapter": 2,
                "ssh_host": "127.0.0.1",
                "ssh_port": ssh_port,
                "bridge_interface": bridge["name"],
                "bridge_selection": bridge["selection"],
                "bridge_env": bridge["env"],
            },
            **artifacts.to_manifest_metadata(),
        },
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
    if private_group is not None:
        raise ValueError("--private-group is not valid with provider virtualbox exposure lan")
    if private_ip is not None:
        raise ValueError("--private-ip is not valid with provider virtualbox exposure lan")


def _planned_endpoint_id(*, provider: str, exposure: str, role: str) -> str:
    return "-".join(path_component(part) for part in ("planned", provider, exposure, role))
