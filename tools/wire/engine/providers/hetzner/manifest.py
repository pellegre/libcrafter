"""Endpoint manifest builders for Hetzner wire operations."""

from __future__ import annotations

from collections.abc import Mapping

from ...model import (
    EndpointManifest,
    EndpointSSHInfo,
    NetworkInterface,
    ProviderResource,
    ProviderResources,
)
from ...state import endpoint_layout, planned_private_group_record, write_endpoint_manifest
from .constants import PLANNED_CREATED_AT
from .resources import _private_endpoint_provider_resources, _wan_provider_resources
from .utils import (
    _network_resource_id,
    _path_component,
    _server_name,
)



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
