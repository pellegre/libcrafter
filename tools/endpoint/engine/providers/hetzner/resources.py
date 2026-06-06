"""Provider resource serialization helpers."""

from __future__ import annotations

from collections.abc import Mapping

from ...model import ProviderResource, ProviderResources



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
        metadata={"created_by": "tools/endpoint", "provider": provider},
    )
