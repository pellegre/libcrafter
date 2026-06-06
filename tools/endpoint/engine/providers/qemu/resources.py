"""QEMU provider resource serialization helpers."""

from __future__ import annotations

from collections.abc import Mapping


def cli_output_manifest(manifest: Mapping[str, object]) -> dict[str, object]:
    """Return a CLI-compatible manifest view without changing stored schema."""

    output = dict(manifest)
    provider_resources = output.get("provider_resources")
    if isinstance(provider_resources, Mapping):
        resources = provider_resources.get("resources")
        if isinstance(resources, list):
            output["provider_resources"] = [_compat_provider_resource(item) for item in resources]
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

