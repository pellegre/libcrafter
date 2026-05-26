"""VirtualBox endpoint destroy operations."""

from __future__ import annotations

from ...model import EndpointManifest
from ...registry import validate_request
from ...state import update_endpoint_status


def destroy_endpoint(manifest: EndpointManifest) -> dict[str, object]:
    """Mark a planned VirtualBox endpoint destroyed.

    Live VM cleanup is added in a later step; this handles manifests produced
    by the dry-run path if callers choose to persist and destroy them.
    """

    if not isinstance(manifest, EndpointManifest):
        raise TypeError("manifest must be an EndpointManifest")
    validate_request(manifest.provider, manifest.exposure)
    if manifest.provider != "virtualbox":
        raise ValueError(f"manifest provider must be 'virtualbox': {manifest.provider!r}")

    updated = update_endpoint_status(manifest.endpoint_id, "destroyed")
    return {
        "endpoint_id": updated.endpoint_id,
        "provider": updated.provider,
        "exposure": updated.exposure,
        "status": updated.status,
        "destroyed": True,
        "ok": True,
        "manifest_path": updated.metadata.get("manifest_path"),
        "artifact_dir": updated.artifact_dir,
    }

