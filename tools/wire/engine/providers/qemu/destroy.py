"""QEMU endpoint destroy operations."""

from __future__ import annotations

from dataclasses import replace

from ...model import EndpointManifest
from ...registry import validate_request
from ...state import write_endpoint_manifest
from ..vm import utc_now


def destroy_endpoint(manifest: EndpointManifest) -> dict[str, object]:
    """Destroy one tracked QEMU endpoint manifest.

    Step 10 only supports dry-run/planned QEMU endpoints, so there are no live
    QEMU processes to terminate here.
    """

    if not isinstance(manifest, EndpointManifest):
        raise TypeError("manifest must be an EndpointManifest")
    if manifest.provider != "qemu":
        raise ValueError(f"manifest provider must be 'qemu': {manifest.provider!r}")
    validate_request(manifest.provider, manifest.exposure)

    if manifest.status == "destroyed":
        return _destroy_output(
            manifest=manifest,
            destroyed=False,
            already_destroyed=True,
            skipped=[
                {
                    "action": "skip",
                    "kind": resource.kind,
                    "provider_id": resource.provider_id,
                    "name": resource.name,
                    "reason": "endpoint already destroyed",
                }
                for resource in manifest.provider_resources.resources
                if resource.cleanup
            ],
        )

    if not _manifest_was_never_created(manifest):
        raise RuntimeError("live qemu destroy-endpoint is not implemented yet")

    skipped = [
        {
            "action": "skip",
            "kind": resource.kind,
            "provider_id": resource.provider_id,
            "name": resource.name,
            "reason": "endpoint was planned only; no QEMU resource was created",
        }
        for resource in manifest.provider_resources.resources
        if resource.cleanup
    ]
    destroyed_at = utc_now()
    destroyed_manifest = replace(
        manifest,
        status="destroyed",
        metadata={
            **manifest.metadata,
            "destroyed_at": destroyed_at,
            "destroy": {
                "provider": "qemu",
                "actions": [],
                "skipped": skipped,
            },
            "qemu": {
                **_qemu_metadata(manifest),
                "destroyed_at": destroyed_at,
            },
        },
    )
    manifest_path = write_endpoint_manifest(destroyed_manifest)
    output = _destroy_output(
        manifest=destroyed_manifest,
        destroyed=True,
        already_destroyed=False,
        skipped=skipped,
    )
    output["manifest_path"] = str(manifest_path)
    output["state_dir"] = str(manifest_path.parent)
    return output


def _destroy_output(
    *,
    manifest: EndpointManifest,
    destroyed: bool,
    already_destroyed: bool,
    skipped: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "endpoint_id": manifest.endpoint_id,
        "provider": manifest.provider,
        "exposure": manifest.exposure,
        "status": manifest.status,
        "destroyed": destroyed,
        "already_destroyed": already_destroyed,
        "ok": True,
        "actions": [],
        "skipped": skipped,
        "artifact_dir": manifest.artifact_dir,
        "manifest_path": manifest.metadata.get("manifest_path"),
        "state_dir": manifest.metadata.get("state_dir"),
    }


def _manifest_was_never_created(manifest: EndpointManifest) -> bool:
    if manifest.status == "planned" or manifest.metadata.get("dry_run") is True:
        return True
    if manifest.metadata.get("created") is False:
        return True
    return False


def _qemu_metadata(manifest: EndpointManifest) -> dict[str, object]:
    value = manifest.metadata.get("qemu")
    return dict(value) if isinstance(value, dict) else {}
