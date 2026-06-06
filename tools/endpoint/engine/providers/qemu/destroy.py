"""QEMU endpoint destroy operations."""

from __future__ import annotations

import os
import signal
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from pathlib import Path

from ...model import EndpointManifest, ProviderResource
from ...registry import validate_request
from ...state import remove_private_group_allocation, write_endpoint_manifest
from ..vm import utc_now


_DEFAULT_SHUTDOWN_TIMEOUT = 30.0
_DEFAULT_POLL_INTERVAL = 1.0
ProcessSignal = Callable[[int, int], None]


def destroy_endpoint(
    manifest: EndpointManifest,
    *,
    process_signal: ProcessSignal = os.kill,
    shutdown_timeout: float = _DEFAULT_SHUTDOWN_TIMEOUT,
    poll_interval: float = _DEFAULT_POLL_INTERVAL,
) -> dict[str, object]:
    """Destroy tracked QEMU resources for one endpoint manifest.

    QEMU endpoints are local daemonized processes. Local endpoint state,
    artifacts, and pidfiles are preserved so failed destroys remain debuggable
    and idempotent retry has the same manifest context.
    """

    if not isinstance(manifest, EndpointManifest):
        raise TypeError("manifest must be an EndpointManifest")
    if manifest.provider != "qemu":
        raise ValueError(f"manifest provider must be 'qemu': {manifest.provider!r}")
    validate_request(manifest.provider, manifest.exposure)

    resources = _cleanup_resources(manifest)
    if manifest.status == "destroyed":
        return _destroy_output(
            manifest=manifest,
            actions=[],
            destroyed=False,
            already_destroyed=True,
            skipped=[
                _destroy_action(resource, action="skip", reason="endpoint already destroyed")
                for resource in resources
            ],
        )

    actions: list[dict[str, object]] = []
    skipped: list[dict[str, object]] = []
    process_resource = _process_resource(resources)
    vm_resource = _qemu_vm_resource(resources)
    was_never_created = _manifest_was_never_created(manifest)
    private_group_update: dict[str, object] | None = None

    if was_never_created:
        skipped.extend(
            _destroy_action(
                resource,
                action="skip",
                reason="endpoint was planned only; no QEMU process was created",
            )
            for resource in resources
            if _normalized_resource_kind(resource.kind) in {"process", "qemu-vm"}
        )
    elif process_resource is None:
        skipped.append(
            {
                "action": "skip",
                "kind": "process",
                "provider_id": None,
                "name": None,
                "reason": "manifest does not track a QEMU process resource",
            }
        )
    else:
        _destroy_qemu_process(
            manifest,
            process_resource,
            actions=actions,
            skipped=skipped,
            process_signal=process_signal,
            shutdown_timeout=shutdown_timeout,
            poll_interval=poll_interval,
        )

    if vm_resource is not None and not was_never_created:
        skipped.append(
            _destroy_action(
                vm_resource,
                action="skip",
                reason="QEMU VM cleanup is handled by the tracked host process",
            )
        )

    private_destroy = _private_destroy_context(manifest)
    if private_destroy is not None and not was_never_created:
        private_group_update = _remove_private_endpoint_from_group(manifest, private_destroy)
        actions.append(
            {
                "action": "remove-private-allocation",
                "kind": "private-group",
                "provider_id": private_destroy["private_group"],
                "name": private_destroy["private_group"],
                "private_ip": private_destroy.get("private_ipv4"),
                "record_found": private_group_update["record_found"],
                "remaining_endpoints": private_group_update["remaining_endpoints"],
            }
        )

    skipped.extend(_preserved_local_resource_skips(resources))

    destroyed_at = utc_now()
    destroyed_manifest = replace(
        manifest,
        status="destroyed",
        metadata={
            **manifest.metadata,
            "destroyed_at": destroyed_at,
            "destroy": {
                "provider": "qemu",
                "actions": actions,
                "skipped": skipped,
            },
            "qemu": {
                **_qemu_metadata(manifest),
                "process_running": False,
                "destroyed_at": destroyed_at,
            },
            **(
                {"private_group_destroy": private_group_update}
                if private_group_update is not None
                else {}
            ),
        },
    )
    manifest_path = write_endpoint_manifest(destroyed_manifest)
    output = _destroy_output(
        manifest=destroyed_manifest,
        actions=actions,
        destroyed=True,
        already_destroyed=False,
        skipped=skipped,
    )
    output["manifest_path"] = str(manifest_path)
    output["state_dir"] = str(manifest_path.parent)
    return output


def _destroy_qemu_process(
    manifest: EndpointManifest,
    resource: ProviderResource,
    *,
    actions: list[dict[str, object]],
    skipped: list[dict[str, object]],
    process_signal: ProcessSignal,
    shutdown_timeout: float,
    poll_interval: float,
) -> None:
    pidfile_path = _pidfile_path(manifest, resource)
    if pidfile_path is None:
        skipped.append(
            _destroy_action(
                resource,
                action="skip",
                reason="manifest does not track a QEMU pidfile",
            )
        )
        return
    pid = _read_pidfile(pidfile_path)
    if pid is None:
        skipped.append(
            _destroy_action(
                resource,
                action="skip",
                reason=f"QEMU pidfile is missing or invalid: {pidfile_path}",
            )
        )
        return

    if not _process_exists(pid, process_signal=process_signal):
        actions.append(
            _destroy_action(
                resource,
                action="already-stopped",
                reason="QEMU process was already stopped",
                pid=pid,
            )
        )
        return

    _send_signal(pid, signal.SIGTERM, process_signal=process_signal)
    actions.append(_destroy_action(resource, action="terminate", pid=pid, signal_name="SIGTERM"))
    if _wait_for_process_exit(
        pid,
        process_signal=process_signal,
        timeout_seconds=shutdown_timeout,
        poll_interval=poll_interval,
    ):
        return

    _send_signal(pid, signal.SIGKILL, process_signal=process_signal)
    actions.append(_destroy_action(resource, action="kill", pid=pid, signal_name="SIGKILL"))
    if _wait_for_process_exit(
        pid,
        process_signal=process_signal,
        timeout_seconds=max(poll_interval, 0.0),
        poll_interval=poll_interval,
    ):
        return
    raise RuntimeError(f"QEMU process {pid} did not stop after SIGKILL")


def _cleanup_resources(manifest: EndpointManifest) -> list[ProviderResource]:
    resources = [
        resource for resource in manifest.provider_resources.resources if resource.cleanup
    ]
    cleanup_order = manifest.provider_resources.cleanup_order
    if not cleanup_order:
        return resources
    order = {_normalized_resource_kind(kind): index for index, kind in enumerate(cleanup_order)}
    return sorted(
        resources,
        key=lambda resource: (order.get(_normalized_resource_kind(resource.kind), len(order)),),
    )


def _process_resource(resources: Sequence[ProviderResource]) -> ProviderResource | None:
    for resource in resources:
        if _normalized_resource_kind(resource.kind) == "process":
            return resource
    return None


def _qemu_vm_resource(resources: Sequence[ProviderResource]) -> ProviderResource | None:
    for resource in resources:
        if _normalized_resource_kind(resource.kind) == "qemu-vm":
            return resource
    return None


def _preserved_local_resource_skips(
    resources: Sequence[ProviderResource],
) -> list[dict[str, object]]:
    return [
        _destroy_action(
            resource,
            action="skip",
            reason="local endpoint state and artifacts are preserved",
        )
        for resource in resources
        if _normalized_resource_kind(resource.kind) in {"local-file", "network"}
    ]


def _manifest_was_never_created(manifest: EndpointManifest) -> bool:
    metadata = manifest.metadata
    if manifest.status == "planned" or metadata.get("dry_run") is True:
        return True
    if metadata.get("created") is False:
        return True
    qemu_metadata = _qemu_metadata(manifest)
    if qemu_metadata.get("pid") is None and qemu_metadata.get("daemonize") is not True:
        return True
    return False


def _pidfile_path(manifest: EndpointManifest, resource: ProviderResource) -> Path | None:
    qemu_metadata = _qemu_metadata(manifest)
    for value in (
        qemu_metadata.get("pidfile_path"),
        qemu_metadata.get("pidfile"),
        resource.metadata.get("pidfile"),
    ):
        if isinstance(value, str) and value:
            return Path(value)
    return None


def _read_pidfile(path: Path) -> int | None:
    try:
        text = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    if text == "":
        return None
    try:
        pid = int(text, 10)
    except ValueError:
        return None
    return pid if pid > 0 else None


def _process_exists(pid: int, *, process_signal: ProcessSignal) -> bool:
    try:
        process_signal(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _send_signal(pid: int, signal_value: signal.Signals, *, process_signal: ProcessSignal) -> None:
    try:
        process_signal(pid, int(signal_value))
    except ProcessLookupError:
        return
    except PermissionError as exc:
        raise RuntimeError(f"permission denied while signaling QEMU process {pid}") from exc


def _wait_for_process_exit(
    pid: int,
    *,
    process_signal: ProcessSignal,
    timeout_seconds: float,
    poll_interval: float,
) -> bool:
    deadline = time.monotonic() + max(0.0, float(timeout_seconds))
    interval = max(0.0, float(poll_interval))
    while time.monotonic() <= deadline:
        if not _process_exists(pid, process_signal=process_signal):
            return True
        if interval <= 0:
            return False
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(interval, remaining))
    return not _process_exists(pid, process_signal=process_signal)


def _private_destroy_context(manifest: EndpointManifest) -> dict[str, object] | None:
    if manifest.exposure != "private":
        return None
    private_group = _private_group_from_manifest(manifest)
    if private_group is None:
        return None
    return {
        "private_group": private_group,
        "private_ipv4": _private_ipv4_from_manifest(manifest),
    }


def _remove_private_endpoint_from_group(
    manifest: EndpointManifest,
    private_destroy: Mapping[str, object],
) -> dict[str, object]:
    private_group = private_destroy.get("private_group")
    if not isinstance(private_group, str):
        raise RuntimeError("private endpoint destroy requires a private group")
    private_ipv4 = private_destroy.get("private_ipv4")
    if not isinstance(private_ipv4, str):
        private_ipv4 = None

    try:
        updated = remove_private_group_allocation(
            provider=manifest.provider,
            group=private_group,
            endpoint_id=manifest.endpoint_id,
            private_ipv4=private_ipv4,
        )
    except FileNotFoundError:
        return {
            "private_group": private_group,
            "record_found": False,
            "remaining_endpoints": [],
        }

    return {
        "private_group": private_group,
        "record_found": True,
        "remaining_endpoints": updated.allocated_endpoint_ids,
        "private_group_record": updated.to_dict(),
    }


def _private_group_from_manifest(manifest: EndpointManifest) -> str | None:
    metadata_group = manifest.metadata.get("private_group")
    if isinstance(metadata_group, str) and metadata_group:
        return metadata_group
    private_metadata = manifest.metadata.get("private")
    if isinstance(private_metadata, Mapping):
        private_group = private_metadata.get("private_group")
        if isinstance(private_group, str) and private_group:
            return private_group
    qemu_metadata = _qemu_metadata(manifest)
    private_group = qemu_metadata.get("private_group")
    if isinstance(private_group, str) and private_group:
        return private_group
    for interface in manifest.interfaces:
        private_group = interface.metadata.get("private_group")
        if isinstance(private_group, str) and private_group:
            return private_group
    return None


def _private_ipv4_from_manifest(manifest: EndpointManifest) -> str | None:
    metadata_ip = manifest.metadata.get("private_ip")
    if isinstance(metadata_ip, str) and metadata_ip:
        return metadata_ip
    private_metadata = manifest.metadata.get("private")
    if isinstance(private_metadata, Mapping):
        private_ip = private_metadata.get("private_ip")
        if isinstance(private_ip, str) and private_ip:
            return private_ip
    qemu_metadata = _qemu_metadata(manifest)
    private_ip = qemu_metadata.get("private_ip")
    if isinstance(private_ip, str) and private_ip:
        return private_ip
    for interface in manifest.interfaces:
        if interface.exposure == "private" and interface.ipv4 is not None:
            return interface.ipv4
    return None


def _qemu_metadata(manifest: EndpointManifest) -> dict[str, object]:
    value = manifest.metadata.get("qemu")
    return dict(value) if isinstance(value, Mapping) else {}


def _destroy_action(
    resource: ProviderResource,
    *,
    action: str,
    reason: str | None = None,
    pid: int | None = None,
    signal_name: str | None = None,
) -> dict[str, object]:
    output: dict[str, object] = {
        "action": action,
        "kind": resource.kind,
        "provider_id": resource.provider_id,
        "name": resource.name,
    }
    if reason is not None:
        output["reason"] = reason
    if pid is not None:
        output["pid"] = pid
    if signal_name is not None:
        output["signal"] = signal_name
    return output


def _destroy_output(
    *,
    manifest: EndpointManifest,
    actions: list[dict[str, object]],
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
        "actions": actions,
        "skipped": skipped,
        "artifact_dir": manifest.artifact_dir,
        "manifest_path": manifest.metadata.get("manifest_path"),
        "state_dir": manifest.metadata.get("state_dir"),
    }


def _normalized_resource_kind(kind: str) -> str:
    return kind.replace("_", "-")
