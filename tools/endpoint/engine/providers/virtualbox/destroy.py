"""VirtualBox endpoint destroy operations."""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from dataclasses import replace

from ...model import EndpointManifest, ProviderResource
from ...process import CommandResult, run_command
from ...registry import validate_request
from ...state import remove_private_group_allocation, write_endpoint_manifest
from ..vm import command_error, utc_now
from .constants import VBOXMANAGE_COMMAND, VirtualBoxRunner


_TERMINAL_VM_STATES = frozenset({"aborted", "poweroff", "saved", "teleported"})
_ACPI_VM_STATES = frozenset({"running"})
_DEFAULT_SHUTDOWN_TIMEOUT = 30.0
_DEFAULT_POLL_INTERVAL = 1.0


def destroy_endpoint(
    manifest: EndpointManifest,
    *,
    command_runner: VirtualBoxRunner = run_command,
    shutdown_timeout: float = _DEFAULT_SHUTDOWN_TIMEOUT,
    poll_interval: float = _DEFAULT_POLL_INTERVAL,
) -> dict[str, object]:
    """Destroy tracked VirtualBox resources for one endpoint."""

    if not isinstance(manifest, EndpointManifest):
        raise TypeError("manifest must be an EndpointManifest")
    if manifest.provider != "virtualbox":
        raise ValueError(f"manifest provider must be 'virtualbox': {manifest.provider!r}")
    validate_request(manifest.provider, manifest.exposure)

    resources = _cleanup_resources(manifest)
    if manifest.status == "destroyed":
        return _destroy_output(
            manifest=manifest,
            actions=[],
            skipped=[
                _destroy_action(resource, action="skip", reason="endpoint already destroyed")
                for resource in resources
            ],
            destroyed=False,
            already_destroyed=True,
        )

    actions: list[dict[str, object]] = []
    skipped: list[dict[str, object]] = []
    vm_resource = _virtualbox_vm_resource(resources)
    was_never_created = _manifest_was_never_created(manifest)
    private_group_update: dict[str, object] | None = None

    if vm_resource is None:
        skipped.append(
            {
                "action": "skip",
                "kind": "virtualbox-vm",
                "provider_id": None,
                "name": None,
                "reason": "manifest does not track a VirtualBox VM resource",
            }
        )
    elif was_never_created:
        skipped.append(
            _destroy_action(
                vm_resource,
                action="skip",
                reason="endpoint was planned only; no VirtualBox VM was created",
            )
        )
    else:
        _destroy_virtualbox_vm(
            vm_resource,
            actions=actions,
            command_runner=command_runner,
            shutdown_timeout=shutdown_timeout,
            poll_interval=poll_interval,
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
                "provider": "virtualbox",
                "actions": actions,
                "skipped": skipped,
            },
            "virtualbox": {
                **_virtualbox_metadata(manifest),
                "vm_registered": False,
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
        skipped=skipped,
        destroyed=True,
        already_destroyed=False,
    )
    output["manifest_path"] = str(manifest_path)
    output["state_dir"] = str(manifest_path.parent)
    return output


def _destroy_virtualbox_vm(
    resource: ProviderResource,
    *,
    actions: list[dict[str, object]],
    command_runner: VirtualBoxRunner,
    shutdown_timeout: float,
    poll_interval: float,
) -> None:
    vm_name = _vm_name(resource)
    info = _showvminfo(vm_name, runner=command_runner)
    if _is_missing_vm_result(info):
        actions.append(
            _destroy_action(
                resource,
                action="already-missing",
                result=info,
                reason="VirtualBox VM was already missing",
            )
        )
        return
    if not info.ok:
        raise RuntimeError(command_error("VirtualBox showvminfo failed", info))

    state = _vm_state(info.stdout)
    actions.append(_destroy_action(resource, action="inspect", result=info, vm_state=state))
    if state in _ACPI_VM_STATES:
        acpi = command_runner(
            [VBOXMANAGE_COMMAND, "controlvm", vm_name, "acpipowerbutton"],
            timeout=60,
        )
        actions.append(_destroy_action(resource, action="acpi-shutdown", result=acpi))
        if acpi.ok:
            state = _wait_for_terminal_state(
                vm_name,
                runner=command_runner,
                timeout_seconds=shutdown_timeout,
                poll_interval=poll_interval,
            )
        if state not in _TERMINAL_VM_STATES:
            _poweroff_vm(resource, vm_name, actions=actions, runner=command_runner)
    elif state not in _TERMINAL_VM_STATES:
        _poweroff_vm(
            resource,
            vm_name,
            actions=actions,
            runner=command_runner,
            reason=f"VMState {state or 'unknown'} is not terminal",
        )

    unregister = command_runner(
        [VBOXMANAGE_COMMAND, "unregistervm", vm_name, "--delete"],
        timeout=120,
    )
    if unregister.ok:
        actions.append(_destroy_action(resource, action="unregister", result=unregister))
        return
    if _is_missing_vm_result(unregister):
        actions.append(
            _destroy_action(
                resource,
                action="already-missing",
                result=unregister,
                reason="VirtualBox VM disappeared before unregister",
            )
        )
        return
    raise RuntimeError(command_error("VirtualBox unregistervm failed", unregister))


def _poweroff_vm(
    resource: ProviderResource,
    vm_name: str,
    *,
    actions: list[dict[str, object]],
    runner: VirtualBoxRunner,
    reason: str | None = "ACPI shutdown did not reach a terminal state",
) -> None:
    result = runner([VBOXMANAGE_COMMAND, "controlvm", vm_name, "poweroff"], timeout=60)
    action = _destroy_action(resource, action="poweroff", result=result, reason=reason)
    actions.append(action)
    if result.ok or _is_missing_vm_result(result):
        if not result.ok:
            action["action"] = "already-missing"
            action["reason"] = "VirtualBox VM disappeared before poweroff"
        return
    raise RuntimeError(command_error("VirtualBox poweroff failed", result))


def _wait_for_terminal_state(
    vm_name: str,
    *,
    runner: VirtualBoxRunner,
    timeout_seconds: float,
    poll_interval: float,
) -> str | None:
    deadline = time.monotonic() + max(0.0, float(timeout_seconds))
    interval = max(0.0, float(poll_interval))
    while time.monotonic() < deadline:
        if interval:
            time.sleep(interval)
        result = _showvminfo(vm_name, runner=runner)
        if _is_missing_vm_result(result):
            return "poweroff"
        if not result.ok:
            raise RuntimeError(command_error("VirtualBox showvminfo failed", result))
        state = _vm_state(result.stdout)
        if state in _TERMINAL_VM_STATES:
            return state
    return None


def _showvminfo(vm_name: str, *, runner: VirtualBoxRunner) -> CommandResult:
    return runner(
        [VBOXMANAGE_COMMAND, "showvminfo", vm_name, "--machinereadable"],
        timeout=60,
    )


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


def _virtualbox_vm_resource(resources: Sequence[ProviderResource]) -> ProviderResource | None:
    for resource in resources:
        if _normalized_resource_kind(resource.kind) == "virtualbox-vm":
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
        if _normalized_resource_kind(resource.kind) != "virtualbox-vm"
    ]


def _manifest_was_never_created(manifest: EndpointManifest) -> bool:
    metadata = manifest.metadata
    if manifest.status == "planned" or metadata.get("dry_run") is True:
        return True
    if metadata.get("created") is False:
        return True
    virtualbox = metadata.get("virtualbox")
    if isinstance(virtualbox, Mapping) and virtualbox.get("vm_registered") is False:
        return True
    return False


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
    private_network = manifest.metadata.get("private_network")
    if isinstance(private_network, Mapping):
        private_group = private_network.get("private_group")
        if isinstance(private_group, str) and private_group:
            return private_group
    virtualbox_network = _virtualbox_metadata(manifest).get("private_network")
    if isinstance(virtualbox_network, Mapping):
        private_group = virtualbox_network.get("private_group")
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
    private_ip = _virtualbox_metadata(manifest).get("private_ip")
    if isinstance(private_ip, str) and private_ip:
        return private_ip
    for interface in manifest.interfaces:
        if interface.exposure == "private" and interface.ipv4 is not None:
            return interface.ipv4
    return None


def _vm_name(resource: ProviderResource) -> str:
    value = resource.metadata.get("vm_name")
    if isinstance(value, str) and value:
        return value
    if resource.name:
        return resource.name
    return resource.provider_id


def _vm_state(stdout: str) -> str | None:
    for line in stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key == "VMState":
            return value.strip().strip('"').lower()
    return None


def _is_missing_vm_result(result: CommandResult) -> bool:
    text = f"{result.stdout}\n{result.stderr}\n{result.error or ''}".lower()
    markers = (
        "could not find a registered machine",
        "could not find registered machine",
        "is not currently registered",
        "vbox_e_object_not_found",
        "object not found",
        "not found",
    )
    return any(marker in text for marker in markers)


def _destroy_action(
    resource: ProviderResource,
    *,
    action: str,
    result: CommandResult | None = None,
    reason: str | None = None,
    vm_state: str | None = None,
) -> dict[str, object]:
    output: dict[str, object] = {
        "action": action,
        "kind": resource.kind,
        "provider_id": resource.provider_id,
        "name": resource.name,
    }
    if reason is not None:
        output["reason"] = reason
    if vm_state is not None:
        output["vm_state"] = vm_state
    if result is not None:
        output["command"] = result.command
        output["exit_code"] = result.exit_code
    return output


def _destroy_output(
    *,
    manifest: EndpointManifest,
    actions: list[dict[str, object]],
    skipped: list[dict[str, object]],
    destroyed: bool,
    already_destroyed: bool,
) -> dict[str, object]:
    return {
        "ok": True,
        "endpoint_id": manifest.endpoint_id,
        "provider": manifest.provider,
        "exposure": manifest.exposure,
        "status": manifest.status,
        "destroyed": destroyed,
        "already_destroyed": already_destroyed,
        "artifact_dir": manifest.artifact_dir,
        "actions": actions,
        "skipped": skipped,
    }


def _virtualbox_metadata(manifest: EndpointManifest) -> dict[str, object]:
    virtualbox = manifest.metadata.get("virtualbox")
    if isinstance(virtualbox, Mapping):
        return dict(virtualbox)
    return {}


def _normalized_resource_kind(kind: str) -> str:
    return kind.replace("_", "-")
