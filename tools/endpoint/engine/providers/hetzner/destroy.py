"""Hetzner endpoint destroy and cleanup operations."""

from __future__ import annotations

import os
import shutil
from collections.abc import Mapping
from dataclasses import replace

from ...model import EndpointManifest, ProviderResource
from ...process import CommandResult, run_command
from ...state import (
    read_private_group_record,
    remove_private_group_allocation,
    write_endpoint_manifest,
)
from .constants import HCLOUD_COMMAND, HCLOUD_TOKEN_ENV, HcloudRunner, TOKEN_ENV
from .hcloud import _hcloud_cleanup, _is_missing_resource_result
from .utils import (
    _command_error,
    _hetzner_token,
    _network_resource_id,
    _optional_mapping_string,
    _utc_now,
)



def destroy_endpoint(
    manifest: EndpointManifest,
    *,
    env: Mapping[str, str] | None = None,
    command_runner: HcloudRunner = run_command,
) -> dict[str, object]:
    """Destroy Hetzner resources recorded in one endpoint manifest."""

    if manifest.provider != "hetzner":
        raise ValueError(f"endpoint provider is not hetzner: {manifest.provider}")

    private_destroy = _private_destroy_context(manifest)
    resources = _cleanup_resources(manifest)
    if manifest.status == "destroyed":
        output = _destroy_output(
            manifest=manifest,
            actions=[],
            skipped=[
                _destroy_action(resource, action="skip", reason="endpoint already destroyed")
                for resource in resources
            ],
            destroyed=False,
            already_destroyed=True,
        )
        return output

    actions: list[dict[str, object]] = []
    skipped: list[dict[str, object]] = []
    real_resources = [
        resource for resource in resources if _destroy_command(resource) is not None
    ]
    needs_private_hcloud = (
        private_destroy is not None
        and (
            private_destroy.get("server_resource") is not None
            or private_destroy.get("network_resource") is not None
        )
    )
    hcloud_env: Mapping[str, str] = {}
    if real_resources or needs_private_hcloud:
        environ = os.environ if env is None else env
        token = _hetzner_token(environ)
        if command_runner is run_command and not token:
            raise RuntimeError(f"{TOKEN_ENV} or {HCLOUD_TOKEN_ENV} must be configured")
        if command_runner is run_command and shutil.which(HCLOUD_COMMAND) is None:
            raise RuntimeError(f"{HCLOUD_COMMAND} was not found on PATH")
        hcloud_env = {HCLOUD_TOKEN_ENV: token} if token else {}

    if private_destroy is not None:
        detach_action = _detach_private_endpoint_from_network(
            private_destroy,
            env=hcloud_env,
            command_runner=command_runner,
        )
        if detach_action is not None:
            actions.append(detach_action)

    for resource in resources:
        argv = _destroy_command(resource)
        if argv is None:
            skipped.append(
                _destroy_action(
                    resource,
                    action="skip",
                    reason=f"resource kind {resource.kind!r} is not destroyed by hetzner provider",
                )
            )
            continue

        result = command_runner(argv, env=hcloud_env, timeout=120)
        if result.ok:
            actions.append(_destroy_action(resource, action="delete", result=result))
            continue
        if _is_missing_resource_result(result):
            actions.append(
                _destroy_action(
                    resource,
                    action="already-missing",
                    result=result,
                    reason="provider resource was already missing",
                )
            )
            continue
        raise RuntimeError(_command_error("hcloud destroy command failed", result))

    private_group_update: dict[str, object] | None = None
    if private_destroy is not None:
        private_group_update = _remove_private_endpoint_from_group(
            manifest,
            private_destroy,
        )
        actions.extend(
            _delete_private_network_if_unused(
                private_destroy,
                private_group_update=private_group_update,
                env=hcloud_env,
                command_runner=command_runner,
            )
        )

    destroyed_at = _utc_now()
    destroyed_manifest = replace(
        manifest,
        status="destroyed",
        metadata={
            **manifest.metadata,
            "destroyed_at": destroyed_at,
            "destroy": {
                "provider": "hetzner",
                "actions": actions,
                "skipped": skipped,
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


def _cleanup_partial_wan(
    *,
    server_id: str | None,
    ssh_key_id: str | None,
    env: Mapping[str, str],
) -> None:
    if server_id is not None:
        _hcloud_cleanup([HCLOUD_COMMAND, "server", "delete", server_id], env=env)
    if ssh_key_id is not None:
        _hcloud_cleanup([HCLOUD_COMMAND, "ssh-key", "delete", ssh_key_id], env=env)


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


def _private_destroy_context(manifest: EndpointManifest) -> dict[str, object] | None:
    if manifest.exposure != "private":
        return None
    private_group = _private_group_from_manifest(manifest)
    if private_group is None:
        return None

    record = None
    try:
        record = read_private_group_record(manifest.provider, private_group)
        network_resource = dict(record.network_resource)
    except FileNotFoundError:
        network_resource = {}

    return {
        "private_group": private_group,
        "private_ipv4": _private_ipv4_from_manifest(manifest),
        "group_record": record,
        "network_resource": network_resource,
        "server_resource": _resource_by_kind(manifest, "server"),
    }


def _detach_private_endpoint_from_network(
    private_destroy: Mapping[str, object],
    *,
    env: Mapping[str, str],
    command_runner: HcloudRunner,
) -> dict[str, object] | None:
    server_resource = private_destroy.get("server_resource")
    network_resource = private_destroy.get("network_resource")
    if not isinstance(server_resource, ProviderResource) or not isinstance(
        network_resource, Mapping
    ):
        return None

    network_id = _network_resource_id(network_resource)
    if network_id is None:
        return None

    result = command_runner(
        [
            HCLOUD_COMMAND,
            "server",
            "detach-from-network",
            server_resource.provider_id,
            "--network",
            network_id,
        ],
        env=env,
        timeout=120,
    )
    action = _destroy_action(
        server_resource,
        action="detach",
        result=result,
        reason=f"detach private endpoint from network {network_id}",
    )
    action["network_id"] = network_id
    if result.ok or _is_missing_resource_result(result):
        if not result.ok:
            action["action"] = "already-missing"
            action["reason"] = "private network attachment was already missing"
        return action
    raise RuntimeError(_command_error("hcloud private network detach command failed", result))


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
            "network_deleted": False,
        }

    return {
        "private_group": private_group,
        "record_found": True,
        "remaining_endpoints": updated.allocated_endpoint_ids,
        "network_deleted": False,
        "private_group_record": updated.to_dict(),
    }


def _delete_private_network_if_unused(
    private_destroy: Mapping[str, object],
    *,
    private_group_update: Mapping[str, object],
    env: Mapping[str, str],
    command_runner: HcloudRunner,
) -> list[dict[str, object]]:
    remaining_endpoints = private_group_update.get("remaining_endpoints")
    if remaining_endpoints:
        return []

    network_resource = private_destroy.get("network_resource")
    if not isinstance(network_resource, Mapping):
        return []
    network_id = _network_resource_id(network_resource)
    if network_id is None:
        return []

    network = ProviderResource(
        kind="network",
        provider_id=network_id,
        name=_optional_mapping_string(network_resource, "network_name"),
        metadata={
            "type": "network",
            "private_group": str(private_destroy.get("private_group", "")),
        },
    )
    result = command_runner(_destroy_command(network) or [], env=env, timeout=120)
    if result.ok:
        if isinstance(private_group_update, dict):
            private_group_update["network_deleted"] = True
        return [_destroy_action(network, action="delete", result=result)]
    if _is_missing_resource_result(result):
        if isinstance(private_group_update, dict):
            private_group_update["network_deleted"] = True
        return [
            _destroy_action(
                network,
                action="already-missing",
                result=result,
                reason="private group network was already missing",
            )
        ]
    raise RuntimeError(_command_error("hcloud private network delete command failed", result))


def _resource_by_kind(
    manifest: EndpointManifest,
    kind: str,
) -> ProviderResource | None:
    normalized_kind = _normalized_resource_kind(kind)
    for resource in manifest.provider_resources.resources:
        if resource.cleanup and _normalized_resource_kind(resource.kind) == normalized_kind:
            return resource
    return None


def _private_group_from_manifest(manifest: EndpointManifest) -> str | None:
    metadata_group = manifest.metadata.get("private_group")
    if isinstance(metadata_group, str) and metadata_group:
        return metadata_group
    private_metadata = manifest.metadata.get("private")
    if isinstance(private_metadata, Mapping):
        private_group = private_metadata.get("private_group")
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
    for interface in manifest.interfaces:
        if interface.exposure == "private" and interface.ipv4 is not None:
            return interface.ipv4
    return None


def _destroy_command(resource: ProviderResource) -> list[str] | None:
    kind = _normalized_resource_kind(resource.kind)
    if kind == "server":
        return [HCLOUD_COMMAND, "server", "delete", resource.provider_id]
    if kind == "ssh-key":
        return [HCLOUD_COMMAND, "ssh-key", "delete", resource.provider_id]
    if kind == "network":
        return [HCLOUD_COMMAND, "network", "delete", resource.provider_id]
    return None


def _normalized_resource_kind(kind: str) -> str:
    return kind.replace("_", "-")


def _destroy_action(
    resource: ProviderResource,
    *,
    action: str,
    result: CommandResult | None = None,
    reason: str | None = None,
) -> dict[str, object]:
    output: dict[str, object] = {
        "action": action,
        "kind": resource.kind,
        "provider_id": resource.provider_id,
        "name": resource.name,
    }
    if reason is not None:
        output["reason"] = reason
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
