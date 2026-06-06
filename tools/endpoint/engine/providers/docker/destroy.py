"""Docker endpoint destroy operations."""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import replace

from ...model import EndpointManifest, ProviderResource
from ...process import CommandResult, run_command
from ...registry import validate_request
from ...state import remove_private_group_allocation, write_endpoint_manifest
from ..vm import command_error, utc_now
from .constants import (
    DOCKER_COMMAND_ENV,
    EXPOSURE_PRIVATE,
    PROVIDER_NAME,
    DockerRunner,
)
from .resources import (
    DOCKER_CONTAINER_KIND,
    DOCKER_LABEL_EXPOSURE,
    DOCKER_LABEL_MANAGED,
    DOCKER_LABEL_PRIVATE_GROUP,
    DOCKER_LABEL_PROVIDER,
    DOCKER_MANAGED_LABEL_VALUE,
    DOCKER_NETWORK_KIND,
    docker_argv,
    docker_inspect_id,
    docker_inspect_labels,
    docker_inspect_name,
    parse_single_docker_inspect_output,
    requested_docker_command,
)


DOCKER_CONTAINER_REMOVE_TIMEOUT = 120
DOCKER_NETWORK_INSPECT_TIMEOUT = 30
DOCKER_NETWORK_REMOVE_TIMEOUT = 120


def destroy_endpoint(
    manifest: EndpointManifest,
    *,
    env: Mapping[str, str] | None = None,
    command_runner: DockerRunner = run_command,
) -> dict[str, object]:
    """Destroy tracked Docker resources for one endpoint manifest.

    Local endpoint state and artifacts are preserved so failed destroys remain
    inspectable and retries retain the original manifest context.
    """

    if not isinstance(manifest, EndpointManifest):
        raise TypeError("manifest must be an EndpointManifest")
    if manifest.provider != PROVIDER_NAME:
        raise ValueError(f"manifest provider must be 'docker': {manifest.provider!r}")
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

    environ = os.environ if env is None else env
    docker_command = _docker_command_from_manifest(manifest, environ)
    planned_only = _manifest_was_planned_only(manifest)
    private_destroy = _private_destroy_context(manifest)
    private_group_update: dict[str, object] | None = None
    actions: list[dict[str, object]] = []
    skipped: list[dict[str, object]] = []

    for resource in resources:
        kind = _normalized_resource_kind(resource.kind)
        if kind == DOCKER_CONTAINER_KIND:
            if planned_only:
                skipped.append(
                    _destroy_action(
                        resource,
                        action="skip",
                        reason="endpoint was planned only; no Docker container was created",
                    )
                )
                continue
            _destroy_docker_container(
                resource,
                actions=actions,
                env=environ,
                command_runner=command_runner,
                docker_command=docker_command,
            )
            continue

        if kind == DOCKER_NETWORK_KIND:
            if planned_only:
                skipped.append(
                    _destroy_action(
                        resource,
                        action="skip",
                        reason="endpoint was planned only; no Docker network was created",
                    )
                )
                continue
            if private_destroy is not None and private_group_update is None:
                private_group_update = _remove_private_endpoint_from_group(
                    manifest,
                    private_destroy,
                )
                actions.append(_private_group_destroy_action(private_destroy, private_group_update))
            _destroy_private_network_if_unused(
                resource,
                manifest=manifest,
                private_destroy=private_destroy,
                private_group_update=private_group_update,
                actions=actions,
                skipped=skipped,
                env=environ,
                command_runner=command_runner,
                docker_command=docker_command,
            )
            continue

        if kind == "local-file":
            skipped.append(
                _destroy_action(
                    resource,
                    action="skip",
                    reason="local endpoint state and artifacts are preserved",
                )
            )
            continue

        skipped.append(
            _destroy_action(
                resource,
                action="skip",
                reason=f"resource kind {resource.kind!r} is not destroyed by docker provider",
            )
        )

    if private_destroy is not None and private_group_update is None and not planned_only:
        private_group_update = _remove_private_endpoint_from_group(manifest, private_destroy)
        actions.append(_private_group_destroy_action(private_destroy, private_group_update))

    destroyed_at = utc_now()
    destroyed_manifest = replace(
        manifest,
        status="destroyed",
        metadata={
            **manifest.metadata,
            "destroyed_at": destroyed_at,
            "destroy": {
                "provider": PROVIDER_NAME,
                "actions": actions,
                "skipped": skipped,
            },
            "docker": {
                **_docker_metadata(manifest),
                "destroyed_at": destroyed_at,
                "container_removed": _has_successful_container_removal(actions),
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


def _destroy_docker_container(
    resource: ProviderResource,
    *,
    actions: list[dict[str, object]],
    env: Mapping[str, str],
    command_runner: DockerRunner,
    docker_command: str,
) -> None:
    container_ref = _container_ref(resource)
    if container_ref is None:
        actions.append(
            _destroy_action(
                resource,
                action="already-missing",
                reason="manifest does not track a Docker container id or name",
            )
        )
        return

    result = command_runner(
        docker_argv(
            "container",
            "rm",
            "--force",
            container_ref,
            docker_command=docker_command,
        ),
        env=env,
        timeout=DOCKER_CONTAINER_REMOVE_TIMEOUT,
    )
    if result.ok:
        actions.append(_destroy_action(resource, action="remove", result=result))
        return
    if _is_missing_container_result(result):
        actions.append(
            _destroy_action(
                resource,
                action="already-missing",
                result=result,
                reason="Docker container was already missing",
            )
        )
        return
    raise RuntimeError(command_error("Docker container remove failed", result))


def _destroy_private_network_if_unused(
    resource: ProviderResource,
    *,
    manifest: EndpointManifest,
    private_destroy: Mapping[str, object] | None,
    private_group_update: Mapping[str, object] | None,
    actions: list[dict[str, object]],
    skipped: list[dict[str, object]],
    env: Mapping[str, str],
    command_runner: DockerRunner,
    docker_command: str,
) -> None:
    if manifest.exposure != EXPOSURE_PRIVATE or private_destroy is None:
        skipped.append(
            _destroy_action(
                resource,
                action="skip",
                reason="Docker network cleanup is only provider-owned for private exposure",
            )
        )
        return
    if private_group_update is None or private_group_update.get("record_found") is not True:
        skipped.append(
            _destroy_action(
                resource,
                action="skip",
                reason="private group allocation record was not found; network retained",
            )
        )
        return
    remaining_endpoints = private_group_update.get("remaining_endpoints")
    if remaining_endpoints:
        skipped.append(
            _destroy_action(
                resource,
                action="skip",
                reason="private group still has allocated endpoints; network retained",
                remaining_endpoints=list(remaining_endpoints)
                if isinstance(remaining_endpoints, Sequence)
                and not isinstance(remaining_endpoints, (str, bytes, bytearray))
                else None,
            )
        )
        return

    network_ref = _network_ref(resource)
    if network_ref is None:
        skipped.append(
            _destroy_action(
                resource,
                action="skip",
                reason="manifest does not track a Docker network id or name",
            )
        )
        return

    inspect = command_runner(
        docker_argv(
            "network",
            "inspect",
            network_ref,
            docker_command=docker_command,
        ),
        env=env,
        timeout=DOCKER_NETWORK_INSPECT_TIMEOUT,
    )
    if not inspect.ok:
        if _is_missing_network_result(inspect):
            actions.append(
                _destroy_action(
                    resource,
                    action="already-missing",
                    result=inspect,
                    reason="Docker private network was already missing",
                )
            )
            if isinstance(private_group_update, dict):
                private_group_update["network_removed"] = True
            return
        raise RuntimeError(command_error("Docker network inspect failed", inspect))

    record = parse_single_docker_inspect_output(
        inspect,
        context=f"Docker network inspect {network_ref!r}",
    )
    label_check = _provider_owned_private_network_label_check(
        record,
        provider=manifest.provider,
        private_group=str(private_destroy["private_group"]),
    )
    actions.append(
        _destroy_action(
            resource,
            action="inspect",
            result=inspect,
            network_id=docker_inspect_id(record),
            network_name=docker_inspect_name(record),
            labels_match=label_check["ok"],
        )
    )
    if label_check["ok"] is not True:
        skipped.append(
            _destroy_action(
                resource,
                action="skip",
                reason=str(label_check["reason"]),
                labels=label_check["labels"],
            )
        )
        return

    remove = command_runner(
        docker_argv("network", "rm", network_ref, docker_command=docker_command),
        env=env,
        timeout=DOCKER_NETWORK_REMOVE_TIMEOUT,
    )
    if remove.ok:
        actions.append(_destroy_action(resource, action="remove", result=remove))
        if isinstance(private_group_update, dict):
            private_group_update["network_removed"] = True
        return
    if _is_missing_network_result(remove):
        actions.append(
            _destroy_action(
                resource,
                action="already-missing",
                result=remove,
                reason="Docker private network disappeared before removal",
            )
        )
        if isinstance(private_group_update, dict):
            private_group_update["network_removed"] = True
        return
    raise RuntimeError(command_error("Docker network remove failed", remove))


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
    if manifest.exposure != EXPOSURE_PRIVATE:
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
            "network_removed": False,
        }

    return {
        "private_group": private_group,
        "record_found": True,
        "remaining_endpoints": updated.allocated_endpoint_ids,
        "network_removed": False,
        "private_group_record": updated.to_dict(),
    }


def _private_group_destroy_action(
    private_destroy: Mapping[str, object],
    private_group_update: Mapping[str, object],
) -> dict[str, object]:
    return {
        "action": "remove-private-allocation",
        "kind": "private-group",
        "provider_id": private_destroy["private_group"],
        "name": private_destroy["private_group"],
        "private_ip": private_destroy.get("private_ipv4"),
        "record_found": private_group_update["record_found"],
        "remaining_endpoints": private_group_update["remaining_endpoints"],
    }


def _provider_owned_private_network_label_check(
    record: Mapping[str, object],
    *,
    provider: str,
    private_group: str,
) -> dict[str, object]:
    labels = docker_inspect_labels(record)
    required = {
        DOCKER_LABEL_PROVIDER: provider,
        DOCKER_LABEL_MANAGED: DOCKER_MANAGED_LABEL_VALUE,
        DOCKER_LABEL_PRIVATE_GROUP: private_group,
        DOCKER_LABEL_EXPOSURE: EXPOSURE_PRIVATE,
    }
    for key, expected in required.items():
        actual = labels.get(key)
        if actual != expected:
            return {
                "ok": False,
                "reason": (
                    f"Docker private network label {key}={actual!r} does not "
                    f"match expected {expected!r}; network retained"
                ),
                "labels": labels,
                "required": required,
            }
    return {"ok": True, "labels": labels, "required": required}


def _private_group_from_manifest(manifest: EndpointManifest) -> str | None:
    metadata_group = manifest.metadata.get("private_group")
    if isinstance(metadata_group, str) and metadata_group:
        return metadata_group
    private_metadata = manifest.metadata.get("private")
    if isinstance(private_metadata, Mapping):
        private_group = private_metadata.get("private_group")
        if isinstance(private_group, str) and private_group:
            return private_group
    private_network = manifest.metadata.get("private_network")
    if isinstance(private_network, Mapping):
        private_group = private_network.get("private_group")
        if isinstance(private_group, str) and private_group:
            return private_group
    docker_metadata = _docker_metadata(manifest)
    docker_private_network = docker_metadata.get("private_network")
    if isinstance(docker_private_network, Mapping):
        private_group = docker_private_network.get("private_group")
        if isinstance(private_group, str) and private_group:
            return private_group
    docker_allocation = docker_metadata.get("private_allocation")
    if isinstance(docker_allocation, Mapping):
        private_group = docker_allocation.get("private_group")
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
        private_ip = private_metadata.get("private_ip") or private_metadata.get("private_ipv4")
        if isinstance(private_ip, str) and private_ip:
            return private_ip
    docker_metadata = _docker_metadata(manifest)
    docker_allocation = docker_metadata.get("private_allocation")
    if isinstance(docker_allocation, Mapping):
        private_ip = docker_allocation.get("private_ipv4")
        if isinstance(private_ip, str) and private_ip:
            return private_ip
    for interface in manifest.interfaces:
        if interface.exposure == EXPOSURE_PRIVATE and interface.ipv4 is not None:
            return interface.ipv4
    return None


def _manifest_was_planned_only(manifest: EndpointManifest) -> bool:
    return manifest.status == "planned" or manifest.metadata.get("dry_run") is True


def _docker_command_from_manifest(
    manifest: EndpointManifest,
    env: Mapping[str, str],
) -> str:
    if (env.get(DOCKER_COMMAND_ENV) or "").strip():
        return requested_docker_command(env)
    command = _docker_metadata(manifest).get("command")
    if isinstance(command, str) and command.strip():
        return command.strip()
    return requested_docker_command(env)


def _docker_metadata(manifest: EndpointManifest) -> dict[str, object]:
    value = manifest.metadata.get("docker")
    return dict(value) if isinstance(value, Mapping) else {}


def _container_ref(resource: ProviderResource) -> str | None:
    for value in (
        resource.metadata.get("container_id"),
        resource.provider_id,
        resource.metadata.get("container_name"),
        resource.name,
    ):
        if isinstance(value, str) and value:
            return value
    return None


def _network_ref(resource: ProviderResource) -> str | None:
    for value in (
        resource.metadata.get("network_id"),
        resource.provider_id,
        resource.metadata.get("network_name"),
        resource.name,
    ):
        if isinstance(value, str) and value:
            return value
    return None


def _has_successful_container_removal(actions: Sequence[Mapping[str, object]]) -> bool:
    return any(
        _normalized_resource_kind(str(action.get("kind", ""))) == DOCKER_CONTAINER_KIND
        and action.get("action") in {"remove", "already-missing"}
        for action in actions
    )


def _is_missing_container_result(result: CommandResult) -> bool:
    return _result_contains_any(
        result,
        (
            "no such container",
            "no such object",
            "container not found",
            "not found",
            "does not exist",
        ),
    )


def _is_missing_network_result(result: CommandResult) -> bool:
    return _result_contains_any(
        result,
        (
            "no such network",
            "no such object",
            "network not found",
            "not found",
            "does not exist",
        ),
    )


def _result_contains_any(result: CommandResult, markers: Sequence[str]) -> bool:
    text = f"{result.stdout}\n{result.stderr}\n{result.error or ''}".lower()
    return any(marker in text for marker in markers)


def _destroy_action(
    resource: ProviderResource,
    *,
    action: str,
    result: CommandResult | None = None,
    reason: str | None = None,
    remaining_endpoints: list[object] | None = None,
    network_id: str | None = None,
    network_name: str | None = None,
    labels_match: bool | None = None,
    labels: Mapping[str, object] | None = None,
) -> dict[str, object]:
    output: dict[str, object] = {
        "action": action,
        "kind": resource.kind,
        "provider_id": resource.provider_id,
        "name": resource.name,
    }
    if reason is not None:
        output["reason"] = reason
    if remaining_endpoints is not None:
        output["remaining_endpoints"] = remaining_endpoints
    if network_id is not None:
        output["network_id"] = network_id
    if network_name is not None:
        output["network_name"] = network_name
    if labels_match is not None:
        output["labels_match"] = labels_match
    if labels is not None:
        output["labels"] = dict(labels)
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


def _normalized_resource_kind(kind: str) -> str:
    return kind.replace("_", "-")

