"""Resolve endpoint manifests into appliance execution targets."""

from __future__ import annotations

import posixpath
from collections.abc import Mapping
from dataclasses import dataclass, field

from tools.appliance.engine.ssh_docker import SSHDockerHostTarget

from .config import WireConfig
from .model import EndpointManifest, JSONObject, JsonModel, NetworkInterface, json_object
from .state import read_endpoint_manifest


DEFAULT_APPLIANCE_REMOTE_BASE = "/var/lib/libcrafter/appliance"
DOCKER_ENDPOINT_TRANSPORT = "docker-localhost-port-forward"


@dataclass(frozen=True, slots=True)
class EndpointApplianceTarget(JsonModel):
    """Endpoint manifest data resolved for appliance profile rendering."""

    endpoint_id: str
    provider: str
    exposure: str
    role: str
    target: SSHDockerHostTarget
    interfaces: list[NetworkInterface] = field(default_factory=list)
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_non_empty_string(self.endpoint_id, "endpoint_id")
        _require_non_empty_string(self.provider, "provider")
        _require_non_empty_string(self.exposure, "exposure")
        _require_non_empty_string(self.role, "role")
        if not isinstance(self.target, SSHDockerHostTarget):
            raise TypeError("target must be an SSHDockerHostTarget")
        object.__setattr__(
            self,
            "interfaces",
            [
                item
                if isinstance(item, NetworkInterface)
                else NetworkInterface.from_dict(_mapping(item, "interfaces[]"))
                for item in self.interfaces
            ],
        )
        object.__setattr__(self, "metadata", json_object(self.metadata, "metadata"))


def resolve_endpoint_appliance_target(
    manifest: EndpointManifest | Mapping[str, object],
) -> EndpointApplianceTarget:
    """Return an appliance target derived from an endpoint manifest."""

    endpoint = _manifest(manifest)
    ssh = endpoint.ssh
    if ssh.identity_file is None:
        raise ValueError("endpoint ssh.identity_file is required for appliance targets")
    if ssh.known_hosts_file is None:
        raise ValueError("endpoint ssh.known_hosts_file is required for appliance targets")

    appliance_metadata = _optional_mapping(endpoint.metadata.get("appliance"), "metadata.appliance")
    docker_metadata = _optional_mapping(endpoint.metadata.get("docker"), "metadata.docker")
    docker_container = _optional_mapping(
        docker_metadata.get("container") if docker_metadata is not None else None,
        "metadata.docker.container",
    )
    docker_endpoint = _is_docker_endpoint(endpoint, docker_container)
    appliance_capable = _is_appliance_capable(appliance_metadata, docker_container)
    nested_docker = _nested_docker_supported(
        appliance_metadata,
        docker_endpoint=docker_endpoint,
        appliance_capable=appliance_capable,
    )

    remote_base = _remote_base(endpoint, appliance_metadata)
    remote_work_root = _remote_root(
        endpoint,
        appliance_metadata,
        field_name="remote_work_root",
        default_name="work",
        remote_base=remote_base,
    )
    remote_artifact_root = _remote_root(
        endpoint,
        appliance_metadata,
        field_name="remote_artifact_root",
        default_name="artifacts",
        remote_base=remote_base,
    )
    runtime_metadata = {
        "target_kind": _target_kind(
            docker_endpoint=docker_endpoint,
            appliance_capable=appliance_capable,
        ),
        "remote_base": remote_base,
        "remote_work_root": remote_work_root,
        "remote_artifact_root": remote_artifact_root,
        "docker_endpoint_container": docker_endpoint,
        "appliance_capable": appliance_capable,
        "nested_docker": nested_docker,
        "docker_execution_supported": nested_docker,
    }
    if docker_endpoint and not nested_docker:
        runtime_metadata["docker_execution_disabled_reason"] = (
            "endpoint is already a Docker container"
        )

    metadata = {
        "endpoint_id": endpoint.endpoint_id,
        "provider": endpoint.provider,
        "exposure": endpoint.exposure,
        "role": endpoint.role,
        "endpoint_status": endpoint.status,
        "interfaces": [interface.to_dict() for interface in endpoint.interfaces],
        "provider_resources": endpoint.provider_resources.to_dict(),
        "endpoint_metadata": endpoint.metadata,
        "ssh_metadata": ssh.metadata,
        "appliance": runtime_metadata,
    }
    if docker_container is not None:
        metadata["docker_container"] = dict(docker_container)

    target = SSHDockerHostTarget(
        host=ssh.host,
        user=ssh.user,
        port=ssh.port,
        identity_file=ssh.identity_file,
        known_hosts_file=ssh.known_hosts_file,
        remote_work_root=remote_work_root,
        remote_artifact_root=remote_artifact_root,
        docker_command=_docker_command(appliance_metadata),
        metadata=metadata,
    )
    return EndpointApplianceTarget(
        endpoint_id=endpoint.endpoint_id,
        provider=endpoint.provider,
        exposure=endpoint.exposure,
        role=endpoint.role,
        target=target,
        interfaces=endpoint.interfaces,
        metadata=metadata,
    )


def read_endpoint_appliance_target(
    endpoint_id: str,
    config: WireConfig | None = None,
) -> EndpointApplianceTarget:
    """Read an endpoint manifest from state and resolve its appliance target."""

    return resolve_endpoint_appliance_target(read_endpoint_manifest(endpoint_id, config))


def _manifest(value: EndpointManifest | Mapping[str, object]) -> EndpointManifest:
    if isinstance(value, EndpointManifest):
        return value
    return EndpointManifest.from_dict(value)


def _remote_base(
    manifest: EndpointManifest,
    appliance_metadata: Mapping[str, object] | None,
) -> str:
    value = _optional_string(
        appliance_metadata.get("remote_base") if appliance_metadata is not None else None,
        "metadata.appliance.remote_base",
    )
    base = value if value is not None else DEFAULT_APPLIANCE_REMOTE_BASE
    return _remote_absolute_path(base, "metadata.appliance.remote_base")


def _remote_root(
    manifest: EndpointManifest,
    appliance_metadata: Mapping[str, object] | None,
    *,
    field_name: str,
    default_name: str,
    remote_base: str,
) -> str:
    value = _optional_string(
        appliance_metadata.get(field_name) if appliance_metadata is not None else None,
        f"metadata.appliance.{field_name}",
    )
    if value is not None:
        return _remote_absolute_path(value, f"metadata.appliance.{field_name}")
    endpoint_component = _remote_component(manifest.endpoint_id, "endpoint_id")
    return _remote_absolute_path(
        posixpath.join(remote_base, endpoint_component, default_name),
        f"metadata.appliance.{field_name}",
    )


def _docker_command(appliance_metadata: Mapping[str, object] | None) -> str:
    value = _optional_string(
        appliance_metadata.get("docker_command") if appliance_metadata is not None else None,
        "metadata.appliance.docker_command",
    )
    return "docker" if value is None else value


def _is_docker_endpoint(
    manifest: EndpointManifest,
    docker_container: Mapping[str, object] | None,
) -> bool:
    if manifest.provider == "docker":
        return True
    if manifest.ssh.metadata.get("transport") == DOCKER_ENDPOINT_TRANSPORT:
        return True
    container_type = (
        _optional_string(docker_container.get("type"), "metadata.docker.container.type")
        if docker_container is not None
        else None
    )
    return container_type == "docker-container"


def _is_appliance_capable(
    appliance_metadata: Mapping[str, object] | None,
    docker_container: Mapping[str, object] | None,
) -> bool:
    for value, name in (
        (
            appliance_metadata.get("appliance_capable")
            if appliance_metadata is not None
            else None,
            "metadata.appliance.appliance_capable",
        ),
        (
            docker_container.get("appliance_capable") if docker_container is not None else None,
            "metadata.docker.container.appliance_capable",
        ),
        (
            docker_container.get("is_appliance") if docker_container is not None else None,
            "metadata.docker.container.is_appliance",
        ),
    ):
        if value is None:
            continue
        return _bool(value, name)
    return False


def _nested_docker_supported(
    appliance_metadata: Mapping[str, object] | None,
    *,
    docker_endpoint: bool,
    appliance_capable: bool,
) -> bool:
    value = (
        appliance_metadata.get("nested_docker")
        if appliance_metadata is not None and "nested_docker" in appliance_metadata
        else None
    )
    if value is not None:
        return _bool(value, "metadata.appliance.nested_docker")
    if docker_endpoint:
        return False
    return True


def _target_kind(*, docker_endpoint: bool, appliance_capable: bool) -> str:
    if docker_endpoint and appliance_capable:
        return "docker-endpoint-appliance-container"
    if docker_endpoint:
        return "docker-endpoint-container"
    return "ssh-docker-host"


def _remote_absolute_path(value: str, name: str) -> str:
    path = _require_non_empty_string(value, name)
    if not path.startswith("/"):
        raise ValueError(f"{name} must be an absolute remote path")
    normalized = posixpath.normpath(path)
    if normalized == ".":
        raise ValueError(f"{name} must be an absolute remote path")
    return normalized


def _remote_component(value: str, name: str) -> str:
    component = _require_non_empty_string(value, name)
    if "/" in component or component in {".", ".."}:
        raise ValueError(f"{name} must be a single remote path component")
    return component


def _optional_mapping(value: object, name: str) -> Mapping[str, object] | None:
    if value is None:
        return None
    return _mapping(value, name)


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    for key in value:
        if not isinstance(key, str):
            raise ValueError(f"{name} keys must be strings")
    return value


def _optional_string(value: object, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def _require_non_empty_string(value: object, name: str) -> str:
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{name} must be a non-empty string")
    return value


__all__ = [
    "DEFAULT_APPLIANCE_REMOTE_BASE",
    "DOCKER_ENDPOINT_TRANSPORT",
    "EndpointApplianceTarget",
    "read_endpoint_appliance_target",
    "resolve_endpoint_appliance_target",
]
