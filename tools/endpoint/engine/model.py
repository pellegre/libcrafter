"""JSON-compatible models for endpoint lifecycle manifests."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any, TypeAlias


JSONScalar: TypeAlias = str | int | float | bool | None
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]
JSONObject: TypeAlias = dict[str, JSONValue]


class JsonModel:
    """Mixin for endpoint models that serialize through JSON objects."""

    def to_dict(self) -> JSONObject:
        value = to_jsonable(self)
        if not isinstance(value, dict):
            raise TypeError(f"{type(self).__name__} did not serialize to an object")
        return value

    def to_json(self, *, indent: int = 2) -> str:
        return dumps_json(self, indent=indent)


@dataclass(frozen=True, slots=True)
class EndpointSSHInfo(JsonModel):
    """SSH connection details for one endpoint."""

    host: str
    user: str
    port: int = 22
    identity_file: str | None = None
    known_hosts_file: str | None = None
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_non_empty_string(self.host, "ssh.host")
        _require_non_empty_string(self.user, "ssh.user")
        port = _int(self.port, "ssh.port")
        if port <= 0:
            raise ValueError("ssh.port must be a positive integer")
        object.__setattr__(self, "port", port)
        object.__setattr__(
            self,
            "identity_file",
            _optional_absolute_path(self.identity_file, "ssh.identity_file"),
        )
        object.__setattr__(
            self,
            "known_hosts_file",
            _optional_absolute_path(self.known_hosts_file, "ssh.known_hosts_file"),
        )
        object.__setattr__(self, "metadata", json_object(self.metadata, "ssh.metadata"))

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "EndpointSSHInfo":
        data = _mapping(value, "ssh")
        return cls(
            host=_string(data.get("host"), "ssh.host"),
            user=_string(data.get("user"), "ssh.user"),
            port=_int(data.get("port", 22), "ssh.port"),
            identity_file=_optional_string(data.get("identity_file"), "ssh.identity_file"),
            known_hosts_file=_optional_string(
                data.get("known_hosts_file"),
                "ssh.known_hosts_file",
            ),
            metadata=json_object(data.get("metadata", {}), "ssh.metadata"),
        )


@dataclass(frozen=True, slots=True)
class NetworkInterface(JsonModel):
    """Network address metadata for an endpoint interface."""

    name: str
    exposure: str
    ipv4: str | None = None
    ipv6: str | None = None
    mac: str | None = None
    provider_network_id: str | None = None
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_non_empty_string(self.name, "interface.name")
        _require_non_empty_string(self.exposure, "interface.exposure")
        object.__setattr__(self, "ipv4", _optional_string(self.ipv4, "interface.ipv4"))
        object.__setattr__(self, "ipv6", _optional_string(self.ipv6, "interface.ipv6"))
        object.__setattr__(self, "mac", _optional_string(self.mac, "interface.mac"))
        object.__setattr__(
            self,
            "provider_network_id",
            _optional_string(self.provider_network_id, "interface.provider_network_id"),
        )
        object.__setattr__(self, "metadata", json_object(self.metadata, "interface.metadata"))

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "NetworkInterface":
        data = _mapping(value, "interface")
        return cls(
            name=_string(data.get("name"), "interface.name"),
            exposure=_string(data.get("exposure"), "interface.exposure"),
            ipv4=_optional_string(data.get("ipv4"), "interface.ipv4"),
            ipv6=_optional_string(data.get("ipv6"), "interface.ipv6"),
            mac=_optional_string(data.get("mac"), "interface.mac"),
            provider_network_id=_optional_string(
                data.get("provider_network_id"),
                "interface.provider_network_id",
            ),
            metadata=json_object(data.get("metadata", {}), "interface.metadata"),
        )


@dataclass(frozen=True, slots=True)
class ProviderResource(JsonModel):
    """Provider-owned resource that may need cleanup during destroy."""

    kind: str
    provider_id: str
    name: str | None = None
    cleanup: bool = True
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_non_empty_string(self.kind, "provider_resource.kind")
        _require_non_empty_string(self.provider_id, "provider_resource.provider_id")
        object.__setattr__(self, "name", _optional_string(self.name, "provider_resource.name"))
        object.__setattr__(
            self,
            "cleanup",
            _bool(self.cleanup, "provider_resource.cleanup"),
        )
        object.__setattr__(
            self,
            "metadata",
            json_object(self.metadata, "provider_resource.metadata"),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ProviderResource":
        data = _mapping(value, "provider_resource")
        return cls(
            kind=_string(data.get("kind"), "provider_resource.kind"),
            provider_id=_string(data.get("provider_id"), "provider_resource.provider_id"),
            name=_optional_string(data.get("name"), "provider_resource.name"),
            cleanup=_bool(data.get("cleanup", True), "provider_resource.cleanup"),
            metadata=json_object(data.get("metadata", {}), "provider_resource.metadata"),
        )


@dataclass(frozen=True, slots=True)
class ProviderResources(JsonModel):
    """Collection of provider resources and cleanup ordering metadata."""

    resources: list[ProviderResource] = field(default_factory=list)
    cleanup_order: list[str] = field(default_factory=list)
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "resources",
            [
                resource
                if isinstance(resource, ProviderResource)
                else ProviderResource.from_dict(_mapping(resource, "provider_resources.resources[]"))
                for resource in self.resources
            ],
        )
        object.__setattr__(
            self,
            "cleanup_order",
            string_list(self.cleanup_order, "provider_resources.cleanup_order"),
        )
        object.__setattr__(
            self,
            "metadata",
            json_object(self.metadata, "provider_resources.metadata"),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ProviderResources":
        data = _mapping(value, "provider_resources")
        resources = _sequence(data.get("resources", []), "provider_resources.resources")
        return cls(
            resources=[
                ProviderResource.from_dict(_mapping(item, "provider_resources.resources[]"))
                for item in resources
            ],
            cleanup_order=string_list(
                data.get("cleanup_order", []),
                "provider_resources.cleanup_order",
            ),
            metadata=json_object(data.get("metadata", {}), "provider_resources.metadata"),
        )


@dataclass(frozen=True, slots=True)
class ArtifactPath(JsonModel):
    """Named local path emitted or consumed by endpoint lifecycle operations."""

    name: str
    path: str
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_non_empty_string(self.name, "artifact_path.name")
        object.__setattr__(self, "path", _absolute_path(self.path, "artifact_path.path"))
        object.__setattr__(self, "metadata", json_object(self.metadata, "artifact_path.metadata"))

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ArtifactPath":
        data = _mapping(value, "artifact_path")
        return cls(
            name=_string(data.get("name"), "artifact_path.name"),
            path=_string(data.get("path"), "artifact_path.path"),
            metadata=json_object(data.get("metadata", {}), "artifact_path.metadata"),
        )


@dataclass(frozen=True, slots=True)
class ArtifactPaths(JsonModel):
    """Absolute local artifact paths associated with an endpoint manifest."""

    artifact_dir: str
    paths: list[ArtifactPath] = field(default_factory=list)
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifact_dir", _absolute_path(self.artifact_dir, "artifact_dir"))
        object.__setattr__(
            self,
            "paths",
            [
                item
                if isinstance(item, ArtifactPath)
                else ArtifactPath.from_dict(_mapping(item, "artifact_paths.paths[]"))
                for item in self.paths
            ],
        )
        object.__setattr__(self, "metadata", json_object(self.metadata, "artifact_paths.metadata"))

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ArtifactPaths":
        data = _mapping(value, "artifact_paths")
        paths = _sequence(data.get("paths", []), "artifact_paths.paths")
        return cls(
            artifact_dir=_string(data.get("artifact_dir"), "artifact_paths.artifact_dir"),
            paths=[
                ArtifactPath.from_dict(_mapping(item, "artifact_paths.paths[]"))
                for item in paths
            ],
            metadata=json_object(data.get("metadata", {}), "artifact_paths.metadata"),
        )


@dataclass(frozen=True, slots=True)
class EndpointManifest(JsonModel):
    """One JSON-serializable manifest for one runnable endpoint."""

    endpoint_id: str
    provider: str
    exposure: str
    status: str
    role: str
    created_at: str
    ssh: EndpointSSHInfo
    interfaces: list[NetworkInterface]
    provider_resources: ProviderResources
    artifact_dir: str
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_non_empty_string(self.endpoint_id, "endpoint_id")
        _require_non_empty_string(self.provider, "provider")
        _require_non_empty_string(self.exposure, "exposure")
        _require_non_empty_string(self.status, "status")
        _require_non_empty_string(self.role, "role")
        _require_non_empty_string(self.created_at, "created_at")
        if not isinstance(self.ssh, EndpointSSHInfo):
            object.__setattr__(self, "ssh", EndpointSSHInfo.from_dict(_mapping(self.ssh, "ssh")))
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
        if not isinstance(self.provider_resources, ProviderResources):
            object.__setattr__(
                self,
                "provider_resources",
                ProviderResources.from_dict(_mapping(self.provider_resources, "provider_resources")),
            )
        object.__setattr__(self, "artifact_dir", _absolute_path(self.artifact_dir, "artifact_dir"))
        object.__setattr__(self, "metadata", json_object(self.metadata, "metadata"))

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "EndpointManifest":
        data = _mapping(value, "endpoint_manifest")
        interfaces = _sequence(data.get("interfaces"), "interfaces")
        return cls(
            endpoint_id=_string(data.get("endpoint_id"), "endpoint_id"),
            provider=_string(data.get("provider"), "provider"),
            exposure=_string(data.get("exposure"), "exposure"),
            status=_string(data.get("status"), "status"),
            role=_string(data.get("role"), "role"),
            created_at=_string(data.get("created_at"), "created_at"),
            ssh=EndpointSSHInfo.from_dict(_mapping(data.get("ssh"), "ssh")),
            interfaces=[
                NetworkInterface.from_dict(_mapping(item, "interfaces[]"))
                for item in interfaces
            ],
            provider_resources=ProviderResources.from_dict(
                _mapping(data.get("provider_resources"), "provider_resources")
            ),
            artifact_dir=_string(data.get("artifact_dir"), "artifact_dir"),
            metadata=json_object(data.get("metadata", {}), "metadata"),
        )

    def artifact_paths(self, paths: Sequence[ArtifactPath] = ()) -> ArtifactPaths:
        """Return a typed artifact path collection rooted at this manifest directory."""

        return ArtifactPaths(artifact_dir=self.artifact_dir, paths=list(paths))


def coerce_json_value(value: object) -> JSONValue:
    """Coerce provider-produced values into JSON-compatible manifest data."""

    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise TypeError(f"non-finite float is not valid JSON: {value!r}")
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        output: JSONObject = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"JSON object keys must be strings: {key!r}")
            output[key] = coerce_json_value(item)
        return output
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [coerce_json_value(item) for item in value]
    if isinstance(value, bytes):
        return {"hex": value.hex()}
    return str(value)


def json_object(value: object, name: str) -> JSONObject:
    """Coerce a mapping into a JSON object with string keys."""

    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    output: JSONObject = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ValueError(f"{name} keys must be strings")
        output[key] = coerce_json_value(item)
    return output


def string_list(value: object, name: str) -> list[str]:
    """Return a JSON array as a list of strings."""

    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{name} must be a list of strings")
    output: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{name} must be a list of strings")
        output.append(item)
    return output


def to_jsonable(value: Any) -> JSONValue:
    """Return a strict JSON-compatible copy of an endpoint model value."""

    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise TypeError(f"non-finite float is not valid JSON: {value!r}")
        return value
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field_info.name: to_jsonable(getattr(value, field_info.name))
            for field_info in fields(value)
        }
    if isinstance(value, Mapping):
        output: JSONObject = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"JSON object keys must be strings: {key!r}")
            output[key] = to_jsonable(item)
        return output
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [to_jsonable(item) for item in value]
    raise TypeError(f"value is not JSON-compatible: {type(value).__name__}")


def dumps_json(value: Any, *, indent: int = 2) -> str:
    """Serialize an endpoint value as deterministic JSON text."""

    return json.dumps(to_jsonable(value), indent=indent, sort_keys=True) + "\n"


def write_json(path: str | Path, value: Any, *, indent: int = 2) -> None:
    """Write an endpoint value as JSON, creating parent directories as needed."""

    output_path = Path(path)
    if not output_path.is_absolute():
        raise ValueError(f"JSON output path must be absolute: {path!r}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(dumps_json(value, indent=indent), encoding="utf-8")


def read_json(path: str | Path) -> JSONValue:
    """Read JSON text for later conversion into endpoint model objects."""

    input_path = Path(path)
    if not input_path.is_absolute():
        raise ValueError(f"JSON input path must be absolute: {path!r}")
    with input_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    for key in value:
        if not isinstance(key, str):
            raise ValueError(f"{name} keys must be strings")
    return value


def _sequence(value: object, name: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{name} must be a list")
    return value


def _string(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _optional_string(value: object, name: str) -> str | None:
    if value is None:
        return None
    return _string(value, name)


def _int(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    return value


def _bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def _require_non_empty_string(value: object, name: str) -> None:
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{name} must be a non-empty string")


def _absolute_path(value: str | Path, name: str) -> str:
    path = Path(value)
    if not path.is_absolute():
        raise ValueError(f"{name} must be an absolute path")
    return str(path)


def _optional_absolute_path(value: str | Path | None, name: str) -> str | None:
    if value is None:
        return None
    return _absolute_path(value, name)
