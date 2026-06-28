"""Persistent endpoint asset records for prepared reusable machines."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from .config import WireConfig, default_config
from .model import JSONObject, JsonModel, json_object, read_json, string_list, write_json


ASSETS_DIRNAME = "assets"
ASSET_RECORD_FILENAME = "asset.json"


@dataclass(frozen=True, slots=True)
class AssetSSHInfo(JsonModel):
    """SSH connection details for one reusable endpoint asset."""

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
    def from_dict(cls, value: Mapping[str, object]) -> "AssetSSHInfo":
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
class AssetHardware(JsonModel):
    """Inspectable hardware metadata for a prepared endpoint asset."""

    architecture: str | None = None
    cpu_count: int | None = None
    memory_mb: int | None = None
    disk_gb: int | None = None
    provider_instance_type: str | None = None
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "architecture",
            _optional_non_empty_string(self.architecture, "hardware.architecture"),
        )
        object.__setattr__(
            self,
            "cpu_count",
            _optional_positive_int(self.cpu_count, "hardware.cpu_count"),
        )
        object.__setattr__(
            self,
            "memory_mb",
            _optional_positive_int(self.memory_mb, "hardware.memory_mb"),
        )
        object.__setattr__(
            self,
            "disk_gb",
            _optional_positive_int(self.disk_gb, "hardware.disk_gb"),
        )
        object.__setattr__(
            self,
            "provider_instance_type",
            _optional_non_empty_string(
                self.provider_instance_type,
                "hardware.provider_instance_type",
            ),
        )
        object.__setattr__(
            self,
            "metadata",
            json_object(self.metadata, "hardware.metadata"),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "AssetHardware":
        data = _mapping(value, "hardware")
        return cls(
            architecture=_optional_string(data.get("architecture"), "hardware.architecture"),
            cpu_count=_optional_int(data.get("cpu_count"), "hardware.cpu_count"),
            memory_mb=_optional_int(data.get("memory_mb"), "hardware.memory_mb"),
            disk_gb=_optional_int(data.get("disk_gb"), "hardware.disk_gb"),
            provider_instance_type=_optional_string(
                data.get("provider_instance_type"),
                "hardware.provider_instance_type",
            ),
            metadata=json_object(data.get("metadata", {}), "hardware.metadata"),
        )


@dataclass(frozen=True, slots=True)
class EndpointLease(JsonModel):
    """Lease state for temporary use of a prepared endpoint asset."""

    holder: str
    leased_until: str
    ttl_seconds: int
    leased_at: str | None = None
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_non_empty_string(self.holder, "lease.holder")
        _require_non_empty_string(self.leased_until, "lease.leased_until")
        ttl_seconds = _int(self.ttl_seconds, "lease.ttl_seconds")
        if ttl_seconds <= 0:
            raise ValueError("lease.ttl_seconds must be a positive integer")
        object.__setattr__(self, "ttl_seconds", ttl_seconds)
        object.__setattr__(
            self,
            "leased_at",
            _optional_non_empty_string(self.leased_at, "lease.leased_at"),
        )
        object.__setattr__(self, "metadata", json_object(self.metadata, "lease.metadata"))

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "EndpointLease":
        data = _mapping(value, "lease")
        return cls(
            holder=_string(data.get("holder"), "lease.holder"),
            leased_until=_string(data.get("leased_until"), "lease.leased_until"),
            ttl_seconds=_int(data.get("ttl_seconds"), "lease.ttl_seconds"),
            leased_at=_optional_string(data.get("leased_at"), "lease.leased_at"),
            metadata=json_object(data.get("metadata", {}), "lease.metadata"),
        )


@dataclass(frozen=True, slots=True)
class EndpointAsset(JsonModel):
    """Persistent record for one prepared reusable endpoint machine."""

    asset_id: str
    substrate: str
    status: str
    supported_profiles: list[str]
    ssh: AssetSSHInfo
    docker: JSONObject = field(default_factory=dict)
    hardware: AssetHardware = field(default_factory=AssetHardware)
    last_check: str | None = None
    lease: EndpointLease | None = None
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "asset_id", asset_component(self.asset_id))
        _require_non_empty_string(self.substrate, "substrate")
        _require_non_empty_string(self.status, "status")
        object.__setattr__(
            self,
            "supported_profiles",
            _unique_non_empty_strings(self.supported_profiles, "supported_profiles"),
        )
        if not isinstance(self.ssh, AssetSSHInfo):
            object.__setattr__(self, "ssh", AssetSSHInfo.from_dict(_mapping(self.ssh, "ssh")))
        object.__setattr__(self, "docker", json_object(self.docker, "docker"))
        if not isinstance(self.hardware, AssetHardware):
            object.__setattr__(
                self,
                "hardware",
                AssetHardware.from_dict(_mapping(self.hardware, "hardware")),
            )
        object.__setattr__(
            self,
            "last_check",
            _optional_non_empty_string(self.last_check, "last_check"),
        )
        if self.lease is not None and not isinstance(self.lease, EndpointLease):
            object.__setattr__(
                self,
                "lease",
                EndpointLease.from_dict(_mapping(self.lease, "lease")),
            )
        object.__setattr__(self, "metadata", json_object(self.metadata, "metadata"))

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "EndpointAsset":
        data = _mapping(value, "endpoint_asset")
        lease_value = data.get("lease")
        return cls(
            asset_id=_string(data.get("asset_id"), "asset_id"),
            substrate=_string(data.get("substrate"), "substrate"),
            status=_string(data.get("status"), "status"),
            supported_profiles=string_list(
                data.get("supported_profiles", []),
                "supported_profiles",
            ),
            ssh=AssetSSHInfo.from_dict(_mapping(data.get("ssh"), "ssh")),
            docker=json_object(data.get("docker", {}), "docker"),
            hardware=AssetHardware.from_dict(_mapping(data.get("hardware", {}), "hardware")),
            last_check=_optional_string(data.get("last_check"), "last_check"),
            lease=None
            if lease_value is None
            else EndpointLease.from_dict(_mapping(lease_value, "lease")),
            metadata=json_object(data.get("metadata", {}), "metadata"),
        )


def asset_state_dir(asset_id: str, config: WireConfig | None = None) -> Path:
    """Return the state directory for one prepared endpoint asset."""

    return _assets_root(config) / asset_component(asset_id)


def asset_record_path(asset_id: str, config: WireConfig | None = None) -> Path:
    """Return the persistent asset record path."""

    return asset_state_dir(asset_id, config) / ASSET_RECORD_FILENAME


def write_endpoint_asset(asset: EndpointAsset, config: WireConfig | None = None) -> Path:
    """Persist one endpoint asset record and return its absolute JSON path."""

    if not isinstance(asset, EndpointAsset):
        raise TypeError("asset must be an EndpointAsset")
    path = asset_record_path(asset.asset_id, config)
    write_json(path, asset)
    return path


def read_endpoint_asset(asset_id: str, config: WireConfig | None = None) -> EndpointAsset:
    """Read one persistent endpoint asset record."""

    path = asset_record_path(asset_id, config)
    value = read_json(path)
    if not isinstance(value, Mapping):
        raise ValueError(f"endpoint asset must be a JSON object: {path}")
    return EndpointAsset.from_dict(value)


def list_endpoint_assets(config: WireConfig | None = None) -> list[EndpointAsset]:
    """Return stored endpoint asset records sorted by asset ID."""

    assets: dict[str, EndpointAsset] = {}
    root = _assets_root(config)
    if root.exists():
        for path in sorted(root.glob(f"*/{ASSET_RECORD_FILENAME}")):
            value = read_json(path)
            if not isinstance(value, Mapping):
                raise ValueError(f"endpoint asset must be a JSON object: {path}")
            asset = EndpointAsset.from_dict(value)
            assets.setdefault(asset.asset_id, asset)
    return [assets[asset_id] for asset_id in sorted(assets)]


def asset_component(asset_id: str) -> str:
    """Validate and return an asset ID usable as one local path component."""

    if not isinstance(asset_id, str) or asset_id == "":
        raise ValueError("asset_id must be a non-empty string")
    path = Path(asset_id)
    if path.is_absolute() or len(path.parts) != 1 or asset_id in {".", ".."}:
        raise ValueError(f"asset_id must be a single path component: {asset_id!r}")
    return asset_id


def _config(config: WireConfig | None) -> WireConfig:
    return default_config() if config is None else config


def _assets_root(config: WireConfig | None = None) -> Path:
    return _config(config).state_root / ASSETS_DIRNAME


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be a JSON object")
    for key in value:
        if not isinstance(key, str):
            raise ValueError(f"{name} keys must be strings")
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


def _optional_int(value: object, name: str) -> int | None:
    if value is None:
        return None
    return _int(value, name)


def _require_non_empty_string(value: object, name: str) -> None:
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{name} must be a non-empty string")


def _optional_non_empty_string(value: object, name: str) -> str | None:
    if value is None:
        return None
    _require_non_empty_string(value, name)
    return value


def _optional_positive_int(value: int | None, name: str) -> int | None:
    if value is None:
        return None
    output = _int(value, name)
    if output <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return output


def _unique_non_empty_strings(value: object, name: str) -> list[str]:
    values = string_list(value, name)
    output: list[str] = []
    for item in values:
        if item == "":
            raise ValueError(f"{name} must contain only non-empty strings")
        if item not in output:
            output.append(item)
    return output


def _absolute_path(value: str | Path, name: str) -> str:
    path = Path(value)
    if not path.is_absolute():
        raise ValueError(f"{name} must be an absolute path")
    return str(path)


def _optional_absolute_path(value: str | Path | None, name: str) -> str | None:
    if value is None:
        return None
    return _absolute_path(value, name)
