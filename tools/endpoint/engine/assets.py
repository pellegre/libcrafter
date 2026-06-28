"""Persistent endpoint asset records for prepared reusable machines."""

from __future__ import annotations

import errno
import fcntl
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import IO, Protocol

from .config import WireConfig, default_config
from .model import JSONObject, JsonModel, json_object, read_json, string_list, write_json


ASSETS_DIRNAME = "assets"
ASSET_RECORD_FILENAME = "asset.json"
ASSET_LOCK_FILENAME = "asset.lock"


class AssetLockBlocked(RuntimeError):
    """Raised when an endpoint asset lock is already held."""


class AssetLeaseConflict(RuntimeError):
    """Raised when an active endpoint asset lease belongs to another holder."""


class AssetLock(Protocol):
    """Context manager for an asset lock."""

    def __enter__(self) -> object: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...


class AssetLockFactory(Protocol):
    """Factory for asset lock context managers."""

    def __call__(self, path: Path) -> AssetLock: ...


class AssetFileLock:
    """Nonblocking advisory file lock for one endpoint asset record."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._handle: IO[str] | None = None

    def __enter__(self) -> "AssetFileLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            handle.close()
            if error.errno in {errno.EACCES, errno.EAGAIN}:
                raise AssetLockBlocked(f"endpoint asset lock is held: {self.path}") from error
            raise
        self._handle = handle
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._handle is not None:
            handle = self._handle
            self._handle = None
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()


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

    @property
    def expires_at(self) -> str:
        """Return the lease expiry timestamp using the newer API wording."""

        return self.leased_until

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "EndpointLease":
        data = _mapping(value, "lease")
        leased_until = data.get("leased_until", data.get("expires_at"))
        return cls(
            holder=_string(data.get("holder"), "lease.holder"),
            leased_until=_string(leased_until, "lease.leased_until"),
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


def asset_lock_path(asset_id: str, config: WireConfig | None = None) -> Path:
    """Return the advisory lock path for one endpoint asset record."""

    return asset_state_dir(asset_id, config) / ASSET_LOCK_FILENAME


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


def acquire_endpoint_asset(
    asset_id: str,
    holder: str,
    ttl_seconds: int,
    *,
    owner: str | None = None,
    metadata: Mapping[str, object] | None = None,
    now: datetime | str | None = None,
    config: WireConfig | None = None,
    lock_factory: AssetLockFactory = AssetFileLock,
) -> EndpointAsset:
    """Acquire or refresh a lease for one endpoint asset under its file lock."""

    _require_non_empty_string(holder, "holder")
    ttl = _int(ttl_seconds, "ttl_seconds")
    if ttl <= 0:
        raise ValueError("ttl_seconds must be a positive integer")
    leased_at = _coerce_utc_datetime(now, "now") if now is not None else _utc_now()
    expires_at = leased_at + timedelta(seconds=ttl)
    lease_metadata = _lease_metadata(holder, owner, metadata)

    with lock_factory(asset_lock_path(asset_id, config)):
        asset = read_endpoint_asset(asset_id, config)
        if asset.lease is not None and not asset_lease_expired(asset.lease, now=leased_at):
            if asset.lease.holder != holder:
                raise AssetLeaseConflict(
                    f"endpoint asset {asset.asset_id!r} is leased by "
                    f"{asset.lease.holder!r} until {asset.lease.expires_at}"
                )
        leased = EndpointAsset(
            asset_id=asset.asset_id,
            substrate=asset.substrate,
            status=asset.status,
            supported_profiles=asset.supported_profiles,
            ssh=asset.ssh,
            docker=asset.docker,
            hardware=asset.hardware,
            last_check=asset.last_check,
            lease=EndpointLease(
                holder=holder,
                leased_at=_format_utc(leased_at),
                leased_until=_format_utc(expires_at),
                ttl_seconds=ttl,
                metadata=lease_metadata,
            ),
            metadata=asset.metadata,
        )
        write_endpoint_asset(leased, config)
        return leased


def release_endpoint_asset(
    asset_id: str,
    holder: str,
    *,
    now: datetime | str | None = None,
    force: bool = False,
    config: WireConfig | None = None,
    lock_factory: AssetLockFactory = AssetFileLock,
) -> EndpointAsset:
    """Release a lease for one endpoint asset under its file lock."""

    _require_non_empty_string(holder, "holder")
    release_at = _coerce_utc_datetime(now, "now") if now is not None else _utc_now()

    with lock_factory(asset_lock_path(asset_id, config)):
        asset = read_endpoint_asset(asset_id, config)
        if asset.lease is None:
            return asset
        if (
            not force
            and asset.lease.holder != holder
            and not asset_lease_expired(asset.lease, now=release_at)
        ):
            raise AssetLeaseConflict(
                f"endpoint asset {asset.asset_id!r} is leased by "
                f"{asset.lease.holder!r} until {asset.lease.expires_at}"
            )
        released = EndpointAsset(
            asset_id=asset.asset_id,
            substrate=asset.substrate,
            status=asset.status,
            supported_profiles=asset.supported_profiles,
            ssh=asset.ssh,
            docker=asset.docker,
            hardware=asset.hardware,
            last_check=asset.last_check,
            lease=None,
            metadata=asset.metadata,
        )
        write_endpoint_asset(released, config)
        return released


def asset_lease_expired(
    lease: EndpointLease,
    *,
    now: datetime | str | None = None,
) -> bool:
    """Return whether a lease has expired at the given UTC instant."""

    current = _coerce_utc_datetime(now, "now") if now is not None else _utc_now()
    return _coerce_utc_datetime(lease.expires_at, "lease.expires_at") <= current


def asset_component(asset_id: str) -> str:
    """Validate and return an asset ID usable as one local path component."""

    if not isinstance(asset_id, str) or asset_id == "":
        raise ValueError("asset_id must be a non-empty string")
    path = Path(asset_id)
    if path.is_absolute() or len(path.parts) != 1 or asset_id in {".", ".."}:
        raise ValueError(f"asset_id must be a single path component: {asset_id!r}")
    return asset_id


def _lease_metadata(
    holder: str,
    owner: str | None,
    metadata: Mapping[str, object] | None,
) -> JSONObject:
    output = json_object({} if metadata is None else metadata, "lease.metadata")
    output.setdefault("owner", holder if owner is None else owner)
    return output


def _utc_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _coerce_utc_datetime(value: datetime | str, name: str) -> datetime:
    if isinstance(value, datetime):
        output = value
    elif isinstance(value, str):
        raw = value
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        try:
            output = datetime.fromisoformat(raw)
        except ValueError as error:
            raise ValueError(f"{name} must be an ISO 8601 timestamp") from error
    else:
        raise ValueError(f"{name} must be an ISO 8601 timestamp")
    if output.tzinfo is None:
        output = output.replace(tzinfo=UTC)
    return output.astimezone(UTC).replace(microsecond=0)


def _format_utc(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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
