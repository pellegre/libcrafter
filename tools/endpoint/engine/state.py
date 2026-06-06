"""Endpoint local state management."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from .config import WireConfig, default_config
from .model import EndpointManifest, read_json, write_json


ENDPOINTS_DIRNAME = "endpoints"
PRIVATE_GROUPS_DIRNAME = "private-groups"
MANIFEST_FILENAME = "endpoint.json"
LEGACY_MANIFEST_FILENAME = "manifest.json"
PRIVATE_KEY_FILENAME = "id_ed25519"
KNOWN_HOSTS_FILENAME = "known_hosts"
DEFAULT_PRIVATE_CIDR = "10.42.19.0/24"


@dataclass(frozen=True, slots=True)
class EndpointLayout:
    """Absolute local paths owned by one endpoint."""

    state_dir: Path
    manifest_path: Path
    private_key_path: Path
    known_hosts_path: Path
    artifact_dir: Path


@dataclass(frozen=True, slots=True)
class PrivateGroupRecord:
    """Internal local state for one provider private network group."""

    provider: str
    group: str
    private_cidr: str = DEFAULT_PRIVATE_CIDR
    network_resource: dict[str, object] = field(default_factory=dict)
    allocated_endpoint_ids: list[str] = field(default_factory=list)
    allocated_private_ipv4s: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        _private_group_component(self.provider, "provider")
        _private_group_component(self.group, "group")
        if not isinstance(self.private_cidr, str) or self.private_cidr == "":
            raise ValueError("private_cidr must be a non-empty string")
        if not isinstance(self.network_resource, Mapping):
            raise ValueError("network_resource must be a JSON object")
        object.__setattr__(self, "network_resource", dict(self.network_resource))
        object.__setattr__(
            self,
            "allocated_endpoint_ids",
            _unique_strings(self.allocated_endpoint_ids, "allocated_endpoint_ids"),
        )
        object.__setattr__(
            self,
            "allocated_private_ipv4s",
            _unique_strings(self.allocated_private_ipv4s, "allocated_private_ipv4s"),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "PrivateGroupRecord":
        data = _mapping(value, "private group record")
        return cls(
            provider=_string(data.get("provider"), "provider"),
            group=_string(data.get("group"), "group"),
            private_cidr=_string(data.get("private_cidr"), "private_cidr"),
            network_resource=dict(_mapping(data.get("network_resource", {}), "network_resource")),
            allocated_endpoint_ids=_string_list(
                data.get("allocated_endpoint_ids", []),
                "allocated_endpoint_ids",
            ),
            allocated_private_ipv4s=_string_list(
                data.get("allocated_private_ipv4s", []),
                "allocated_private_ipv4s",
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "group": self.group,
            "private_cidr": self.private_cidr,
            "network_resource": self.network_resource,
            "allocated_endpoint_ids": self.allocated_endpoint_ids,
            "allocated_private_ipv4s": self.allocated_private_ipv4s,
        }


def endpoint_layout(endpoint_id: str, config: WireConfig | None = None) -> EndpointLayout:
    """Return all absolute local paths for an endpoint."""

    return EndpointLayout(
        state_dir=endpoint_state_dir(endpoint_id, config),
        manifest_path=endpoint_manifest_path(endpoint_id, config),
        private_key_path=endpoint_private_key_path(endpoint_id, config),
        known_hosts_path=endpoint_known_hosts_path(endpoint_id, config),
        artifact_dir=endpoint_artifact_dir(endpoint_id, config),
    )


def endpoint_state_dir(endpoint_id: str, config: WireConfig | None = None) -> Path:
    """Return the endpoint state directory."""

    return _endpoints_root(config) / _endpoint_component(endpoint_id)


def endpoint_manifest_path(endpoint_id: str, config: WireConfig | None = None) -> Path:
    """Return the endpoint manifest JSON path."""

    return endpoint_state_dir(endpoint_id, config) / MANIFEST_FILENAME


def endpoint_private_key_path(endpoint_id: str, config: WireConfig | None = None) -> Path:
    """Return the endpoint private SSH key path."""

    return endpoint_state_dir(endpoint_id, config) / PRIVATE_KEY_FILENAME


def endpoint_known_hosts_path(endpoint_id: str, config: WireConfig | None = None) -> Path:
    """Return the endpoint known-hosts file path."""

    return endpoint_state_dir(endpoint_id, config) / KNOWN_HOSTS_FILENAME


def endpoint_artifact_dir(endpoint_id: str, config: WireConfig | None = None) -> Path:
    """Return the endpoint artifact directory."""

    return _config(config).artifact_root / _endpoint_component(endpoint_id)


def private_group_path(
    provider: str,
    group: str,
    config: WireConfig | None = None,
) -> Path:
    """Return the private group record path."""

    return (
        _private_groups_root(config)
        / _private_group_component(provider, "provider")
        / f"{_private_group_component(group, 'group')}.json"
    )


def planned_private_group_record(
    *,
    provider: str,
    group: str,
    private_cidr: str = DEFAULT_PRIVATE_CIDR,
    network_resource: Mapping[str, object] | None = None,
) -> PrivateGroupRecord:
    """Return an unsaved private group record for planning output."""

    return PrivateGroupRecord(
        provider=provider,
        group=group,
        private_cidr=private_cidr,
        network_resource={} if network_resource is None else dict(network_resource),
    )


def read_private_group_record(
    provider: str,
    group: str,
    config: WireConfig | None = None,
) -> PrivateGroupRecord:
    """Read one internal private group record from local state."""

    path = private_group_path(provider, group, config)
    value = read_json(path)
    if not isinstance(value, Mapping):
        raise ValueError(f"private group record must be a JSON object: {path}")
    return PrivateGroupRecord.from_dict(value)


def write_private_group_record(
    record: PrivateGroupRecord,
    config: WireConfig | None = None,
) -> Path:
    """Persist one internal private group record and return its path."""

    if not isinstance(record, PrivateGroupRecord):
        raise TypeError("record must be a PrivateGroupRecord")
    path = private_group_path(record.provider, record.group, config)
    write_json(path, record.to_dict())
    return path


def update_private_group_allocation(
    *,
    provider: str,
    group: str,
    endpoint_id: str,
    private_ipv4: str | None = None,
    private_cidr: str = DEFAULT_PRIVATE_CIDR,
    network_resource: Mapping[str, object] | None = None,
    config: WireConfig | None = None,
) -> PrivateGroupRecord:
    """Add one endpoint allocation to an internal private group record."""

    path = private_group_path(provider, group, config)
    if path.exists():
        record = read_private_group_record(provider, group, config)
    else:
        record = PrivateGroupRecord(
            provider=provider,
            group=group,
            private_cidr=private_cidr,
            network_resource={} if network_resource is None else dict(network_resource),
        )

    endpoint_ids = [*record.allocated_endpoint_ids]
    if endpoint_id not in endpoint_ids:
        endpoint_ids.append(endpoint_id)

    private_ipv4s = [*record.allocated_private_ipv4s]
    if private_ipv4 is not None and private_ipv4 not in private_ipv4s:
        private_ipv4s.append(private_ipv4)

    updated = PrivateGroupRecord(
        provider=record.provider,
        group=record.group,
        private_cidr=record.private_cidr,
        network_resource=(
            record.network_resource if network_resource is None else dict(network_resource)
        ),
        allocated_endpoint_ids=endpoint_ids,
        allocated_private_ipv4s=private_ipv4s,
    )
    write_private_group_record(updated, config)
    return updated


def remove_private_group_allocation(
    *,
    provider: str,
    group: str,
    endpoint_id: str,
    private_ipv4: str | None = None,
    config: WireConfig | None = None,
) -> PrivateGroupRecord:
    """Remove one endpoint allocation from an internal private group record."""

    record = read_private_group_record(provider, group, config)
    endpoint_was_allocated = endpoint_id in record.allocated_endpoint_ids
    endpoint_ids = [
        allocated_endpoint_id
        for allocated_endpoint_id in record.allocated_endpoint_ids
        if allocated_endpoint_id != endpoint_id
    ]
    private_ipv4s = [*record.allocated_private_ipv4s]
    if endpoint_was_allocated and private_ipv4 is not None:
        private_ipv4s = [
            allocated_private_ipv4
            for allocated_private_ipv4 in private_ipv4s
            if allocated_private_ipv4 != private_ipv4
        ]

    updated = PrivateGroupRecord(
        provider=record.provider,
        group=record.group,
        private_cidr=record.private_cidr,
        network_resource=record.network_resource,
        allocated_endpoint_ids=endpoint_ids,
        allocated_private_ipv4s=private_ipv4s,
    )
    write_private_group_record(updated, config)
    return updated


def ensure_endpoint_dirs(endpoint_id: str, config: WireConfig | None = None) -> EndpointLayout:
    """Create the local state and artifact directories for an endpoint."""

    layout = endpoint_layout(endpoint_id, config)
    layout.state_dir.mkdir(parents=True, exist_ok=True)
    layout.artifact_dir.mkdir(parents=True, exist_ok=True)
    return layout


def write_endpoint_manifest(
    manifest: EndpointManifest,
    config: WireConfig | None = None,
) -> Path:
    """Persist one endpoint manifest and return its absolute JSON path."""

    if not isinstance(manifest, EndpointManifest):
        raise TypeError("manifest must be an EndpointManifest")
    layout = ensure_endpoint_dirs(manifest.endpoint_id, config)
    write_json(layout.manifest_path, manifest)
    return layout.manifest_path


def read_endpoint_manifest(
    endpoint_id: str,
    config: WireConfig | None = None,
) -> EndpointManifest:
    """Read one endpoint manifest from local state."""

    path = _existing_manifest_path(endpoint_id, config)
    value = read_json(path)
    if not isinstance(value, Mapping):
        raise ValueError(f"endpoint manifest must be a JSON object: {path}")
    return EndpointManifest.from_dict(value)


def update_endpoint_status(
    endpoint_id: str,
    status: str,
    config: WireConfig | None = None,
) -> EndpointManifest:
    """Update one endpoint manifest status and return the stored manifest."""

    if not isinstance(status, str) or status == "":
        raise ValueError("status must be a non-empty string")
    manifest = replace(read_endpoint_manifest(endpoint_id, config), status=status)
    write_endpoint_manifest(manifest, config)
    return manifest


def list_endpoint_manifests(config: WireConfig | None = None) -> list[EndpointManifest]:
    """Return all stored endpoint manifests sorted by endpoint ID."""

    manifests: dict[str, EndpointManifest] = {}
    for path in _manifest_paths(config):
        value = read_json(path)
        if not isinstance(value, Mapping):
            raise ValueError(f"endpoint manifest must be a JSON object: {path}")
        manifest = EndpointManifest.from_dict(value)
        manifests.setdefault(manifest.endpoint_id, manifest)
    return [manifests[endpoint_id] for endpoint_id in sorted(manifests)]


def _config(config: WireConfig | None) -> WireConfig:
    return default_config() if config is None else config


def _endpoints_root(config: WireConfig | None = None) -> Path:
    return _config(config).state_root / ENDPOINTS_DIRNAME


def _private_groups_root(config: WireConfig | None = None) -> Path:
    return _config(config).state_root / PRIVATE_GROUPS_DIRNAME


def _legacy_endpoint_state_dir(endpoint_id: str, config: WireConfig | None = None) -> Path:
    return _config(config).state_root / _endpoint_component(endpoint_id)


def _legacy_endpoint_manifest_path(endpoint_id: str, config: WireConfig | None = None) -> Path:
    return _legacy_endpoint_state_dir(endpoint_id, config) / LEGACY_MANIFEST_FILENAME


def _existing_manifest_path(endpoint_id: str, config: WireConfig | None = None) -> Path:
    preferred = endpoint_manifest_path(endpoint_id, config)
    if preferred.exists():
        return preferred
    legacy = _legacy_endpoint_manifest_path(endpoint_id, config)
    if legacy.exists():
        return legacy
    raise FileNotFoundError(f"endpoint manifest not found for {endpoint_id!r}: {preferred}")


def _manifest_paths(config: WireConfig | None = None) -> list[Path]:
    cfg = _config(config)
    paths: list[Path] = []
    endpoints_root = cfg.state_root / ENDPOINTS_DIRNAME
    if endpoints_root.exists():
        paths.extend(sorted(endpoints_root.glob(f"*/{MANIFEST_FILENAME}")))
    if cfg.state_root.exists():
        paths.extend(sorted(cfg.state_root.glob(f"*/{LEGACY_MANIFEST_FILENAME}")))
    return paths


def _endpoint_component(endpoint_id: str) -> str:
    if not isinstance(endpoint_id, str) or endpoint_id == "":
        raise ValueError("endpoint_id must be a non-empty string")
    path = Path(endpoint_id)
    if path.is_absolute() or len(path.parts) != 1 or endpoint_id in {".", ".."}:
        raise ValueError(f"endpoint_id must be a single path component: {endpoint_id!r}")
    return endpoint_id


def _private_group_component(value: str, name: str) -> str:
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{name} must be a non-empty string")
    path = Path(value)
    if path.is_absolute() or len(path.parts) != 1 or value in {".", ".."}:
        raise ValueError(f"{name} must be a single path component: {value!r}")
    return value


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be a JSON object")
    for key in value:
        if not isinstance(key, str):
            raise ValueError(f"{name} keys must be strings")
    return value


def _string(value: object, name: str) -> str:
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _string_list(value: object, name: str) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{name} must be a list")
    return _unique_strings(value, name)


def _unique_strings(values: Sequence[object], name: str) -> list[str]:
    output: list[str] = []
    for value in values:
        if not isinstance(value, str) or value == "":
            raise ValueError(f"{name} must contain only non-empty strings")
        if value not in output:
            output.append(value)
    return output
