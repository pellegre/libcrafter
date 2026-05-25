"""Wire local state management."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path

from .config import WireConfig, default_config
from .model import EndpointManifest, read_json, write_json


ENDPOINTS_DIRNAME = "endpoints"
MANIFEST_FILENAME = "endpoint.json"
LEGACY_MANIFEST_FILENAME = "manifest.json"
PRIVATE_KEY_FILENAME = "id_ed25519"
KNOWN_HOSTS_FILENAME = "known_hosts"


@dataclass(frozen=True, slots=True)
class EndpointLayout:
    """Absolute local paths owned by one endpoint."""

    state_dir: Path
    manifest_path: Path
    private_key_path: Path
    known_hosts_path: Path
    artifact_dir: Path


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
