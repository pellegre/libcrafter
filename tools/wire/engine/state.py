"""Wire local state management."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .config import WireConfig, default_config


MANIFEST_FILENAME = "manifest.json"
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

    return _config(config).state_root / _endpoint_component(endpoint_id)


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


def _config(config: WireConfig | None) -> WireConfig:
    return default_config() if config is None else config


def _endpoint_component(endpoint_id: str) -> str:
    if not isinstance(endpoint_id, str) or endpoint_id == "":
        raise ValueError("endpoint_id must be a non-empty string")
    path = Path(endpoint_id)
    if path.is_absolute() or len(path.parts) != 1 or endpoint_id in {".", ".."}:
        raise ValueError(f"endpoint_id must be a single path component: {endpoint_id!r}")
    return endpoint_id
