"""Lab session local state management."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from .model import LabSession, read_json, write_json
from .paths import (
    MANIFEST_FILENAME,
    SESSIONS_DIRNAME,
    LabConfig,
    LabSessionLayout,
    default_config,
    session_layout,
    session_manifest_path,
)


def ensure_session_dirs(session_id: str, config: LabConfig | None = None) -> LabSessionLayout:
    """Create the local state and artifact directories for a session."""

    layout = session_layout(session_id, config)
    layout.state_dir.mkdir(parents=True, exist_ok=True)
    layout.command_artifact_root.mkdir(parents=True, exist_ok=True)
    return layout


def write_session_manifest(
    session: LabSession,
    config: LabConfig | None = None,
) -> Path:
    """Persist one lab session manifest and return its absolute JSON path."""

    if not isinstance(session, LabSession):
        raise TypeError("session must be a LabSession")
    layout = ensure_session_dirs(session.session_id, config)
    write_json(layout.manifest_path, session)
    return layout.manifest_path


def read_session_manifest(
    session_id: str,
    config: LabConfig | None = None,
) -> LabSession:
    """Read one lab session manifest from local state."""

    path = session_manifest_path(session_id, config)
    value = read_json(path)
    if not isinstance(value, Mapping):
        raise ValueError(f"lab session manifest must be a JSON object: {path}")
    return LabSession.from_dict(value)


def list_session_manifests(config: LabConfig | None = None) -> list[LabSession]:
    """Return all stored lab session manifests sorted by session ID."""

    manifests: dict[str, LabSession] = {}
    for path in _manifest_paths(config):
        value = read_json(path)
        if not isinstance(value, Mapping):
            raise ValueError(f"lab session manifest must be a JSON object: {path}")
        session = LabSession.from_dict(value)
        manifests.setdefault(session.session_id, session)
    return [manifests[session_id] for session_id in sorted(manifests)]


def _manifest_paths(config: LabConfig | None = None) -> list[Path]:
    cfg = default_config() if config is None else config
    sessions_root = cfg.state_root / SESSIONS_DIRNAME
    if not sessions_root.exists():
        return []
    return sorted(sessions_root.glob(f"*/{MANIFEST_FILENAME}"))
