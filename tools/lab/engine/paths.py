"""Lab local and remote path helpers."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


LAB_STATE_ROOT_ENV = "LIBCRAFTER_LAB_STATE_ROOT"
LAB_ARTIFACT_ROOT_ENV = "LIBCRAFTER_LAB_ARTIFACT_ROOT"
LAB_STATE_DIR_ENV = "LIBCRAFTER_LAB_STATE_DIR"
LAB_ARTIFACT_DIR_ENV = "LIBCRAFTER_LAB_ARTIFACT_DIR"

LAB_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STATE_ROOT = LAB_ROOT / ".state"
DEFAULT_ARTIFACT_ROOT = LAB_ROOT / "artifacts"
DEFAULT_REMOTE_ROOT = PurePosixPath("/opt/libcrafter-lab")

SESSIONS_DIRNAME = "sessions"
COMMANDS_DIRNAME = "commands"
MANIFEST_FILENAME = "session.json"
REMOTE_ARTIFACTS_DIRNAME = "artifacts"

_PATH_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


@dataclass(frozen=True, slots=True)
class LabConfig:
    """Local lab path configuration."""

    state_root: Path
    artifact_root: Path

    def __post_init__(self) -> None:
        object.__setattr__(self, "state_root", absolute_path(self.state_root))
        object.__setattr__(self, "artifact_root", absolute_path(self.artifact_root))


@dataclass(frozen=True, slots=True)
class LabSessionLayout:
    """Absolute local paths owned by one lab session."""

    state_dir: Path
    manifest_path: Path
    artifact_dir: Path
    command_artifact_root: Path


def default_config(env: Mapping[str, str] | None = None) -> LabConfig:
    """Return lab configuration from environment overrides and local defaults."""

    source = os.environ if env is None else env
    return LabConfig(
        state_root=_env_path(
            source,
            LAB_STATE_ROOT_ENV,
            LAB_STATE_DIR_ENV,
            default=DEFAULT_STATE_ROOT,
        ),
        artifact_root=_env_path(
            source,
            LAB_ARTIFACT_ROOT_ENV,
            LAB_ARTIFACT_DIR_ENV,
            default=DEFAULT_ARTIFACT_ROOT,
        ),
    )


def absolute_path(path: str | Path) -> Path:
    """Return an absolute local path without requiring it to exist."""

    output = Path(path).expanduser()
    if not output.is_absolute():
        output = Path.cwd() / output
    return output.resolve(strict=False)


def session_layout(session_id: str, config: LabConfig | None = None) -> LabSessionLayout:
    """Return all absolute local paths for a lab session."""

    artifact_dir = session_artifact_dir(session_id, config)
    return LabSessionLayout(
        state_dir=session_state_dir(session_id, config),
        manifest_path=session_manifest_path(session_id, config),
        artifact_dir=artifact_dir,
        command_artifact_root=artifact_dir / COMMANDS_DIRNAME,
    )


def session_state_dir(session_id: str, config: LabConfig | None = None) -> Path:
    """Return the session state directory."""

    return _sessions_root(config) / path_component(session_id, "session_id")


def session_manifest_path(session_id: str, config: LabConfig | None = None) -> Path:
    """Return the session manifest JSON path."""

    return session_state_dir(session_id, config) / MANIFEST_FILENAME


def session_artifact_dir(session_id: str, config: LabConfig | None = None) -> Path:
    """Return the session artifact directory."""

    return _config(config).artifact_root / path_component(session_id, "session_id")


def command_artifact_dir(
    session_id: str,
    command_id: str,
    config: LabConfig | None = None,
) -> Path:
    """Return the local artifact directory for one command in a session."""

    return (
        session_artifact_dir(session_id, config)
        / COMMANDS_DIRNAME
        / path_component(command_id, "command_id")
    )


def command_artifact_path(
    session_id: str,
    command_id: str,
    name: str,
    config: LabConfig | None = None,
) -> Path:
    """Return one local command artifact path."""

    return command_artifact_dir(session_id, command_id, config) / path_component(
        name,
        "artifact_name",
    )


def remote_session_dir(
    session_id: str,
    *,
    remote_root: str | PurePosixPath | None = None,
) -> str:
    """Return the remote session directory for a lab session."""

    root = _remote_absolute_path(DEFAULT_REMOTE_ROOT if remote_root is None else remote_root)
    return str(root / path_component(session_id, "session_id"))


def remote_artifact_root(
    session_id: str,
    *,
    remote_dir: str | PurePosixPath | None = None,
    remote_root: str | PurePosixPath | None = None,
) -> str:
    """Return the remote artifact root for a lab session."""

    base = (
        _remote_absolute_path(remote_dir)
        if remote_dir is not None
        else PurePosixPath(remote_session_dir(session_id, remote_root=remote_root))
    )
    return str(base / REMOTE_ARTIFACTS_DIRNAME)


def path_component(value: str, name: str) -> str:
    """Validate and return one filesystem-safe path component."""

    if not isinstance(value, str) or value == "":
        raise ValueError(f"{name} must be a non-empty string")
    if _PATH_COMPONENT_RE.fullmatch(value) is None:
        raise ValueError(f"{name} must be a safe path component")
    path = Path(value)
    if path.is_absolute() or len(path.parts) != 1 or value in {".", ".."}:
        raise ValueError(f"{name} must be a single path component")
    return value


def _config(config: LabConfig | None) -> LabConfig:
    return default_config() if config is None else config


def _sessions_root(config: LabConfig | None = None) -> Path:
    return _config(config).state_root / SESSIONS_DIRNAME


def _env_path(
    env: Mapping[str, str],
    primary_name: str,
    legacy_name: str,
    *,
    default: Path,
) -> Path:
    value = env.get(primary_name) or env.get(legacy_name)
    if value is None:
        return absolute_path(default)
    return absolute_path(value)


def _remote_absolute_path(path: str | PurePosixPath) -> PurePosixPath:
    output = PurePosixPath(path)
    if not output.is_absolute():
        raise ValueError(f"remote path must be absolute: {path!r}")
    return output
