"""Endpoint lifecycle configuration helpers."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path


WIRE_STATE_ROOT_ENV = "LIBCRAFTER_ENDPOINT_STATE_ROOT"
WIRE_ARTIFACT_ROOT_ENV = "LIBCRAFTER_ENDPOINT_ARTIFACT_ROOT"
WIRE_STATE_DIR_ENV = "LIBCRAFTER_ENDPOINT_STATE_DIR"
WIRE_ARTIFACT_DIR_ENV = "LIBCRAFTER_ENDPOINT_ARTIFACT_DIR"

WIRE_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STATE_ROOT = WIRE_ROOT / ".state"
DEFAULT_ARTIFACT_ROOT = WIRE_ROOT / "artifacts"


@dataclass(frozen=True, slots=True)
class WireConfig:
    """Local endpoint path configuration."""

    state_root: Path
    artifact_root: Path

    def __post_init__(self) -> None:
        object.__setattr__(self, "state_root", absolute_path(self.state_root))
        object.__setattr__(self, "artifact_root", absolute_path(self.artifact_root))


def default_config(env: Mapping[str, str] | None = None) -> WireConfig:
    """Return endpoint configuration from environment overrides and local defaults."""

    source = os.environ if env is None else env
    return WireConfig(
        state_root=_env_path(
            source,
            WIRE_STATE_ROOT_ENV,
            WIRE_STATE_DIR_ENV,
            default=DEFAULT_STATE_ROOT,
        ),
        artifact_root=_env_path(
            source,
            WIRE_ARTIFACT_ROOT_ENV,
            WIRE_ARTIFACT_DIR_ENV,
            default=DEFAULT_ARTIFACT_ROOT,
        ),
    )


def absolute_path(path: str | Path) -> Path:
    """Return an absolute local path without requiring it to exist."""

    output = Path(path).expanduser()
    if not output.is_absolute():
        output = Path.cwd() / output
    return output.resolve(strict=False)


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
