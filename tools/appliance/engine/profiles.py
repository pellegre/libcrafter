"""Registry for built-in appliance profile manifests."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

from tools.appliance.engine.model import read_json
from tools.appliance.engine.profile import ApplianceProfile


class UnknownApplianceProfileError(ValueError):
    """Raised when a requested appliance profile is not registered."""

    def __init__(self, name: str, known: tuple[str, ...]) -> None:
        known_text = ", ".join(known) or "<none>"
        super().__init__(f"unknown appliance profile {name!r}; known profiles: {known_text}")
        self.name = name
        self.known = known


def profiles_dir() -> Path:
    """Return the tracked built-in appliance profile manifest directory."""

    return Path(__file__).resolve().parents[1] / "profiles"


def load_profiles(profile_dir: str | Path | None = None) -> dict[str, ApplianceProfile]:
    """Load and validate all appliance profile manifests from ``profile_dir``."""

    directory = _manifest_dir(profile_dir)
    profiles: dict[str, ApplianceProfile] = {}
    origins: dict[str, Path] = {}
    for path in sorted(directory.glob("*.json"), key=lambda item: item.name):
        profile = _load_profile(path)
        if profile.name in profiles:
            previous = origins[profile.name]
            raise ValueError(
                f"duplicate appliance profile {profile.name!r}: {previous.name} and {path.name}"
            )
        profiles[profile.name] = profile
        origins[profile.name] = path
    return profiles


def list_profile_names(profile_dir: str | Path | None = None) -> tuple[str, ...]:
    """Return available appliance profile names in deterministic sorted order."""

    return tuple(sorted(load_profiles(profile_dir)))


def resolve_profile(name: str, profile_dir: str | Path | None = None) -> ApplianceProfile:
    """Return the named appliance profile or raise a clear unknown-profile error."""

    profiles = load_profiles(profile_dir)
    try:
        return profiles[name]
    except KeyError as exc:
        raise UnknownApplianceProfileError(name, tuple(sorted(profiles))) from exc


def _manifest_dir(profile_dir: str | Path | None) -> Path:
    directory = profiles_dir() if profile_dir is None else Path(profile_dir)
    directory = directory.resolve()
    if not directory.is_dir():
        raise FileNotFoundError(f"appliance profile directory not found: {directory}")
    return directory


def _load_profile(path: Path) -> ApplianceProfile:
    try:
        data = read_json(path)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc.msg}") from exc
    except ValueError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, Mapping):
        raise ValueError(f"{path}: profile manifest must be a JSON object")
    try:
        return ApplianceProfile.from_dict(data)
    except ValueError as exc:
        raise ValueError(f"{path}: {exc}") from exc


__all__ = [
    "UnknownApplianceProfileError",
    "list_profile_names",
    "load_profiles",
    "profiles_dir",
    "resolve_profile",
]
