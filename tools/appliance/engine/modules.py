"""Registry for tracked appliance module manifests."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

from tools.appliance.engine.model import read_json
from tools.appliance.engine.module import ApplianceModule


class UnknownApplianceModuleError(ValueError):
    """Raised when a requested appliance module is not registered."""

    def __init__(self, name: str, known: tuple[str, ...]) -> None:
        known_text = ", ".join(known) or "<none>"
        super().__init__(f"unknown appliance module {name!r}; known modules: {known_text}")
        self.name = name
        self.known = known


def modules_dir() -> Path:
    """Return the tracked built-in appliance module manifest directory."""

    return Path(__file__).resolve().parents[1] / "modules"


def load_modules(module_dir: str | Path | None = None) -> dict[str, ApplianceModule]:
    """Load and validate all appliance module manifests from ``module_dir``."""

    directory = _manifest_dir(module_dir)
    modules: dict[str, ApplianceModule] = {}
    origins: dict[str, Path] = {}
    for path in sorted(directory.glob("*/module.json"), key=lambda item: item.parent.name):
        module = _load_module(path)
        if module.name in modules:
            previous = origins[module.name]
            raise ValueError(
                f"duplicate appliance module {module.name!r}: "
                f"{previous.parent.name} and {path.parent.name}"
            )
        modules[module.name] = module
        origins[module.name] = path
    return modules


def list_module_names(module_dir: str | Path | None = None) -> tuple[str, ...]:
    """Return available appliance module names in deterministic sorted order."""

    return tuple(sorted(load_modules(module_dir)))


def resolve_module(name: str, module_dir: str | Path | None = None) -> ApplianceModule:
    """Return the named appliance module or raise a clear unknown-module error."""

    modules = load_modules(module_dir)
    try:
        return modules[name]
    except KeyError as exc:
        raise UnknownApplianceModuleError(name, tuple(sorted(modules))) from exc


def filter_modules_by_profile(
    profile: str,
    module_dir: str | Path | None = None,
) -> tuple[ApplianceModule, ...]:
    """Return modules that declare support for ``profile`` in name-sorted order."""

    modules = load_modules(module_dir)
    return tuple(modules[name] for name in sorted(modules) if profile in modules[name].profiles)


def _manifest_dir(module_dir: str | Path | None) -> Path:
    directory = modules_dir() if module_dir is None else Path(module_dir)
    directory = directory.resolve()
    if not directory.is_dir():
        raise FileNotFoundError(f"appliance module directory not found: {directory}")
    return directory


def _load_module(path: Path) -> ApplianceModule:
    try:
        data = read_json(path)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc.msg}") from exc
    except ValueError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, Mapping):
        raise ValueError(f"{path}: module manifest must be a JSON object")
    try:
        return ApplianceModule.from_dict(data)
    except ValueError as exc:
        raise ValueError(f"{path}: {exc}") from exc


__all__ = [
    "UnknownApplianceModuleError",
    "filter_modules_by_profile",
    "list_module_names",
    "load_modules",
    "modules_dir",
    "resolve_module",
]
