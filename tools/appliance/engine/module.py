"""Typed appliance module manifests for optional runtime extensions."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from tools.appliance.engine.model import (
    JSONObject,
    JsonModel,
    json_object,
    require_non_empty_string,
    string_list,
)


_PATH_SAFE_LABEL = re.compile(r"^[a-z0-9][a-z0-9-]*$")
_USB_ID = re.compile(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{4}$")
_MAC_ADDRESS = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")
_SENSITIVE_HARDWARE_KEYS = frozenset(
    {
        "bssid",
        "hardware_id",
        "hardware_ids",
        "mac",
        "mac_address",
        "pid",
        "serial",
        "serial_number",
        "serial_numbers",
        "ssid",
        "usb_id",
        "usb_ids",
        "vid",
        "vid_pid",
    }
)


@dataclass(frozen=True, slots=True)
class ModuleDockerfile(JsonModel):
    """Optional Dockerfile overlay metadata for an appliance module."""

    path: str = "Dockerfile"
    context: str = "."
    target: str = ""
    build_args: dict[str, str] = field(default_factory=dict)
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _relative_path(self.path, "dockerfile.path"))
        object.__setattr__(
            self,
            "context",
            _relative_path(self.context, "dockerfile.context", allow_current=True),
        )
        object.__setattr__(self, "target", _string(self.target, "dockerfile.target"))
        object.__setattr__(
            self,
            "build_args",
            _string_mapping(self.build_args, "dockerfile.build_args"),
        )
        metadata = json_object(self.metadata, "dockerfile.metadata")
        _reject_tracked_hardware_ids(metadata, "dockerfile.metadata")
        object.__setattr__(self, "metadata", metadata)

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ModuleDockerfile":
        data = _mapping(value, "image_extensions[]")
        _reject_unknown_keys(
            data,
            {"path", "dockerfile", "context", "target", "build_args", "metadata"},
            "image_extensions[]",
        )
        if "path" in data and "dockerfile" in data:
            raise ValueError("image_extensions[] must not set both path and dockerfile")
        path = data.get("path", data.get("dockerfile", "Dockerfile"))
        return cls(
            path=_string(path, "dockerfile.path"),
            context=_string(data.get("context", "."), "dockerfile.context"),
            target=_string(data.get("target", ""), "dockerfile.target"),
            build_args=_string_mapping(data.get("build_args", {}), "dockerfile.build_args"),
            metadata=json_object(data.get("metadata", {}), "dockerfile.metadata"),
        )


@dataclass(frozen=True, slots=True)
class ModuleHostRequirement(JsonModel):
    """Host or VM preparation requirement declared by a module."""

    name: str
    description: str = ""
    kind: str = "host"
    scope: str = "host"
    command: list[str] = field(default_factory=list)
    required: bool = True
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", require_non_empty_string(self.name, "host_prepare.name"))
        object.__setattr__(
            self,
            "description",
            _string(self.description, "host_prepare.description"),
        )
        object.__setattr__(self, "kind", require_non_empty_string(self.kind, "host_prepare.kind"))
        object.__setattr__(
            self,
            "scope",
            require_non_empty_string(self.scope, "host_prepare.scope"),
        )
        object.__setattr__(
            self,
            "command",
            _non_empty_string_list(self.command, "host_prepare.command"),
        )
        object.__setattr__(self, "required", _bool(self.required, "host_prepare.required"))
        metadata = json_object(self.metadata, "host_prepare.metadata")
        _reject_tracked_hardware_ids(metadata, "host_prepare.metadata")
        object.__setattr__(self, "metadata", metadata)

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ModuleHostRequirement":
        data = _mapping(value, "host_prepare[]")
        _reject_unknown_keys(
            data,
            {"name", "description", "kind", "scope", "command", "required", "metadata"},
            "host_prepare[]",
        )
        return cls(
            name=_string(data.get("name"), "host_prepare.name"),
            description=_string(data.get("description", ""), "host_prepare.description"),
            kind=_string(data.get("kind", "host"), "host_prepare.kind"),
            scope=_string(data.get("scope", "host"), "host_prepare.scope"),
            command=_non_empty_string_list(data.get("command", []), "host_prepare.command"),
            required=_bool(data.get("required", True), "host_prepare.required"),
            metadata=json_object(data.get("metadata", {}), "host_prepare.metadata"),
        )


@dataclass(frozen=True, slots=True)
class ModuleCheck(JsonModel):
    """Non-mutating readiness check declared by an appliance module."""

    name: str
    description: str = ""
    scope: str = "host"
    command: list[str] = field(default_factory=list)
    required: bool = True
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", require_non_empty_string(self.name, "check.name"))
        object.__setattr__(self, "description", _string(self.description, "check.description"))
        object.__setattr__(self, "scope", require_non_empty_string(self.scope, "check.scope"))
        object.__setattr__(self, "command", _non_empty_string_list(self.command, "check.command"))
        object.__setattr__(self, "required", _bool(self.required, "check.required"))
        metadata = json_object(self.metadata, "check.metadata")
        _reject_tracked_hardware_ids(metadata, "check.metadata")
        object.__setattr__(self, "metadata", metadata)

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ModuleCheck":
        data = _mapping(value, "checks[]")
        _reject_unknown_keys(
            data,
            {"name", "description", "scope", "command", "required", "metadata"},
            "checks[]",
        )
        return cls(
            name=_string(data.get("name"), "check.name"),
            description=_string(data.get("description", ""), "check.description"),
            scope=_string(data.get("scope", "host"), "check.scope"),
            command=_non_empty_string_list(data.get("command", []), "check.command"),
            required=_bool(data.get("required", True), "check.required"),
            metadata=json_object(data.get("metadata", {}), "check.metadata"),
        )


@dataclass(frozen=True, slots=True)
class ApplianceModule(JsonModel):
    """Optional appliance extension for hardware or userland support."""

    name: str
    description: str = ""
    profiles: list[str] = field(default_factory=list)
    image_extensions: list[ModuleDockerfile] = field(default_factory=list)
    host_prepare: list[ModuleHostRequirement] = field(default_factory=list)
    checks: list[ModuleCheck] = field(default_factory=list)
    devices: list[str] = field(default_factory=list)
    interfaces: list[str] = field(default_factory=list)
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _path_safe_label(self.name, "name"))
        object.__setattr__(self, "description", _string(self.description, "description"))
        object.__setattr__(self, "profiles", _non_empty_string_list(self.profiles, "profiles"))
        object.__setattr__(
            self,
            "image_extensions",
            [
                item
                if isinstance(item, ModuleDockerfile)
                else ModuleDockerfile.from_dict(_mapping(item, "image_extensions[]"))
                for item in _sequence(self.image_extensions, "image_extensions")
            ],
        )
        object.__setattr__(
            self,
            "host_prepare",
            [
                item
                if isinstance(item, ModuleHostRequirement)
                else ModuleHostRequirement.from_dict(_mapping(item, "host_prepare[]"))
                for item in _sequence(self.host_prepare, "host_prepare")
            ],
        )
        object.__setattr__(
            self,
            "checks",
            [
                item
                if isinstance(item, ModuleCheck)
                else ModuleCheck.from_dict(_mapping(item, "checks[]"))
                for item in _sequence(self.checks, "checks")
            ],
        )
        devices = _non_empty_string_list(self.devices, "devices")
        _reject_identifier_values(devices, "devices")
        object.__setattr__(self, "devices", devices)
        interfaces = _non_empty_string_list(self.interfaces, "interfaces")
        _reject_identifier_values(interfaces, "interfaces")
        object.__setattr__(self, "interfaces", interfaces)
        metadata = json_object(self.metadata, "metadata")
        _reject_tracked_hardware_ids(metadata, "metadata")
        object.__setattr__(self, "metadata", metadata)

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ApplianceModule":
        data = _mapping(value, "module")
        _reject_unknown_keys(
            data,
            {
                "name",
                "description",
                "profiles",
                "image_extensions",
                "host_prepare",
                "checks",
                "devices",
                "interfaces",
                "metadata",
            },
            "module",
        )
        return cls(
            name=_string(data.get("name"), "name"),
            description=_string(data.get("description", ""), "description"),
            profiles=_non_empty_string_list(data.get("profiles", []), "profiles"),
            image_extensions=[
                ModuleDockerfile.from_dict(_mapping(item, "image_extensions[]"))
                for item in _sequence(data.get("image_extensions", []), "image_extensions")
            ],
            host_prepare=[
                ModuleHostRequirement.from_dict(_mapping(item, "host_prepare[]"))
                for item in _sequence(data.get("host_prepare", []), "host_prepare")
            ],
            checks=[
                ModuleCheck.from_dict(_mapping(item, "checks[]"))
                for item in _sequence(data.get("checks", []), "checks")
            ],
            devices=_non_empty_string_list(data.get("devices", []), "devices"),
            interfaces=_non_empty_string_list(data.get("interfaces", []), "interfaces"),
            metadata=json_object(data.get("metadata", {}), "metadata"),
        )


def _path_safe_label(value: object, name: str) -> str:
    label = require_non_empty_string(value, name)
    if not _PATH_SAFE_LABEL.fullmatch(label):
        raise ValueError(f"{name} must be a stable path-safe label")
    return label


def _relative_path(value: object, name: str, *, allow_current: bool = False) -> str:
    path_text = require_non_empty_string(value, name)
    path = PurePosixPath(path_text)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{name} must be a relative manifest path")
    if path_text == "." and not allow_current:
        raise ValueError(f"{name} must be a relative manifest path")
    return path_text


def _non_empty_string_list(value: object, name: str) -> list[str]:
    output = string_list(value, name)
    for item in output:
        if item == "":
            raise ValueError(f"{name} entries must be non-empty strings")
    return output


def _string_mapping(value: object, name: str) -> dict[str, str]:
    data = _mapping(value, name)
    output: dict[str, str] = {}
    for key, item in data.items():
        if key == "":
            raise ValueError(f"{name} keys must be non-empty strings")
        if not isinstance(item, str):
            raise ValueError(f"{name}.{key} must be a string")
        output[key] = item
    return output


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    for key in value:
        if not isinstance(key, str):
            raise ValueError(f"{name} keys must be strings")
    return value


def _sequence(value: object, name: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{name} must be a list")
    return value


def _string(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def _reject_unknown_keys(data: Mapping[str, object], allowed: set[str], name: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        joined = ", ".join(unknown)
        raise ValueError(f"{name} contains unknown field(s): {joined}")


def _reject_identifier_values(values: Sequence[str], name: str) -> None:
    for item in values:
        if _USB_ID.fullmatch(item) or _MAC_ADDRESS.fullmatch(item):
            raise ValueError(f"{name} must not require real serial numbers or hardware IDs")


def _reject_tracked_hardware_ids(value: object, name: str) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = key.lower().replace("-", "_")
            if normalized in _SENSITIVE_HARDWARE_KEYS and _has_non_empty_value(item):
                raise ValueError(f"{name} must not require real serial numbers or hardware IDs")
            _reject_tracked_hardware_ids(item, f"{name}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            _reject_tracked_hardware_ids(item, f"{name}[{index}]")
    elif isinstance(value, str) and (_USB_ID.fullmatch(value) or _MAC_ADDRESS.fullmatch(value)):
        raise ValueError(f"{name} must not require real serial numbers or hardware IDs")


def _has_non_empty_value(value: object) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return value != ""
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return any(_has_non_empty_value(item) for item in value)
    if isinstance(value, Mapping):
        return any(_has_non_empty_value(item) for item in value.values())
    return True


__all__ = [
    "ApplianceModule",
    "ModuleCheck",
    "ModuleDockerfile",
    "ModuleHostRequirement",
]
