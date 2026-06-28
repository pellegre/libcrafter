"""Typed runtime profiles for libcrafter appliance workloads."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from tools.appliance.engine.model import (
    JSONObject,
    JsonModel,
    json_object,
    require_non_empty_string,
    string_list,
)


DEFAULT_IMAGE = "libcrafter/appliance:latest"
ALLOWED_PROFILE_NAMES = ("wan-raw", "lan-raw", "whad-serial", "dot11-monitor")
_ALLOWED_PROFILE_NAME_SET = frozenset(ALLOWED_PROFILE_NAMES)


@dataclass(frozen=True, slots=True)
class ProfileDevice(JsonModel):
    """One host device exposed to an appliance container."""

    host_path: str
    container_path: str
    permissions: str = "rwm"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "host_path",
            require_non_empty_string(self.host_path, "device.host_path"),
        )
        object.__setattr__(
            self,
            "container_path",
            require_non_empty_string(self.container_path, "device.container_path"),
        )
        permissions = require_non_empty_string(self.permissions, "device.permissions")
        if any(flag not in "rwm" for flag in permissions):
            raise ValueError("device.permissions may only contain r, w, and m")
        object.__setattr__(self, "permissions", permissions)

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ProfileDevice":
        data = _mapping(value, "device")
        _reject_unknown_keys(
            data,
            {"host_path", "container_path", "permissions"},
            "device",
        )
        host_path = _string(data.get("host_path"), "device.host_path")
        container_path = data.get("container_path", host_path)
        return cls(
            host_path=host_path,
            container_path=_string(container_path, "device.container_path"),
            permissions=_string(data.get("permissions", "rwm"), "device.permissions"),
        )


@dataclass(frozen=True, slots=True)
class ProfileMount(JsonModel):
    """One host path mounted into an appliance container."""

    source: str
    target: str
    read_only: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "source",
            require_non_empty_string(self.source, "mount.source"),
        )
        object.__setattr__(
            self,
            "target",
            require_non_empty_string(self.target, "mount.target"),
        )
        object.__setattr__(self, "read_only", _bool(self.read_only, "mount.read_only"))

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ProfileMount":
        data = _mapping(value, "mount")
        _reject_unknown_keys(data, {"source", "target", "read_only"}, "mount")
        return cls(
            source=_string(data.get("source"), "mount.source"),
            target=_string(data.get("target"), "mount.target"),
            read_only=_bool(data.get("read_only", False), "mount.read_only"),
        )


@dataclass(frozen=True, slots=True)
class ProfileCheck(JsonModel):
    """A non-mutating readiness check associated with a profile."""

    name: str
    description: str = ""
    command: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", require_non_empty_string(self.name, "check.name"))
        object.__setattr__(self, "description", _string(self.description, "check.description"))
        object.__setattr__(self, "command", _string_list(self.command, "check.command"))

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ProfileCheck":
        data = _mapping(value, "check")
        _reject_unknown_keys(data, {"name", "description", "command"}, "check")
        return cls(
            name=_string(data.get("name"), "check.name"),
            description=_string(data.get("description", ""), "check.description"),
            command=_string_list(data.get("command", []), "check.command"),
        )


@dataclass(frozen=True, slots=True)
class DockerRunPolicy(JsonModel):
    """Docker runtime options derived from an appliance profile."""

    image: str = DEFAULT_IMAGE
    network_mode: str = "bridge"
    cap_add: list[str] = field(default_factory=list)
    devices: list[ProfileDevice] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    mounts: list[ProfileMount] = field(default_factory=list)

    def __post_init__(self) -> None:
        object.__setattr__(self, "image", require_non_empty_string(self.image, "image"))
        object.__setattr__(
            self,
            "network_mode",
            require_non_empty_string(self.network_mode, "network_mode"),
        )
        object.__setattr__(self, "cap_add", _string_list(self.cap_add, "cap_add"))
        object.__setattr__(
            self,
            "devices",
            [
                item
                if isinstance(item, ProfileDevice)
                else ProfileDevice.from_dict(_mapping(item, "devices[]"))
                for item in _sequence(self.devices, "devices")
            ],
        )
        object.__setattr__(self, "env", _environment(self.env, "env"))
        object.__setattr__(
            self,
            "mounts",
            [
                item
                if isinstance(item, ProfileMount)
                else ProfileMount.from_dict(_mapping(item, "mounts[]"))
                for item in _sequence(self.mounts, "mounts")
            ],
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "DockerRunPolicy":
        data = _mapping(value, "docker_run_policy")
        _reject_unknown_keys(
            data,
            {"image", "network_mode", "cap_add", "devices", "env", "mounts"},
            "docker_run_policy",
        )
        return cls(
            image=_string(data.get("image", DEFAULT_IMAGE), "image"),
            network_mode=_string(data.get("network_mode", "bridge"), "network_mode"),
            cap_add=_string_list(data.get("cap_add", []), "cap_add"),
            devices=[
                ProfileDevice.from_dict(_mapping(item, "devices[]"))
                for item in _sequence(data.get("devices", []), "devices")
            ],
            env=_environment(data.get("env", {}), "env"),
            mounts=[
                ProfileMount.from_dict(_mapping(item, "mounts[]"))
                for item in _sequence(data.get("mounts", []), "mounts")
            ],
        )


@dataclass(frozen=True, slots=True)
class ApplianceProfile(JsonModel):
    """Coarse appliance execution shape for one runtime placement."""

    name: str
    description: str = ""
    image: str = DEFAULT_IMAGE
    network_mode: str = "bridge"
    cap_add: list[str] = field(default_factory=list)
    devices: list[ProfileDevice] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    mounts: list[ProfileMount] = field(default_factory=list)
    checks: list[ProfileCheck | JSONObject] = field(default_factory=list)
    host_requirements: list[str] = field(default_factory=list)
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _profile_name(self.name))
        object.__setattr__(self, "description", _string(self.description, "description"))
        object.__setattr__(self, "image", require_non_empty_string(self.image, "image"))
        object.__setattr__(
            self,
            "network_mode",
            require_non_empty_string(self.network_mode, "network_mode"),
        )
        object.__setattr__(self, "cap_add", _string_list(self.cap_add, "cap_add"))
        object.__setattr__(
            self,
            "devices",
            [
                item
                if isinstance(item, ProfileDevice)
                else ProfileDevice.from_dict(_mapping(item, "devices[]"))
                for item in _sequence(self.devices, "devices")
            ],
        )
        object.__setattr__(self, "env", _environment(self.env, "env"))
        object.__setattr__(
            self,
            "mounts",
            [
                item
                if isinstance(item, ProfileMount)
                else ProfileMount.from_dict(_mapping(item, "mounts[]"))
                for item in _sequence(self.mounts, "mounts")
            ],
        )
        object.__setattr__(
            self,
            "checks",
            [
                item if isinstance(item, ProfileCheck) else _profile_check(item)
                for item in _sequence(self.checks, "checks")
            ],
        )
        object.__setattr__(
            self,
            "host_requirements",
            _string_list(self.host_requirements, "host_requirements"),
        )
        object.__setattr__(self, "metadata", json_object(self.metadata, "metadata"))

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ApplianceProfile":
        data = _mapping(value, "profile")
        _reject_unknown_keys(
            data,
            {
                "name",
                "description",
                "image",
                "network_mode",
                "cap_add",
                "devices",
                "env",
                "mounts",
                "checks",
                "host_requirements",
                "metadata",
            },
            "profile",
        )
        return cls(
            name=_string(data.get("name"), "name"),
            description=_string(data.get("description", ""), "description"),
            image=_string(data.get("image", DEFAULT_IMAGE), "image"),
            network_mode=_string(data.get("network_mode", "bridge"), "network_mode"),
            cap_add=_string_list(data.get("cap_add", []), "cap_add"),
            devices=[
                ProfileDevice.from_dict(_mapping(item, "devices[]"))
                for item in _sequence(data.get("devices", []), "devices")
            ],
            env=_environment(data.get("env", {}), "env"),
            mounts=[
                ProfileMount.from_dict(_mapping(item, "mounts[]"))
                for item in _sequence(data.get("mounts", []), "mounts")
            ],
            checks=[
                _profile_check(item)
                for item in _sequence(data.get("checks", []), "checks")
            ],
            host_requirements=_string_list(
                data.get("host_requirements", []),
                "host_requirements",
            ),
            metadata=json_object(data.get("metadata", {}), "metadata"),
        )

    def docker_run_policy(self) -> DockerRunPolicy:
        """Return the Docker runtime policy for this appliance profile."""

        return DockerRunPolicy(
            image=self.image,
            network_mode=self.network_mode,
            cap_add=list(self.cap_add),
            devices=list(self.devices),
            env=dict(self.env),
            mounts=list(self.mounts),
        )


def _profile_name(value: object) -> str:
    name = require_non_empty_string(value, "name")
    if name not in _ALLOWED_PROFILE_NAME_SET:
        allowed = ", ".join(ALLOWED_PROFILE_NAMES)
        raise ValueError(f"name must be one of coarse placements: {allowed}")
    return name


def _environment(value: object, name: str) -> dict[str, str]:
    data = _mapping(value, name)
    output: dict[str, str] = {}
    for key, item in data.items():
        if key == "":
            raise ValueError(f"{name} keys must be non-empty strings")
        if "=" in key:
            raise ValueError(f"{name} keys must not contain '='")
        if not isinstance(item, str):
            raise ValueError(f"{name}.{key} must be a string")
        output[key] = item
    return output


def _profile_check(value: object) -> ProfileCheck | JSONObject:
    data = _mapping(value, "checks[]")
    simple_keys = {"name", "description", "command"}
    if set(data) <= simple_keys:
        return ProfileCheck.from_dict(data)
    _reject_unknown_keys(
        data,
        {
            "name",
            "kind",
            "description",
            "command",
            "command_argv",
            "scope",
            "required",
            "parameters",
            "args",
            "metadata",
        },
        "checks[]",
    )
    return json_object(data, "checks[]")


def _string_list(value: object, name: str) -> list[str]:
    output = string_list(value, name)
    for item in output:
        if item == "":
            raise ValueError(f"{name} entries must be non-empty strings")
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


__all__ = [
    "ALLOWED_PROFILE_NAMES",
    "DEFAULT_IMAGE",
    "ApplianceProfile",
    "DockerRunPolicy",
    "ProfileCheck",
    "ProfileDevice",
    "ProfileMount",
]
