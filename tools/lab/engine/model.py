"""JSON-compatible contracts for provider-backed lab sessions."""

from __future__ import annotations

import json
import math
import re
import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, fields, is_dataclass
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import Any, TypeAlias


JSONScalar: TypeAlias = str | int | float | bool | None
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]
JSONObject: TypeAlias = dict[str, JSONValue]


_PROVIDER_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_ROLE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_PATH_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")


class JsonModel:
    """Mixin for lab models that serialize through JSON objects."""

    def to_dict(self) -> JSONObject:
        value = to_jsonable(self)
        if not isinstance(value, dict):
            raise TypeError(f"{type(self).__name__} did not serialize to an object")
        return value

    def to_json(self, *, indent: int = 2) -> str:
        return dumps_json(self, indent=indent)


@dataclass(frozen=True, slots=True)
class LabRole(JsonModel):
    """One caller-defined endpoint role in a lab session."""

    name: str
    requested_private_ipv4: str | None = None
    planned_ipv4: str | None = None
    peer_roles: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    bootstrap_metadata: JSONObject = field(default_factory=dict)
    workload_metadata: JSONObject = field(default_factory=dict)
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _role_name(self.name, "role.name"))
        object.__setattr__(
            self,
            "requested_private_ipv4",
            _optional_ipv4_address(self.requested_private_ipv4, "role.requested_private_ipv4"),
        )
        object.__setattr__(
            self,
            "planned_ipv4",
            _optional_ipv4_address(self.planned_ipv4, "role.planned_ipv4"),
        )
        object.__setattr__(
            self,
            "peer_roles",
            [
                _role_name(role, "role.peer_roles[]")
                for role in _sequence(self.peer_roles, "role.peer_roles")
            ],
        )
        object.__setattr__(
            self,
            "capabilities",
            string_list(self.capabilities, "role.capabilities"),
        )
        object.__setattr__(
            self,
            "bootstrap_metadata",
            json_object(self.bootstrap_metadata, "role.bootstrap_metadata"),
        )
        object.__setattr__(
            self,
            "workload_metadata",
            json_object(self.workload_metadata, "role.workload_metadata"),
        )
        object.__setattr__(self, "metadata", json_object(self.metadata, "role.metadata"))

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "LabRole":
        data = _mapping(value, "lab_role")
        return cls(
            name=_string(data.get("name"), "role.name"),
            requested_private_ipv4=_optional_string(
                data.get("requested_private_ipv4"),
                "role.requested_private_ipv4",
            ),
            planned_ipv4=_optional_string(data.get("planned_ipv4"), "role.planned_ipv4"),
            peer_roles=string_list(data.get("peer_roles", []), "role.peer_roles"),
            capabilities=string_list(data.get("capabilities", []), "role.capabilities"),
            bootstrap_metadata=json_object(
                data.get("bootstrap_metadata", {}),
                "role.bootstrap_metadata",
            ),
            workload_metadata=json_object(
                data.get("workload_metadata", {}),
                "role.workload_metadata",
            ),
            metadata=json_object(data.get("metadata", {}), "role.metadata"),
        )


@dataclass(frozen=True, slots=True)
class LabRequest(JsonModel):
    """Normalized request to plan or create a lab session."""

    provider: str
    profile: str
    seed: int
    roles: list[LabRole]
    dry_run: bool = True
    confirm_live_run: bool = False
    remote_dir: str | None = None
    workload_label: str | None = None
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", _provider_name(self.provider, "request.provider"))
        object.__setattr__(self, "profile", _path_component(self.profile, "request.profile"))
        object.__setattr__(self, "seed", _int(self.seed, "request.seed"))
        object.__setattr__(self, "roles", _coerce_roles(self.roles, "request.roles"))
        _require_non_empty(self.roles, "request.roles")
        _require_unique_roles(self.roles, "request.roles")
        object.__setattr__(self, "dry_run", _bool(self.dry_run, "request.dry_run"))
        object.__setattr__(
            self,
            "confirm_live_run",
            _bool(self.confirm_live_run, "request.confirm_live_run"),
        )
        object.__setattr__(
            self,
            "remote_dir",
            _optional_absolute_path(self.remote_dir, "request.remote_dir"),
        )
        object.__setattr__(
            self,
            "workload_label",
            _optional_path_component(self.workload_label, "request.workload_label"),
        )
        object.__setattr__(self, "metadata", json_object(self.metadata, "request.metadata"))

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "LabRequest":
        data = _mapping(value, "lab_request")
        roles = _sequence(data.get("roles"), "request.roles")
        return cls(
            provider=_string(data.get("provider"), "request.provider"),
            profile=_string(data.get("profile"), "request.profile"),
            seed=_int(data.get("seed"), "request.seed"),
            roles=[LabRole.from_dict(_mapping(item, "request.roles[]")) for item in roles],
            dry_run=_bool(data.get("dry_run", True), "request.dry_run"),
            confirm_live_run=_bool(
                data.get("confirm_live_run", False),
                "request.confirm_live_run",
            ),
            remote_dir=_optional_string(data.get("remote_dir"), "request.remote_dir"),
            workload_label=_optional_string(data.get("workload_label"), "request.workload_label"),
            metadata=json_object(data.get("metadata", {}), "request.metadata"),
        )


@dataclass(frozen=True, slots=True)
class LabEndpoint(JsonModel):
    """Normalized wire endpoint selected for one lab role."""

    endpoint_id: str
    role: str
    interface: str
    ipv4: str
    ipv6: str | None = None
    mac: str | None = None
    peer_addresses: JSONObject = field(default_factory=dict)
    wire_manifest: JSONObject = field(default_factory=dict)
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "endpoint_id",
            _endpoint_id(self.endpoint_id, "endpoint.endpoint_id"),
        )
        object.__setattr__(self, "role", _role_name(self.role, "endpoint.role"))
        _require_non_empty_string(self.interface, "endpoint.interface")
        object.__setattr__(self, "ipv4", _ipv4_address(self.ipv4, "endpoint.ipv4"))
        object.__setattr__(self, "ipv6", _optional_ipv6_address(self.ipv6, "endpoint.ipv6"))
        object.__setattr__(self, "mac", _optional_mac(self.mac, "endpoint.mac"))
        object.__setattr__(
            self,
            "peer_addresses",
            _peer_address_object(self.peer_addresses, "endpoint.peer_addresses"),
        )
        object.__setattr__(
            self,
            "wire_manifest",
            json_object(self.wire_manifest, "endpoint.wire_manifest"),
        )
        object.__setattr__(self, "metadata", json_object(self.metadata, "endpoint.metadata"))

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "LabEndpoint":
        data = _mapping(value, "lab_endpoint")
        return cls(
            endpoint_id=_string(data.get("endpoint_id"), "endpoint.endpoint_id"),
            role=_string(data.get("role"), "endpoint.role"),
            interface=_string(data.get("interface"), "endpoint.interface"),
            ipv4=_string(data.get("ipv4"), "endpoint.ipv4"),
            ipv6=_optional_string(data.get("ipv6"), "endpoint.ipv6"),
            mac=_optional_string(data.get("mac"), "endpoint.mac"),
            peer_addresses=json_object(
                data.get("peer_addresses", {}),
                "endpoint.peer_addresses",
            ),
            wire_manifest=json_object(data.get("wire_manifest", {}), "endpoint.wire_manifest"),
            metadata=json_object(data.get("metadata", {}), "endpoint.metadata"),
        )


@dataclass(frozen=True, slots=True)
class LabCommandPlan(JsonModel):
    """A planned or executed provider/workload command."""

    purpose: str
    role: str | None
    argv: list[str]
    operation: str
    dry_run: bool = True
    live_mutation: bool = False
    artifacts: list[str] = field(default_factory=list)
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_non_empty_string(self.purpose, "command.purpose")
        object.__setattr__(self, "role", _optional_role_name(self.role, "command.role"))
        object.__setattr__(self, "argv", _non_empty_string_list(self.argv, "command.argv"))
        _require_non_empty_string(self.operation, "command.operation")
        object.__setattr__(self, "dry_run", _bool(self.dry_run, "command.dry_run"))
        object.__setattr__(
            self,
            "live_mutation",
            _bool(self.live_mutation, "command.live_mutation"),
        )
        object.__setattr__(
            self,
            "artifacts",
            _absolute_path_list(self.artifacts, "command.artifacts"),
        )
        object.__setattr__(self, "metadata", json_object(self.metadata, "command.metadata"))

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "LabCommandPlan":
        data = _mapping(value, "lab_command_plan")
        return cls(
            purpose=_string(data.get("purpose"), "command.purpose"),
            role=_optional_string(data.get("role"), "command.role"),
            argv=string_list(data.get("argv"), "command.argv"),
            operation=_string(data.get("operation"), "command.operation"),
            dry_run=_bool(data.get("dry_run", True), "command.dry_run"),
            live_mutation=_bool(data.get("live_mutation", False), "command.live_mutation"),
            artifacts=string_list(data.get("artifacts", []), "command.artifacts"),
            metadata=json_object(data.get("metadata", {}), "command.metadata"),
        )

    def shell(self) -> str:
        """Return the command as a shell-escaped display string."""

        return shlex.join(self.argv)


@dataclass(frozen=True, slots=True)
class LabValidationCheck(JsonModel):
    """A validation performed on provider-neutral lab data."""

    name: str
    passed: bool
    subject: str
    errors: list[str] = field(default_factory=list)
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _path_component(self.name, "validation.name"))
        object.__setattr__(self, "passed", _bool(self.passed, "validation.passed"))
        _require_non_empty_string(self.subject, "validation.subject")
        object.__setattr__(self, "errors", string_list(self.errors, "validation.errors"))
        object.__setattr__(self, "metadata", json_object(self.metadata, "validation.metadata"))

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "LabValidationCheck":
        data = _mapping(value, "lab_validation_check")
        return cls(
            name=_string(data.get("name"), "validation.name"),
            passed=_bool(data.get("passed"), "validation.passed"),
            subject=_string(data.get("subject"), "validation.subject"),
            errors=string_list(data.get("errors", []), "validation.errors"),
            metadata=json_object(data.get("metadata", {}), "validation.metadata"),
        )


@dataclass(frozen=True, slots=True)
class LabSession(JsonModel):
    """Provider-neutral description of one planned or created lab session."""

    provider: str
    wire_provider: str
    wire_exposure: str
    session_id: str
    roles: list[LabRole]
    endpoints: list[LabEndpoint] = field(default_factory=list)
    provider_capabilities: JSONObject = field(default_factory=dict)
    infrastructure_metadata: JSONObject = field(default_factory=dict)
    provider_workflow: list[LabCommandPlan] = field(default_factory=list)
    command_records: list[LabCommandPlan] = field(default_factory=list)
    remote_dir: str | None = None
    remote_artifact_root: str | None = None
    created_endpoint_ids: list[str] = field(default_factory=list)
    dry_run: bool = True
    cleanup_state: JSONObject = field(default_factory=dict)
    validation_checks: list[LabValidationCheck] = field(default_factory=list)
    schema_version: int = 1
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", _provider_name(self.provider, "session.provider"))
        object.__setattr__(
            self,
            "wire_provider",
            _provider_name(self.wire_provider, "session.wire_provider"),
        )
        object.__setattr__(
            self,
            "wire_exposure",
            _provider_name(self.wire_exposure, "session.wire_exposure"),
        )
        object.__setattr__(self, "session_id", _endpoint_id(self.session_id, "session.session_id"))
        object.__setattr__(self, "roles", _coerce_roles(self.roles, "session.roles"))
        _require_non_empty(self.roles, "session.roles")
        _require_unique_roles(self.roles, "session.roles")
        role_names = {role.name for role in self.roles}
        object.__setattr__(
            self,
            "endpoints",
            _coerce_endpoints(self.endpoints, "session.endpoints"),
        )
        _require_unique_endpoint_ids(self.endpoints, "session.endpoints")
        _require_known_endpoint_roles(self.endpoints, role_names, "session.endpoints")
        object.__setattr__(
            self,
            "provider_capabilities",
            json_object(self.provider_capabilities, "session.provider_capabilities"),
        )
        object.__setattr__(
            self,
            "infrastructure_metadata",
            json_object(self.infrastructure_metadata, "session.infrastructure_metadata"),
        )
        object.__setattr__(
            self,
            "provider_workflow",
            _coerce_commands(self.provider_workflow, "session.provider_workflow"),
        )
        object.__setattr__(
            self,
            "command_records",
            _coerce_commands(self.command_records, "session.command_records"),
        )
        object.__setattr__(
            self,
            "remote_dir",
            _optional_absolute_path(self.remote_dir, "session.remote_dir"),
        )
        object.__setattr__(
            self,
            "remote_artifact_root",
            _optional_absolute_path(self.remote_artifact_root, "session.remote_artifact_root"),
        )
        object.__setattr__(
            self,
            "created_endpoint_ids",
            [
                _endpoint_id(item, "session.created_endpoint_ids[]")
                for item in _sequence(
                    self.created_endpoint_ids,
                    "session.created_endpoint_ids",
                )
            ],
        )
        object.__setattr__(self, "dry_run", _bool(self.dry_run, "session.dry_run"))
        object.__setattr__(
            self,
            "cleanup_state",
            json_object(self.cleanup_state, "session.cleanup_state"),
        )
        object.__setattr__(
            self,
            "validation_checks",
            _coerce_validation_checks(self.validation_checks, "session.validation_checks"),
        )
        object.__setattr__(
            self,
            "schema_version",
            _positive_int(self.schema_version, "session.schema_version"),
        )
        object.__setattr__(self, "metadata", json_object(self.metadata, "session.metadata"))

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "LabSession":
        data = _mapping(value, "lab_session")
        roles = _sequence(data.get("roles"), "session.roles")
        endpoints = _sequence(data.get("endpoints", []), "session.endpoints")
        provider_workflow = _sequence(
            data.get("provider_workflow", []),
            "session.provider_workflow",
        )
        command_records = _sequence(data.get("command_records", []), "session.command_records")
        validation_checks = _sequence(
            data.get("validation_checks", []),
            "session.validation_checks",
        )
        return cls(
            provider=_string(data.get("provider"), "session.provider"),
            wire_provider=_string(data.get("wire_provider"), "session.wire_provider"),
            wire_exposure=_string(data.get("wire_exposure"), "session.wire_exposure"),
            session_id=_string(data.get("session_id"), "session.session_id"),
            roles=[LabRole.from_dict(_mapping(item, "session.roles[]")) for item in roles],
            endpoints=[
                LabEndpoint.from_dict(_mapping(item, "session.endpoints[]"))
                for item in endpoints
            ],
            provider_capabilities=json_object(
                data.get("provider_capabilities", {}),
                "session.provider_capabilities",
            ),
            infrastructure_metadata=json_object(
                data.get("infrastructure_metadata", {}),
                "session.infrastructure_metadata",
            ),
            provider_workflow=[
                LabCommandPlan.from_dict(_mapping(item, "session.provider_workflow[]"))
                for item in provider_workflow
            ],
            command_records=[
                LabCommandPlan.from_dict(_mapping(item, "session.command_records[]"))
                for item in command_records
            ],
            remote_dir=_optional_string(data.get("remote_dir"), "session.remote_dir"),
            remote_artifact_root=_optional_string(
                data.get("remote_artifact_root"),
                "session.remote_artifact_root",
            ),
            created_endpoint_ids=string_list(
                data.get("created_endpoint_ids", []),
                "session.created_endpoint_ids",
            ),
            dry_run=_bool(data.get("dry_run", True), "session.dry_run"),
            cleanup_state=json_object(data.get("cleanup_state", {}), "session.cleanup_state"),
            validation_checks=[
                LabValidationCheck.from_dict(_mapping(item, "session.validation_checks[]"))
                for item in validation_checks
            ],
            schema_version=_positive_int(
                data.get("schema_version", 1),
                "session.schema_version",
            ),
            metadata=json_object(data.get("metadata", {}), "session.metadata"),
        )


def coerce_json_value(value: object) -> JSONValue:
    """Coerce provider-produced values into JSON-compatible lab data."""

    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise TypeError(f"non-finite float is not valid JSON: {value!r}")
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        output: JSONObject = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"JSON object keys must be strings: {key!r}")
            output[key] = coerce_json_value(item)
        return output
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [coerce_json_value(item) for item in value]
    if isinstance(value, bytes):
        return {"hex": value.hex()}
    return str(value)


def json_object(value: object, name: str) -> JSONObject:
    """Coerce a mapping into a JSON object with string keys."""

    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    output: JSONObject = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ValueError(f"{name} keys must be strings")
        output[key] = coerce_json_value(item)
    return output


def string_list(value: object, name: str) -> list[str]:
    """Return a JSON array as a list of strings."""

    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{name} must be a list of strings")
    output: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{name} must be a list of strings")
        output.append(item)
    return output


def to_jsonable(value: Any) -> JSONValue:
    """Return a strict JSON-compatible copy of a lab model value."""

    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise TypeError(f"non-finite float is not valid JSON: {value!r}")
        return value
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field_info.name: to_jsonable(getattr(value, field_info.name))
            for field_info in fields(value)
        }
    if isinstance(value, Mapping):
        output: JSONObject = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"JSON object keys must be strings: {key!r}")
            output[key] = to_jsonable(item)
        return output
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [to_jsonable(item) for item in value]
    raise TypeError(f"value is not JSON-compatible: {type(value).__name__}")


def dumps_json(value: Any, *, indent: int = 2) -> str:
    """Serialize a lab value as deterministic JSON text."""

    return json.dumps(to_jsonable(value), indent=indent, sort_keys=True) + "\n"


def write_json(path: str | Path, value: Any, *, indent: int = 2) -> None:
    """Write a lab value as JSON, creating parent directories as needed."""

    output_path = Path(path)
    if not output_path.is_absolute():
        raise ValueError(f"JSON output path must be absolute: {path!r}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(dumps_json(value, indent=indent), encoding="utf-8")


def read_json(path: str | Path) -> JSONValue:
    """Read JSON text for later conversion into lab model objects."""

    input_path = Path(path)
    if not input_path.is_absolute():
        raise ValueError(f"JSON input path must be absolute: {path!r}")
    with input_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _coerce_roles(value: object, name: str) -> list[LabRole]:
    return [
        item if isinstance(item, LabRole) else LabRole.from_dict(_mapping(item, f"{name}[]"))
        for item in _sequence(value, name)
    ]


def _coerce_endpoints(value: object, name: str) -> list[LabEndpoint]:
    return [
        item
        if isinstance(item, LabEndpoint)
        else LabEndpoint.from_dict(_mapping(item, f"{name}[]"))
        for item in _sequence(value, name)
    ]


def _coerce_commands(value: object, name: str) -> list[LabCommandPlan]:
    return [
        item
        if isinstance(item, LabCommandPlan)
        else LabCommandPlan.from_dict(_mapping(item, f"{name}[]"))
        for item in _sequence(value, name)
    ]


def _coerce_validation_checks(value: object, name: str) -> list[LabValidationCheck]:
    return [
        item
        if isinstance(item, LabValidationCheck)
        else LabValidationCheck.from_dict(_mapping(item, f"{name}[]"))
        for item in _sequence(value, name)
    ]


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


def _optional_string(value: object, name: str) -> str | None:
    if value is None:
        return None
    return _string(value, name)


def _int(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    return value


def _positive_int(value: object, name: str) -> int:
    output = _int(value, name)
    if output <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return output


def _bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def _require_non_empty_string(value: object, name: str) -> None:
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{name} must be a non-empty string")


def _require_non_empty(value: Sequence[object], name: str) -> None:
    if len(value) == 0:
        raise ValueError(f"{name} must contain at least one item")


def _non_empty_string_list(value: object, name: str) -> list[str]:
    output = string_list(value, name)
    if len(output) == 0:
        raise ValueError(f"{name} must contain at least one string")
    for item in output:
        _require_non_empty_string(item, f"{name}[]")
    return output


def _absolute_path(value: str | Path, name: str) -> str:
    path = Path(value)
    if not path.is_absolute():
        raise ValueError(f"{name} must be an absolute path")
    return str(path)


def _optional_absolute_path(value: str | Path | None, name: str) -> str | None:
    if value is None:
        return None
    return _absolute_path(value, name)


def _absolute_path_list(value: object, name: str) -> list[str]:
    return [_absolute_path(item, f"{name}[]") for item in string_list(value, name)]


def _provider_name(value: object, name: str) -> str:
    output = _string(value, name)
    if _PROVIDER_NAME_RE.fullmatch(output) is None:
        raise ValueError(f"{name} must be a lower-case provider name")
    return output


def _role_name(value: object, name: str) -> str:
    output = _string(value, name)
    if _ROLE_NAME_RE.fullmatch(output) is None:
        raise ValueError(f"{name} must be a role name")
    return output


def _optional_role_name(value: object, name: str) -> str | None:
    if value is None:
        return None
    return _role_name(value, name)


def _path_component(value: object, name: str) -> str:
    output = _string(value, name)
    if _PATH_COMPONENT_RE.fullmatch(output) is None:
        raise ValueError(f"{name} must be a safe path component")
    path = Path(output)
    if path.is_absolute() or len(path.parts) != 1 or output in {".", ".."}:
        raise ValueError(f"{name} must be a single path component")
    return output


def _optional_path_component(value: object, name: str) -> str | None:
    if value is None:
        return None
    return _path_component(value, name)


def _endpoint_id(value: object, name: str) -> str:
    try:
        return _path_component(value, name)
    except ValueError as error:
        raise ValueError(f"{name} must be a well-formed endpoint id") from error


def _ipv4_address(value: object, name: str) -> str:
    output = _string(value, name)
    try:
        return str(IPv4Address(output))
    except ValueError as error:
        raise ValueError(f"{name} must be an IPv4 address") from error


def _optional_ipv4_address(value: object, name: str) -> str | None:
    if value is None:
        return None
    return _ipv4_address(value, name)


def _optional_ipv6_address(value: object, name: str) -> str | None:
    if value is None:
        return None
    output = _string(value, name)
    try:
        return str(IPv6Address(output))
    except ValueError as error:
        raise ValueError(f"{name} must be an IPv6 address") from error


def _optional_mac(value: object, name: str) -> str | None:
    if value is None:
        return None
    output = _string(value, name)
    if _MAC_RE.fullmatch(output) is None:
        raise ValueError(f"{name} must be a MAC address")
    return output.lower()


def _peer_address_object(value: object, name: str) -> JSONObject:
    output = json_object(value, name)
    for role_name in output:
        _role_name(role_name, f"{name} key")
    return output


def _require_unique_roles(roles: Sequence[LabRole], name: str) -> None:
    seen: set[str] = set()
    for role in roles:
        if role.name in seen:
            raise ValueError(f"{name} must not contain duplicate role names")
        seen.add(role.name)


def _require_unique_endpoint_ids(endpoints: Sequence[LabEndpoint], name: str) -> None:
    seen: set[str] = set()
    for endpoint in endpoints:
        if endpoint.endpoint_id in seen:
            raise ValueError(f"{name} must not contain duplicate endpoint ids")
        seen.add(endpoint.endpoint_id)


def _require_known_endpoint_roles(
    endpoints: Sequence[LabEndpoint],
    role_names: set[str],
    name: str,
) -> None:
    for endpoint in endpoints:
        if endpoint.role not in role_names:
            raise ValueError(f"{name} contains endpoint role not declared in session roles")
