"""JSON-compatible data contracts for probe validation."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any, TypeAlias


JSONScalar: TypeAlias = str | int | float | bool | None
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]
JSONObject: TypeAlias = dict[str, JSONValue]


class JsonModel:
    """Mixin for dataclasses that serialize through the probe JSON contract."""

    def to_dict(self) -> JSONObject:
        value = to_jsonable(self)
        if not isinstance(value, dict):
            raise TypeError(f"{type(self).__name__} did not serialize to an object")
        return value

    def to_json(self, *, indent: int = 2) -> str:
        return dumps_json(self, indent=indent)


@dataclass(frozen=True, slots=True)
class ProbeCase(JsonModel):
    """One behavioral probe case requested for a lab endpoint pair."""

    name: str
    description: str
    stimulus: str
    expected_response: str
    required_capabilities: list[str] = field(default_factory=list)
    endpoint_roles: list[str] = field(default_factory=list)
    metadata: JSONObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class EndpointRole(JsonModel):
    """A role an endpoint plays during a probe run."""

    role: str
    responsibilities: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    metadata: JSONObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ProbeRunRequest(JsonModel):
    """Normalized probe run request."""

    provider: str
    profile: str
    seed: int
    count: int
    case_names: list[str] = field(default_factory=list)
    dry_run: bool = False
    confirm_live_run: bool = False
    out: str | None = None
    metadata: JSONObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ObservedResponse(JsonModel):
    """Captured or planned probe response evidence."""

    case: str
    sequence: int
    endpoint_role: str
    observed: bool
    response_type: str | None = None
    raw_hex: str | None = None
    decoded: JSONObject = field(default_factory=dict)
    metadata: JSONObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ProbeSkip(JsonModel):
    """A probe case that was not executed and the stable reason why."""

    case: str
    sequence: int
    reason: str
    capability: str | None = None
    metadata: JSONObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ProbeResult(JsonModel):
    """One probe case outcome."""

    case: str
    sequence: int
    status: str
    endpoint_role: str
    passed: bool | None = None
    observed_response: ObservedResponse | None = None
    skip: ProbeSkip | None = None
    metadata: JSONObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ProbeReport(JsonModel):
    """Machine-readable report for a probe command invocation."""

    mode: str
    provider: str
    profile: str
    seed: int
    count: int
    status: str
    request: ProbeRunRequest
    cases: list[ProbeCase] = field(default_factory=list)
    endpoint_roles: list[EndpointRole] = field(default_factory=list)
    results: list[ProbeResult] = field(default_factory=list)
    skips: list[ProbeSkip] = field(default_factory=list)
    observed_responses: list[ObservedResponse] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    artifact_paths: list[str] = field(default_factory=list)
    schema_version: int = 1
    metadata: JSONObject = field(default_factory=dict)


def coerce_json_value(value: object) -> JSONValue:
    """Coerce provider-produced values into JSON-compatible report data."""

    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, Mapping):
        return {str(key): coerce_json_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [coerce_json_value(item) for item in value]
    if isinstance(value, bytes):
        return {"hex": value.hex()}
    return str(value)


def json_object(value: object, name: str) -> JSONObject:
    """Coerce a mapping into a JSON object with string keys."""

    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    return {str(key): coerce_json_value(item) for key, item in value.items()}


def to_jsonable(value: Any) -> JSONValue:
    """Return a strict JSON-compatible copy of a probe value."""

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
    """Serialize a probe value as deterministic JSON text."""

    return json.dumps(to_jsonable(value), indent=indent, sort_keys=True) + "\n"


def write_json(path: str | Path, value: Any, *, indent: int = 2) -> None:
    """Write a probe value as JSON, creating parent directories as needed."""

    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(dumps_json(value, indent=indent), encoding="utf-8")
