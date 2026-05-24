"""JSON-compatible data contracts for oracle validation."""

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
LayerFields: TypeAlias = dict[str, JSONObject]


class JsonModel:
    """Mixin for dataclasses that serialize through the oracle JSON contract."""

    def to_dict(self) -> JSONObject:
        value = to_jsonable(self)
        if not isinstance(value, dict):
            raise TypeError(f"{type(self).__name__} did not serialize to an object")
        return value

    def to_json(self, *, indent: int = 2) -> str:
        return dumps_json(self, indent=indent)


@dataclass(frozen=True, slots=True)
class PacketPlan(JsonModel):
    """Generated packet intent before any backend materializes bytes."""

    stack: list[str]
    fields: LayerFields
    profile: str
    seed: int
    index: int
    direction: str
    family: str | None = None
    feature_tags: list[str] = field(default_factory=list)
    case: str | None = None
    strict_bytes: bool = True
    metadata: JSONObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class EncodedVector(JsonModel):
    """Backend-emitted packet bytes plus decoder metadata."""

    plan: PacketPlan
    backend: str
    raw_hex: str
    root: str | None = None
    decoder: str | None = None
    metadata: JSONObject = field(default_factory=dict)

    @classmethod
    def from_bytes(
        cls,
        *,
        plan: PacketPlan,
        backend: str,
        raw: bytes,
        root: str | None = None,
        decoder: str | None = None,
        metadata: JSONObject | None = None,
    ) -> "EncodedVector":
        return cls(
            plan=plan,
            backend=backend,
            raw_hex=raw.hex(),
            root=root,
            decoder=decoder,
            metadata=metadata or {},
        )

    def to_bytes(self) -> bytes:
        return bytes.fromhex(self.raw_hex)


@dataclass(frozen=True, slots=True)
class DecodedModel(JsonModel):
    """Normalized packet model used as the backend comparison boundary."""

    backend: str
    layers: list[str]
    fields: LayerFields
    root: str | None = None
    source_hex: str | None = None
    feature_tags: list[str] = field(default_factory=list)
    metadata: JSONObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ComparisonResult(JsonModel):
    """One structured comparison between expected and actual packet behavior."""

    passed: bool
    direction: str
    expected: JSONObject
    actual: JSONObject
    plan: PacketPlan | None = None
    strict_bytes: bool = True
    byte_equal: bool | None = None
    differences: list[JSONObject] = field(default_factory=list)
    reproduction_command: str | None = None
    artifacts: list[str] = field(default_factory=list)
    metadata: JSONObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RunReport(JsonModel):
    """Machine-readable report for an oracle command invocation."""

    mode: str
    backend: str
    profile: str
    seed: int
    count: int
    status: str
    selected_specs: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    artifact_paths: list[str] = field(default_factory=list)
    results: list[ComparisonResult] = field(default_factory=list)
    failures: list[ComparisonResult] = field(default_factory=list)
    reproduction_commands: list[str] = field(default_factory=list)
    backend_versions: JSONObject = field(default_factory=dict)
    libcrafter: JSONObject = field(default_factory=dict)
    metadata: JSONObject = field(default_factory=dict)


def normalized_decoded_model(
    model: DecodedModel | Mapping[str, object],
    *,
    fallback_feature_tags: Sequence[str] = (),
) -> JSONObject:
    """Return the backend-neutral decoded model used for comparisons."""

    raw_model = decoded_model_object(model)
    fields = json_object(raw_model.get("fields", {}), "fields")
    return {
        "layers": string_list(raw_model.get("layers", []), "layers"),
        "fields": _canonical_fields(fields),
        "root": optional_string(raw_model.get("root")),
        "source_hex": optional_string(raw_model.get("source_hex")),
        "feature_tags": feature_tag_list(
            raw_model.get("feature_tags"),
            fallback=fallback_feature_tags,
        ),
    }


def decoded_backend_metadata(model: DecodedModel | Mapping[str, object]) -> JSONObject:
    """Return backend identity and native metadata outside comparison payloads."""

    raw_model = decoded_model_object(model)
    metadata: JSONObject = {}
    backend = optional_string(raw_model.get("backend"))
    if backend is not None:
        metadata["backend"] = backend
    native_metadata = raw_model.get("metadata")
    if isinstance(native_metadata, Mapping):
        metadata["metadata"] = json_object(native_metadata, "metadata")
    elif native_metadata is not None:
        metadata["metadata"] = coerce_json_value(native_metadata)
    return metadata


def decoded_model_object(model: DecodedModel | Mapping[str, object]) -> JSONObject:
    """Return a decoded model as a JSON object without accepting scalar values."""

    if isinstance(model, DecodedModel):
        return model.to_dict()
    return json_object(model, "decoded model")


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


def feature_tag_list(
    value: object,
    *,
    fallback: Sequence[str] = (),
) -> list[str]:
    """Return deterministic feature tags, using the packet plan when absent."""

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        tags = string_list(value, "feature_tags")
        if tags:
            return list(dict.fromkeys(tags))
    return list(dict.fromkeys(fallback))


def optional_string(value: object) -> str | None:
    """Return a nullable string, stringifying legacy scalar values."""

    if value is None or isinstance(value, str):
        return value
    return str(value)


def coerce_json_value(value: object) -> JSONValue:
    """Coerce backend-produced values into JSON-compatible comparison data."""

    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, Mapping):
        return {str(key): coerce_json_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [coerce_json_value(item) for item in value]
    if isinstance(value, bytes):
        return {"hex": value.hex()}
    return str(value)


def _canonical_fields(fields: Mapping[str, object]) -> JSONObject:
    output: JSONObject = {}
    for layer_name, raw_fields in fields.items():
        layer_fields = json_object(raw_fields, f"fields.{layer_name}")
        canonical_layer: JSONObject = {}
        base_layer = _base_layer_name(layer_name)
        for field_name, value in layer_fields.items():
            canonical_value = _canonical_field_value(base_layer, field_name, value)
            if canonical_value is _SKIP:
                continue
            canonical_layer[field_name] = canonical_value
        output[layer_name] = canonical_layer
    return output


def _canonical_field_value(layer_name: str, field_name: str, value: object) -> JSONValue | object:
    if layer_name == "payload" and field_name == "ascii":
        return _SKIP
    if layer_name in {"icmp", "icmpv6"} and field_name == "unused":
        return _SKIP
    if layer_name == "ipv6_routing" and field_name in {
        "alert",
        "hmac",
        "last_entry",
        "lastentry",
        "oam",
        "protected",
        "reserved",
        "tag",
        "tlv_objects",
        "unused1",
        "unused2",
    }:
        return _SKIP
    if field_name == "options":
        return _SKIP
    if field_name == "hex" and isinstance(value, str):
        return value.lower()
    return coerce_json_value(value)


def _base_layer_name(layer_name: str) -> str:
    return layer_name.split("#", 1)[0]


class _Skip:
    pass


_SKIP = _Skip()


def to_jsonable(value: Any) -> JSONValue:
    """Return a strict JSON-compatible copy of an oracle value."""

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
    """Serialize an oracle value as deterministic JSON text."""

    return json.dumps(to_jsonable(value), indent=indent, sort_keys=True) + "\n"


def write_json(path: str | Path, value: Any, *, indent: int = 2) -> None:
    """Write an oracle value as JSON, creating parent directories as needed."""

    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(dumps_json(value, indent=indent), encoding="utf-8")


def read_json(path: str | Path) -> JSONValue:
    """Read JSON text for later conversion into oracle model objects."""

    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)
