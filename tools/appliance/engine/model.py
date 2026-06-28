"""Strict JSON-compatible model helpers for appliance manifests."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import fields, is_dataclass
from pathlib import Path
from typing import Any, TypeAlias


JSONScalar: TypeAlias = str | int | float | bool | None
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]
JSONObject: TypeAlias = dict[str, JSONValue]


class JsonModel:
    """Mixin for appliance models that serialize through JSON objects."""

    def to_dict(self) -> JSONObject:
        value = to_jsonable(self)
        if not isinstance(value, dict):
            raise TypeError(f"{type(self).__name__} did not serialize to an object")
        return value

    def to_json(self, *, indent: int = 2) -> str:
        return dumps_json(self, indent=indent)


def to_jsonable(value: Any) -> JSONValue:
    """Return a strict JSON-compatible copy of an appliance model value."""

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


def coerce_json_value(value: object) -> JSONValue:
    """Coerce supported appliance values into strict JSON-compatible data."""

    return to_jsonable(value)


def dumps_json(value: Any, *, indent: int = 2) -> str:
    """Serialize an appliance value as deterministic JSON text."""

    return json.dumps(to_jsonable(value), indent=indent, sort_keys=True) + "\n"


def read_json(path: str | Path) -> JSONValue:
    """Read strict JSON text from an absolute path."""

    input_path = absolute_path(path, "JSON input path")
    with Path(input_path).open("r", encoding="utf-8") as handle:
        return json.load(handle, parse_constant=_reject_json_constant)


def write_json(path: str | Path, value: Any, *, indent: int = 2) -> None:
    """Write deterministic JSON text to an absolute path."""

    output_path = Path(absolute_path(path, "JSON output path"))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(dumps_json(value, indent=indent), encoding="utf-8")


def require_non_empty_string(value: object, name: str) -> str:
    """Return a non-empty string field or raise a validation error."""

    if not isinstance(value, str) or value == "":
        raise ValueError(f"{name} must be a non-empty string")
    return value


def optional_string(value: object, name: str) -> str | None:
    """Return an optional string field or raise a validation error."""

    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def string_list(value: object, name: str) -> list[str]:
    """Return a JSON array field as a list of strings."""

    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{name} must be a list of strings")
    output: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{name} must be a list of strings")
        output.append(item)
    return output


def absolute_path(value: str | Path, name: str) -> str:
    """Return an absolute path string or raise a validation error."""

    if not isinstance(value, (str, Path)):
        raise ValueError(f"{name} must be an absolute path")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError(f"{name} must be an absolute path")
    return str(path)


def optional_absolute_path(value: str | Path | None, name: str) -> str | None:
    """Return an optional absolute path string or raise a validation error."""

    if value is None:
        return None
    return absolute_path(value, name)


def json_object(value: object, name: str) -> JSONObject:
    """Return a JSON object with string keys and strict JSON-compatible values."""

    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    output: JSONObject = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ValueError(f"{name} keys must be strings")
        output[key] = to_jsonable(item)
    return output


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite float is not valid JSON: {value}")
