"""Protocol-agnostic helpers shared by Scapy decode/normalize routines.

These primitives are reused by more than one ``_normalize_<layer>_*`` /
``_parse_<layer>`` function in ``normalize.py`` and by the per-protocol decoder
plugins that later steps split out. Keeping them here lets those plugins import
the shared machinery without depending on the ``normalize.py`` orchestrator
(which would create a circular import). This module must not import from
``normalize.py``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ...model import JSONObject, JSONValue


def _bool_flag(value: JSONValue) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value not in {"", "0", "false", "False"}
    return bool(value)


def _mac_text(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)


def _int_or_zero(value: object) -> int:
    return value if isinstance(value, int) else 0


def _internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += int.from_bytes(data[index : index + 2], "big")
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _crc32c(data: bytes) -> int:
    crc = 0xFFFF_FFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x82F6_3B78
            else:
                crc >>= 1
    return (~crc) & 0xFFFF_FFFF


def _field_key(existing: Mapping[str, JSONObject], layer_name: str) -> str:
    if layer_name not in existing:
        return layer_name
    index = 2
    while f"{layer_name}#{index}" in existing:
        index += 1
    return f"{layer_name}#{index}"


def _json_value(value: Any) -> JSONValue:
    if isinstance(value, bytes):
        return {"hex": value.hex(), "ascii": value.decode("utf-8", "replace")}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    return str(value)


def _object(value: JSONValue, name: str) -> JSONObject:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    return dict(value)


def _text(value: object) -> str:
    if isinstance(value, str):
        return value
    return str(value)


def _text_or_none(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return str(value)
