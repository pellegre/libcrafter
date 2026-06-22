"""Shared, protocol-agnostic helpers for Scapy packet materialization.

These low-level field accessors, value coercions, and constant maps are used by
multiple per-layer builders in :mod:`packets` (and, as builders migrate, by the
per-protocol encoder plugins). They are extracted here so plugins can import them
without depending on the ``packets`` orchestrator, avoiding a circular import.

This module must not import from :mod:`packets`.
"""

from __future__ import annotations

from collections.abc import Mapping

from ...model import JSONObject

_ETHERTYPES: dict[str, int] = {
    "arp": 0x0806,
    "eapol": 0x888E,
    "experimental": 0x9000,
    "ipv4": 0x0800,
    "ip": 0x0800,
    "ipv6": 0x86DD,
    "unknown": 0x9000,
    "vlan": 0x8100,
}
_IP_PROTOCOLS: dict[str, int] = {
    "ah": 51,
    "esp": 50,
    "icmp": 1,
    "igmp": 2,
    "tcp": 6,
    "unknown": 253,
    "udp": 17,
}


def _layer_fields(fields: Mapping[str, JSONObject], layer: str) -> JSONObject:
    value = fields.get(layer)
    if value is None and layer == "ipv4":
        value = fields.get("ip")
    if value is None and layer == "payload":
        value = fields.get("raw")
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"{layer} fields must be an object")
    return dict(value)


def _required_field(fields: Mapping[str, object], layer: str, *names: str) -> object:
    value = _optional_field(fields, *names)
    if value is None:
        joined = "/".join(names)
        raise ValueError(f"{layer} materialization requires field {joined}")
    return value


def _optional_field(fields: Mapping[str, object], *names: str) -> object | None:
    for name in names:
        if name in fields:
            return fields[name]
    return None


def _ethertype_value(value: object) -> int:
    if isinstance(value, str):
        lowered = value.lower()
        if lowered in _ETHERTYPES:
            return _ETHERTYPES[lowered]
        return int(lowered, 0)
    return _int(value, 0x9000)


def _bool_int(value: object, default: int) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, str):
        lowered = value.lower().replace("_", "-")
        if lowered in {"true", "yes", "response"}:
            return 1
        if lowered in {"false", "no", "query"}:
            return 0
    return _int(value, default)


def _int(value: object, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError(f"expected integer-compatible value, got {value!r}")


def _text(value: object, default: str) -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value
    return str(value)
