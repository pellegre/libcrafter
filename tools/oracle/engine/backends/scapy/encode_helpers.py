"""Shared, protocol-agnostic helpers for Scapy packet materialization.

These low-level field accessors, value coercions, and constant maps are used by
multiple per-layer builders in :mod:`packets` (and, as builders migrate, by the
per-protocol encoder plugins). They are extracted here so plugins can import them
without depending on the ``packets`` orchestrator, avoiding a circular import.

This module must not import from :mod:`packets`.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

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
# IPv6 ``next_header`` / extension-header protocol numbers. Shared by the base
# IPv6 builder (migrated to ``protocols/ipv6.py``), the IPv6 extension-header
# builders, and the IPv6 raw-bytes path in ``packets``, so it lives here in the
# stage helper module rather than in ``packets`` to avoid a circular import.
_IPV6_NEXT_HEADERS: dict[str, int] = {
    "destination-options": 60,
    "destination_options": 60,
    "dstopts": 60,
    "fragment": 44,
    "hop-by-hop": 0,
    "hop-by-hop-options": 0,
    "hop_by_hop": 0,
    "hop_by_hop_options": 0,
    "hopopts": 0,
    "routing": 43,
    "icmpv6": 58,
    "no-next": 59,
    "no_next": 59,
    "payload": 253,
    "raw": 253,
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


def _layer_fields_for_stack_index(
    fields: Mapping[str, JSONObject],
    stack: Sequence[str],
    index: int,
) -> JSONObject:
    layer = stack[index]
    occurrence = sum(1 for item in stack[: index + 1] if item == layer)
    if occurrence > 1:
        value = fields.get(f"{layer}#{occurrence}")
        if value is not None:
            if not isinstance(value, Mapping):
                raise ValueError(f"{layer}#{occurrence} fields must be an object")
            return dict(value)
    return _layer_fields(fields, layer)


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


def _hardware_type_value(value: object) -> int:
    if isinstance(value, str):
        lowered = value.lower()
        if lowered in {"ether", "ethernet"}:
            return 1
        return int(lowered, 0)
    return _int(value, 1)


def _bytes_field(value: object, *, pad_to: int | None = None) -> bytes:
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, Mapping):
        hex_value = value.get("hex")
        if not isinstance(hex_value, str):
            raise ValueError(f"bytes field object requires hex, got {value!r}")
        raw = bytes.fromhex(hex_value)
    elif isinstance(value, str):
        cleaned = value.replace(":", "").replace("-", "")
        raw = bytes.fromhex(cleaned)
    else:
        raise ValueError(f"expected bytes-compatible value, got {value!r}")
    if pad_to is not None and len(raw) < pad_to:
        raw = raw + (b"\x00" * (pad_to - len(raw)))
    return raw


def _bytes_optional(value: object) -> bytes:
    if value is None:
        return b""
    return _bytes_field(value)


def _bytes_exact(value: object, length: int) -> bytes:
    raw = _bytes_optional(value)
    if len(raw) > length:
        return raw[:length]
    return raw.ljust(length, b"\x00")


def _payload_bytes(fields: Mapping[str, JSONObject]) -> bytes:
    payload = _layer_fields(fields, "payload")
    if not payload:
        return b""
    if "hex" in payload:
        raw = bytes.fromhex(_text(payload.get("hex"), ""))
        _validate_payload_length(payload, raw)
        return raw
    if "bytes_hex" in payload:
        raw = bytes.fromhex(_text(payload.get("bytes_hex"), ""))
        _validate_payload_length(payload, raw)
        return raw
    if "text" in payload:
        raw = _text(payload.get("text"), "").encode("utf-8")
        _validate_payload_length(payload, raw)
        return raw
    if "value" in payload:
        raw = _text(payload.get("value"), "").encode("utf-8")
        _validate_payload_length(payload, raw)
        return raw
    raise ValueError("payload materialization requires bytes in hex, bytes_hex, text, or value")


def _validate_payload_length(payload: Mapping[str, object], raw: bytes) -> None:
    if "length" not in payload:
        return
    length = _int(payload.get("length"), 0)
    if length != len(raw):
        raise ValueError(
            f"payload length mismatch: declared={length} materialized={len(raw)}"
        )


def _protocol_value(value: object, mapping: Mapping[str, int]) -> int:
    if isinstance(value, str):
        lowered = value.lower()
        if lowered in mapping:
            return mapping[lowered]
        return int(lowered, 0)
    return _int(value, 0)


def _ipv4_flags(value: object) -> object:
    names = {
        "mf": 0b001,
        "more-fragments": 0b001,
        "df": 0b010,
        "dont-fragment": 0b010,
        "reserved": 0b100,
    }
    if isinstance(value, str):
        lowered = value.lower().replace("_", "-")
        if lowered in {"none", "0"}:
            return 0
        if lowered == "df-mf":
            return names["df"] | names["mf"]
        if lowered == "all":
            return names["reserved"] | names["df"] | names["mf"]
        if lowered in names:
            return names[lowered]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        flags = 0
        for item in value:
            flags |= _int(_ipv4_flags(item), 0)
        return flags
    return value


def _option_bytes(value: object) -> bytes | None:
    if isinstance(value, bytes):
        return value
    if isinstance(value, Mapping):
        hex_value = value.get("hex")
        if isinstance(hex_value, str):
            return bytes.fromhex(hex_value)
    if isinstance(value, str):
        return bytes.fromhex(value)
    return None


def _internet_checksum(data: bytes) -> int:
    """Compute the 16-bit one's-complement Internet checksum (RFC 1071).

    Shared by the IPv4/ICMP/IGMP/RIPng raw-header builders; extracted here so the
    per-protocol plugins can fold their own header checksums without importing the
    ``packets`` orchestrator.
    """

    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += int.from_bytes(data[index : index + 2], "big")
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ipv4_address_bytes(value: object, default: str = "0.0.0.0") -> bytes:
    """Pack a dotted-quad IPv4 address string into four network-order bytes.

    Shared by the ICMP router/quoted-datagram builders and the IPv4/IGMP raw
    builders; extracted here so the per-protocol plugins can serialize an IPv4
    address without importing the ``packets`` orchestrator.
    """

    text = _text(value, default)
    return bytes(int(part) & 0xFF for part in text.split("."))
