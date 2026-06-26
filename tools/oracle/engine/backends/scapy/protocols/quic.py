"""Scapy-stage encode and decode helpers for QUIC UDP payloads."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ....model import JSONObject
from ..encode_helpers import _bytes_field, _layer_fields, _optional_field
from .base import ScapyProtocol, register


_SUPPORTED_FIELDS = frozenset({"raw_hex"})
_QUIC_UDP_PORTS = {443, 4433}
_QUIC_VERSION_1 = 0x0000_0001
_QUIC_VERSION_2 = 0x6B33_43CF


def _build(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    del plan, stack, index
    quic_fields = _layer_fields(fields, "quic")
    raw = _bytes_field(_required_quic_bytes(quic_fields))
    return scapy_all.Raw(load=raw)


def _required_quic_bytes(fields: Mapping[str, object]) -> object:
    value = _optional_field(fields, "raw_hex", "hex", "bytes_hex")
    if value is None:
        raise ValueError("quic materialization requires raw_hex")
    return value


def canonicalize_quic_payload(
    packet: Any,
    layers: list[str],
    fields: dict[str, JSONObject],
) -> None:
    """Rename a Raw UDP/443 or UDP/4433 payload to the neutral ``quic`` layer."""

    udp = _scapy_layer(packet, "UDP")
    if udp is None:
        return
    sport = _int(getattr(udp, "sport", 0))
    dport = _int(getattr(udp, "dport", 0))
    if sport not in _QUIC_UDP_PORTS and dport not in _QUIC_UDP_PORTS:
        return

    payload_index = _payload_index_after_udp(layers)
    if payload_index is None:
        return
    raw = _raw_payload_from_packet(packet)
    if raw is None:
        payload_key = _layer_key_at(layers, payload_index)
        raw = _raw_payload_from_fields(fields.get(payload_key, {}))
    if not raw or not _looks_like_quic(raw):
        return

    payload_key = _layer_key_at(layers, payload_index)
    fields.pop(payload_key, None)
    layers[payload_index] = "quic"
    quic_key = _layer_key_at(layers, payload_index)
    fields[quic_key] = quic_fields_from_bytes(raw)


def quic_fields_from_bytes(raw: bytes) -> JSONObject:
    return {
        "raw_hex": raw.hex(),
        "raw_len": len(raw),
        "packet_count": _packet_count(raw),
    }


def _looks_like_quic(raw: bytes) -> bool:
    return bool(raw) and raw[0] & 0x80 != 0 and _packet_count(raw) > 0


def _packet_count(raw: bytes) -> int:
    cursor = 0
    count = 0
    while cursor < len(raw):
        parsed = _next_packet_end(raw, cursor)
        if parsed is None:
            return count
        count += 1
        cursor = parsed
    return count


def _next_packet_end(raw: bytes, cursor: int) -> int | None:
    if cursor >= len(raw) or raw[cursor] & 0x80 == 0:
        return None
    first = raw[cursor]
    if cursor + 7 > len(raw):
        return None
    version = int.from_bytes(raw[cursor + 1 : cursor + 5], "big")
    pos = cursor + 5
    dcid_len = raw[pos]
    pos += 1
    if pos + dcid_len >= len(raw):
        return None
    pos += dcid_len
    scid_len = raw[pos]
    pos += 1
    if pos + scid_len > len(raw):
        return None
    pos += scid_len

    if version == 0:
        # Version Negotiation carries a whole-number list of version values and
        # has no per-packet length field. It cannot be coalesced with protected
        # packets in this oracle suite.
        remaining = len(raw) - pos
        return len(raw) if remaining % 4 == 0 else None

    if _is_retry(version, first):
        # Retry has no QUIC long-header Length field; the integrity tag terminates
        # the datagram in this raw-preserving oracle representation.
        return len(raw)

    if _is_initial(version, first):
        token_len = _read_varint(raw, pos)
        if token_len is None:
            return None
        token_length, pos = token_len
        if pos + token_length > len(raw):
            return None
        pos += token_length

    length_value = _read_varint(raw, pos)
    if length_value is None:
        return None
    payload_len, pos = length_value
    end = pos + payload_len
    if end > len(raw):
        return None
    return end


def _is_initial(version: int, first: int) -> bool:
    bits = (first & 0x30) >> 4
    if version == _QUIC_VERSION_2:
        return bits == 1
    return bits == 0


def _is_retry(version: int, first: int) -> bool:
    bits = (first & 0x30) >> 4
    if version == _QUIC_VERSION_2:
        return bits == 0
    return version == _QUIC_VERSION_1 and bits == 3


def _read_varint(raw: bytes, cursor: int) -> tuple[int, int] | None:
    if cursor >= len(raw):
        return None
    first = raw[cursor]
    length = 1 << (first >> 6)
    if cursor + length > len(raw):
        return None
    value = first & (0x3F >> (first >> 6))
    for byte in raw[cursor + 1 : cursor + length]:
        value = (value << 8) | byte
    return value, cursor + length


def _payload_index_after_udp(layers: Sequence[str]) -> int | None:
    try:
        udp_index = list(layers).index("udp")
    except ValueError:
        return None
    for index in range(udp_index + 1, len(layers)):
        if layers[index] == "payload":
            return index
    return None


def _raw_payload_from_packet(packet: Any) -> bytes | None:
    raw_layer = _scapy_layer(packet, "Raw")
    if raw_layer is None:
        return None
    load = getattr(raw_layer, "load", None)
    if isinstance(load, bytes):
        return load
    if load is None:
        return None
    try:
        return bytes(load)
    except (TypeError, ValueError):
        return None


def _raw_payload_from_fields(fields: Mapping[str, object]) -> bytes | None:
    value = fields.get("hex") or fields.get("raw_hex")
    if isinstance(value, str):
        return bytes.fromhex(value)
    load = fields.get("load")
    if isinstance(load, Mapping):
        hex_value = load.get("hex")
        if isinstance(hex_value, str):
            return bytes.fromhex(hex_value)
    return None


def _scapy_layer(packet: Any, class_name: str) -> Any:
    current = packet
    while current is not None and current.__class__.__name__ != "NoPayload":
        if current.__class__.__name__ == class_name:
            return current
        current = current.payload
    return None


def _layer_key_at(layers: Sequence[str], index: int) -> str:
    layer_name = layers[index]
    occurrence = sum(1 for position in range(index + 1) if layers[position] == layer_name)
    return layer_name if occurrence == 1 else f"{layer_name}#{occurrence}"


def _int(value: object) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


register(
    ScapyProtocol(
        layer="quic",
        scapy_class="Raw",
        supported_fields=_SUPPORTED_FIELDS,
        build=_build,
    )
)
