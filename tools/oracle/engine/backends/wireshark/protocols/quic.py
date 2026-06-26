"""Wireshark-stage parser-only normalization for QUIC UDP payloads."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ....model import JSONObject
from ..decode_helpers import (
    _fields_from_aliases,
    _hex_bytes,
    _layer,
    _parse_int,
    _parse_int_fields,
    _string_field,
)
from .base import WiresharkProtocol, register


_QUIC_UDP_PORTS = {443, 4433}
_QUIC_VERSION_1 = 0x0000_0001
_QUIC_VERSION_2 = 0x6B33_43CF

_QUIC_TSHARK_ALIASES: JSONObject = {
    "version": ("quic.version",),
    "dcid": ("quic.dcid", "quic.dcid_str"),
    "scid": ("quic.scid", "quic.scid_str"),
}


def _normalize(layers: JSONObject, *, source_hex: str | None = None) -> JSONObject:
    raw = _udp_payload_from_source(source_hex) if source_hex else None
    if raw is not None and _looks_like_quic(raw):
        return quic_fields_from_bytes(raw)
    output = _fields_from_aliases(_layer(layers, "quic"), dict(_QUIC_TSHARK_ALIASES))
    if "version" in output:
        _parse_int_fields(output, "version")
    return output


def canonicalize_quic_payload(
    layers: list[str],
    fields: dict[str, JSONObject],
    layers_object: JSONObject,
    *,
    source_hex: str | None = None,
) -> None:
    """Promote Wireshark ``data`` on UDP/443/4433 to the neutral ``quic`` layer."""

    if "quic" in layers:
        key = _first_layer_key(fields, "quic")
        raw = _udp_payload_from_source(source_hex) if source_hex else None
        if key is not None and raw is not None and _looks_like_quic(raw):
            fields[key] = quic_fields_from_bytes(raw)
        return

    udp_key = _first_layer_key(fields, "udp")
    if udp_key is None:
        return
    udp = fields.get(udp_key, {})
    src_port = _int_value(udp.get("src_port"))
    dst_port = _int_value(udp.get("dst_port"))
    if src_port not in _QUIC_UDP_PORTS and dst_port not in _QUIC_UDP_PORTS:
        return

    payload_index = _payload_index_after_udp(layers)
    if payload_index is None:
        return
    payload_key = _layer_key_at(layers, payload_index)
    raw = _payload_bytes_from_fields(fields.get(payload_key, {}))
    if raw is None:
        raw = _payload_bytes_from_tshark_data(layers_object)
    if raw is None and source_hex is not None:
        raw = _udp_payload_from_source(source_hex)
    if raw is None or not _looks_like_quic(raw):
        return

    fields.pop(payload_key, None)
    layers[payload_index] = "quic"
    fields[_layer_key_at(layers, payload_index)] = quic_fields_from_bytes(raw)


def quic_fields_from_bytes(raw: bytes) -> JSONObject:
    return {
        "raw_hex": raw.hex(),
        "raw_len": len(raw),
        "packet_count": _packet_count(raw),
    }


def _payload_bytes_from_tshark_data(layers: JSONObject) -> bytes | None:
    data = _string_field(_layer(layers, "data"), "data.data", "data.text")
    if data is None:
        return None
    return bytes.fromhex(_hex_bytes(data))


def _payload_bytes_from_fields(fields: Mapping[str, object]) -> bytes | None:
    hex_value = fields.get("hex") or fields.get("raw_hex")
    if isinstance(hex_value, str):
        return bytes.fromhex(hex_value)
    return None


def _udp_payload_from_source(source_hex: str | None) -> bytes | None:
    if not source_hex:
        return None
    raw = bytes.fromhex(source_hex)
    for offset in _candidate_l3_offsets(raw):
        payload = _udp_payload_at_l3(raw, offset)
        if payload is not None:
            return payload
    return None


def _candidate_l3_offsets(raw: bytes) -> list[int]:
    offsets = [0]
    if len(raw) >= 14 and raw[12:14] in {b"\x08\x00", b"\x86\xdd"}:
        offsets.append(14)
    if len(raw) >= 5:
        offsets.append(4)
    return list(dict.fromkeys(offsets))


def _udp_payload_at_l3(raw: bytes, offset: int) -> bytes | None:
    if offset >= len(raw):
        return None
    version = raw[offset] >> 4
    if version == 4:
        return _udp_payload_ipv4(raw, offset)
    if version == 6:
        return _udp_payload_ipv6(raw, offset)
    return None


def _udp_payload_ipv4(raw: bytes, offset: int) -> bytes | None:
    if len(raw) < offset + 28:
        return None
    ihl = (raw[offset] & 0x0F) * 4
    if ihl < 20 or len(raw) < offset + ihl + 8 or raw[offset + 9] != 17:
        return None
    total_length = int.from_bytes(raw[offset + 2 : offset + 4], "big")
    end = offset + min(total_length, len(raw) - offset)
    udp_offset = offset + ihl
    if udp_offset + 8 > end:
        return None
    udp_length = int.from_bytes(raw[udp_offset + 4 : udp_offset + 6], "big")
    if udp_length < 8 or udp_offset + udp_length > end:
        return None
    return raw[udp_offset + 8 : udp_offset + udp_length]


def _udp_payload_ipv6(raw: bytes, offset: int) -> bytes | None:
    if len(raw) < offset + 48 or raw[offset + 6] != 17:
        return None
    payload_length = int.from_bytes(raw[offset + 4 : offset + 6], "big")
    end = offset + 40 + payload_length
    udp_offset = offset + 40
    if udp_offset + 8 > end or end > len(raw):
        return None
    udp_length = int.from_bytes(raw[udp_offset + 4 : udp_offset + 6], "big")
    if udp_length < 8 or udp_offset + udp_length > end:
        return None
    return raw[udp_offset + 8 : udp_offset + udp_length]


def _looks_like_quic(raw: bytes) -> bool:
    return bool(raw) and raw[0] & 0x80 != 0 and _packet_count(raw) > 0


def _packet_count(raw: bytes) -> int:
    cursor = 0
    count = 0
    while cursor < len(raw):
        next_end = _next_packet_end(raw, cursor)
        if next_end is None:
            return count
        count += 1
        cursor = next_end
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
        return len(raw) if (len(raw) - pos) % 4 == 0 else None
    if _is_retry(version, first):
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
    return end if end <= len(raw) else None


def _is_initial(version: int, first: int) -> bool:
    bits = (first & 0x30) >> 4
    return bits == 1 if version == _QUIC_VERSION_2 else bits == 0


def _is_retry(version: int, first: int) -> bool:
    bits = (first & 0x30) >> 4
    return bits == 0 if version == _QUIC_VERSION_2 else version == _QUIC_VERSION_1 and bits == 3


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


def _first_layer_key(fields: Mapping[str, JSONObject], layer: str) -> str | None:
    if layer in fields:
        return layer
    prefix = f"{layer}#"
    return next((key for key in fields if key.startswith(prefix)), None)


def _layer_key_at(layers: Sequence[str], index: int) -> str:
    layer_name = layers[index]
    occurrence = sum(1 for position in range(index + 1) if layers[position] == layer_name)
    return layer_name if occurrence == 1 else f"{layer_name}#{occurrence}"


def _int_value(value: object) -> int:
    parsed = _parse_int(value)
    return parsed if parsed is not None else 0


register(
    WiresharkProtocol(
        layer="quic",
        normalize=_normalize,
        tshark_aliases=dict(_QUIC_TSHARK_ALIASES),
    )
)
