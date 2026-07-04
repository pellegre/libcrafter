"""Scapy-stage SCTP encode and decode normalization support.

Scapy installations vary in SCTP layer availability and chunk fidelity. The
oracle's first executable SCTP slice therefore materializes deterministic raw
SCTP bytes and canonicalizes the decoded payload back into the backend-neutral
``sctp`` layer model from the original wire bytes. Native Scapy SCTP layers are
still aliased when present, but strict comparison does not depend on them.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ....model import JSONObject
from ..decode_helpers import _crc32c
from ..encode_helpers import _bytes_field, _int, _layer_fields, _optional_field, _text
from .base import ScapyProtocol, register


_SCTP_PROTOCOL = 132
_SCTP_UDP_ENCAP_PORT = 9899
_SCTP_COMMON_HEADER_LEN = 12
_SCTP_CHUNK_HEADER_LEN = 4
_SCTP_DATA_VALUE_HEADER_LEN = 12
_SCTP_INIT_FIXED_VALUE_LEN = 16
_SCTP_PARAMETER_HEADER_LEN = 4
_SCTP_PPID_WEBRTC_STRING = 51

_CHUNK_TYPE_NAMES: dict[int, str] = {
    0: "data",
    1: "init",
    2: "init_ack",
    3: "sack",
    4: "heartbeat",
    5: "heartbeat_ack",
    6: "abort",
    7: "shutdown",
    8: "shutdown_ack",
    9: "error",
    10: "cookie_echo",
    11: "cookie_ack",
    12: "ecne",
    13: "cwr",
    14: "shutdown_complete",
    15: "auth",
    64: "i_data",
    128: "asconf_ack",
    130: "re_config",
    132: "pad",
    192: "forward_tsn",
    193: "asconf",
    194: "i_forward_tsn",
}
_PARAMETER_TYPE_NAMES: dict[int, str] = {
    5: "ipv4_address",
    6: "ipv6_address",
    7: "state_cookie",
    8: "unrecognized_parameter",
    9: "cookie_preservative",
    11: "host_name_address",
    12: "supported_address_types",
    0x8000: "ecn_capable",
    0x8001: "zero_checksum_acceptable",
    0x8002: "random",
    0x8003: "chunk_list",
    0x8004: "requested_hmac_algorithm",
    0x8005: "padding",
    0x8006: "dtls_key_management",
    0x8008: "supported_extensions",
    0xC000: "forward_tsn_supported",
}

_SUPPORTED_FIELDS = frozenset(
    {
        "checksum",
        "checksum_status",
        "chunk",
        "chunk_flags",
        "chunk_length",
        "chunk_type",
        "chunk_value_hex",
        "chunks",
        "dst_port",
        "dport",
        "nonzero_padding_hex",
        "payload_protocol_identifier",
        "ppid",
        "src_port",
        "sport",
        "stream_id",
        "stream_sequence",
        "stream_sequence_number",
        "tag",
        "tsn",
        "udp_encapsulation",
        "user_data",
        "user_data_hex",
        "user_data_text",
        "verification_tag",
        "vtag",
    }
)


def _build(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Sequence[str],
    index: int,
    scapy_all: Any,
) -> Any:
    del plan, stack, index
    return scapy_all.Raw(load=_sctp_packet_bytes(_layer_fields(fields, "sctp")))


def _normalize(fields: JSONObject) -> JSONObject:
    source = _optional_field(fields, "load", "payload")
    if isinstance(source, (bytes, bytearray)):
        parsed = _parse_sctp_fields(bytes(source))
        if parsed is not None:
            return parsed
    return {
        "src_port": _int(_optional_field(fields, "sport", "src_port"), 0),
        "dst_port": _int(_optional_field(fields, "dport", "dst_port"), 0),
        "verification_tag": _int(_optional_field(fields, "tag", "vtag", "verification_tag"), 0),
        "checksum": _int(_optional_field(fields, "chksum", "checksum"), 0),
    }


def _sctp_packet_bytes(fields: Mapping[str, object]) -> bytes:
    src_port = _int(_optional_field(fields, "src_port", "sport"), 49152)
    dst_port = _int(_optional_field(fields, "dst_port", "dport"), 5000)
    verification_tag = _int(
        _optional_field(fields, "verification_tag", "vtag", "tag"),
        0x11223344,
    )
    chunks = _sctp_chunks_bytes(fields)
    packet = bytearray()
    packet.extend(src_port.to_bytes(2, "big"))
    packet.extend(dst_port.to_bytes(2, "big"))
    packet.extend(verification_tag.to_bytes(4, "big"))
    packet.extend(b"\x00\x00\x00\x00")
    packet.extend(chunks)

    checksum = _checksum_override(_optional_field(fields, "checksum", "chksum"))
    if checksum is None:
        checksum = _crc32c(bytes(packet))
    packet[8:12] = checksum.to_bytes(4, "big")
    return bytes(packet)


def _sctp_chunks_bytes(fields: Mapping[str, object]) -> bytes:
    chunks = _optional_field(fields, "chunks")
    if chunks is None:
        chunk_names: list[object] = [_optional_field(fields, "chunk", "chunk_type") or "data"]
    elif isinstance(chunks, Sequence) and not isinstance(chunks, (str, bytes, bytearray)):
        chunk_names = list(chunks)
    else:
        chunk_names = [chunks]
    if not chunk_names:
        chunk_names = ["data"]

    output = bytearray()
    for chunk in chunk_names:
        if isinstance(chunk, Mapping):
            merged = {**fields, **chunk}
            chunk_name = _optional_field(merged, "type", "chunk", "chunk_type") or "data"
            output.extend(_sctp_chunk_bytes(merged, chunk_name))
        else:
            output.extend(_sctp_chunk_bytes(fields, chunk))
    return bytes(output)


def _sctp_chunk_bytes(fields: Mapping[str, object], chunk: object) -> bytes:
    chunk_type = _chunk_type_value(chunk, _optional_field(fields, "chunk_type"))
    flags = _chunk_flags(_optional_field(fields, "chunk_flags", "flags"), chunk_type)
    if chunk_type == 0:
        value = _data_chunk_value(fields)
    else:
        value = _chunk_value(fields)
    declared_length = _chunk_declared_length(fields, value)
    chunk_bytes = bytearray([chunk_type, flags])
    chunk_bytes.extend(declared_length.to_bytes(2, "big"))
    chunk_bytes.extend(value[: max(0, declared_length - _SCTP_CHUNK_HEADER_LEN)])
    padding = _chunk_padding(fields, declared_length)
    chunk_bytes.extend(padding)
    return bytes(chunk_bytes)


def _data_chunk_value(fields: Mapping[str, object]) -> bytes:
    tsn = _int(_optional_field(fields, "tsn"), 0x01020304)
    stream_id = _int(_optional_field(fields, "stream_id"), 1)
    stream_sequence = _int(
        _optional_field(fields, "stream_sequence", "stream_sequence_number"),
        2,
    )
    ppid = _ppid_value(_optional_field(fields, "payload_protocol_identifier", "ppid"))
    user_data = _user_data_bytes(fields)
    return b"".join(
        (
            tsn.to_bytes(4, "big"),
            stream_id.to_bytes(2, "big"),
            stream_sequence.to_bytes(2, "big"),
            ppid.to_bytes(4, "big"),
            user_data,
        )
    )


def _chunk_value(fields: Mapping[str, object]) -> bytes:
    explicit = _optional_field(fields, "chunk_value_hex", "value")
    if explicit is None:
        return b""
    return _bytes_field(explicit)


def _user_data_bytes(fields: Mapping[str, object]) -> bytes:
    value = _optional_field(fields, "user_data_hex")
    if value is not None:
        return _bytes_field(value)
    value = _optional_field(fields, "user_data_text")
    if value is not None:
        return _text(value, "").encode("utf-8")
    value = _optional_field(fields, "user_data")
    if value is None:
        return b"crafter-sctp-fixture"
    if isinstance(value, Mapping) and "text" in value:
        return _text(value.get("text"), "").encode("utf-8")
    return _bytes_field(value)


def _checksum_override(value: object | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, str):
        normalized = value.lower().replace("-", "_")
        if normalized in {"derived_crc32c", "auto", "explicit_valid"}:
            return None
        if normalized == "explicit_invalid":
            return 0x01020304
        if normalized == "explicit_zero":
            return 0
        if normalized == "boundary":
            return 0xFFFFFFFF
    return _int(value, 0)


def _chunk_type_value(chunk: object, explicit: object | None) -> int:
    if explicit is not None:
        return _chunk_type_value(explicit, None)
    if isinstance(chunk, Mapping):
        return _chunk_type_value(_optional_field(chunk, "type", "chunk_type") or "data", None)
    if isinstance(chunk, int):
        return chunk & 0xFF
    if isinstance(chunk, str):
        normalized = chunk.lower().replace("-", "_")
        for number, name in _CHUNK_TYPE_NAMES.items():
            if normalized == name:
                return number
        if normalized == "unknown":
            return 0x83
        return int(normalized, 0) & 0xFF
    return 0


def _chunk_flags(value: object | None, chunk_type: int) -> int:
    if value is None:
        return 0x03 if chunk_type == 0 else 0
    if isinstance(value, str):
        normalized = value.lower().replace("-", "_")
        if normalized == "zero":
            return 0
        if normalized == "data_ube_bits":
            return 0x07
        if normalized == "data_i_bit":
            return 0x08
        if normalized in {"boundary", "unassigned_preserved"}:
            return 0xFF
        return int(normalized, 0) & 0xFF
    return _int(value, 0) & 0xFF


def _chunk_declared_length(fields: Mapping[str, object], value: bytes) -> int:
    explicit = _optional_field(fields, "chunk_length", "length")
    if explicit is None:
        return _SCTP_CHUNK_HEADER_LEN + len(value)
    if isinstance(explicit, str):
        normalized = explicit.lower().replace("-", "_")
        if normalized == "derived":
            return _SCTP_CHUNK_HEADER_LEN + len(value)
        if normalized == "minimum":
            return _SCTP_CHUNK_HEADER_LEN
        if normalized == "malformed_short":
            return _SCTP_CHUNK_HEADER_LEN - 1
        if normalized == "malformed_overrun":
            return _SCTP_CHUNK_HEADER_LEN + len(value) + 8
    return _int(explicit, _SCTP_CHUNK_HEADER_LEN + len(value))


def _chunk_padding(fields: Mapping[str, object], declared_length: int) -> bytes:
    explicit = _optional_field(fields, "nonzero_padding_hex", "padding_hex")
    needed = (-declared_length) % 4
    if explicit is None:
        return b"\x00" * needed
    raw = _bytes_field(explicit)
    return (raw + (b"\x00" * needed))[:needed]


def _ppid_value(value: object | None) -> int:
    if value is None:
        return _SCTP_PPID_WEBRTC_STRING
    if isinstance(value, str):
        normalized = value.lower().replace("-", "_")
        if normalized in {"webrtc_string", "web_rtc_string"}:
            return _SCTP_PPID_WEBRTC_STRING
        if normalized in {"webrtc_binary", "web_rtc_binary"}:
            return 53
        if normalized == "reserved":
            return 0
        if normalized == "user_defined":
            return 0x80000000
    return _int(value, _SCTP_PPID_WEBRTC_STRING)


def _parse_sctp_fields(raw: bytes) -> JSONObject | None:
    if len(raw) < _SCTP_COMMON_HEADER_LEN:
        return None
    checksum = int.from_bytes(raw[8:12], "big")
    checksum_input = raw[:8] + b"\x00\x00\x00\x00" + raw[12:]
    expected_checksum = _crc32c(checksum_input)
    status = "zero_checksum" if checksum == 0 else "valid" if checksum == expected_checksum else "invalid"
    chunks = _parse_chunks(raw[_SCTP_COMMON_HEADER_LEN:])
    if chunks is None:
        return None
    return {
        "src_port": int.from_bytes(raw[0:2], "big"),
        "dst_port": int.from_bytes(raw[2:4], "big"),
        "verification_tag": int.from_bytes(raw[4:8], "big"),
        "checksum": checksum,
        "checksum_status": status,
        "chunk_count": len(chunks),
        "chunks": chunks,
    }


def _parse_chunks(raw: bytes) -> list[JSONObject] | None:
    chunks: list[JSONObject] = []
    offset = 0
    while offset < len(raw):
        if len(raw) - offset < _SCTP_CHUNK_HEADER_LEN:
            return None
        chunk_type = raw[offset]
        flags = raw[offset + 1]
        declared_length = int.from_bytes(raw[offset + 2 : offset + 4], "big")
        if declared_length < _SCTP_CHUNK_HEADER_LEN:
            return None
        padded_length = declared_length + ((-declared_length) % 4)
        if offset + padded_length > len(raw):
            return None
        value = raw[offset + _SCTP_CHUNK_HEADER_LEN : offset + declared_length]
        padding = raw[offset + declared_length : offset + padded_length]
        item: JSONObject = {
            "type": chunk_type,
            "type_name": _CHUNK_TYPE_NAMES.get(chunk_type, "unknown"),
            "flags": flags,
            "length": declared_length,
            "value_hex": value.hex(),
            "padding_hex": padding.hex(),
            "padding_length": len(padding),
        }
        if chunk_type == 0 and len(value) >= _SCTP_DATA_VALUE_HEADER_LEN:
            user_data = value[_SCTP_DATA_VALUE_HEADER_LEN:]
            item.update(
                {
                    "tsn": int.from_bytes(value[0:4], "big"),
                    "stream_id": int.from_bytes(value[4:6], "big"),
                    "stream_sequence": int.from_bytes(value[6:8], "big"),
                    "payload_protocol_identifier": int.from_bytes(value[8:12], "big"),
                    "user_data_hex": user_data.hex(),
                    "user_data_ascii": user_data.decode("utf-8", "replace"),
                }
            )
        if chunk_type in {1, 2} and len(value) >= _SCTP_INIT_FIXED_VALUE_LEN:
            parameters = _parse_parameters(value[_SCTP_INIT_FIXED_VALUE_LEN:])
            if parameters is None:
                return None
            item.update(
                {
                    "initiate_tag": int.from_bytes(value[0:4], "big"),
                    "advertised_receiver_window_credit": int.from_bytes(value[4:8], "big"),
                    "outbound_streams": int.from_bytes(value[8:10], "big"),
                    "inbound_streams": int.from_bytes(value[10:12], "big"),
                    "initial_tsn": int.from_bytes(value[12:16], "big"),
                    "parameter_count": len(parameters),
                    "parameters": parameters,
                }
            )
        chunks.append(item)
        offset += padded_length
    return chunks


def _parse_parameters(raw: bytes) -> list[JSONObject] | None:
    parameters: list[JSONObject] = []
    offset = 0
    while offset < len(raw):
        if len(raw) - offset < _SCTP_PARAMETER_HEADER_LEN:
            return None
        parameter_type = int.from_bytes(raw[offset : offset + 2], "big")
        declared_length = int.from_bytes(raw[offset + 2 : offset + 4], "big")
        if declared_length < _SCTP_PARAMETER_HEADER_LEN:
            return None
        padded_length = declared_length + ((-declared_length) % 4)
        if offset + padded_length > len(raw):
            return None
        value = raw[offset + _SCTP_PARAMETER_HEADER_LEN : offset + declared_length]
        padding = raw[offset + declared_length : offset + padded_length]
        parameters.append(
            {
                "type": parameter_type,
                "type_name": _PARAMETER_TYPE_NAMES.get(parameter_type, "unknown"),
                "length": declared_length,
                "value_hex": value.hex(),
                "padding_hex": padding.hex(),
                "padding_length": len(padding),
            }
        )
        offset += padded_length
    return parameters


def canonicalize_sctp_payload(
    packet: Any,
    layers: list[str],
    fields: dict[str, JSONObject],
    *,
    root: str | None,
    source_hex: str | None,
) -> None:
    del packet
    if source_hex is None:
        return
    try:
        raw = bytes.fromhex(source_hex)
    except ValueError:
        return
    layout = _sctp_layout(root, raw)
    if layout is None:
        return
    sctp_start, sctp_end, carrier = layout
    parsed = _parse_sctp_fields(raw[sctp_start:sctp_end])
    if parsed is None:
        return
    try:
        carrier_index = max(index for index, layer in enumerate(layers) if layer == carrier)
    except ValueError:
        return
    for index in range(carrier_index + 1, len(layers)):
        fields.pop(_layer_key_at(layers, index), None)
    del layers[carrier_index + 1 :]
    layers.append("sctp")
    fields[_field_key(fields, "sctp")] = parsed


def _sctp_layout(root: str | None, raw: bytes) -> tuple[int, int, str] | None:
    l3_start = _l3_start_offset(root, raw)
    if l3_start is None or len(raw) <= l3_start:
        return None
    version = raw[l3_start] >> 4
    if version == 4:
        return _ipv4_sctp_layout(raw, l3_start)
    if version == 6:
        return _ipv6_sctp_layout(raw, l3_start)
    return None


def _ipv4_sctp_layout(raw: bytes, l3_start: int) -> tuple[int, int, str] | None:
    if len(raw) < l3_start + 20:
        return None
    ihl = (raw[l3_start] & 0x0F) * 4
    total_length = int.from_bytes(raw[l3_start + 2 : l3_start + 4], "big")
    protocol = raw[l3_start + 9]
    if ihl < 20 or len(raw) < l3_start + total_length:
        return None
    payload_start = l3_start + ihl
    ip_end = l3_start + total_length
    if protocol == _SCTP_PROTOCOL:
        return (payload_start, ip_end, "ipv4")
    if protocol == 17:
        return _udp_sctp_layout(raw, payload_start, ip_end)
    return None


def _ipv6_sctp_layout(raw: bytes, l3_start: int) -> tuple[int, int, str] | None:
    if len(raw) < l3_start + 40:
        return None
    payload_length = int.from_bytes(raw[l3_start + 4 : l3_start + 6], "big")
    next_header = raw[l3_start + 6]
    payload_start = l3_start + 40
    ip_end = payload_start + payload_length
    if len(raw) < ip_end:
        return None
    if next_header == _SCTP_PROTOCOL:
        return (payload_start, ip_end, "ipv6")
    if next_header == 17:
        return _udp_sctp_layout(raw, payload_start, ip_end)
    return None


def _udp_sctp_layout(raw: bytes, udp_start: int, ip_end: int) -> tuple[int, int, str] | None:
    if len(raw) < udp_start + 8:
        return None
    src_port = int.from_bytes(raw[udp_start : udp_start + 2], "big")
    dst_port = int.from_bytes(raw[udp_start + 2 : udp_start + 4], "big")
    udp_length = int.from_bytes(raw[udp_start + 4 : udp_start + 6], "big")
    if src_port != _SCTP_UDP_ENCAP_PORT and dst_port != _SCTP_UDP_ENCAP_PORT:
        return None
    if udp_length < 8 or udp_start + udp_length > ip_end:
        return None
    return (udp_start + 8, udp_start + udp_length, "udp")


def _l3_start_offset(root: str | None, raw: bytes) -> int | None:
    if root == "link:ethernet":
        if len(raw) < 14:
            return None
        offset = 14
        ethertype = int.from_bytes(raw[12:14], "big")
        while ethertype in {0x8100, 0x88A8, 0x9100}:
            if len(raw) < offset + 4:
                return None
            ethertype = int.from_bytes(raw[offset + 2 : offset + 4], "big")
            offset += 4
        return offset
    if root in {"link:linux-cooked", "link:linux-sll"}:
        return 16
    if root == "link:null-loopback":
        return 4
    return 0


def _field_key(existing: Mapping[str, JSONObject], layer_name: str) -> str:
    if layer_name not in existing:
        return layer_name
    index = 2
    while f"{layer_name}#{index}" in existing:
        index += 1
    return f"{layer_name}#{index}"


def _layer_key_at(layers: Sequence[str], index: int) -> str:
    layer = layers[index]
    occurrence = sum(1 for item in layers[: index + 1] if item == layer)
    return layer if occurrence == 1 else f"{layer}#{occurrence}"


register(
    ScapyProtocol(
        layer="sctp",
        scapy_class="Raw",
        supported_fields=_SUPPORTED_FIELDS,
        build=_build,
        normalize=_normalize,
        layer_aliases=(("SCTP", "sctp"),),
        field_aliases=(
            ("sport", "src_port"),
            ("dport", "dst_port"),
            ("tag", "verification_tag"),
            ("chksum", "checksum"),
        ),
    )
)
