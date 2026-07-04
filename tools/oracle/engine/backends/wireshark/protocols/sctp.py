"""Wireshark-stage decode plugin for SCTP packets.

Wireshark/tshark is parser-only in the oracle. Its SCTP JSON field names vary
across versions and do not expose every byte-preservation detail the oracle
compares, so the plugin prefers source-hex normalization of the SCTP packet
inside IPv4/IPv6 or RFC 6951 UDP/9899. The tshark field aliases remain as a
common-header fallback when source bytes are unavailable.
"""

from __future__ import annotations

from ....model import JSONObject
from ..decode_helpers import _fields_from_aliases, _layer, _parse_int_fields
from .base import WiresharkProtocol, register


_SCTP_PROTOCOL = 132
_SCTP_UDP_ENCAP_PORT = 9899
_SCTP_COMMON_HEADER_LEN = 12
_SCTP_CHUNK_HEADER_LEN = 4
_SCTP_DATA_VALUE_HEADER_LEN = 12
_SCTP_INIT_FIXED_VALUE_LEN = 16
_SCTP_PARAMETER_HEADER_LEN = 4

_SCTP_TSHARK_ALIASES: JSONObject = {
    "src_port": ("sctp.srcport",),
    "dst_port": ("sctp.dstport",),
    "verification_tag": ("sctp.verification_tag",),
    "checksum": ("sctp.checksum",),
}
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


def _normalize_sctp(layers: JSONObject, *, source_hex: str | None = None) -> JSONObject:
    if source_hex is not None:
        try:
            raw = bytes.fromhex(source_hex)
        except ValueError:
            raw = b""
        layout = _sctp_layout(raw)
        if layout is not None:
            start, end = layout
            parsed = _parse_sctp_fields(raw[start:end])
            if parsed is not None:
                return parsed

    output = _fields_from_aliases(_layer(layers, "sctp"), dict(_SCTP_TSHARK_ALIASES))
    _parse_int_fields(output, "src_port", "dst_port", "verification_tag", "checksum")
    return output


def _sctp_layout(raw: bytes) -> tuple[int, int] | None:
    for l3_start in _candidate_l3_offsets(raw):
        if len(raw) <= l3_start:
            continue
        version = raw[l3_start] >> 4
        if version == 4:
            layout = _ipv4_sctp_layout(raw, l3_start)
        elif version == 6:
            layout = _ipv6_sctp_layout(raw, l3_start)
        else:
            layout = None
        if layout is not None:
            return layout
    return None


def _candidate_l3_offsets(raw: bytes) -> tuple[int, ...]:
    offsets = [0]
    if len(raw) >= 14:
        ethertype = int.from_bytes(raw[12:14], "big")
        if ethertype in {0x0800, 0x86DD}:
            offsets.append(14)
    return tuple(dict.fromkeys(offsets))


def _ipv4_sctp_layout(raw: bytes, l3_start: int) -> tuple[int, int] | None:
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
        return (payload_start, ip_end)
    if protocol == 17:
        return _udp_sctp_layout(raw, payload_start, ip_end)
    return None


def _ipv6_sctp_layout(raw: bytes, l3_start: int) -> tuple[int, int] | None:
    if len(raw) < l3_start + 40:
        return None
    payload_length = int.from_bytes(raw[l3_start + 4 : l3_start + 6], "big")
    next_header = raw[l3_start + 6]
    payload_start = l3_start + 40
    ip_end = payload_start + payload_length
    if len(raw) < ip_end:
        return None
    if next_header == _SCTP_PROTOCOL:
        return (payload_start, ip_end)
    if next_header == 17:
        return _udp_sctp_layout(raw, payload_start, ip_end)
    return None


def _udp_sctp_layout(raw: bytes, udp_start: int, ip_end: int) -> tuple[int, int] | None:
    if len(raw) < udp_start + 8:
        return None
    src_port = int.from_bytes(raw[udp_start : udp_start + 2], "big")
    dst_port = int.from_bytes(raw[udp_start + 2 : udp_start + 4], "big")
    udp_length = int.from_bytes(raw[udp_start + 4 : udp_start + 6], "big")
    if src_port != _SCTP_UDP_ENCAP_PORT and dst_port != _SCTP_UDP_ENCAP_PORT:
        return None
    if udp_length < 8 or udp_start + udp_length > ip_end:
        return None
    return (udp_start + 8, udp_start + udp_length)


def _parse_sctp_fields(raw: bytes) -> JSONObject | None:
    if len(raw) < _SCTP_COMMON_HEADER_LEN:
        return None
    checksum = int.from_bytes(raw[8:12], "big")
    chunks = _parse_chunks(raw[_SCTP_COMMON_HEADER_LEN:])
    if chunks is None:
        return None
    output: JSONObject = {
        "src_port": int.from_bytes(raw[0:2], "big"),
        "dst_port": int.from_bytes(raw[2:4], "big"),
        "verification_tag": int.from_bytes(raw[4:8], "big"),
        "checksum": checksum,
        "chunk_count": len(chunks),
        "chunks": chunks,
    }
    return output


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


register(
    WiresharkProtocol(
        layer="sctp",
        normalize=_normalize_sctp,
        tshark_aliases=dict(_SCTP_TSHARK_ALIASES),
    )
)
