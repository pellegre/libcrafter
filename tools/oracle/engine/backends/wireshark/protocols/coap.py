"""Wireshark-stage parser-only CoAP normalization.

The normalizer prefers the captured UDP payload so tshark presentation changes
cannot lose unknown codes, ordered options, raw option headers, or opaque OSCORE
ciphertext.  Native tshark fields remain a fallback for callers without source
bytes.  No secret-assisted OSCORE or reliable-stream capability is claimed.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ....model import JSONObject
from ..decode_helpers import _field, _field_list, _fields_from_aliases, _hex_bytes, _layer, _parse_int
from .base import WiresharkProtocol, register


WIRESHARK_COAP_CAPABILITIES: JSONObject = {
    "parser_only": True,
    "cleartext_datagram": True,
    "gaps": {
        "reliable_framing": "TCP stream framing is not normalized as one packet layer",
        "extended_tokens": "tshark version-dependent; source bytes remain authoritative",
        "advanced_options": "unknown values are preserved without fabricated typed semantics",
        "oscore": "ciphertext stays opaque and no secrets are provisioned",
    },
}

_TSHARK_ALIASES: JSONObject = {
    "version": ("coap.version",),
    "message_type": ("coap.type",),
    "token_length": ("coap.token_len", "coap.tkl"),
    "code": ("coap.code",),
    "message_id": ("coap.mid", "coap.message_id"),
    "token": ("coap.token",),
    "payload": ("coap.payload",),
}

_TYPE_LABELS = {
    0: "confirmable",
    1: "non_confirmable",
    2: "acknowledgement",
    3: "reset",
}


def _normalize(layers: JSONObject, *, source_hex: str | None = None) -> JSONObject:
    payload = _udp_payload_from_source_hex(source_hex)
    if payload is not None:
        normalized = coap_fields_from_bytes(payload)
        return normalized if normalized is not None else {}
    if source_hex is not None:
        # A captured non-cleartext/non-UDP/5683 packet must stay Raw; do not
        # synthesize a default CoAP model merely because this plugin was asked.
        return {}

    layer = _layer(layers, "coap")
    output = _fields_from_aliases(layer, dict(_TSHARK_ALIASES))
    version = _parse_int(output.get("version"))
    message_type = _parse_int(output.get("message_type"))
    token_length = _parse_int(output.get("token_length"))
    code = _parse_int(output.get("code"))
    message_id = _parse_int(output.get("message_id"))
    token = _native_bytes(output.get("token"))
    payload_bytes = _native_bytes(output.get("payload"))
    return {
        "transport": "datagram",
        "version": 1 if version is None else version,
        "message_type": _TYPE_LABELS.get(0 if message_type is None else message_type, message_type),
        "token_length": {
            "nibble": len(token) if token_length is None else token_length,
            "extension_hex": "",
            "declared_length": len(token) if token_length is None else token_length,
        },
        "code": 0 if code is None else code,
        "message_id": 0 if message_id is None else message_id,
        "token": _json_bytes(token),
        "options": _native_options(layer),
        "payload_marker": "present" if payload_bytes else "absent",
        "payload": _json_bytes(payload_bytes),
    }


def coap_fields_from_bytes(raw: bytes) -> JSONObject | None:
    """Parse a structurally valid cleartext CoAP datagram independently of tshark."""

    if len(raw) < 4 or raw[0] >> 6 != 1:
        return None
    nibble = raw[0] & 0x0F
    token_info = _token_length(nibble, raw, 4)
    if token_info is None:
        return None
    token_length, extension, cursor = token_info
    token_end = cursor + token_length
    if token_end > len(raw):
        return None
    token = raw[cursor:token_end]
    decoded = _options(raw, token_end)
    if decoded is None:
        return None
    options, marker, payload = decoded
    code = raw[1]
    if code == 0 and (token or options or marker or payload):
        return None
    return {
        "transport": "datagram",
        "version": 1,
        "message_type": _TYPE_LABELS[(raw[0] >> 4) & 0x03],
        "token_length": {
            "nibble": nibble,
            "extension_hex": extension.hex(),
            "declared_length": token_length,
        },
        "code": code,
        "message_id": int.from_bytes(raw[2:4], "big"),
        "token": _json_bytes(token),
        "options": options,
        "payload_marker": "present" if marker else "absent",
        "payload": _json_bytes(payload),
    }


def _token_length(
    nibble: int, raw: bytes, cursor: int
) -> tuple[int, bytes, int] | None:
    if nibble <= 12:
        return nibble, b"", cursor
    if nibble == 13:
        if cursor >= len(raw):
            return None
        extension = raw[cursor : cursor + 1]
        return 13 + extension[0], extension, cursor + 1
    if nibble == 14:
        if cursor + 2 > len(raw):
            return None
        extension = raw[cursor : cursor + 2]
        return 269 + int.from_bytes(extension, "big"), extension, cursor + 2
    return None


def _options(raw: bytes, cursor: int) -> tuple[list[JSONObject], bool, bytes] | None:
    output: list[JSONObject] = []
    previous = 0
    while cursor < len(raw):
        if raw[cursor] == 0xFF:
            return output, True, raw[cursor + 1 :]
        header_start = cursor
        header = raw[cursor]
        cursor += 1
        delta_info = _option_component(header >> 4, raw, cursor)
        if delta_info is None:
            return None
        delta, cursor = delta_info
        length_info = _option_component(header & 0x0F, raw, cursor)
        if length_info is None:
            return None
        length, cursor = length_info
        end = cursor + length
        number = previous + delta
        if end > len(raw) or number > 0xFFFF:
            return None
        value = raw[cursor:end]
        output.append(
            {
                "number": number,
                "delta": delta,
                "length": length,
                "value": _json_bytes(value),
                "order": len(output),
                "raw_header": raw[header_start:cursor].hex(),
            }
        )
        previous = number
        cursor = end
    return output, False, b""


def _option_component(nibble: int, raw: bytes, cursor: int) -> tuple[int, int] | None:
    if nibble <= 12:
        return nibble, cursor
    if nibble == 13:
        if cursor >= len(raw):
            return None
        return 13 + raw[cursor], cursor + 1
    if nibble == 14:
        if cursor + 2 > len(raw):
            return None
        return 269 + int.from_bytes(raw[cursor : cursor + 2], "big"), cursor + 2
    return None


def _native_options(layer: JSONObject) -> list[JSONObject]:
    deltas = _field_list(layer, "coap.opt.delta")
    lengths = _field_list(layer, "coap.opt.length", "coap.opt.len")
    values = _field_list(layer, "coap.opt.value")
    count = max(len(deltas), len(lengths), len(values), 0)
    output: list[JSONObject] = []
    previous = 0
    for index in range(count):
        delta = _parse_int(deltas[index]) if index < len(deltas) else 0
        value = _native_bytes(values[index]) if index < len(values) else b""
        length = _parse_int(lengths[index]) if index < len(lengths) else len(value)
        delta_value = 0 if delta is None else delta
        number = previous + delta_value
        output.append(
            {
                "number": number,
                "delta": delta_value,
                "length": len(value) if length is None else length,
                "value": _json_bytes(value),
                "order": index,
                "raw_header": None,
            }
        )
        previous = number
    return output


def _udp_payload_from_source_hex(source_hex: str | None) -> bytes | None:
    if not source_hex:
        return None
    try:
        raw = bytes.fromhex(source_hex)
    except ValueError:
        return None
    offset = 0
    if len(raw) >= 14 and int.from_bytes(raw[12:14], "big") in {0x0800, 0x86DD}:
        offset = 14
    if offset >= len(raw):
        return None
    version = raw[offset] >> 4
    if version == 4:
        if len(raw) < offset + 20 or raw[offset + 9] != 17:
            return None
        header_length = (raw[offset] & 0x0F) * 4
        if header_length < 20:
            return None
        udp_offset = offset + header_length
    elif version == 6:
        if len(raw) < offset + 40 or raw[offset + 6] != 17:
            return None
        udp_offset = offset + 40
    else:
        return None
    if len(raw) < udp_offset + 8:
        return None
    source_port = int.from_bytes(raw[udp_offset : udp_offset + 2], "big")
    destination_port = int.from_bytes(raw[udp_offset + 2 : udp_offset + 4], "big")
    if source_port != 5683 and destination_port != 5683:
        return None
    udp_length = int.from_bytes(raw[udp_offset + 4 : udp_offset + 6], "big")
    if udp_length < 8 or udp_offset + udp_length > len(raw):
        return None
    return raw[udp_offset + 8 : udp_offset + udp_length]


def _native_bytes(value: object) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, Mapping):
        value = value.get("value", value.get("show", value.get("hex")))
    if isinstance(value, str):
        cleaned = _hex_bytes(value)
        if cleaned and len(cleaned) % 2 == 0:
            return bytes.fromhex(cleaned)
        return value.encode("utf-8")
    if isinstance(value, Sequence):
        return bytes(int(item) & 0xFF for item in value)
    return b""


def _json_bytes(raw: bytes) -> JSONObject:
    return {"hex": raw.hex(), "ascii": raw.decode("utf-8", "replace")}


register(
    WiresharkProtocol(
        layer="coap",
        normalize=_normalize,
        tshark_aliases=dict(_TSHARK_ALIASES),
    )
)


__all__ = [
    "WIRESHARK_COAP_CAPABILITIES",
    "coap_fields_from_bytes",
]
