"""Scapy-stage CoAP materialization and conservative decode normalization.

Scapy's contrib ``CoAP`` layer is authoritative for RFC 7252 base datagrams,
but it has no RFC 8323 reliable framing, RFC 8974 extended-token grammar, or
OSCORE context support.  Base cases use the verified native layer.  Cases for
which that layer would rewrite or misinterpret bytes use the protocol-local
wire builder and remain explicitly capability-scoped rather than being
reported as independent Scapy agreement.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ....model import JSONObject
from ..bootstrap import import_scapy
from ..encode_helpers import _layer_fields
from .base import ScapyProtocol, register


_COAP_PORT = 5683
_COAPS_PORT = 5684
_PAYLOAD_MARKER = 0xFF

_SUPPORTED_FIELDS = frozenset(
    {
        "transport",
        "version",
        "message_type",
        "code",
        "message_id",
        "token",
        "token_length",
        "reliable_length",
        "options",
        "payload_marker",
        "payload",
        "signaling_options",
    }
)

_LAYER_ALIASES = (("CoAP", "coap"),)
_FIELD_ALIASES = (
    ("ver", "version"),
    ("type", "message_type"),
    ("tkl", "token_length"),
    ("msg_id", "message_id"),
    ("paymark", "payload_marker"),
)

# Stable, testable capability record. Raw materialization is not independent
# protocol agreement; only the native RFC 7252 subset is described as such.
SCAPY_COAP_CAPABILITIES: JSONObject = {
    "native_core_datagram": True,
    "raw_byte_materialization": True,
    "gaps": {
        "reliable_framing": "no native RFC 8323 frame or signaling model",
        "extended_tokens": "native CoAP treats TKL as a direct four-bit length",
        "advanced_options": "raw bytes preserve values but Scapy has no complete typed registry",
        "oscore": "no native OSCORE protect, unprotect, or context support",
    },
}

_MESSAGE_TYPES = {
    "confirmable": 0,
    "con": 0,
    "non_confirmable": 1,
    "non-confirmable": 1,
    "non": 1,
    "acknowledgement": 2,
    "acknowledgment": 2,
    "ack": 2,
    "reset": 3,
    "rst": 3,
}
_MESSAGE_TYPE_LABELS = {
    0: "confirmable",
    1: "non_confirmable",
    2: "acknowledgement",
    3: "reset",
}


def _build(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Sequence[str],
    index: int,
    scapy_all: Any,
) -> Any:
    del stack, index
    coap = _layer_fields(fields, "coap")
    if _native_core_eligible(plan, fields, coap):
        native = import_scapy()["coap"]
        options = [
            (_option_number(option), _option_value(option))
            for option in _option_list(coap.get("options"))
        ]
        token = _bytes_value(coap.get("token"))
        layer = native.CoAP(
            ver=_int_value(coap.get("version"), 1),
            type=_message_type_value(coap.get("message_type")),
            code=_int_value(coap.get("code"), 0),
            msg_id=_int_value(coap.get("message_id"), 0),
            token=token,
            options=options,
            paymark=b"\xff" if _marker_present(coap.get("payload_marker")) else b"",
        )
        payload = _bytes_value(coap.get("payload"))
        return layer if not payload else layer / scapy_all.Raw(load=payload)
    return scapy_all.Raw(load=coap_message_bytes(fields))


def _native_core_eligible(
    plan: Any,
    fields: Mapping[str, JSONObject],
    coap: Mapping[str, object],
) -> bool:
    if str(coap.get("transport", "datagram")) != "datagram":
        return False
    if getattr(plan, "case", "") == "coap-secure-port-raw":
        return False
    udp = fields.get("udp", {})
    if _int_value(udp.get("src_port"), 0) == _COAPS_PORT or _int_value(
        udp.get("dst_port"), 0
    ) == _COAPS_PORT:
        return False
    token = _bytes_value(coap.get("token"))
    if len(token) > 8 or coap.get("token_length") is not None:
        return False
    if any(_option_number(option) == 9 for option in _option_list(coap.get("options"))):
        return False
    if any("raw_header" in option for option in _option_list(coap.get("options"))):
        return False
    return True


def coap_message_bytes(fields: Mapping[str, JSONObject]) -> bytes:
    """Materialize one CoAP datagram or one reliable frame byte-exactly."""

    coap = _layer_fields(fields, "coap")
    if str(coap.get("transport", "datagram")) == "reliable":
        return _reliable_message_bytes(coap)
    return _datagram_message_bytes(coap)


def _datagram_message_bytes(coap: Mapping[str, object]) -> bytes:
    token = _bytes_value(coap.get("token"))
    token_nibble, token_extension = _token_length_wire(coap.get("token_length"), len(token))
    first = (
        ((_int_value(coap.get("version"), 1) & 0x03) << 6)
        | ((_message_type_value(coap.get("message_type")) & 0x03) << 4)
        | (token_nibble & 0x0F)
    )
    output = bytearray(
        [
            first,
            _int_value(coap.get("code"), 0) & 0xFF,
            (_int_value(coap.get("message_id"), 0) >> 8) & 0xFF,
            _int_value(coap.get("message_id"), 0) & 0xFF,
        ]
    )
    output.extend(token_extension)
    output.extend(token)
    output.extend(_encode_options(_option_list(coap.get("options"))))
    if _marker_present(coap.get("payload_marker")):
        output.append(_PAYLOAD_MARKER)
    output.extend(_bytes_value(coap.get("payload")))
    return bytes(output)


def _reliable_message_bytes(coap: Mapping[str, object]) -> bytes:
    token = _bytes_value(coap.get("token"))
    token_nibble, token_extension = _token_length_wire(coap.get("token_length"), len(token))
    options_value = coap.get("signaling_options")
    options = _option_list(options_value if options_value else coap.get("options"))
    body = bytearray(_encode_options(options))
    if _marker_present(coap.get("payload_marker")):
        body.append(_PAYLOAD_MARKER)
    body.extend(_bytes_value(coap.get("payload")))
    length_nibble, length_extension = _reliable_length_wire(
        coap.get("reliable_length"), len(body)
    )
    output = bytearray([(length_nibble << 4) | (token_nibble & 0x0F)])
    output.extend(length_extension)
    output.append(_int_value(coap.get("code"), 0) & 0xFF)
    output.extend(token_extension)
    output.extend(token)
    output.extend(body)
    return bytes(output)


def _token_length_wire(value: object, actual_length: int) -> tuple[int, bytes]:
    if isinstance(value, Mapping):
        return (
            _int_value(value.get("nibble"), 0) & 0x0F,
            bytes.fromhex(str(value.get("extension_hex", ""))),
        )
    if actual_length <= 12:
        return actual_length, b""
    if actual_length <= 268:
        return 13, bytes([actual_length - 13])
    if actual_length <= 65_804:
        return 14, (actual_length - 269).to_bytes(2, "big")
    raise ValueError("CoAP token length exceeds RFC 8974 maximum")


def _reliable_length_wire(value: object, body_length: int) -> tuple[int, bytes]:
    if isinstance(value, Mapping):
        return (
            _int_value(value.get("nibble"), 0) & 0x0F,
            bytes.fromhex(str(value.get("extension_hex", ""))),
        )
    if body_length <= 12:
        return body_length, b""
    if body_length <= 268:
        return 13, bytes([body_length - 13])
    if body_length <= 65_804:
        return 14, (body_length - 269).to_bytes(2, "big")
    if body_length <= 0xFFFF_FFFF + 65_805:
        return 15, (body_length - 65_805).to_bytes(4, "big")
    raise ValueError("CoAP reliable body length exceeds RFC 8323 maximum")


def _encode_options(options: Sequence[Mapping[str, object]]) -> bytes:
    output = bytearray()
    previous = 0
    for option in options:
        number = _option_number(option)
        value = _option_value(option)
        raw_header = option.get("raw_header")
        if isinstance(raw_header, str):
            output.extend(bytes.fromhex(raw_header))
        elif isinstance(raw_header, Mapping) and isinstance(raw_header.get("hex"), str):
            output.extend(bytes.fromhex(str(raw_header["hex"])))
        else:
            delta = _int_value(option.get("delta"), number - previous)
            length = _int_value(option.get("length"), len(value))
            delta_nibble, delta_extension = _option_component(delta)
            length_nibble, length_extension = _option_component(length)
            output.append((delta_nibble << 4) | length_nibble)
            output.extend(delta_extension)
            output.extend(length_extension)
        output.extend(value)
        previous = number
    return bytes(output)


def _option_component(value: int) -> tuple[int, bytes]:
    if value <= 12:
        return value, b""
    if value <= 268:
        return 13, bytes([value - 13])
    if value <= 65_804:
        return 14, (value - 269).to_bytes(2, "big")
    raise ValueError("CoAP option delta/length exceeds 65804")


def coap_fields_from_bytes(raw: bytes) -> JSONObject | None:
    """Parse one structurally valid cleartext CoAP datagram into the shared model."""

    if len(raw) < 4:
        return None
    first = raw[0]
    version = first >> 6
    if version != 1:
        return None
    token_nibble = first & 0x0F
    decoded_token = _decode_token_length(token_nibble, raw, 4)
    if decoded_token is None:
        return None
    token_length, token_extension, cursor = decoded_token
    token_end = cursor + token_length
    if token_end > len(raw):
        return None
    code = raw[1]
    token = raw[cursor:token_end]
    cursor = token_end
    parsed_options = _decode_options(raw, cursor)
    if parsed_options is None:
        return None
    options, marker_present, payload, cursor = parsed_options
    if cursor != len(raw):
        return None
    if code == 0 and (token or options or marker_present or payload):
        return None
    return {
        "transport": "datagram",
        "version": version,
        "message_type": _MESSAGE_TYPE_LABELS[(first >> 4) & 0x03],
        "token_length": {
            "nibble": token_nibble,
            "extension_hex": token_extension.hex(),
            "declared_length": token_length,
        },
        "code": code,
        "message_id": int.from_bytes(raw[2:4], "big"),
        "token": _json_bytes(token),
        "options": options,
        "payload_marker": "present" if marker_present else "absent",
        "payload": _json_bytes(payload),
    }


def coap_reliable_fields_from_bytes(raw: bytes) -> JSONObject | None:
    """Parse exactly one structurally valid RFC 8323 cleartext frame."""

    if len(raw) < 2:
        return None
    first = raw[0]
    length_nibble = first >> 4
    decoded_length = _decode_reliable_length(length_nibble, raw, 1)
    if decoded_length is None:
        return None
    body_length, length_extension, cursor = decoded_length
    if cursor >= len(raw):
        return None
    code = raw[cursor]
    cursor += 1
    token_nibble = first & 0x0F
    decoded_token = _decode_token_length(token_nibble, raw, cursor)
    if decoded_token is None:
        return None
    token_length, token_extension, cursor = decoded_token
    token_end = cursor + token_length
    body_end = token_end + body_length
    if token_end > len(raw) or body_end != len(raw):
        return None
    token = raw[cursor:token_end]
    parsed_options = _decode_options(raw[token_end:body_end], 0)
    if parsed_options is None:
        return None
    options, marker_present, payload, cursor = parsed_options
    if cursor != body_length:
        return None
    return {
        "transport": "reliable",
        "reliable_length": {
            "nibble": length_nibble,
            "extension_hex": length_extension.hex(),
            "declared_length": body_length,
        },
        "token_length": {
            "nibble": token_nibble,
            "extension_hex": token_extension.hex(),
            "declared_length": token_length,
        },
        "code": code,
        "token": _json_bytes(token),
        "options": options,
        "payload_marker": "present" if marker_present else "absent",
        "payload": _json_bytes(payload),
    }


def _decode_reliable_length(
    nibble: int, raw: bytes, cursor: int
) -> tuple[int, bytes, int] | None:
    if nibble <= 12:
        return nibble, b"", cursor
    extension_size = {13: 1, 14: 2, 15: 4}[nibble]
    end = cursor + extension_size
    if end > len(raw):
        return None
    extension = raw[cursor:end]
    base = {13: 13, 14: 269, 15: 65_805}[nibble]
    return base + int.from_bytes(extension, "big"), extension, end


def _decode_token_length(
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


def _decode_options(
    raw: bytes, cursor: int
) -> tuple[list[JSONObject], bool, bytes, int] | None:
    options: list[JSONObject] = []
    previous = 0
    while cursor < len(raw):
        if raw[cursor] == _PAYLOAD_MARKER:
            return options, True, raw[cursor + 1 :], len(raw)
        header_start = cursor
        header = raw[cursor]
        cursor += 1
        decoded_delta = _decode_option_component(header >> 4, raw, cursor)
        if decoded_delta is None:
            return None
        delta, cursor = decoded_delta
        decoded_length = _decode_option_component(header & 0x0F, raw, cursor)
        if decoded_length is None:
            return None
        length, cursor = decoded_length
        end = cursor + length
        if end > len(raw):
            return None
        number = previous + delta
        if number > 0xFFFF:
            return None
        value = raw[cursor:end]
        options.append(
            {
                "number": number,
                "delta": delta,
                "length": length,
                "value": _json_bytes(value),
                "order": len(options),
                "raw_header": raw[header_start:cursor].hex(),
            }
        )
        previous = number
        cursor = end
    return options, False, b"", cursor


def _decode_option_component(nibble: int, raw: bytes, cursor: int) -> tuple[int, int] | None:
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


def canonicalize_coap_payload(
    packet: Any,
    layers: list[str],
    fields: dict[str, JSONObject],
    *,
    source_hex: str | None = None,
) -> None:
    """Replace a cleartext UDP/TCP port 5683 payload with canonical CoAP."""

    udp = _scapy_layer(packet, "UDP")
    tcp = _scapy_layer(packet, "TCP")
    payload: bytes | None
    transport: str
    if udp is not None and _uses_cleartext_coap_port(udp):
        payload = _udp_payload_from_source_hex(source_hex)
        if payload is None:
            native = _scapy_layer(packet, "CoAP")
            if native is not None:
                try:
                    payload = bytes(native)
                except (TypeError, ValueError):
                    payload = None
        parser = coap_fields_from_bytes
        transport = "udp"
    elif tcp is not None and _uses_cleartext_coap_port(tcp):
        payload = _tcp_payload_from_source_hex(source_hex)
        parser = coap_reliable_fields_from_bytes
        transport = "tcp"
    else:
        return
    if payload is None:
        payload = _raw_payload(packet)
    if payload is None:
        return
    normalized = parser(payload)
    if normalized is None:
        return
    target = _layer_index(layers, {"coap", "payload", "raw"}, after=transport)
    if target is None:
        return
    old_key = _layer_key_at(layers, target)
    fields.pop(old_key, None)
    layers[target] = "coap"
    fields[_layer_key_at(layers, target)] = normalized
    for index in range(len(layers) - 1, target, -1):
        if layers[index] in {"payload", "raw"}:
            fields.pop(_layer_key_at(layers, index), None)
            layers.pop(index)


def _normalize(fields: JSONObject) -> JSONObject:
    # The whole-packet canonicalizer reparses source bytes. This fallback keeps
    # direct native-layer normalization useful for payload-free base messages.
    version = _int_value(fields.get("ver", fields.get("version")), 1)
    message_type = _int_value(fields.get("type", fields.get("message_type")), 0) & 0x03
    token = _bytes_value(fields.get("token"))
    output: JSONObject = {
        "transport": "datagram",
        "version": version,
        "message_type": _MESSAGE_TYPE_LABELS[message_type],
        "token_length": {
            "nibble": _int_value(fields.get("tkl"), len(token)),
            "extension_hex": "",
            "declared_length": _int_value(fields.get("tkl"), len(token)),
        },
        "code": _int_value(fields.get("code"), 0),
        "message_id": _int_value(fields.get("msg_id"), 0),
        "token": _json_bytes(token),
        "options": [],
        "payload_marker": "present" if _bytes_value(fields.get("paymark")) else "absent",
        "payload": _json_bytes(b""),
    }
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
    udp_length = int.from_bytes(raw[udp_offset + 4 : udp_offset + 6], "big")
    if udp_length < 8 or udp_offset + udp_length > len(raw):
        return None
    return raw[udp_offset + 8 : udp_offset + udp_length]


def _tcp_payload_from_source_hex(source_hex: str | None) -> bytes | None:
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
        if len(raw) < offset + 20 or raw[offset + 9] != 6:
            return None
        ip_header_length = (raw[offset] & 0x0F) * 4
        total_length = int.from_bytes(raw[offset + 2 : offset + 4], "big")
        if ip_header_length < 20 or total_length < ip_header_length:
            return None
        tcp_offset = offset + ip_header_length
        packet_end = offset + total_length
    elif version == 6:
        if len(raw) < offset + 40 or raw[offset + 6] != 6:
            return None
        tcp_offset = offset + 40
        packet_end = tcp_offset + int.from_bytes(raw[offset + 4 : offset + 6], "big")
    else:
        return None
    if packet_end > len(raw) or tcp_offset + 20 > packet_end:
        return None
    tcp_header_length = (raw[tcp_offset + 12] >> 4) * 4
    if tcp_header_length < 20 or tcp_offset + tcp_header_length > packet_end:
        return None
    return raw[tcp_offset + tcp_header_length : packet_end]


def _uses_cleartext_coap_port(layer: Any) -> bool:
    return _int_value(getattr(layer, "sport", 0), 0) == _COAP_PORT or _int_value(
        getattr(layer, "dport", 0), 0
    ) == _COAP_PORT


def _option_list(value: object) -> list[Mapping[str, object]]:
    if value is None:
        return []
    if not isinstance(value, Sequence) or isinstance(value, (bytes, bytearray, str)):
        raise ValueError("CoAP options must be a list")
    output: list[Mapping[str, object]] = []
    for option in value:
        if not isinstance(option, Mapping):
            raise ValueError("CoAP option must be an object")
        output.append(option)
    return output


def _option_number(option: Mapping[str, object]) -> int:
    return _int_value(option.get("number"), 0)


def _option_value(option: Mapping[str, object]) -> bytes:
    value = option.get("value", option.get("value_hex"))
    return _bytes_value(value)


def _bytes_value(value: object) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        try:
            return bytes.fromhex(value)
        except ValueError:
            return value.encode("utf-8")
    if isinstance(value, Mapping):
        hex_value = value.get("hex")
        if isinstance(hex_value, str):
            return bytes.fromhex(hex_value)
        ascii_value = value.get("ascii")
        if isinstance(ascii_value, str):
            return ascii_value.encode("utf-8")
    if isinstance(value, Sequence):
        return bytes(_int_value(item, 0) & 0xFF for item in value)
    raise ValueError(f"CoAP byte value is not bytes-compatible: {value!r}")


def _json_bytes(raw: bytes) -> JSONObject:
    return {"hex": raw.hex(), "ascii": raw.decode("utf-8", "replace")}


def _message_type_value(value: object) -> int:
    if isinstance(value, str):
        normalized = value.lower().replace(" ", "_")
        if normalized in _MESSAGE_TYPES:
            return _MESSAGE_TYPES[normalized]
        return int(normalized, 0)
    return _int_value(value, 0)


def _marker_present(value: object) -> bool:
    if isinstance(value, str):
        return value in {"present", "explicit_empty"}
    return bool(value)


def _int_value(value: object, default: int) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return default
    if isinstance(value, Mapping):
        raw = value.get("raw", value.get("value"))
        return _int_value(raw, default)
    return default


def _scapy_layer(packet: Any, class_name: str) -> Any:
    current = packet
    while current is not None and current.__class__.__name__ != "NoPayload":
        if current.__class__.__name__ == class_name:
            return current
        current = getattr(current, "payload", None)
    return None


def _raw_payload(packet: Any) -> bytes | None:
    layer = _scapy_layer(packet, "Raw")
    load = getattr(layer, "load", None) if layer is not None else None
    return load if isinstance(load, bytes) else None


def _layer_index(
    layers: Sequence[str], names: set[str], *, after: str
) -> int | None:
    try:
        start = list(layers).index(after) + 1
    except ValueError:
        return None
    for index in range(start, len(layers)):
        if layers[index] in names:
            return index
    return None


def _layer_key_at(layers: Sequence[str], index: int) -> str:
    name = layers[index]
    occurrence = sum(1 for layer in layers[: index + 1] if layer == name)
    return name if occurrence == 1 else f"{name}#{occurrence}"


register(
    ScapyProtocol(
        layer="coap",
        scapy_class="CoAP",
        supported_fields=_SUPPORTED_FIELDS,
        build=_build,
        normalize=_normalize,
        layer_aliases=_LAYER_ALIASES,
        field_aliases=_FIELD_ALIASES,
    )
)


__all__ = [
    "SCAPY_COAP_CAPABILITIES",
    "canonicalize_coap_payload",
    "coap_fields_from_bytes",
    "coap_message_bytes",
    "coap_reliable_fields_from_bytes",
]
