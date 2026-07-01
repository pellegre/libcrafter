"""Wireshark-stage parser-only normalization for TLS records.

Wireshark/tshark is parser-only in the oracle. For stable cross-backend
comparison this plugin prefers source bytes and derives the same compact TLS
record model used by the Scapy and libcrafter oracle adapters. Native tshark TLS
fields remain inspectable in backend metadata; the comparison surface is kept to
record framing, generic handshake framing, alerts, ChangeCipherSpec, and opaque
application data bytes.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ....model import DecodedModel, JSONObject
from ..decode_helpers import (
    _fields_from_aliases,
    _hex_bytes,
    _layer,
    _parse_int_fields,
    _string_field,
)
from .base import WiresharkProtocol, register


_TLS_TCP_PORTS = {443, 853, 4433, 8883}
_LEGACY_RECORD_VERSIONS = {0x0300, 0x0301, 0x0302, 0x0303}
_CONTENT_TYPES = {
    20: "change_cipher_spec",
    21: "alert",
    22: "handshake",
    23: "application_data",
    24: "heartbeat",
}
_HANDSHAKE_TYPES = {
    1: "client_hello",
    2: "server_hello",
    4: "new_session_ticket",
    5: "end_of_early_data",
    8: "encrypted_extensions",
    11: "certificate",
    13: "certificate_request",
    15: "certificate_verify",
    20: "finished",
    24: "key_update",
}
_ALERT_DESCRIPTIONS = {
    0: "close_notify",
    40: "handshake_failure",
    50: "decode_error",
    70: "protocol_version",
}

_TLS_TSHARK_ALIASES: JSONObject = {
    "record_content_type": ("tls.record.content_type",),
    "record_legacy_version": ("tls.record.version",),
    "record_length": ("tls.record.length",),
    "handshake_type": ("tls.handshake.type",),
    "handshake_length": ("tls.handshake.length",),
    "alert_level": ("tls.alert_message.level", "tls.alert.level"),
    "alert_description": ("tls.alert_message.desc", "tls.alert.description"),
}


def _normalize(layers: JSONObject, *, source_hex: str | None = None) -> JSONObject:
    raw = _tcp_payload_from_source(source_hex) if source_hex else None
    parsed = parse_tls_records(raw, allow_unknown_first=False) if raw is not None else None
    if parsed is not None:
        return parsed
    output = _fields_from_aliases(_layer(layers, "tls"), dict(_TLS_TSHARK_ALIASES))
    _parse_int_fields(
        output,
        "record_content_type",
        "record_legacy_version",
        "record_length",
        "handshake_type",
        "handshake_length",
        "alert_level",
        "alert_description",
    )
    return output


def decoded_model_from_raw_tls(
    raw: bytes,
    *,
    root: str,
    source_hex: str,
    feature_tags: Sequence[str],
) -> DecodedModel:
    parsed = parse_tls_records(raw, allow_unknown_first=True)
    if parsed is None:
        parsed = {
            "record_count": 0,
            "record_content_types": [],
        }
    layers = ["tls"]
    fields: dict[str, JSONObject] = {"tls": parsed}
    raw_tail = parsed.pop("raw_tail_hex", None)
    if isinstance(raw_tail, str) and raw_tail:
        tail = bytes.fromhex(raw_tail)
        layers.append("payload")
        fields["payload"] = _payload_fields_from_bytes(tail)
    return DecodedModel(
        backend="wireshark",
        layers=layers,
        fields=fields,
        root=root,
        source_hex=source_hex,
        feature_tags=list(feature_tags),
        metadata={
            "native": {
                "protocols": ["tls"],
                "layers": {},
            },
            "reencoded_hex": source_hex,
            "tshark": {
                "source_model": "raw:tls",
                "note": "raw TLS records have no tshark datalink decoder",
            },
        },
    )


def canonicalize_tls_payload(
    layers: list[str],
    fields: dict[str, JSONObject],
    layers_object: JSONObject,
    *,
    source_hex: str | None = None,
) -> None:
    """Promote tshark TLS/data payloads to the neutral ``tls`` layer."""

    raw = _tcp_payload_from_source(source_hex) if source_hex else None
    parsed = parse_tls_records(raw, allow_unknown_first=False) if raw is not None else None
    if "tls" in layers:
        key = _first_layer_key(fields, "tls")
        if key is not None and parsed is not None:
            fields[key] = parsed
            _append_raw_tail(layers, fields, layers.index("tls"), parsed)
        return

    payload_index = _payload_index_after_tcp(layers)
    if payload_index is None:
        return
    payload_key = _layer_key_at(layers, payload_index)
    if parsed is None:
        raw = _payload_bytes_from_fields(fields.get(payload_key, {}))
        if raw is None:
            raw = _payload_bytes_from_tshark_data(layers_object)
        parsed = parse_tls_records(raw, allow_unknown_first=False) if raw is not None else None
    if parsed is None:
        return

    fields.pop(payload_key, None)
    layers[payload_index] = "tls"
    fields[_layer_key_at(layers, payload_index)] = parsed
    _append_raw_tail(layers, fields, payload_index, parsed)


def parse_tls_records(raw: bytes | None, *, allow_unknown_first: bool) -> JSONObject | None:
    if raw is None:
        return None
    cursor = 0
    records: list[JSONObject] = []
    while cursor < len(raw):
        if len(raw) - cursor < 5:
            break
        content_type = raw[cursor]
        version = int.from_bytes(raw[cursor + 1 : cursor + 3], "big")
        length = int.from_bytes(raw[cursor + 3 : cursor + 5], "big")
        end = cursor + 5 + length
        if end > len(raw):
            break
        if not records and not allow_unknown_first:
            if content_type not in _CONTENT_TYPES or version not in _LEGACY_RECORD_VERSIONS:
                return None
        fragment = raw[cursor + 5 : end]
        records.append(
            _record_model(
                content_type,
                version,
                length,
                fragment,
                raw[cursor:end].hex(),
            )
        )
        cursor = end
    if not records:
        return None
    model: JSONObject = {
        "record_count": len(records),
        "record_content_types": [record["content_type"] for record in records],
        "records": records,
    }
    if cursor < len(raw):
        model["raw_tail_hex"] = raw[cursor:].hex()
    return model


def _record_model(
    content_type: int,
    version: int,
    length: int,
    fragment: bytes,
    record_hex: str,
) -> JSONObject:
    fields: JSONObject = {
        "content_type": _content_type_label(content_type),
        "content_type_raw": content_type,
        "legacy_record_version": version,
        "record_length": length,
        "fragment_hex": fragment.hex(),
        "record_hex": record_hex,
        "body_kind": _record_body_kind_label(content_type),
    }
    if content_type == 22:
        fields["handshake_messages"] = _handshake_models(fragment)
    elif content_type == 21 and len(fragment) >= 2:
        fields["alert_level"] = "fatal" if fragment[0] == 2 else "warning" if fragment[0] == 1 else "unknown"
        fields["alert_description"] = _ALERT_DESCRIPTIONS.get(fragment[1], "unknown")
    elif content_type == 20 and fragment:
        fields["change_cipher_spec"] = fragment[0]
    elif content_type == 23:
        fields["application_data_hex"] = fragment.hex()
    return fields


def _handshake_models(fragment: bytes) -> list[JSONObject]:
    messages: list[JSONObject] = []
    cursor = 0
    while cursor + 4 <= len(fragment):
        handshake_type = fragment[cursor]
        length = int.from_bytes(fragment[cursor + 1 : cursor + 4], "big")
        end = cursor + 4 + length
        if end > len(fragment):
            break
        body = fragment[cursor + 4 : end]
        messages.append(
            {
                "handshake_type": _handshake_type_label(handshake_type),
                "handshake_type_raw": handshake_type,
                "handshake_length": length,
                "body_hex": body.hex(),
            }
        )
        cursor = end
    if cursor < len(fragment):
        messages.append({"handshake_type": "raw_tail", "body_hex": fragment[cursor:].hex()})
    return messages


def _tcp_payload_from_source(source_hex: str | None) -> bytes | None:
    if not source_hex:
        return None
    raw = bytes.fromhex(source_hex)
    for offset in _candidate_l3_offsets(raw):
        payload = _tcp_payload_at_l3(raw, offset)
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


def _tcp_payload_at_l3(raw: bytes, offset: int) -> bytes | None:
    if offset >= len(raw):
        return None
    version = raw[offset] >> 4
    if version == 4:
        return _tcp_payload_ipv4(raw, offset)
    if version == 6:
        return _tcp_payload_ipv6(raw, offset)
    return None


def _tcp_payload_ipv4(raw: bytes, offset: int) -> bytes | None:
    if len(raw) < offset + 40:
        return None
    ihl = (raw[offset] & 0x0F) * 4
    if ihl < 20 or len(raw) < offset + ihl + 20 or raw[offset + 9] != 6:
        return None
    total_length = int.from_bytes(raw[offset + 2 : offset + 4], "big")
    end = offset + min(total_length, len(raw) - offset)
    tcp_offset = offset + ihl
    return _tcp_payload(raw, tcp_offset, end)


def _tcp_payload_ipv6(raw: bytes, offset: int) -> bytes | None:
    if len(raw) < offset + 60 or raw[offset + 6] != 6:
        return None
    payload_length = int.from_bytes(raw[offset + 4 : offset + 6], "big")
    end = offset + 40 + payload_length
    if end > len(raw):
        return None
    return _tcp_payload(raw, offset + 40, end)


def _tcp_payload(raw: bytes, tcp_offset: int, end: int) -> bytes | None:
    if tcp_offset + 20 > end:
        return None
    src_port = int.from_bytes(raw[tcp_offset : tcp_offset + 2], "big")
    dst_port = int.from_bytes(raw[tcp_offset + 2 : tcp_offset + 4], "big")
    if src_port not in _TLS_TCP_PORTS and dst_port not in _TLS_TCP_PORTS:
        return None
    data_offset = (raw[tcp_offset + 12] >> 4) * 4
    if data_offset < 20 or tcp_offset + data_offset > end:
        return None
    return raw[tcp_offset + data_offset : end]


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


def _append_raw_tail(
    layers: list[str],
    fields: dict[str, JSONObject],
    tls_index: int,
    parsed: JSONObject,
) -> None:
    raw_tail = parsed.pop("raw_tail_hex", None)
    if not isinstance(raw_tail, str) or not raw_tail:
        return
    tail = bytes.fromhex(raw_tail)
    insert_at = tls_index + 1
    layers.insert(insert_at, "payload")
    fields[_layer_key_at(layers, insert_at)] = _payload_fields_from_bytes(tail)


def _payload_fields_from_bytes(body: bytes) -> JSONObject:
    return {
        "hex": body.hex(),
        "length": len(body),
        "ascii": body.decode("utf-8", "replace"),
    }


def _payload_index_after_tcp(layers: Sequence[str]) -> int | None:
    try:
        tcp_index = list(layers).index("tcp")
    except ValueError:
        return None
    for index in range(tcp_index + 1, len(layers)):
        if layers[index] == "payload":
            return index
    return None


def _first_layer_key(fields: Mapping[str, object], layer_name: str) -> str | None:
    if layer_name in fields:
        return layer_name
    prefix = f"{layer_name}#"
    for key in fields:
        if key.startswith(prefix):
            return key
    return None


def _layer_key_at(layers: Sequence[str], index: int) -> str:
    layer_name = layers[index]
    occurrence = sum(1 for position in range(index + 1) if layers[position] == layer_name)
    return layer_name if occurrence == 1 else f"{layer_name}#{occurrence}"


def _content_type_label(content_type: int) -> str:
    known = _CONTENT_TYPES.get(content_type)
    if known is not None:
        return known
    if 32 <= content_type <= 63:
        return f"reserved content type 0x{content_type:02x}"
    return f"unassigned content type 0x{content_type:02x}"


def _record_body_kind_label(content_type: int) -> str:
    return _CONTENT_TYPES.get(content_type, "opaque_raw")


def _handshake_type_label(handshake_type: int) -> str:
    known = _HANDSHAKE_TYPES.get(handshake_type)
    if known is not None:
        return known
    return f"unassigned handshake type 0x{handshake_type:02x}"


register(
    WiresharkProtocol(
        layer="tls",
        normalize=_normalize,
        tshark_aliases=dict(_TLS_TSHARK_ALIASES),
    )
)
