"""Scapy-stage TLS byte materialization and normalization helpers.

The Scapy TLS contrib classes are optional and their high-level builders do not
cover every raw-preserving oracle case. This adapter therefore serializes the
backend-neutral TLS plan to deterministic record bytes and wraps them in
``Raw``. Decode normalization also parses record bytes directly so Scapy and the
libcrafter bridge compare the same compact packet-layer model.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ....model import JSONObject
from ..encode_helpers import _int, _layer_fields, _optional_field, _text
from .base import ScapyProtocol, register


_SUPPORTED_FIELDS = frozenset(
    {
        "alert_description",
        "alert_level",
        "application_data_hex",
        "change_cipher_spec",
        "cipher_suites",
        "compression_methods",
        "extension_body_hex",
        "extension_type",
        "extensions",
        "handshake_length",
        "handshake_messages",
        "handshake_type",
        "heartbeat_message_type",
        "hello_random",
        "raw_preservation",
        "raw_root",
        "record_body_kind",
        "record_content_type",
        "record_fragment_hex",
        "record_legacy_version",
        "record_length",
        "records",
        "session_id",
    }
)

_CONTENT_TYPES = {
    "change_cipher_spec": 20,
    "alert": 21,
    "handshake": 22,
    "application_data": 23,
    "heartbeat": 24,
}
_CONTENT_TYPE_LABELS = {value: key for key, value in _CONTENT_TYPES.items()}

_HANDSHAKE_TYPES = {
    "client_hello": 1,
    "server_hello": 2,
    "new_session_ticket": 4,
    "end_of_early_data": 5,
    "encrypted_extensions": 8,
    "certificate": 11,
    "certificate_request": 13,
    "certificate_verify": 15,
    "finished": 20,
    "key_update": 24,
}
_HANDSHAKE_LABELS = {value: key for key, value in _HANDSHAKE_TYPES.items()}

_EXTENSION_TYPES = {
    "server_name": 0,
    "sni": 0,
    "status_request": 5,
    "supported_groups": 10,
    "signature_algorithms": 13,
    "application_layer_protocol_negotiation": 16,
    "alpn": 16,
    "padding": 21,
    "record_size_limit": 28,
    "pre_shared_key": 41,
    "supported_versions": 43,
    "cookie": 44,
    "psk_key_exchange_modes": 45,
    "certificate_authorities": 47,
    "key_share": 51,
}

_ALERT_LEVELS = {"warning": 1, "fatal": 2}
_ALERT_DESCRIPTIONS = {
    "close_notify": 0,
    "handshake_failure": 40,
    "decode_error": 50,
    "protocol_version": 70,
}
_CERTIFICATE_TYPES = {
    "rsa_sign": 1,
    "dss_sign": 2,
    "rsa_fixed_dh": 3,
    "dss_fixed_dh": 4,
    "ecdsa_sign": 64,
    "rsa_fixed_ecdh": 65,
    "ecdsa_fixed_ecdh": 66,
}
_PSK_MODES = {"psk_ke": 0, "psk_dhe_ke": 1}
_KEY_UPDATE_REQUESTS = {"update_not_requested": 0, "update_requested": 1}

_TLS_TCP_PORTS = {443, 853, 4433, 8883}
_LEGACY_RECORD_VERSIONS = {0x0300, 0x0301, 0x0302, 0x0303}


def _build(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    del plan, stack, index
    tls_fields = _layer_fields(fields, "tls")
    return scapy_all.Raw(load=tls_records_bytes(tls_fields))


def tls_records_bytes(fields: Mapping[str, object]) -> bytes:
    records = _records_from_fields(fields)
    return b"".join(_record_bytes(record, fields) for record in records)


def _records_from_fields(fields: Mapping[str, object]) -> list[Mapping[str, object]]:
    records = fields.get("records")
    if isinstance(records, Sequence) and not isinstance(records, (str, bytes, bytearray)):
        return [item for item in records if isinstance(item, Mapping)]
    return [fields]


def _record_bytes(record: Mapping[str, object], tls_fields: Mapping[str, object]) -> bytes:
    content_type = _content_type_value(
        _first_present(record, tls_fields, "content_type", "record_content_type"),
        default=_CONTENT_TYPES["handshake"],
    )
    body = _record_body_bytes(content_type, record, tls_fields)
    legacy_version = _int_value(
        _first_present(record, tls_fields, "legacy_record_version", "record_legacy_version"),
        0x0303,
    )
    declared_length = _declared_length(
        _first_present(record, tls_fields, "declared_length", "record_length"),
        len(body),
    )
    return bytes([content_type]) + _u16(legacy_version) + _u16(declared_length) + body


def _record_body_bytes(
    content_type: int,
    record: Mapping[str, object],
    tls_fields: Mapping[str, object],
) -> bytes:
    if content_type == _CONTENT_TYPES["handshake"]:
        messages = _first_present(record, tls_fields, "handshake_messages")
        if isinstance(messages, Sequence) and not isinstance(messages, (str, bytes, bytearray)):
            return b"".join(
                _handshake_bytes(message)
                for message in messages
                if isinstance(message, Mapping)
            )
        raw = _first_present(record, tls_fields, "fragment_hex", "record_fragment_hex")
        return _bytes_value(raw)
    if content_type == _CONTENT_TYPES["alert"]:
        raw = _first_present(record, tls_fields, "fragment_hex", "record_fragment_hex")
        if raw is not None:
            return _bytes_value(raw)
        alert = _mapping(record.get("alert"))
        level = _alert_level(_first_present(alert, record, tls_fields, "level", "alert_level"))
        description = _alert_description(
            _first_present(alert, record, tls_fields, "description", "alert_description")
        )
        return bytes([level, description])
    if content_type == _CONTENT_TYPES["change_cipher_spec"]:
        raw = _first_present(record, tls_fields, "fragment_hex", "record_fragment_hex")
        if raw is not None:
            return _bytes_value(raw)
        return bytes([_int_value(_first_present(record, tls_fields, "value", "change_cipher_spec"), 1)])
    if content_type == _CONTENT_TYPES["application_data"]:
        raw = _first_present(
            record,
            tls_fields,
            "fragment_hex",
            "application_data_hex",
            "record_fragment_hex",
        )
        return _bytes_value(raw)
    raw = _first_present(
        record,
        tls_fields,
        "raw_fragment_hex",
        "fragment_hex",
        "raw_preservation",
        "record_fragment_hex",
    )
    return _bytes_value(raw)


def _handshake_bytes(message: Mapping[str, object]) -> bytes:
    handshake_type = _handshake_type_value(message)
    body = _handshake_body_bytes(handshake_type, message)
    declared_length = _declared_length(message.get("declared_length", message.get("handshake_length")), len(body))
    return bytes([handshake_type]) + _u24(declared_length) + body


def _handshake_type_value(message: Mapping[str, object]) -> int:
    raw = message.get("type_raw")
    if raw is not None:
        return _int_value(raw, 0)
    value = message.get("type", message.get("handshake_type"))
    if isinstance(value, str):
        if value in _HANDSHAKE_TYPES:
            return _HANDSHAKE_TYPES[value]
        return _int(value, 0)
    return _int_value(value, _HANDSHAKE_TYPES["client_hello"])


def _handshake_body_bytes(handshake_type: int, message: Mapping[str, object]) -> bytes:
    raw = message.get("body_hex")
    if raw is not None:
        return _bytes_value(raw)
    if handshake_type == _HANDSHAKE_TYPES["client_hello"]:
        return _client_hello_body(message)
    if handshake_type == _HANDSHAKE_TYPES["server_hello"]:
        return _server_hello_body(message)
    if handshake_type == _HANDSHAKE_TYPES["encrypted_extensions"]:
        return _extension_vector(message)
    if handshake_type == _HANDSHAKE_TYPES["certificate"]:
        return _certificate_body(message)
    if handshake_type == _HANDSHAKE_TYPES["certificate_request"]:
        return _certificate_request_body(message)
    if handshake_type == _HANDSHAKE_TYPES["certificate_verify"]:
        signature = _bytes_value(message.get("signature_hex"))
        return _u16(_int_value(message.get("signature_scheme"), 0x0804)) + _u16_vector(signature)
    if handshake_type == _HANDSHAKE_TYPES["finished"]:
        return _bytes_value(message.get("verify_data_hex"))
    if handshake_type == _HANDSHAKE_TYPES["new_session_ticket"]:
        return _new_session_ticket_body(message)
    if handshake_type == _HANDSHAKE_TYPES["key_update"]:
        return bytes([_key_update_value(message.get("request_update"))])
    if handshake_type == _HANDSHAKE_TYPES["end_of_early_data"]:
        return b""
    return _bytes_value(message.get("body_hex"))


def _client_hello_body(message: Mapping[str, object]) -> bytes:
    session_id = _bytes_value(message.get("session_id_hex", message.get("session_id")))
    cipher_suites = _u16_list(message.get("cipher_suites"))
    compression = _bytes_value(message.get("compression_methods_hex", message.get("compression_methods")), b"\x00")
    return b"".join(
        (
            _u16(_int_value(message.get("legacy_version"), 0x0303)),
            _bytes_value(message.get("random_hex"), b"\x00" * 32, pad_to=32)[:32],
            _u8_vector(session_id),
            _u16_vector(cipher_suites),
            _u8_vector(compression),
            _extension_vector(message),
        )
    )


def _server_hello_body(message: Mapping[str, object]) -> bytes:
    session_id = _bytes_value(message.get("session_id_echo_hex", message.get("session_id_hex")))
    return b"".join(
        (
            _u16(_int_value(message.get("legacy_version"), 0x0303)),
            _bytes_value(message.get("random_hex"), b"\x00" * 32, pad_to=32)[:32],
            _u8_vector(session_id),
            _u16(_int_value(message.get("cipher_suite"), 0x1301)),
            bytes([_int_value(message.get("compression_method"), 0)]),
            _extension_vector(message),
        )
    )


def _extension_vector(message: Mapping[str, object]) -> bytes:
    extensions = message.get("extensions")
    if not isinstance(extensions, Sequence) or isinstance(extensions, (str, bytes, bytearray)):
        return _u16_vector(b"")
    body = b"".join(_extension_bytes(ext, message) for ext in extensions if isinstance(ext, Mapping))
    return _u16_vector(body)


def _extension_bytes(extension: Mapping[str, object], message: Mapping[str, object]) -> bytes:
    extension_type = _extension_type_value(extension)
    body = _extension_body(extension, message)
    return _u16(extension_type) + _u16_vector(body)


def _extension_type_value(extension: Mapping[str, object]) -> int:
    raw = extension.get("type_raw")
    if raw is not None:
        return _int_value(raw, 0)
    value = extension.get("type", extension.get("extension_type"))
    if isinstance(value, str):
        if value in _EXTENSION_TYPES:
            return _EXTENSION_TYPES[value]
        return _int(value, 0)
    return _int_value(value, 0)


def _extension_body(extension: Mapping[str, object], message: Mapping[str, object]) -> bytes:
    raw = extension.get("body_hex")
    if raw is not None:
        return _bytes_value(raw)
    extension_type = _extension_type_value(extension)
    if extension_type == _EXTENSION_TYPES["server_name"]:
        return _server_name_body(extension)
    if extension_type == _EXTENSION_TYPES["application_layer_protocol_negotiation"]:
        return _alpn_body(extension)
    if extension_type == _EXTENSION_TYPES["supported_versions"]:
        if extension.get("context") == "server_hello" or "selected_version" in extension:
            return _u16(_int_value(extension.get("selected_version"), 0x0304))
        return _u8_vector(_u16_list(extension.get("versions"), default=(0x0304, 0x0303)))
    if extension_type == _EXTENSION_TYPES["supported_groups"]:
        return _u16_vector(_u16_list(extension.get("named_groups")))
    if extension_type == _EXTENSION_TYPES["signature_algorithms"]:
        return _u16_vector(_u16_list(extension.get("signature_schemes")))
    if extension_type == _EXTENSION_TYPES["key_share"]:
        return _key_share_body(extension)
    if extension_type == _EXTENSION_TYPES["psk_key_exchange_modes"]:
        return _u8_vector(bytes(_psk_mode_value(item) for item in _list(extension.get("modes"))))
    if extension_type == _EXTENSION_TYPES["pre_shared_key"]:
        return _pre_shared_key_body(extension)
    if extension_type == _EXTENSION_TYPES["cookie"]:
        return _u16_vector(_bytes_value(extension.get("cookie_hex")))
    if extension_type == _EXTENSION_TYPES["padding"]:
        return _bytes_value(extension.get("padding_hex"))
    if extension_type == _EXTENSION_TYPES["record_size_limit"]:
        return _u16(_int_value(extension.get("limit"), 64))
    if extension_type == _EXTENSION_TYPES["status_request"]:
        return _status_request_body(extension)
    if extension_type == _EXTENSION_TYPES["certificate_authorities"]:
        return _distinguished_names_vector(extension.get("distinguished_names_hex"))
    return b""


def _server_name_body(extension: Mapping[str, object]) -> bytes:
    names = _list(extension.get("host_names"))
    entries = b"".join(
        bytes([0]) + _u16_vector(_text(name, "").encode("ascii"))
        for name in names
    )
    return _u16_vector(entries)


def _alpn_body(extension: Mapping[str, object]) -> bytes:
    protocols = _list(extension.get("protocols"))
    entries = b"".join(_u8_vector(_text(proto, "").encode("ascii")) for proto in protocols)
    return _u16_vector(entries)


def _key_share_body(extension: Mapping[str, object]) -> bytes:
    context = _text(extension.get("context"), "client_hello")
    if context == "hello_retry_request":
        return _u16(_int_value(extension.get("selected_group"), 0x001D))
    if context == "server_hello":
        return _u16(_int_value(extension.get("group"), 0x001D)) + _u16_vector(
            _bytes_value(extension.get("key_exchange_hex"))
        )
    shares = _list(extension.get("shares"))
    body = b"".join(
        _u16(_int_value(_mapping(share).get("group"), 0x001D))
        + _u16_vector(_bytes_value(_mapping(share).get("key_exchange_hex")))
        for share in shares
    )
    return _u16_vector(body)


def _pre_shared_key_body(extension: Mapping[str, object]) -> bytes:
    if extension.get("context") == "server_hello" or "selected_identity" in extension:
        return _u16(_int_value(extension.get("selected_identity"), 0))
    identities = b"".join(
        _u16_vector(_bytes_value(_mapping(identity).get("identity_hex")))
        + _u32(_int_value(_mapping(identity).get("obfuscated_ticket_age"), 0))
        for identity in _list(extension.get("identities"))
    )
    binders = b"".join(
        _u8_vector(_bytes_value(_mapping(binder).get("binder_hex")))
        for binder in _list(extension.get("binders"))
    )
    return _u16_vector(identities) + _u16_vector(binders)


def _status_request_body(extension: Mapping[str, object]) -> bytes:
    status_type = 1 if _text(extension.get("status_type"), "ocsp") == "ocsp" else _int_value(extension.get("status_type"), 1)
    responders = _distinguished_names_vector(extension.get("responder_ids"))
    request_extensions = _u16_vector(_bytes_value(extension.get("request_extensions_hex")))
    return bytes([status_type]) + responders + request_extensions


def _certificate_body(message: Mapping[str, object]) -> bytes:
    entries = _certificate_entries(message)
    if message.get("form") == "tls13":
        return _u8_vector(_bytes_value(message.get("request_context_hex"))) + _u24_vector(entries)
    return _u24_vector(entries)


def _certificate_entries(message: Mapping[str, object]) -> bytes:
    entries = []
    for item in _list(message.get("certificates")):
        cert = _mapping(item)
        body = _u24_vector(_bytes_value(cert.get("hex")))
        if message.get("form") == "tls13":
            ext_owner = {"extensions": cert.get("extensions", [])}
            body += _extension_vector(ext_owner)
        entries.append(body)
    return b"".join(entries)


def _certificate_request_body(message: Mapping[str, object]) -> bytes:
    if message.get("form") == "tls13":
        return _u8_vector(_bytes_value(message.get("request_context_hex"))) + _extension_vector(message)
    certificate_types = bytes(_certificate_type_value(item) for item in _list(message.get("certificate_types")))
    signatures = _u16_vector(_u16_list(message.get("signature_algorithms")))
    authorities = _distinguished_names_vector(message.get("certificate_authorities_hex"))
    return _u8_vector(certificate_types) + signatures + authorities


def _new_session_ticket_body(message: Mapping[str, object]) -> bytes:
    if message.get("form") == "tls13":
        return b"".join(
            (
                _u32(_int_value(message.get("ticket_lifetime"), 0)),
                _u32(_int_value(message.get("ticket_age_add"), 0)),
                _u8_vector(_bytes_value(message.get("ticket_nonce_hex"))),
                _u16_vector(_bytes_value(message.get("ticket_hex"))),
                _extension_vector(message),
            )
        )
    ticket = _bytes_value(message.get("ticket_hex"))
    return _u32(_int_value(message.get("lifetime_hint"), 0)) + _u16_vector(ticket)


def _distinguished_names_vector(value: object) -> bytes:
    body = b"".join(_u16_vector(_bytes_value(item)) for item in _list(value))
    return _u16_vector(body)


def canonicalize_tls_payload(
    packet: Any,
    layers: list[str],
    fields: dict[str, JSONObject],
    *,
    root: str | None = None,
) -> None:
    """Promote Scapy Raw TLS bytes to the neutral ``tls`` layer."""

    if root == "raw:tls":
        raw = _raw_payload_from_packet(packet)
        if raw is None:
            return
        parsed = parse_tls_records(raw, allow_unknown_first=True)
        if parsed is None:
            return
        if not layers:
            return
        payload_index = _payload_index(layers)
        if payload_index is None:
            return
        _replace_payload_with_tls(layers, fields, payload_index, parsed)
        return

    tcp = _scapy_layer(packet, "TCP")
    if tcp is None:
        return
    sport = _int_value(getattr(tcp, "sport", 0), 0)
    dport = _int_value(getattr(tcp, "dport", 0), 0)
    if sport not in _TLS_TCP_PORTS and dport not in _TLS_TCP_PORTS:
        return
    raw = _raw_payload_from_packet(packet)
    if raw is None or not _looks_like_tls_payload(raw):
        return
    parsed = parse_tls_records(raw, allow_unknown_first=False)
    if parsed is None:
        return
    payload_index = _payload_index_after_tcp(layers)
    if payload_index is None:
        return
    _replace_payload_with_tls(layers, fields, payload_index, parsed)


def parse_tls_records(raw: bytes, *, allow_unknown_first: bool) -> JSONObject | None:
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
            if content_type not in _CONTENT_TYPES.values() or version not in _LEGACY_RECORD_VERSIONS:
                return None
        fragment = raw[cursor + 5 : end]
        record_hex = raw[cursor:end].hex()
        records.append(_record_model(content_type, version, length, fragment, record_hex))
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


def _looks_like_tls_payload(raw: bytes) -> bool:
    parsed = parse_tls_records(raw, allow_unknown_first=False)
    if parsed is None:
        return False
    return parsed.get("record_count", 0) > 0


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
    if content_type == _CONTENT_TYPES["handshake"]:
        fields["handshake_messages"] = _handshake_models(fragment)
    elif content_type == _CONTENT_TYPES["alert"] and len(fragment) >= 2:
        fields["alert_level"] = "fatal" if fragment[0] == 2 else "warning" if fragment[0] == 1 else "unknown"
        fields["alert_description"] = _alert_description_label(fragment[1])
    elif content_type == _CONTENT_TYPES["change_cipher_spec"] and fragment:
        fields["change_cipher_spec"] = fragment[0]
    elif content_type == _CONTENT_TYPES["application_data"]:
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


def _replace_payload_with_tls(
    layers: list[str],
    fields: dict[str, JSONObject],
    payload_index: int,
    parsed: JSONObject,
) -> None:
    fields.pop(_layer_key_at(layers, payload_index), None)
    layers[payload_index] = "tls"
    fields[_layer_key_at(layers, payload_index)] = parsed
    raw_tail = parsed.pop("raw_tail_hex", None)
    if isinstance(raw_tail, str) and raw_tail:
        tail = bytes.fromhex(raw_tail)
        layers.insert(payload_index + 1, "payload")
        fields[_layer_key_at(layers, payload_index + 1)] = _payload_fields_from_bytes(tail)


def _payload_fields_from_bytes(body: bytes) -> JSONObject:
    return {
        "hex": body.hex(),
        "length": len(body),
        "ascii": body.decode("utf-8", "replace"),
    }


def _content_type_label(content_type: int) -> str:
    known = _CONTENT_TYPE_LABELS.get(content_type)
    if known is not None:
        return known
    if 32 <= content_type <= 63:
        return f"reserved content type 0x{content_type:02x}"
    return f"unassigned content type 0x{content_type:02x}"


def _record_body_kind_label(content_type: int) -> str:
    return _CONTENT_TYPE_LABELS.get(content_type, "opaque_raw")


def _handshake_type_label(handshake_type: int) -> str:
    known = _HANDSHAKE_LABELS.get(handshake_type)
    if known is not None:
        return known
    return f"unassigned handshake type 0x{handshake_type:02x}"


def _payload_index_after_tcp(layers: Sequence[str]) -> int | None:
    try:
        tcp_index = list(layers).index("tcp")
    except ValueError:
        return None
    for index in range(tcp_index + 1, len(layers)):
        if layers[index] == "payload":
            return index
    return None


def _payload_index(layers: Sequence[str]) -> int | None:
    for index, layer in enumerate(layers):
        if layer == "payload":
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


def _first_present(*sources_and_names: object) -> object | None:
    sources = [item for item in sources_and_names if isinstance(item, Mapping)]
    names = [item for item in sources_and_names if isinstance(item, str)]
    for source in sources:
        for name in names:
            if name in source:
                return source[name]
    return None


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _list(value: object) -> list[object]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return list(value)
    return []


def _content_type_value(value: object, *, default: int) -> int:
    if isinstance(value, Mapping):
        return _int_value(value.get("raw"), default)
    if isinstance(value, str):
        if value in _CONTENT_TYPES:
            return _CONTENT_TYPES[value]
        return _int(value, default)
    return _int_value(value, default)


def _extension_int(value: object, default: int) -> int:
    if isinstance(value, Mapping):
        return _int_value(value.get("raw"), default)
    return _int_value(value, default)


def _int_value(value: object, default: int) -> int:
    if isinstance(value, Mapping):
        return _int_value(value.get("raw", value.get("value")), default)
    if value is None or value == "derived":
        return default
    return _int(value, default)


def _declared_length(value: object, actual: int) -> int:
    if value is None or value == "derived":
        return actual
    return _int_value(value, actual)


def _bytes_value(value: object, default: bytes = b"", *, pad_to: int | None = None) -> bytes:
    if value is None:
        raw = default
    elif isinstance(value, Mapping):
        raw = _bytes_value(value.get("hex"), default)
    elif isinstance(value, bytes):
        raw = value
    elif isinstance(value, bytearray):
        raw = bytes(value)
    elif isinstance(value, str):
        raw = bytes.fromhex(value.replace(":", "").replace("-", ""))
    else:
        raise ValueError(f"expected TLS bytes-compatible value, got {value!r}")
    if pad_to is not None and len(raw) < pad_to:
        raw = raw + (b"\x00" * (pad_to - len(raw)))
    return raw


def _u8_vector(body: bytes) -> bytes:
    return bytes([len(body) & 0xFF]) + body


def _u16_vector(body: bytes) -> bytes:
    return _u16(len(body)) + body


def _u24_vector(body: bytes) -> bytes:
    return _u24(len(body)) + body


def _u16_list(value: object, default: Sequence[int] = ()) -> bytes:
    values = _list(value) or list(default)
    return b"".join(_u16(_extension_int(item, 0)) for item in values)


def _u16(value: int) -> bytes:
    return int(value & 0xFFFF).to_bytes(2, "big")


def _u24(value: int) -> bytes:
    return int(value & 0xFFFFFF).to_bytes(3, "big")


def _u32(value: int) -> bytes:
    return int(value & 0xFFFF_FFFF).to_bytes(4, "big")


def _alert_level(value: object) -> int:
    if isinstance(value, Mapping):
        return _int_value(value.get("raw"), 2)
    if isinstance(value, str):
        if value in _ALERT_LEVELS:
            return _ALERT_LEVELS[value]
        return _int(value, 2)
    return _int_value(value, 2)


def _alert_description(value: object) -> int:
    if isinstance(value, Mapping):
        return _int_value(value.get("raw"), 50)
    if isinstance(value, str):
        if value in _ALERT_DESCRIPTIONS:
            return _ALERT_DESCRIPTIONS[value]
        return _int(value, 50)
    return _int_value(value, 50)


def _alert_description_label(value: int) -> str:
    for name, code in _ALERT_DESCRIPTIONS.items():
        if code == value:
            return name
    return "unknown"


def _certificate_type_value(value: object) -> int:
    if isinstance(value, Mapping):
        return _int_value(value.get("raw"), 0)
    if isinstance(value, str):
        if value in _CERTIFICATE_TYPES:
            return _CERTIFICATE_TYPES[value]
        return _int(value, 0)
    return _int_value(value, 0)


def _psk_mode_value(value: object) -> int:
    if isinstance(value, Mapping):
        return _int_value(value.get("raw"), 0)
    if isinstance(value, str):
        if value in _PSK_MODES:
            return _PSK_MODES[value]
        return _int(value, 0)
    return _int_value(value, 0)


def _key_update_value(value: object) -> int:
    if isinstance(value, Mapping):
        return _int_value(value.get("raw"), 0)
    if isinstance(value, str):
        if value in _KEY_UPDATE_REQUESTS:
            return _KEY_UPDATE_REQUESTS[value]
        return _int(value, 0)
    return _int_value(value, 0)


register(
    ScapyProtocol(
        layer="tls",
        scapy_class="Raw",
        supported_fields=_SUPPORTED_FIELDS,
        build=_build,
    )
)
