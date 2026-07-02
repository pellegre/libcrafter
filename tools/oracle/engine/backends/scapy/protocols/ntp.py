"""Scapy-stage encode and decode helpers for NTP UDP payloads.

The Scapy backend uses deterministic NTP wire bytes in a ``Raw`` layer under UDP.
That keeps extension fields, NTS packet extensions, malformed declared lengths,
and legacy MAC tails byte-preserving across Scapy versions and optional native
NTP dissector support.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ....model import JSONObject, JSONValue
from ..encode_helpers import _int, _layer_fields, _optional_field
from .base import ScapyProtocol, register


_NTP_PORT = 123
_NTP_FIXED_HEADER_LEN = 48
_NTP_EXTENSION_HEADER_LEN = 4
_NTP_EXTENSION_MIN_LEN = 16
_NTP_FINAL_EXTENSION_WITHOUT_MAC_MIN_LEN = 28
_NTP_LEGACY_MAC_LENGTHS = frozenset({4, 20, 24})

_SUPPORTED_FIELDS = frozenset(
    {
        "expected_error",
        "expected_layers",
        "extension_field_body",
        "extension_field_length",
        "extension_field_type",
        "extension_fields",
        "extension_header_hex",
        "first_octet",
        "leap_indicator",
        "legacy_mac",
        "mac_digest",
        "mac_key_id",
        "mode",
        "malformed",
        "nts_extension",
        "origin_timestamp",
        "payload_hex",
        "poll",
        "precision",
        "raw_fallback",
        "receive_timestamp",
        "reference_id",
        "reference_timestamp",
        "root_delay",
        "root_dispersion",
        "stratum",
        "tail_hex",
        "trailing_mac_hex",
        "transmit_timestamp",
        "version",
    }
)

_LAYER_ALIASES = (("NTP", "ntp"),)
_NTP_NATIVE_LAYERS = frozenset(
    {
        "ntp",
        "ntpheader",
        "ntpcontrol",
        "ntpprivate",
        "ntpextensions",
        "ntpauthenticator",
    }
)
_FIELD_ALIASES = (
    ("delay", "root_delay"),
    ("dispersion", "root_dispersion"),
    ("id", "reference_id"),
    ("leap", "leap_indicator"),
    ("orig", "origin_timestamp"),
    ("recv", "receive_timestamp"),
    ("ref", "reference_timestamp"),
    ("sent", "transmit_timestamp"),
)

_LEAP_INDICATORS = {
    "no-warning": 0,
    "no_warning": 0,
    "last-minute-61-seconds": 1,
    "last_minute_61_seconds": 1,
    "last-minute-59-seconds": 2,
    "last_minute_59_seconds": 2,
    "alarm-unsynchronized": 3,
    "alarm_unsynchronized": 3,
}
_VERSIONS = {
    "ntp-v4": 4,
    "ntp_v4": 4,
    "v4": 4,
    "ntp-v3-sntp": 3,
    "ntp_v3_sntp": 3,
    "v3": 3,
}
_MODES = {
    "reserved": 0,
    "symmetric-active": 1,
    "symmetric_active": 1,
    "symmetric-passive": 2,
    "symmetric_passive": 2,
    "client": 3,
    "server": 4,
    "broadcast": 5,
    "control": 6,
    "private-use": 7,
    "private_use": 7,
}
_STRATA = {
    "unspecified-or-kod": 0,
    "unspecified_or_kod": 0,
    "primary": 1,
    "secondary": 2,
    "unsynchronized": 16,
}
_NTS_EXTENSION_KINDS = {
    0x0104: "unique_identifier",
    0x0204: "cookie",
    0x0304: "cookie_placeholder",
    0x0404: "authenticator",
}
_EXTENSION_LABELS = {
    0x0104: "Unique Identifier",
    0x0204: "Autokey Message Request / NTS Cookie",
    0x0304: "NTS Cookie Placeholder",
    0x0404: "NTS Authenticator and Encrypted Extension Fields",
    0x2005: "UDP Checksum Complement",
}


def _build(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    del plan, stack, index
    return scapy_all.Raw(load=_ntp_message_bytes(fields))


def _ntp_message_bytes(fields: Mapping[str, JSONObject]) -> bytes:
    ntp = _layer_fields(fields, "ntp")
    payload = _explicit_payload_bytes(ntp)
    if payload is not None:
        return payload

    header = _ntp_header_bytes(ntp)
    tail_hex = ntp.get("tail_hex")
    if isinstance(tail_hex, str):
        return header + bytes.fromhex(tail_hex)

    output = bytearray(header)
    extension_header_hex = ntp.get("extension_header_hex")
    if isinstance(extension_header_hex, str):
        output.extend(bytes.fromhex(extension_header_hex))
    else:
        output.extend(_extension_fields_bytes(ntp))

    legacy_mac = _legacy_mac_bytes(ntp.get("legacy_mac"))
    if legacy_mac is not None:
        output.extend(legacy_mac)

    trailing_mac_hex = ntp.get("trailing_mac_hex")
    if isinstance(trailing_mac_hex, str):
        output.extend(bytes.fromhex(trailing_mac_hex))

    return bytes(output)


def _explicit_payload_bytes(ntp: Mapping[str, object]) -> bytes | None:
    payload_hex = ntp.get("payload_hex")
    if isinstance(payload_hex, str):
        return bytes.fromhex(payload_hex)
    raw_fallback = ntp.get("raw_fallback")
    if isinstance(raw_fallback, Mapping):
        raw_hex = raw_fallback.get("hex")
        if isinstance(raw_hex, str):
            return bytes.fromhex(raw_hex)
    return None


def _ntp_header_bytes(ntp: Mapping[str, object]) -> bytes:
    first_octet = _optional_field(ntp, "first_octet")
    if first_octet is None:
        leap = _enum_value(ntp.get("leap_indicator"), _LEAP_INDICATORS, 0)
        version = _enum_value(ntp.get("version"), _VERSIONS, 4)
        mode = _enum_value(ntp.get("mode"), _MODES, 3)
        first_octet_value = ((leap & 0x03) << 6) | ((version & 0x07) << 3) | (mode & 0x07)
    else:
        first_octet_value = _int_value(first_octet, 0) & 0xFF

    header = bytearray()
    header.append(first_octet_value)
    header.append(_enum_value(ntp.get("stratum"), _STRATA, 0) & 0xFF)
    header.append(_signed_octet(ntp.get("poll"), 6))
    header.append(_signed_octet(ntp.get("precision"), -20))
    header.extend(_u32(ntp.get("root_delay"), 0))
    header.extend(_u32(ntp.get("root_dispersion"), 0))
    header.extend(_bytes_exact(ntp.get("reference_id"), 4))
    header.extend(_u64(ntp.get("reference_timestamp"), 0))
    header.extend(_u64(ntp.get("origin_timestamp"), 0))
    header.extend(_u64(ntp.get("receive_timestamp"), 0))
    header.extend(_u64(ntp.get("transmit_timestamp"), 0))
    return bytes(header)


def _extension_fields_bytes(ntp: Mapping[str, object]) -> bytes:
    extension_fields = ntp.get("extension_fields")
    if not isinstance(extension_fields, Sequence) or isinstance(
        extension_fields, (bytes, bytearray, str)
    ):
        return b""
    has_legacy_mac = (
        _legacy_mac_bytes(ntp.get("legacy_mac")) is not None
        or isinstance(ntp.get("trailing_mac_hex"), str)
    )
    output = bytearray()
    field_mappings = [field for field in extension_fields if isinstance(field, Mapping)]
    for index, field in enumerate(field_mappings):
        last_without_mac = index + 1 == len(field_mappings) and not has_legacy_mac
        output.extend(_extension_field_bytes(field, last_without_mac=last_without_mac))
    return bytes(output)


def _extension_field_bytes(field: Mapping[str, object], *, last_without_mac: bool) -> bytes:
    field_type = _int_value(
        _optional_field(field, "field_type", "extension_field_type", "type"),
        0,
    )
    body = _extension_body_bytes(field)
    declared = _optional_field(field, "declared_length", "length", "extension_field_length")
    if declared is None:
        minimum = _NTP_FINAL_EXTENSION_WITHOUT_MAC_MIN_LEN if last_without_mac else _NTP_EXTENSION_MIN_LEN
        encoded_len = _align_4(max(_NTP_EXTENSION_HEADER_LEN + len(body), minimum))
        declared_len = encoded_len
    else:
        declared_len = _int_value(declared, _NTP_EXTENSION_HEADER_LEN)
        encoded_len = max(declared_len, _NTP_EXTENSION_HEADER_LEN)

    if not 0 <= declared_len <= 0xFFFF:
        raise ValueError(f"NTP extension declared length must fit u16: {declared_len}")
    encoded = bytearray()
    encoded.extend((field_type & 0xFFFF).to_bytes(2, "big"))
    encoded.extend(declared_len.to_bytes(2, "big"))
    body_len = encoded_len - _NTP_EXTENSION_HEADER_LEN
    encoded.extend(body[:body_len])
    padding = _hex_field(field, "padding_hex", "padding")
    if len(encoded) < encoded_len and padding is not None:
        needed = encoded_len - len(encoded)
        encoded.extend(padding[:needed])
    if len(encoded) < encoded_len:
        encoded.extend(b"\x00" * (encoded_len - len(encoded)))
    return bytes(encoded)


def _extension_body_bytes(field: Mapping[str, object]) -> bytes:
    body = _hex_field(field, "body_hex", "extension_field_body", "value_hex")
    if body is not None:
        return body
    if any(name in field for name in ("nonce_hex", "ciphertext_hex", "tag_hex", "additional_padding_hex")):
        nonce = _hex_field(field, "nonce_hex") or b""
        ciphertext = _hex_field(field, "ciphertext_hex") or b""
        tag = _hex_field(field, "tag_hex") or b""
        additional_padding = _hex_field(field, "additional_padding_hex") or b""
        ciphertext_with_tag = ciphertext + tag
        output = bytearray()
        output.extend(len(nonce).to_bytes(2, "big"))
        output.extend(len(ciphertext_with_tag).to_bytes(2, "big"))
        output.extend(nonce)
        output.extend(b"\x00" * (_align_4(len(nonce)) - len(nonce)))
        output.extend(ciphertext_with_tag)
        output.extend(b"\x00" * (_align_4(len(ciphertext_with_tag)) - len(ciphertext_with_tag)))
        output.extend(additional_padding)
        return bytes(output)
    return b""


def _legacy_mac_bytes(value: object) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return bytes.fromhex(value)
    if not isinstance(value, Mapping):
        raise ValueError(f"NTP legacy_mac must be an object or bytes, got {value!r}")
    raw = _hex_field(value, "hex", "raw_hex", "legacy_mac")
    if raw is not None:
        return raw
    key_id = _int_value(_optional_field(value, "key_id", "mac_key_id"), 0)
    digest = _hex_field(value, "digest_hex", "mac_digest") or b""
    return key_id.to_bytes(4, "big") + digest


def ntp_fields_from_bytes(raw: bytes) -> JSONObject | None:
    if len(raw) < _NTP_FIXED_HEADER_LEN:
        return None
    first_octet = raw[0]
    leap_indicator = (first_octet >> 6) & 0x03
    version = (first_octet >> 3) & 0x07
    mode = first_octet & 0x07
    if not 1 <= version <= 7 or mode == 0:
        return None

    tail = _parse_tail(raw[_NTP_FIXED_HEADER_LEN :])
    if tail is None:
        return None
    extension_fields, legacy_mac = tail

    fields: JSONObject = {
        "first_octet": first_octet,
        "leap_indicator": leap_indicator,
        "version": version,
        "mode": mode,
        "stratum": raw[1],
        "poll": _signed_value(raw[2]),
        "precision": _signed_value(raw[3]),
        "root_delay": int.from_bytes(raw[4:8], "big"),
        "root_dispersion": int.from_bytes(raw[8:12], "big"),
        "reference_id": {"hex": raw[12:16].hex()},
        "reference_timestamp": int.from_bytes(raw[16:24], "big"),
        "origin_timestamp": int.from_bytes(raw[24:32], "big"),
        "receive_timestamp": int.from_bytes(raw[32:40], "big"),
        "transmit_timestamp": int.from_bytes(raw[40:48], "big"),
        "extension_count": len(extension_fields),
        "extension_fields": extension_fields,
    }
    if legacy_mac is not None:
        fields.update(_legacy_mac_fields(legacy_mac))
    return fields


def _parse_tail(tail: bytes) -> tuple[list[JSONObject], bytes | None] | None:
    fields: list[JSONObject] = []
    offset = 0
    while offset < len(tail):
        remaining = tail[offset:]
        if fields and len(remaining) in _NTP_LEGACY_MAC_LENGTHS:
            return fields, remaining
        if len(remaining) < _NTP_EXTENSION_HEADER_LEN:
            return None

        field_type = int.from_bytes(remaining[0:2], "big")
        declared_len = int.from_bytes(remaining[2:4], "big")
        if not _valid_extension_length(declared_len, len(remaining)):
            if _can_partition_as_legacy_mac(not fields, remaining):
                return fields, remaining
            return None

        final_without_mac = offset + declared_len == len(tail)
        if final_without_mac and declared_len < _NTP_FINAL_EXTENSION_WITHOUT_MAC_MIN_LEN:
            if _can_partition_as_legacy_mac(not fields, remaining):
                return fields, remaining
            return None

        body = remaining[_NTP_EXTENSION_HEADER_LEN:declared_len]
        fields.append(_extension_fields(field_type, declared_len, body))
        offset += declared_len
    return fields, None


def _valid_extension_length(declared_len: int, available: int) -> bool:
    return (
        declared_len >= _NTP_EXTENSION_MIN_LEN
        and declared_len % 4 == 0
        and declared_len <= available
    )


def _can_partition_as_legacy_mac(no_extensions_seen: bool, remaining: bytes) -> bool:
    if len(remaining) not in _NTP_LEGACY_MAC_LENGTHS:
        return False
    if no_extensions_seen and len(remaining) == 4:
        return int.from_bytes(remaining[2:4], "big") >= _NTP_EXTENSION_MIN_LEN
    return True


def _extension_fields(field_type: int, declared_len: int, body: bytes) -> JSONObject:
    output: JSONObject = {
        "extension_field_type": field_type,
        "extension_field_length": declared_len,
        "extension_field_body": {"hex": body.hex()},
        "summary_label": _extension_summary_label(field_type),
    }
    nts_kind = _NTS_EXTENSION_KINDS.get(field_type)
    if nts_kind is not None:
        output["nts_extension"] = nts_kind
    if field_type == 0x0404:
        output["authenticator"] = _nts_authenticator_fields(body)
    return output


def _extension_summary_label(field_type: int) -> str:
    label = _EXTENSION_LABELS.get(field_type)
    if label is not None:
        return label
    if 0xF000 <= field_type <= 0xFFFF:
        return f"extension-field-0x{field_type:04x} (private-or-experimental)"
    return f"extension-field-0x{field_type:04x}"


def _nts_authenticator_fields(body: bytes) -> JSONObject:
    parts = _split_nts_authenticator(body)
    if parts is None:
        return {
            "parts_present": False,
            "body_hex": body.hex(),
            "crypto_verified": False,
        }
    return {
        "parts_present": True,
        "nonce_hex": parts["nonce"].hex(),
        "nonce_padding_hex": parts["nonce_padding"].hex(),
        "ciphertext_hex": parts["ciphertext"].hex(),
        "ciphertext_padding_hex": parts["ciphertext_padding"].hex(),
        "additional_padding_hex": parts["additional_padding"].hex(),
        "crypto_verified": False,
    }


def _split_nts_authenticator(body: bytes) -> dict[str, bytes] | None:
    if len(body) < 4:
        return None
    nonce_len = int.from_bytes(body[0:2], "big")
    ciphertext_len = int.from_bytes(body[2:4], "big")
    nonce_start = 4
    nonce_end = nonce_start + nonce_len
    padded_nonce_end = nonce_start + _align_4(nonce_len)
    ciphertext_start = padded_nonce_end
    ciphertext_end = ciphertext_start + ciphertext_len
    padded_ciphertext_end = ciphertext_start + _align_4(ciphertext_len)
    if padded_ciphertext_end > len(body):
        return None
    return {
        "nonce": body[nonce_start:nonce_end],
        "nonce_padding": body[nonce_end:padded_nonce_end],
        "ciphertext": body[ciphertext_start:ciphertext_end],
        "ciphertext_padding": body[ciphertext_end:padded_ciphertext_end],
        "additional_padding": body[padded_ciphertext_end:],
    }


def _legacy_mac_fields(raw: bytes) -> JSONObject:
    key_id = int.from_bytes(raw[:4], "big") if len(raw) >= 4 else 0
    digest = raw[4:] if len(raw) >= 4 else b""
    return {
        "legacy_mac": {"hex": raw.hex()},
        "mac_key_id": key_id,
        "mac_digest": {"hex": digest.hex()},
        "mac_digest_len": len(digest),
        "mac_total_len": len(raw),
    }


def canonicalize_ntp_payload(
    packet: Any,
    layers: list[str],
    fields: dict[str, JSONObject],
    *,
    source_hex: str | None = None,
    root: str | None = None,
) -> None:
    """Rename a UDP/123 Raw payload to ``ntp`` when the NTP shape gate accepts it."""

    if not _udp_port_matches(packet, layers, fields):
        return
    payload = _ntp_payload_bytes(packet, layers, fields, source_hex=source_hex, root=root)
    if payload is None:
        return
    normalized = ntp_fields_from_bytes(payload)
    if normalized is None:
        return

    ntp_index = _first_layer_index(layers, "ntp")
    if ntp_index is None:
        ntp_index = _first_native_ntp_layer_index(layers)
    payload_index = _payload_index_after_udp(layers)
    target_index = ntp_index if ntp_index is not None else payload_index
    if target_index is None:
        return

    target_key = _layer_key_at(layers, target_index)
    fields.pop(target_key, None)
    layers[target_index] = "ntp"
    ntp_key = _layer_key_at(layers, target_index)
    fields[ntp_key] = normalized

    for index in range(len(layers) - 1, target_index, -1):
        if layers[index] in {"payload", "raw"} or layers[index] in _NTP_NATIVE_LAYERS:
            fields.pop(_layer_key_at(layers, index), None)
            layers.pop(index)


def _normalize(fields: JSONObject) -> JSONObject:
    raw = _raw_payload_from_fields(fields)
    if raw is not None:
        normalized = ntp_fields_from_bytes(raw)
        if normalized is not None:
            return normalized

    output: JSONObject = {}
    aliases = dict(_FIELD_ALIASES)
    for native_name, value in fields.items():
        normalized_name = aliases.get(native_name, native_name)
        if normalized_name == "reference_id":
            try:
                output[normalized_name] = _json_bytes(value, width=4)
            except ValueError:
                output[normalized_name] = _json_value(value)
        else:
            output[normalized_name] = _json_value(value)
    return output


def _ntp_payload_bytes(
    packet: Any,
    layers: Sequence[str],
    fields: Mapping[str, JSONObject],
    *,
    source_hex: str | None,
    root: str | None,
) -> bytes | None:
    payload = _udp_payload_from_source_hex(source_hex, root=root)
    if payload is not None:
        return payload
    raw = _raw_payload_from_packet(packet)
    if raw is not None:
        return raw
    payload_index = _payload_index_after_udp(layers)
    if payload_index is None:
        return None
    payload_key = _layer_key_at(layers, payload_index)
    return _raw_payload_from_fields(fields.get(payload_key, {}))


def _udp_payload_from_source_hex(source_hex: str | None, *, root: str | None) -> bytes | None:
    if source_hex is None:
        return None
    try:
        raw = bytes.fromhex(source_hex)
    except ValueError:
        return None

    offset = 0
    if root in {"link:ethernet", "l2:ethernet"}:
        if len(raw) < 14:
            return None
        ethertype = int.from_bytes(raw[12:14], "big")
        if ethertype not in {0x0800, 0x86DD}:
            return None
        offset = 14

    if len(raw) <= offset:
        return None
    version = raw[offset] >> 4
    if version == 4:
        if len(raw) < offset + 20:
            return None
        ihl = (raw[offset] & 0x0F) * 4
        if ihl < 20 or len(raw) < offset + ihl + 8 or raw[offset + 9] != 17:
            return None
        udp_start = offset + ihl
    elif version == 6:
        if len(raw) < offset + 48 or raw[offset + 6] != 17:
            return None
        udp_start = offset + 40
    else:
        return None

    udp_len = int.from_bytes(raw[udp_start + 4 : udp_start + 6], "big")
    if udp_len < 8 or len(raw) < udp_start + udp_len:
        return None
    return raw[udp_start + 8 : udp_start + udp_len]


def _udp_port_matches(packet: Any, layers: Sequence[str], fields: Mapping[str, JSONObject]) -> bool:
    udp = _scapy_layer(packet, "UDP")
    if udp is not None:
        sport = _int_value(getattr(udp, "sport", 0), 0)
        dport = _int_value(getattr(udp, "dport", 0), 0)
        if sport == _NTP_PORT or dport == _NTP_PORT:
            return True

    for index, layer in enumerate(layers):
        if layer != "udp":
            continue
        udp_fields = fields.get(_layer_key_at(layers, index), {})
        if not isinstance(udp_fields, Mapping):
            continue
        for name in ("src_port", "dst_port", "sport", "dport"):
            if _int_value(udp_fields.get(name), 0) == _NTP_PORT:
                return True
    return False


def _payload_index_after_udp(layers: Sequence[str]) -> int | None:
    try:
        udp_index = list(layers).index("udp")
    except ValueError:
        return None
    for index in range(udp_index + 1, len(layers)):
        if layers[index] in {"payload", "raw"}:
            return index
    return None


def _first_layer_index(layers: Sequence[str], name: str) -> int | None:
    for index, layer in enumerate(layers):
        if layer == name:
            return index
    return None


def _first_native_ntp_layer_index(layers: Sequence[str]) -> int | None:
    for index, layer in enumerate(layers):
        if layer in _NTP_NATIVE_LAYERS:
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
    for name in ("hex", "raw_hex", "payload_hex"):
        value = fields.get(name)
        if isinstance(value, str):
            return bytes.fromhex(value)
    load = fields.get("load")
    if isinstance(load, Mapping):
        hex_value = load.get("hex")
        if isinstance(hex_value, str):
            return bytes.fromhex(hex_value)
    if isinstance(load, str):
        return load.encode("utf-8")
    return None


def _scapy_layer(packet: Any, class_name: str) -> Any:
    current = packet
    while current is not None and current.__class__.__name__ != "NoPayload":
        if current.__class__.__name__ == class_name:
            return current
        current = getattr(current, "payload", None)
    return None


def _layer_key_at(layers: Sequence[str], index: int) -> str:
    layer_name = layers[index]
    count = sum(1 for item in layers[: index + 1] if item == layer_name)
    return layer_name if count == 1 else f"{layer_name}#{count}"


def _enum_value(value: object, mapping: Mapping[str, int], default: int) -> int:
    if isinstance(value, Mapping):
        return _int_value(value.get("raw", value.get("value")), default)
    if isinstance(value, str):
        lowered = value.lower().replace(" ", "_")
        if lowered in mapping:
            return mapping[lowered]
        dashed = lowered.replace("_", "-")
        if dashed in mapping:
            return mapping[dashed]
    return _int_value(value, default)


def _int_value(value: object, default: int) -> int:
    if isinstance(value, Mapping):
        return _int_value(value.get("raw", value.get("value")), default)
    return _int(value, default)


def _signed_octet(value: object, default: int) -> int:
    return _int_value(value, default) & 0xFF


def _signed_value(value: int) -> int:
    return value - 256 if value >= 128 else value


def _u32(value: object, default: int) -> bytes:
    return (_int_value(value, default) & 0xFFFFFFFF).to_bytes(4, "big")


def _u64(value: object, default: int) -> bytes:
    return (_int_value(value, default) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")


def _bytes_exact(value: object, width: int) -> bytes:
    if value is None:
        raw = b""
    else:
        raw = _bytes_value(value)
    return raw[:width].ljust(width, b"\x00")


def _bytes_value(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, Mapping):
        for key in ("hex", "raw_hex", "body_hex", "value"):
            item = value.get(key)
            if isinstance(item, str):
                return bytes.fromhex(item)
    if isinstance(value, str):
        cleaned = value.replace(":", "").replace("-", "")
        if len(cleaned) % 2 == 0 and all(char in "0123456789abcdefABCDEF" for char in cleaned):
            return bytes.fromhex(cleaned)
        return value.encode("ascii")
    raise ValueError(f"expected bytes-compatible value, got {value!r}")


def _hex_field(mapping: Mapping[str, object], *names: str) -> bytes | None:
    value = _optional_field(mapping, *names)
    if value is None:
        return None
    return _bytes_value(value)


def _json_bytes(value: object, *, width: int | None = None) -> JSONObject:
    raw = _bytes_value(value)
    if width is not None:
        raw = raw[:width].ljust(width, b"\x00")
    return {"hex": raw.hex()}


def _json_value(value: object) -> JSONValue:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, bytes):
        return {"hex": value.hex()}
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_value(item) for item in value]
    return str(value)


def _align_4(value: int) -> int:
    return (value + 3) & ~3


register(
    ScapyProtocol(
        layer="ntp",
        scapy_class="Raw",
        supported_fields=_SUPPORTED_FIELDS,
        build=_build,
        normalize=_normalize,
        layer_aliases=_LAYER_ALIASES,
        field_aliases=_FIELD_ALIASES,
    )
)
