"""Wireshark-stage parser-only decode plugin for NTP over UDP/123.

The Wireshark backend is decode-only. This module normalizes tshark's native
``ntp`` fields when they are available, and prefers byte-level parsing from the
oracle source bytes when possible so extension fields, NTS bodies, and legacy
MAC tails stay aligned with libcrafter's packet model. It intentionally does not
import or reuse the Scapy NTP encoder.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

from ....model import JSONObject
from ..decode_helpers import (
    _field,
    _fields_from_aliases,
    _layer,
    _parse_int,
    _parse_int_fields,
)
from .base import WiresharkProtocol, register


_NTP_PORT = 123
_NTP_FIXED_HEADER_LEN = 48
_NTP_EXTENSION_HEADER_LEN = 4
_NTP_EXTENSION_MIN_LEN = 16
_NTP_FINAL_EXTENSION_WITHOUT_MAC_MIN_LEN = 28
_NTP_LEGACY_MAC_LENGTHS = frozenset({4, 20, 24})

_NTS_EXTENSION_KINDS = {
    0x0104: "unique_identifier",
    0x0204: "cookie",
    0x0304: "cookie_placeholder",
    0x0404: "authenticator",
}
_EXTENSION_LABELS = {
    0x0104: "nts-unique-identifier",
    0x0204: "nts-cookie",
    0x0304: "nts-cookie-placeholder",
    0x0404: "nts-authenticator",
    0x2005: "udp-checksum-complement",
}

_NTP_TSHARK_ALIASES: JSONObject = {
    "first_octet": ("ntp.flags", "ntp.flags.byte", "ntp.flags_byte"),
    "leap_indicator": ("ntp.flags.li", "ntp.li", "ntp.leap_indicator"),
    "version": ("ntp.flags.vn", "ntp.vn", "ntp.version"),
    "mode": ("ntp.flags.mode", "ntp.mode"),
    "stratum": ("ntp.stratum",),
    "poll": ("ntp.ppoll", "ntp.poll"),
    "precision": ("ntp.precision",),
}

_FIXED_RAW_ALIASES: dict[str, tuple[str, ...]] = {
    "root_delay": ("ntp.rootdelay", "ntp.root_delay"),
    "root_dispersion": ("ntp.rootdispersion", "ntp.root_dispersion"),
    "reference_id": ("ntp.refid", "ntp.ref_id", "ntp.reference_id"),
}
_TIMESTAMP_RAW_ALIASES: dict[str, tuple[str, ...]] = {
    "reference_timestamp": (
        "ntp.reftime",
        "ntp.ref_time",
        "ntp.reference_timestamp",
    ),
    "origin_timestamp": (
        "ntp.org",
        "ntp.originate_timestamp",
        "ntp.origin_timestamp",
    ),
    "receive_timestamp": (
        "ntp.rec",
        "ntp.receive_timestamp",
    ),
    "transmit_timestamp": (
        "ntp.xmt",
        "ntp.sent",
        "ntp.transmit_timestamp",
    ),
}
_TIMESTAMP_PART_ALIASES: dict[str, tuple[tuple[str, str], ...]] = {
    "reference_timestamp": (
        ("ntp.reftime.seconds", "ntp.reftime.fraction"),
        ("ntp.reference_timestamp.seconds", "ntp.reference_timestamp.fraction"),
    ),
    "origin_timestamp": (
        ("ntp.org.seconds", "ntp.org.fraction"),
        ("ntp.origin_timestamp.seconds", "ntp.origin_timestamp.fraction"),
    ),
    "receive_timestamp": (
        ("ntp.rec.seconds", "ntp.rec.fraction"),
        ("ntp.receive_timestamp.seconds", "ntp.receive_timestamp.fraction"),
    ),
    "transmit_timestamp": (
        ("ntp.xmt.seconds", "ntp.xmt.fraction"),
        ("ntp.transmit_timestamp.seconds", "ntp.transmit_timestamp.fraction"),
    ),
}
_EXTENSION_TYPE_ALIASES = (
    "ntp.extension.type",
    "ntp.ext.type",
    "ntp.extension.field_type",
    "ntp.ext.field_type",
)
_EXTENSION_LENGTH_ALIASES = (
    "ntp.extension.length",
    "ntp.ext.length",
    "ntp.extension.len",
    "ntp.ext.len",
)
_EXTENSION_BODY_ALIASES = (
    "ntp.extension.value",
    "ntp.ext.value",
    "ntp.extension.data",
    "ntp.ext.data",
)
_MAC_ALIASES = (
    "ntp.mac",
    "ntp.authenticator",
    "ntp.digest",
)


def _normalize_ntp(layers: JSONObject, *, source_hex: str | None = None) -> JSONObject:
    payload = _ntp_payload_from_source_hex(source_hex)
    if payload is not None:
        normalized = ntp_fields_from_bytes(payload)
        return normalized if normalized is not None else {}

    layer = _layer(layers, "ntp")
    output = _fields_from_aliases(layer, dict(_NTP_TSHARK_ALIASES))
    _parse_int_fields(output, "first_octet", "leap_indicator", "version", "mode", "stratum")
    _parse_small_int_fields(output, "poll", "precision")
    _normalize_first_octet(output)
    _normalize_fixed_raw_fields(layer, output)
    _normalize_timestamps(layer, output)
    _normalize_native_extensions(layer, output)
    _normalize_native_mac(layer, output)
    return output


def ntp_fields_from_bytes(raw: bytes) -> JSONObject | None:
    if len(raw) < _NTP_FIXED_HEADER_LEN:
        return None
    first_octet = raw[0]
    leap_indicator = (first_octet >> 6) & 0x03
    version = (first_octet >> 3) & 0x07
    mode = first_octet & 0x07
    if not 1 <= version <= 4 or mode == 0:
        return None

    tail = _parse_tail(raw[_NTP_FIXED_HEADER_LEN :])
    if tail is None:
        return None
    extension_fields, legacy_mac = tail

    output: JSONObject = {
        "first_octet": first_octet,
        "leap_indicator": leap_indicator,
        "version": version,
        "mode": mode,
        "stratum": raw[1],
        "poll": _signed_octet_value(raw[2]),
        "precision": _signed_octet_value(raw[3]),
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
        output.update(_legacy_mac_fields(legacy_mac))
    return output


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
        "summary_label": _EXTENSION_LABELS.get(field_type, "unknown-preserved"),
    }
    nts_kind = _NTS_EXTENSION_KINDS.get(field_type)
    if nts_kind is not None:
        output["nts_extension"] = nts_kind
    if field_type == 0x0404:
        output["authenticator"] = _nts_authenticator_fields(body)
    return output


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


def _ntp_payload_from_source_hex(source_hex: str | None) -> bytes | None:
    if source_hex is None:
        return None
    try:
        raw = bytes.fromhex(source_hex)
    except ValueError:
        return None

    for offset in (0, 4, 14, 16, 18):
        payload = _udp_payload_from_ip(raw, offset)
        if payload is not None:
            return payload
    payload = _udp_payload_from_datagram(raw, 0)
    if payload is not None:
        return payload
    if ntp_fields_from_bytes(raw) is not None:
        return raw
    return None


def _udp_payload_from_ip(raw: bytes, offset: int) -> bytes | None:
    if len(raw) <= offset:
        return None
    version = raw[offset] >> 4
    if version == 4:
        if len(raw) < offset + 20:
            return None
        ihl = (raw[offset] & 0x0F) * 4
        total_len = int.from_bytes(raw[offset + 2 : offset + 4], "big")
        if ihl < 20 or total_len < ihl + 8 or raw[offset + 9] != 17:
            return None
        packet_end = offset + total_len
        udp_start = offset + ihl
    elif version == 6:
        if len(raw) < offset + 48 or raw[offset + 6] != 17:
            return None
        payload_len = int.from_bytes(raw[offset + 4 : offset + 6], "big")
        packet_end = offset + 40 + payload_len
        udp_start = offset + 40
    else:
        return None

    if len(raw) < packet_end or udp_start + 8 > packet_end:
        return None
    return _udp_payload_from_datagram(raw, udp_start, packet_end=packet_end)


def _udp_payload_from_datagram(
    raw: bytes, offset: int, *, packet_end: int | None = None
) -> bytes | None:
    if len(raw) < offset + 8:
        return None
    packet_end = len(raw) if packet_end is None else packet_end
    src_port = int.from_bytes(raw[offset : offset + 2], "big")
    dst_port = int.from_bytes(raw[offset + 2 : offset + 4], "big")
    if src_port != _NTP_PORT and dst_port != _NTP_PORT:
        return None
    udp_len = int.from_bytes(raw[offset + 4 : offset + 6], "big")
    if udp_len < 8 or offset + udp_len > packet_end:
        return None
    return raw[offset + 8 : offset + udp_len]


def _normalize_first_octet(output: JSONObject) -> None:
    for name in ("first_octet", "leap_indicator", "version", "mode"):
        value = _parse_numberish(output.get(name))
        if value is not None:
            output[name] = value

    first_octet = output.get("first_octet")
    if isinstance(first_octet, int):
        output.setdefault("leap_indicator", (first_octet >> 6) & 0x03)
        output.setdefault("version", (first_octet >> 3) & 0x07)
        output.setdefault("mode", first_octet & 0x07)
        return

    leap = output.get("leap_indicator")
    version = output.get("version")
    mode = output.get("mode")
    if isinstance(leap, int) and isinstance(version, int) and isinstance(mode, int):
        output["first_octet"] = ((leap & 0x03) << 6) | ((version & 0x07) << 3) | (
            mode & 0x07
        )


def _normalize_fixed_raw_fields(layer: JSONObject, output: JSONObject) -> None:
    for name in ("root_delay", "root_dispersion"):
        value = _short_format_from_native(layer, *_FIXED_RAW_ALIASES[name])
        if value is not None:
            output[name] = value

    reference_id = _bytes_from_native(layer, *_FIXED_RAW_ALIASES["reference_id"], width=4)
    if reference_id is not None:
        output["reference_id"] = {"hex": reference_id.hex()}


def _normalize_timestamps(layer: JSONObject, output: JSONObject) -> None:
    for target, names in _TIMESTAMP_RAW_ALIASES.items():
        value = _timestamp_from_native(layer, names, _TIMESTAMP_PART_ALIASES[target])
        if value is not None:
            output[target] = value


def _normalize_native_extensions(layer: JSONObject, output: JSONObject) -> None:
    types = _native_int_list(layer, *_EXTENSION_TYPE_ALIASES)
    lengths = _native_int_list(layer, *_EXTENSION_LENGTH_ALIASES)
    bodies = _native_bytes_list(layer, *_EXTENSION_BODY_ALIASES)
    count = max(len(types), len(lengths), len(bodies))
    if count == 0:
        return

    fields: list[JSONObject] = []
    for index in range(count):
        field_type = types[index] if index < len(types) else 0
        declared_len = lengths[index] if index < len(lengths) else _NTP_EXTENSION_HEADER_LEN
        body = bodies[index] if index < len(bodies) else b""
        fields.append(_extension_fields(field_type & 0xFFFF, declared_len & 0xFFFF, body))
    output["extension_count"] = len(fields)
    output["extension_fields"] = fields


def _normalize_native_mac(layer: JSONObject, output: JSONObject) -> None:
    for raw in _native_bytes_list(layer, *_MAC_ALIASES):
        if len(raw) in _NTP_LEGACY_MAC_LENGTHS:
            output.update(_legacy_mac_fields(raw))
            return


def _short_format_from_native(layer: JSONObject, *names: str) -> int | None:
    for name in names:
        raw = _native_value(layer, name, prefer_value=True)
        value = _parse_wire_int(raw)
        if value is not None:
            return value & 0xFFFFFFFF
        seconds = _parse_decimal_seconds(raw)
        if seconds is not None:
            return int(round(seconds * 65536.0)) & 0xFFFFFFFF
    return None


def _timestamp_from_native(
    layer: JSONObject,
    raw_names: Sequence[str],
    part_names: Sequence[tuple[str, str]],
) -> int | None:
    for name in raw_names:
        raw = _native_value(layer, name, prefer_value=True)
        value = _parse_fixed_width_hex_int(raw, width=8)
        if value is not None:
            return value

    for seconds_name, fraction_name in part_names:
        seconds = _parse_wire_int(_native_value(layer, seconds_name, prefer_value=True))
        fraction = _parse_wire_int(_native_value(layer, fraction_name, prefer_value=True))
        if seconds is not None and fraction is not None:
            return ((seconds & 0xFFFFFFFF) << 32) | (fraction & 0xFFFFFFFF)
    return None


def _native_int_list(layer: JSONObject, *names: str) -> list[int]:
    output: list[int] = []
    for value in _native_list(layer, *names, prefer_value=True):
        parsed = _parse_wire_int(value)
        if parsed is not None:
            output.append(parsed)
    return output


def _native_bytes_list(layer: JSONObject, *names: str) -> list[bytes]:
    output: list[bytes] = []
    for value in _native_list(layer, *names, prefer_value=True):
        raw = _bytes_value(value)
        if raw is not None:
            output.append(raw)
    return output


def _bytes_from_native(layer: JSONObject, *names: str, width: int) -> bytes | None:
    for name in names:
        raw = _bytes_value(_native_value(layer, name, prefer_value=True))
        if raw is not None:
            return raw[:width].ljust(width, b"\x00")
        text = _field(layer, name)
        raw = _bytes_value(text)
        if raw is not None:
            return raw[:width].ljust(width, b"\x00")
    return None


def _native_list(layer: JSONObject, *names: str, prefer_value: bool = False) -> list[object]:
    for name in names:
        value = layer.get(name)
        if value is None:
            continue
        if isinstance(value, list):
            return [_native_scalar(item, prefer_value=prefer_value) for item in value]
        return [_native_scalar(value, prefer_value=prefer_value)]
    return []


def _native_value(layer: JSONObject, name: str, *, prefer_value: bool = False) -> object | None:
    values = _native_list(layer, name, prefer_value=prefer_value)
    return values[0] if values else None


def _native_scalar(value: object, *, prefer_value: bool = False) -> object:
    if isinstance(value, list):
        if not value:
            return None
        return _native_scalar(value[0], prefer_value=prefer_value)
    if isinstance(value, Mapping):
        if prefer_value and value.get("value") is not None:
            return _native_scalar(value["value"], prefer_value=prefer_value)
        if value.get("show") is not None:
            return _native_scalar(value["show"], prefer_value=prefer_value)
        if value.get("value") is not None:
            return _native_scalar(value["value"], prefer_value=prefer_value)
    return value


def _parse_small_int_fields(output: JSONObject, *names: str) -> None:
    for name in names:
        parsed = _parse_numberish(output.get(name))
        if parsed is not None:
            output[name] = _signed_octet_value(parsed & 0xFF)


def _parse_wire_int(value: object) -> int | None:
    if not isinstance(value, str):
        return _parse_int(value)
    candidate = value.strip()
    if not candidate:
        return None
    hex_value = _hex_text(candidate)
    if len(hex_value) >= 4 and len(hex_value) % 2 == 0:
        try:
            return int(hex_value, 16)
        except ValueError:
            return None
    parsed = _parse_int(value)
    if parsed is not None:
        return parsed
    return _parse_numberish(candidate)


def _parse_numberish(value: object) -> int | None:
    parsed = _parse_int(value)
    if parsed is not None:
        return parsed
    if not isinstance(value, str):
        return None
    hex_matches = re.findall(r"0x[0-9a-fA-F]+", value)
    if hex_matches:
        return int(hex_matches[-1], 16)
    matches = re.findall(r"-?\d+", value)
    if not matches:
        return None
    return int(matches[-1], 10)


def _parse_fixed_width_hex_int(value: object, *, width: int) -> int | None:
    if isinstance(value, int):
        return value & ((1 << (width * 8)) - 1)
    if not isinstance(value, str):
        return None
    hex_value = _hex_text(value)
    if len(hex_value) < width * 2:
        return None
    try:
        return int(hex_value[: width * 2], 16)
    except ValueError:
        return None


def _parse_decimal_seconds(value: object) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str):
        return None
    match = re.search(r"-?\d+(?:\.\d+)?", value)
    if match is None:
        return None
    try:
        return float(match.group(0))
    except ValueError:
        return None


def _bytes_value(value: object) -> bytes | None:
    if isinstance(value, bytes):
        return value
    if isinstance(value, Mapping):
        for key in ("hex", "raw_hex", "body_hex", "value"):
            item = value.get(key)
            if isinstance(item, str):
                parsed = _bytes_value(item)
                if parsed is not None:
                    return parsed
    if isinstance(value, str):
        hex_value = _hex_text(value)
        if len(hex_value) >= 2 and len(hex_value) % 2 == 0:
            try:
                return bytes.fromhex(hex_value)
            except ValueError:
                return None
        try:
            return value.encode("ascii")
        except UnicodeEncodeError:
            return None
    return None


def _hex_text(value: str) -> str:
    candidate = value.strip()
    if candidate.startswith(("0x", "0X")):
        candidate = candidate[2:]
    cleaned = "".join(char for char in candidate if char not in ":-_ .")
    if cleaned and all(char in "0123456789abcdefABCDEF" for char in cleaned):
        return cleaned.lower()
    return ""


def _signed_octet_value(value: int) -> int:
    return value - 256 if value >= 128 else value


def _align_4(value: int) -> int:
    return (value + 3) & ~3


register(
    WiresharkProtocol(
        layer="ntp",
        normalize=_normalize_ntp,
        tshark_aliases=dict(_NTP_TSHARK_ALIASES),
    )
)
