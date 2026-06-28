"""Scapy-stage encode and decode helpers for SSDP UDP payloads.

Scapy does not ship a native SSDP layer. The oracle therefore materializes SSDP
as source-backed HTTP-like datagram bytes carried in a Scapy ``Raw`` layer under
UDP, and exposes parser helpers that normalize those bytes into the backend-
neutral SSDP model when a decode path elects to classify a UDP/1900 payload as
SSDP.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ....model import JSONObject, JSONValue
from ..encode_helpers import _layer_fields, _optional_field, _text
from .base import ScapyProtocol, register


_SUPPORTED_FIELDS = frozenset(
    {
        "body",
        "expected_error",
        "fixture",
        "headers",
        "message_kind",
        "method",
        "payload",
        "reason_phrase",
        "request_target",
        "start_line",
        "status_code",
        "version",
    }
)

_SSDP_UDP_PORT = 1900
_SSDP_EVIDENCE_RESPONSE_HEADERS = {
    "BOOTID.UPNP.ORG",
    "CONFIGID.UPNP.ORG",
    "EXT",
    "OPT",
    "SEARCHPORT.UPNP.ORG",
    "SECURELOCATION.UPNP.ORG",
    "ST",
    "USN",
}
_KNOWN_HEADERS: dict[str, tuple[str, str]] = {
    "BOOTID.UPNP.ORG": ("BOOTID.UPNP.ORG", "boot_id"),
    "CACHE-CONTROL": ("CACHE-CONTROL", "cache_control"),
    "CONFIGID.UPNP.ORG": ("CONFIGID.UPNP.ORG", "config_id"),
    "CPFN.UPNP.ORG": ("CPFN.UPNP.ORG", "cpfn"),
    "CPUUID.UPNP.ORG": ("CPUUID.UPNP.ORG", "cpuuid"),
    "DATE": ("DATE", "date"),
    "EXT": ("EXT", "ext"),
    "HOST": ("HOST", "host"),
    "LOCATION": ("LOCATION", "location"),
    "MAN": ("MAN", "man"),
    "MX": ("MX", "mx"),
    "NEXTBOOTID.UPNP.ORG": ("NEXTBOOTID.UPNP.ORG", "next_boot_id"),
    "NT": ("NT", "nt"),
    "NTS": ("NTS", "nts"),
    "OPT": ("OPT", "opt"),
    "SEARCHPORT.UPNP.ORG": ("SEARCHPORT.UPNP.ORG", "search_port"),
    "SECURELOCATION.UPNP.ORG": ("SECURELOCATION.UPNP.ORG", "secure_location"),
    "SERVER": ("SERVER", "server"),
    "ST": ("ST", "st"),
    "TCPPORT.UPNP.ORG": ("TCPPORT.UPNP.ORG", "tcp_port"),
    "USER-AGENT": ("USER-AGENT", "user_agent"),
    "USN": ("USN", "usn"),
}


def _build(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    del plan, stack, index
    return scapy_all.Raw(load=_ssdp_message_bytes(fields))


def _ssdp_message_bytes(fields: Mapping[str, JSONObject]) -> bytes:
    ssdp = _layer_fields(fields, "ssdp")
    raw_payload = _bytes_mapping(_optional_field(ssdp, "payload"))
    if raw_payload is not None:
        return raw_payload

    fixture = ssdp.get("fixture")
    if isinstance(fixture, str):
        return _fixture_bytes(fixture)

    start_line = _start_line(ssdp)
    output = bytearray(start_line.encode("ascii"))
    output.extend(b"\r\n")
    for header in _headers(ssdp.get("headers")):
        output.extend(_header_line(header))
    output.extend(b"\r\n")
    output.extend(_bytes_mapping(_optional_field(ssdp, "body")) or b"")
    return bytes(output)


def _start_line(ssdp: Mapping[str, object]) -> str:
    explicit = ssdp.get("start_line")
    if isinstance(explicit, str):
        return explicit

    message_kind = _text(ssdp.get("message_kind"), "m_search")
    version = _text(ssdp.get("version"), "HTTP/1.1")
    if message_kind in {"response", "unknown_response_preserved"}:
        status_code = _text(ssdp.get("status_code"), "200")
        reason_phrase = _text(ssdp.get("reason_phrase"), "OK")
        return f"{version} {status_code} {reason_phrase}"

    default_method = "NOTIFY" if message_kind == "notify" else "M-SEARCH"
    method = _text(ssdp.get("method"), default_method)
    request_target = _text(ssdp.get("request_target"), "*")
    return f"{method} {request_target} {version}"


def _headers(value: object) -> list[Mapping[str, object]]:
    if value is None:
        return []
    if not isinstance(value, Sequence) or isinstance(value, (bytes, bytearray, str)):
        raise ValueError("SSDP headers materialization requires a header list")
    headers: list[Mapping[str, object]] = []
    for header in value:
        if not isinstance(header, Mapping):
            raise ValueError(f"SSDP header must be an object, got {header!r}")
        if not isinstance(header.get("name"), str):
            raise ValueError(f"SSDP header requires string name, got {header!r}")
        headers.append(header)
    return headers


def _header_line(header: Mapping[str, object]) -> bytes:
    name = _text(header.get("name"), "")
    wire_value = header.get("wire_value")
    if isinstance(wire_value, str):
        value = wire_value
        separator = ":"
    else:
        value = _text(header.get("value"), "")
        separator = ":" if value == "" else ": "
    return f"{name}{separator}{value}\r\n".encode("ascii")


def _bytes_mapping(value: object) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    if not isinstance(value, Mapping):
        raise ValueError(f"SSDP byte field must be bytes, str, or object, got {value!r}")
    hex_value = value.get("hex")
    if isinstance(hex_value, str):
        return bytes.fromhex(hex_value)
    utf8_value = value.get("utf8")
    if isinstance(utf8_value, str):
        return utf8_value.encode("utf-8")
    raw_value = value.get("value")
    encoding = value.get("encoding")
    if isinstance(raw_value, str):
        if encoding == "hex":
            return bytes.fromhex(raw_value)
        if encoding in {None, "utf8"}:
            return raw_value.encode("utf-8")
    raise ValueError(f"SSDP byte field object requires hex or utf8 bytes, got {value!r}")


def _fixture_bytes(path_text: str) -> bytes:
    path = Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("SSDP fixture path must be project-relative")
    return path.read_bytes()


def canonicalize_ssdp_payload(
    packet: Any,
    layers: list[str],
    fields: dict[str, JSONObject],
) -> None:
    """Rename a Raw UDP/1900 payload to ``ssdp`` when SSDP shape gates accept it."""

    udp = _scapy_layer(packet, "UDP")
    if udp is None:
        return
    sport = _int_value(getattr(udp, "sport", 0))
    dport = _int_value(getattr(udp, "dport", 0))
    if sport != _SSDP_UDP_PORT and dport != _SSDP_UDP_PORT:
        return

    payload_index = _payload_index_after_udp(layers)
    if payload_index is None:
        return
    raw = _raw_payload_from_packet(packet)
    if raw is None:
        payload_key = _layer_key_at(layers, payload_index)
        raw = _raw_payload_from_fields(fields.get(payload_key, {}))
    if raw is None:
        return

    normalized = ssdp_fields_from_bytes(raw)
    if normalized is None or not _passes_port_shape_gate(normalized):
        return

    payload_key = _layer_key_at(layers, payload_index)
    fields.pop(payload_key, None)
    layers[payload_index] = "ssdp"
    ssdp_key = _layer_key_at(layers, payload_index)
    fields[ssdp_key] = normalized


def ssdp_fields_from_bytes(raw: bytes) -> JSONObject | None:
    delimiter = b"\r\n\r\n"
    header_end = raw.find(delimiter)
    if header_end < 0 or b"\n" in raw[:header_end].replace(b"\r\n", b""):
        return None

    head = raw[:header_end]
    body = raw[header_end + len(delimiter) :]
    lines = head.split(b"\r\n")
    if not lines:
        return None
    try:
        start_line = lines[0].decode("ascii")
    except UnicodeDecodeError:
        return None

    fields = _start_line_fields(start_line)
    if fields is None:
        return None

    header_entries: list[JSONObject] = []
    seen: defaultdict[str, int] = defaultdict(int)
    for order, line in enumerate(lines[1:]):
        parsed = _header_fields(line, order, seen)
        if parsed is None:
            return None
        header_entries.append(parsed)

    fields["headers"] = header_entries
    fields["body"] = {"hex": body.hex()}
    fields["body_length"] = len(body)
    return fields


def _start_line_fields(start_line: str) -> JSONObject | None:
    if start_line.startswith("HTTP/"):
        parts = start_line.split(" ", 2)
        if len(parts) != 3 or len(parts[1]) != 3 or not parts[1].isdigit():
            return None
        return {
            "message_kind": "response",
            "start_line": start_line,
            "version": parts[0],
            "status_code": int(parts[1]),
            "reason_phrase": parts[2],
            "status_code_status": "source_backed" if parts[1] == "200" else "unknown_preserved",
        }

    parts = start_line.split(" ", 2)
    if len(parts) != 3:
        return None
    method, request_target, version = parts
    if not method or not request_target or not version.startswith("HTTP/"):
        return None
    if method == "M-SEARCH":
        message_kind = "m_search"
        method_status = "source_backed"
    elif method == "NOTIFY":
        message_kind = "notify"
        method_status = "source_backed"
    else:
        message_kind = "unknown_request_preserved"
        method_status = "unknown_preserved"
    return {
        "message_kind": message_kind,
        "start_line": start_line,
        "method": method,
        "method_status": method_status,
        "request_target": request_target,
        "version": version,
    }


def _header_fields(
    line: bytes,
    order: int,
    seen: defaultdict[str, int],
) -> JSONObject | None:
    if b":" not in line:
        return None
    raw_name, raw_value = line.split(b":", 1)
    try:
        name = raw_name.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not name or not _valid_header_name(name):
        return None

    original_value = raw_value.decode("utf-8", "surrogateescape")
    value = original_value.strip(" \t")
    canonical, kind, namespace = _header_identity(name)
    duplicate_key = canonical or name.lower()
    duplicate_index = seen[duplicate_key]
    seen[duplicate_key] += 1

    header: JSONObject = {
        "name": name,
        "original_name": name,
        "value": value,
        "wire_value": original_value,
        "order": order,
        "duplicate_index": duplicate_index,
        "name_kind": kind,
        "header_name_status": "source_backed" if canonical is not None else "unknown_preserved",
    }
    if canonical is not None:
        header["canonical_name"] = canonical
    if namespace is not None:
        header["nls_namespace"] = namespace
    return header


def _header_identity(name: str) -> tuple[str | None, str, str | None]:
    upper = name.upper()
    known = _KNOWN_HEADERS.get(upper)
    if known is not None:
        return known[0], known[1], None
    if len(name) > 4 and upper.endswith("-NLS"):
        namespace = name[:-4]
        if namespace:
            return "NLS", "nls_prefixed", namespace
    return None, "unknown", None


def _valid_header_name(name: str) -> bool:
    separators = set('()<>@,;:\\"/[]?={} \t')
    return all(33 <= ord(char) <= 126 and char not in separators for char in name)


def _passes_port_shape_gate(fields: Mapping[str, JSONValue]) -> bool:
    kind = fields.get("message_kind")
    if kind in {"m_search", "notify"}:
        return fields.get("request_target") == "*" and fields.get("version") == "HTTP/1.1"
    if kind == "response" and fields.get("status_code") == 200:
        return _has_response_evidence(fields.get("headers"))
    return False


def _has_response_evidence(value: object) -> bool:
    if not isinstance(value, Sequence) or isinstance(value, (bytes, bytearray, str)):
        return False
    for item in value:
        if not isinstance(item, Mapping):
            continue
        canonical = item.get("canonical_name")
        if isinstance(canonical, str) and canonical in _SSDP_EVIDENCE_RESPONSE_HEADERS:
            return True
    return False


def _normalize(fields: JSONObject) -> JSONObject:
    raw = _raw_payload_from_fields(fields)
    if raw is None:
        return dict(fields)
    normalized = ssdp_fields_from_bytes(raw)
    if normalized is not None:
        return normalized
    return {"payload": {"hex": raw.hex()}, "payload_length": len(raw)}


def _payload_index_after_udp(layers: Sequence[str]) -> int | None:
    try:
        udp_index = list(layers).index("udp")
    except ValueError:
        return None
    for index in range(udp_index + 1, len(layers)):
        if layers[index] in {"payload", "raw"}:
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
    if isinstance(load, str):
        return load.encode("utf-8")
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
    count = sum(1 for item in layers[: index + 1] if item == layer_name)
    return layer_name if count == 1 else f"{layer_name}#{count}"


def _int_value(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    return 0


register(
    ScapyProtocol(
        layer="ssdp",
        scapy_class="Raw",
        supported_fields=_SUPPORTED_FIELDS,
        build=_build,
        normalize=_normalize,
    )
)
