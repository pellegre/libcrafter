"""Scapy-stage encode plugin for the SNMP layer.

Scapy 2.7 has native SNMPv1/v2c classes, but no stable SNMPv3 materializer. The
oracle therefore uses deterministic BER bytes for every generated SNMP case and
wraps them in a Scapy ``Raw`` layer under UDP. That keeps the Scapy backend useful
as an IP/UDP packet writer while avoiding a split implementation where v3 and
unknown-preservation cases use different encoders.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from typing import Any

from ....model import JSONObject, JSONValue
from ..encode_helpers import _int, _layer_fields, _optional_field, _text
from .base import ScapyProtocol, register


_SUPPORTED_FIELDS = frozenset(
    {
        "agent_address",
        "community",
        "context_engine_id",
        "context_name",
        "encrypted_scoped_pdu",
        "enterprise_oid",
        "error_index",
        "error_status",
        "generic_trap",
        "max_repetitions",
        "message_length",
        "msg_flags",
        "msg_id",
        "msg_max_size",
        "msg_security_model",
        "msg_security_parameters",
        "non_repeaters",
        "pdu_length",
        "pdu_tag",
        "raw_pdu",
        "request_id",
        "scoped_data_kind",
        "specific_trap",
        "timestamp",
        "varbinds",
        "version",
    }
)

_VERSION_CODES = {"v1": 0, "v2c": 1, "v3": 3}
_PDU_TAGS = {
    "get_request": 0xA0,
    "get_next_request": 0xA1,
    "response": 0xA2,
    "set_request": 0xA3,
    "trap_v1": 0xA4,
    "get_bulk_request": 0xA5,
    "inform_request": 0xA6,
    "snmpv2_trap": 0xA7,
    "report": 0xA8,
}
_ERROR_STATUS = {
    "no_error": 0,
    "too_big": 1,
    "no_such_name": 2,
    "bad_value": 3,
    "read_only": 4,
    "gen_err": 5,
}
_GENERIC_TRAPS = {
    "cold_start": 0,
    "warm_start": 1,
    "link_down": 2,
    "link_up": 3,
    "authentication_failure": 4,
    "egp_neighbor_loss": 5,
    "enterprise_specific": 6,
}
_SECURITY_MODELS = {
    "snmpv1": 1,
    "snmpv2c": 2,
    "usm": 3,
    "tsm": 4,
}


def _build(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    return scapy_all.Raw(load=_snmp_message_bytes(fields))


def _snmp_message_bytes(fields: Mapping[str, JSONObject]) -> bytes:
    snmp = _layer_fields(fields, "snmp")
    if _is_malformed(snmp):
        raise ValueError("SNMP structured-error cases are not Scapy strict-byte materialized")
    version = _version_code(_optional_field(snmp, "version"))
    if version == 3:
        body = b"".join(
            (
                _ber_integer(version),
                _v3_header_data(snmp),
                _ber_octet_string(_security_parameters_bytes(snmp)),
                _v3_scoped_data(snmp),
            )
        )
    else:
        body = b"".join(
            (
                _ber_integer(version),
                _ber_octet_string(_bytes_value(_optional_field(snmp, "community"), b"doc-community")),
                _snmp_pdu_bytes(snmp),
            )
        )
    return _ber_sequence(body)


def _is_malformed(snmp: Mapping[str, object]) -> bool:
    for name in ("message_length", "pdu_length", "msg_id", "scoped_data_kind"):
        value = snmp.get(name)
        if isinstance(value, Mapping) and "malformed" in value:
            return True
    varbinds = snmp.get("varbinds")
    if isinstance(varbinds, Sequence) and not isinstance(varbinds, (str, bytes, bytearray)):
        return any(isinstance(item, Mapping) and "malformed" in item for item in varbinds)
    security = snmp.get("msg_security_parameters")
    return isinstance(security, Mapping) and security.get("kind") == "malformed_usm"


def _version_code(value: object) -> int:
    if isinstance(value, Mapping):
        return _int(value.get("raw"), 1)
    if isinstance(value, str):
        if value in _VERSION_CODES:
            return _VERSION_CODES[value]
        return _int(value, 1)
    return _int(value, 1)


def _snmp_pdu_bytes(snmp: Mapping[str, object]) -> bytes:
    raw_pdu = snmp.get("raw_pdu")
    if isinstance(raw_pdu, Mapping) and isinstance(raw_pdu.get("hex"), str):
        return bytes.fromhex(str(raw_pdu["hex"]))

    pdu_tag = snmp.get("pdu_tag", "get_request")
    tag = _pdu_tag_value(pdu_tag)
    if tag == _PDU_TAGS["trap_v1"]:
        return _v1_trap_pdu(snmp, tag)

    varbinds = _varbind_list_bytes(snmp.get("varbinds"))
    if tag == _PDU_TAGS["get_bulk_request"]:
        content = b"".join(
            (
                _ber_integer(_int_value(snmp.get("request_id"), 0)),
                _ber_integer(_int_value(snmp.get("non_repeaters"), 0)),
                _ber_integer(_int_value(snmp.get("max_repetitions"), 0)),
                varbinds,
            )
        )
    else:
        content = b"".join(
            (
                _ber_integer(_int_value(snmp.get("request_id"), 0)),
                _ber_integer(_error_status(snmp.get("error_status"))),
                _ber_integer(_int_value(snmp.get("error_index"), 0)),
                varbinds,
            )
        )
    return _ber_tlv(tag, content)


def _pdu_tag_value(value: object) -> int:
    if isinstance(value, Mapping):
        return _int(value.get("raw"), _PDU_TAGS["get_request"])
    if isinstance(value, str):
        if value in _PDU_TAGS:
            return _PDU_TAGS[value]
        return _int(value, _PDU_TAGS["get_request"])
    return _int(value, _PDU_TAGS["get_request"])


def _error_status(value: object) -> int:
    if isinstance(value, Mapping):
        return _int(value.get("raw"), 0)
    if isinstance(value, str):
        if value in _ERROR_STATUS:
            return _ERROR_STATUS[value]
        return _int(value, 0)
    return _int(value, 0)


def _v1_trap_pdu(snmp: Mapping[str, object], tag: int) -> bytes:
    content = b"".join(
        (
            _ber_oid(_text(snmp.get("enterprise_oid"), "1.3.6.1.2.1.1.2.0")),
            _ber_tlv(0x40, ipaddress.IPv4Address(_text(snmp.get("agent_address"), "192.0.2.10")).packed),
            _ber_integer(_generic_trap(snmp.get("generic_trap"))),
            _ber_integer(_int_value(snmp.get("specific_trap"), 0)),
            _ber_tlv(0x43, _unsigned_integer_content(_int_value(snmp.get("timestamp"), 0))),
            _varbind_list_bytes(snmp.get("varbinds")),
        )
    )
    return _ber_tlv(tag, content)


def _generic_trap(value: object) -> int:
    if isinstance(value, Mapping):
        return _int(value.get("raw"), 0)
    if isinstance(value, str):
        if value in _GENERIC_TRAPS:
            return _GENERIC_TRAPS[value]
        return _int(value, 0)
    return _int(value, 0)


def _varbind_list_bytes(value: object) -> bytes:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return _ber_sequence(b"")
    return _ber_sequence(b"".join(_varbind_bytes(item) for item in value))


def _varbind_bytes(value: object) -> bytes:
    if not isinstance(value, Mapping):
        raise ValueError(f"SNMP varbind must be an object, got {value!r}")
    name = _text(value.get("name"), "1.3.6.1.2.1.1.1.0")
    raw_value = value.get("value")
    if not isinstance(raw_value, Mapping):
        raw_value = {"type": "null"}
    return _ber_sequence(_ber_oid(name) + _varbind_value_bytes(raw_value))


def _varbind_value_bytes(value: Mapping[str, object]) -> bytes:
    kind = _text(value.get("type"), "null")
    if kind == "raw":
        raw = value.get("tlv_hex")
        if not isinstance(raw, str):
            raise ValueError("SNMP raw varbind value requires tlv_hex")
        return bytes.fromhex(raw)
    if kind == "null":
        return _ber_tlv(0x05, b"")
    if kind == "integer":
        return _ber_integer(_int_value(value.get("value"), 0))
    if kind == "octet_string":
        return _ber_octet_string(_bytes_value(value, b""))
    if kind == "object_identifier":
        return _ber_oid(_text(value.get("value"), "1.3.6.1.2.1.1.2.0"))
    if kind == "ip_address":
        return _ber_tlv(0x40, ipaddress.IPv4Address(_text(value.get("value"), "192.0.2.10")).packed)
    if kind == "counter32":
        return _ber_tlv(0x41, _unsigned_integer_content(_int_value(value.get("value"), 0)))
    if kind in {"gauge32", "unsigned32"}:
        return _ber_tlv(0x42, _unsigned_integer_content(_int_value(value.get("value"), 0)))
    if kind == "time_ticks":
        return _ber_tlv(0x43, _unsigned_integer_content(_int_value(value.get("value"), 0)))
    if kind == "opaque":
        return _ber_tlv(0x44, _bytes_value(value, b""))
    if kind == "counter64":
        return _ber_tlv(0x46, _unsigned_integer_content(_int_value(value.get("value"), 0)))
    if kind == "no_such_object":
        return _ber_tlv(0x80, b"")
    if kind == "no_such_instance":
        return _ber_tlv(0x81, b"")
    if kind == "end_of_mib_view":
        return _ber_tlv(0x82, b"")
    raise ValueError(f"unsupported SNMP varbind value type: {kind}")


def _v3_header_data(snmp: Mapping[str, object]) -> bytes:
    flags = _msg_flags(snmp.get("msg_flags"))
    content = b"".join(
        (
            _ber_integer(_int_value(snmp.get("msg_id"), 1000)),
            _ber_integer(_int_value(snmp.get("msg_max_size"), 65507)),
            _ber_octet_string(bytes([flags])),
            _ber_integer(_security_model(snmp.get("msg_security_model"))),
        )
    )
    return _ber_sequence(content)


def _msg_flags(value: object) -> int:
    if isinstance(value, Mapping):
        return _int(value.get("raw"), 0)
    flags = value if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)) else [value]
    result = 0
    for flag in flags:
        if flag == "auth":
            result |= 0x01
        elif flag == "privacy":
            result |= 0x02
        elif flag == "reportable":
            result |= 0x04
    return result


def _security_model(value: object) -> int:
    if isinstance(value, Mapping):
        return _int(value.get("raw"), 3)
    if isinstance(value, str):
        if value in _SECURITY_MODELS:
            return _SECURITY_MODELS[value]
        return _int(value, 3)
    return _int(value, 3)


def _security_parameters_bytes(snmp: Mapping[str, object]) -> bytes:
    value = snmp.get("msg_security_parameters")
    if isinstance(value, Mapping) and value.get("kind") == "usm":
        return _usm_parameters_bytes(value)
    return _bytes_value(value, b"")


def _usm_parameters_bytes(value: Mapping[str, object]) -> bytes:
    content = b"".join(
        (
            _ber_octet_string(_bytes_value(value.get("engine_id"), b"doc-engine")),
            _ber_integer(_int_value(value.get("engine_boots"), 0)),
            _ber_integer(_int_value(value.get("engine_time"), 0)),
            _ber_octet_string(_bytes_value(value.get("user_name"), b"doc-user")),
            _ber_octet_string(_bytes_value(value.get("authentication_parameters"), b"")),
            _ber_octet_string(_bytes_value(value.get("privacy_parameters"), b"")),
        )
    )
    return _ber_sequence(content)


def _v3_scoped_data(snmp: Mapping[str, object]) -> bytes:
    if snmp.get("scoped_data_kind") == "encrypted_opaque":
        return _ber_octet_string(_bytes_value(snmp.get("encrypted_scoped_pdu"), b""))
    content = b"".join(
        (
            _ber_octet_string(_bytes_value(snmp.get("context_engine_id"), b"")),
            _ber_octet_string(_bytes_value(snmp.get("context_name"), b"")),
            _snmp_pdu_bytes(snmp),
        )
    )
    return _ber_sequence(content)


def _ber_sequence(content: bytes) -> bytes:
    return _ber_tlv(0x30, content)


def _ber_integer(value: int) -> bytes:
    return _ber_tlv(0x02, _unsigned_integer_content(value))


def _ber_octet_string(value: bytes) -> bytes:
    return _ber_tlv(0x04, value)


def _ber_oid(value: str) -> bytes:
    arcs = [int(part) for part in value.strip(".").split(".") if part]
    if len(arcs) < 2:
        raise ValueError(f"SNMP OID requires at least two arcs: {value!r}")
    first = (40 * arcs[0]) + arcs[1]
    content = bytes([first]) + b"".join(_base128_arc(arc) for arc in arcs[2:])
    return _ber_tlv(0x06, content)


def _base128_arc(value: int) -> bytes:
    if value < 0:
        raise ValueError(f"SNMP OID arc must be non-negative: {value}")
    chunks = [value & 0x7F]
    value >>= 7
    while value:
        chunks.append(0x80 | (value & 0x7F))
        value >>= 7
    return bytes(reversed(chunks))


def _ber_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _ber_length(len(content)) + content


def _ber_length(length: int) -> bytes:
    if length < 0:
        raise ValueError(f"BER length cannot be negative: {length}")
    if length < 0x80:
        return bytes([length])
    width = max(1, (length.bit_length() + 7) // 8)
    return bytes([0x80 | width]) + length.to_bytes(width, "big")


def _unsigned_integer_content(value: int) -> bytes:
    if value < 0:
        raise ValueError(f"SNMP integer materializer only supports non-negative values: {value}")
    if value == 0:
        return b"\x00"
    width = max(1, (value.bit_length() + 7) // 8)
    content = value.to_bytes(width, "big")
    if content[0] & 0x80:
        content = b"\x00" + content
    return content


def _int_value(value: object, default: int) -> int:
    if isinstance(value, Mapping):
        return _int(value.get("raw", value.get("value")), default)
    return _int(value, default)


def _bytes_value(value: object, default: bytes) -> bytes:
    if value is None:
        return default
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, Mapping):
        hex_value = value.get("hex")
        if isinstance(hex_value, str):
            return bytes.fromhex(hex_value)
        if "value" in value:
            return _bytes_value(value.get("value"), default)
    raise ValueError(f"expected SNMP bytes-compatible value, got {value!r}")


def _normalize(fields: JSONObject) -> JSONObject:
    output: JSONObject = {}
    version = fields.get("version")
    if version is not None:
        output["version"] = _json_scalar(version)
    community = fields.get("community")
    if community is not None:
        output["community"] = _json_scalar(community)
    pdu = fields.get("PDU")
    if isinstance(pdu, Mapping):
        output["pdu"] = dict(pdu)  # type: ignore[arg-type]
    return output


def _json_scalar(value: JSONValue) -> JSONValue:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return value


register(
    ScapyProtocol(
        layer="snmp",
        scapy_class="Raw",
        supported_fields=_SUPPORTED_FIELDS,
        build=_build,
        normalize=_normalize,
        layer_aliases=(("SNMP", "snmp"),),
    )
)
