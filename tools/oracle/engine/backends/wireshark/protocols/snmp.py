"""Wireshark-stage decode plugin for the SNMP layer.

Wireshark/tshark is parser-only in the oracle. This normalizer consumes the
stable top-level SNMP dissector fields when tshark emits an ``snmp`` layer and
maps them onto the oracle's SNMP names. It stays intentionally conservative:
credential-like bytes are left as synthetic test values from the packet plan, and
unknown or backend-specific nested fields remain in the native metadata.
"""

from __future__ import annotations

from ....model import JSONObject
from ..decode_helpers import (
    _field_list,
    _fields_from_aliases,
    _layer,
    _parse_int,
    _parse_int_fields,
)
from .base import WiresharkProtocol, register


_SNMP_TSHARK_ALIASES: JSONObject = {
    "version": ("snmp.version",),
    "community": ("snmp.community", "snmp.community_string"),
    "pdu_tag": ("snmp.pdu_type", "snmp.pdu.type", "snmp.data"),
    "request_id": ("snmp.request_id", "snmp.reqid"),
    "error_status": ("snmp.error_status",),
    "error_index": ("snmp.error_index",),
    "non_repeaters": ("snmp.non_repeaters",),
    "max_repetitions": ("snmp.max_repetitions",),
    "generic_trap": ("snmp.generic_trap",),
    "specific_trap": ("snmp.specific_trap",),
    "timestamp": ("snmp.timestamp", "snmp.time_stamp"),
    "msg_id": ("snmp.msgID", "snmp.msg_id"),
    "msg_max_size": ("snmp.msgMaxSize", "snmp.msg_max_size"),
    "msg_flags": ("snmp.msgFlags", "snmp.msg_flags"),
    "msg_security_model": ("snmp.msgSecurityModel", "snmp.msg_security_model"),
    "context_engine_id": ("snmp.contextEngineID", "snmp.context_engine_id"),
    "context_name": ("snmp.contextName", "snmp.context_name"),
}

_PDU_TAGS = {
    0: "get_request",
    1: "get_next_request",
    2: "response",
    3: "set_request",
    4: "trap_v1",
    5: "get_bulk_request",
    6: "inform_request",
    7: "snmpv2_trap",
    8: "report",
    0xA0: "get_request",
    0xA1: "get_next_request",
    0xA2: "response",
    0xA3: "set_request",
    0xA4: "trap_v1",
    0xA5: "get_bulk_request",
    0xA6: "inform_request",
    0xA7: "snmpv2_trap",
    0xA8: "report",
}
_VERSION_LABELS = {0: "v1", 1: "v2c", 3: "v3"}


def _normalize_snmp(layers: JSONObject, *, source_hex: str | None = None) -> JSONObject:
    layer = _layer(layers, "snmp")
    output = _fields_from_aliases(layer, dict(_SNMP_TSHARK_ALIASES))
    _parse_int_fields(
        output,
        "version",
        "request_id",
        "error_status",
        "error_index",
        "non_repeaters",
        "max_repetitions",
        "generic_trap",
        "specific_trap",
        "timestamp",
        "msg_id",
        "msg_max_size",
        "msg_flags",
        "msg_security_model",
    )
    _normalize_version(output)
    _normalize_pdu_tag(output)
    _normalize_varbinds(layer, output)
    return output


def _normalize_version(output: JSONObject) -> None:
    value = output.get("version")
    if isinstance(value, int) and value in _VERSION_LABELS:
        output["version"] = _VERSION_LABELS[value]


def _normalize_pdu_tag(output: JSONObject) -> None:
    value = output.get("pdu_tag")
    parsed = _parse_int(value)
    if parsed is None:
        return
    output["pdu_tag"] = _PDU_TAGS.get(parsed, {"raw": parsed})


def _normalize_varbinds(layer: JSONObject, output: JSONObject) -> None:
    names = [
        str(item)
        for item in _field_list(
            layer,
            "snmp.name",
            "snmp.oid",
            "snmp.varbind.oid",
            "snmp.variable_oid",
        )
    ]
    if names:
        output["varbinds"] = [{"name": name} for name in names]


register(
    WiresharkProtocol(
        layer="snmp",
        normalize=_normalize_snmp,
        tshark_aliases=dict(_SNMP_TSHARK_ALIASES),
    )
)
