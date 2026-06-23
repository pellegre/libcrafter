"""Scapy-stage encode plugin for the IGMP layer.

Moves the ``_igmp`` builder, its body/header/flag helpers, the
``_igmp_query_bytes`` / ``_igmp_report_bytes`` / ``_igmp_extension_layer_bytes``
sub-layer bytes builders, and the IGMP maps (``_IGMP_TYPE_CODES``,
``_IGMP_RECORD_TYPES``, ``_IGMP_QUERY_FLAG_BITS``, ``_IGMP_REPORT_FLAG_BITS``,
``_IGMP_EXTENSION_TYPES``, ``_IGMP_BODY_STACK_LAYERS``) verbatim out of
:mod:`..packets` and registers the ``igmp`` layer through the
:class:`~.base.ScapyProtocol` contract; only the dispatch moves out of the legacy
``_build_layer`` if/elif. Behavior must stay byte-identical.

Scapy's IGMP contrib classes are not exposed through ``scapy.all`` consistently, so
IGMP is materialized as exact bytes wrapped in a Scapy ``Raw`` layer while
preserving IPv4 protocol number 2. The plugin therefore registers with
``scapy_class="Raw"`` (the former ``packets._SCAPY_LAYER_BY_LAYER["igmp"]`` value,
which feeds the ``scapy_stack`` encode metadata) and its ``build`` returns
``scapy_all.Raw(load=...)``, exactly as the legacy ``_igmp`` did.

``igmp_query`` / ``igmp_report`` / ``igmp_extension`` are IGMP *sub-layers*
(``igmp.yaml`` children), not top-level spec layers, so registering them under their
own names would trip the strict plugin-coverage guard. They keep their legacy
per-layer ``_build_layer`` dispatch (a ``Raw`` wrapping the co-located bytes
builder) and their ``_SCAPY_LAYER_BY_LAYER`` / ``_SUPPORTED_FIELDS_BY_LAYER``
entries in :mod:`..packets`; the bytes builders are co-located here and re-imported
into :mod:`..packets`, the same co-locate-and-re-import pattern used for the IPv6
extension-header builders.

IGMP decode is the whole-packet ``_canonicalize_igmp`` pass that rebuilds Scapy's
opaque IPv4 protocol-2 payload as IGMP layers; like ``_canonicalize_icmpv4`` /
``_canonicalize_rip`` it is a whole-packet post-pass rather than a per-layer
normalize, so it stays in :mod:`..normalize` (the established pattern), and this
plugin carries no ``normalize`` callback. Wireshark exposes no IGMP normalize logic,
so there is no Wireshark IGMP plugin.

Shared primitives come from the helper modules so this plugin does not depend on the
``packets`` orchestrator (which would create a circular import). Relative imports
only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ....model import JSONObject
from ..encode_helpers import (
    _bool_int,
    _bytes_field,
    _int,
    _internet_checksum,
    _ipv4_address_bytes,
    _layer_fields,
    _layer_fields_for_stack_index,
    _optional_field,
    _payload_bytes,
)
from .base import ScapyProtocol, register


# Encode-side field allowlist for ``_validate_layer_fields`` — the canonical IGMP
# field names plus every oracle alias the builder accepts. Mirrors the former
# ``packets._SUPPORTED_FIELDS_BY_LAYER["igmp"]`` entry exactly.
_SUPPORTED_FIELDS = frozenset(
    {
        "checksum",
        "chksum",
        "code",
        "extensions",
        "extension_tlvs",
        "group",
        "group_address",
        "group_records",
        "gaddr",
        "max_response_code",
        "max_response_time_tenths",
        "mrd_advertisement_interval",
        "mrd_query_interval",
        "mrd_reserved",
        "mrd_robustness_variable",
        "number_of_group_records",
        "number_of_records",
        "number_of_sources",
        "payload",
        "qqic",
        "query_flags",
        "raw",
        "raw_body",
        "raw_flags_qrv",
        "raw_tail",
        "report_flags",
        "reserved_flags",
        "source_addresses",
        "tail",
        "type",
        "type_code",
        "v2_max_response_time_tenths",
    }
)


_IGMP_TYPE_CODES: dict[str, int] = {
    "reserved": 0x00,
    "unassigned": 0x09,
    "membership-query": 0x11,
    "membership_query": 0x11,
    "v1-membership-report": 0x12,
    "v1_membership_report": 0x12,
    "dvmrp": 0x13,
    "dvmrp-unsupported-assigned": 0x13,
    "dvmrp_unsupported_assigned": 0x13,
    "pim-v1": 0x14,
    "pim_v1": 0x14,
    "pim-v1-unsupported-assigned": 0x14,
    "pim_v1_unsupported_assigned": 0x14,
    "cisco-trace-unsupported-assigned": 0x15,
    "cisco_trace_unsupported_assigned": 0x15,
    "v2-membership-report": 0x16,
    "v2_membership_report": 0x16,
    "v2-leave-group": 0x17,
    "v2_leave_group": 0x17,
    "multicast-traceroute-response-unsupported-assigned": 0x1E,
    "multicast_traceroute_response_unsupported_assigned": 0x1E,
    "multicast-traceroute-unsupported-assigned": 0x1F,
    "multicast_traceroute_unsupported_assigned": 0x1F,
    "v3-membership-report": 0x22,
    "v3_membership_report": 0x22,
    "multicast-router-advertisement": 0x30,
    "multicast_router_advertisement": 0x30,
    "multicast-router-solicitation": 0x31,
    "multicast_router_solicitation": 0x31,
    "multicast-router-termination": 0x32,
    "multicast_router_termination": 0x32,
    "experimental": 0xF0,
}
_IGMP_RECORD_TYPES: dict[str, int] = {
    "reserved": 0,
    "mode-is-include": 1,
    "mode_is_include": 1,
    "mode-is-exclude": 2,
    "mode_is_exclude": 2,
    "change-to-include-mode": 3,
    "change_to_include_mode": 3,
    "change-to-exclude-mode": 4,
    "change_to_exclude_mode": 4,
    "allow-new-sources": 5,
    "allow_new_sources": 5,
    "block-old-sources": 6,
    "block_old_sources": 6,
    "unknown": 0xC8,
}
_IGMP_QUERY_FLAG_BITS: dict[str, int] = {
    "zero": 0,
    "none": 0,
    "extension": 0x80,
    "unassigned": 0x70,
    "suppress-router-side-processing": 0x08,
    "suppress_router_side_processing": 0x08,
    "qrv": 0x02,
}
_IGMP_REPORT_FLAG_BITS: dict[str, int] = {
    "zero": 0,
    "none": 0,
    "extension": 0x8000,
    "unassigned": 0x0001,
}
_IGMP_EXTENSION_TYPES: dict[str, int] = {
    "noop": 0,
    "no-op": 0,
    "unassigned": 1,
    "experimental": 0xFFFE,
}
_IGMP_MRD_SHORT_TYPES = frozenset({0x31, 0x32})
_IGMP_BODY_STACK_LAYERS = frozenset(
    {"igmp_query", "igmp_report", "igmp_extension", "payload"}
)


def _build_igmp(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    return _igmp(fields, list(stack), index, scapy_all)


def _igmp(
    fields: Mapping[str, JSONObject],
    stack: list[str],
    index: int,
    scapy_all: Any,
) -> Any:
    igmp_fields = _layer_fields(fields, "igmp")
    body_is_in_following_layers = any(
        layer in _IGMP_BODY_STACK_LAYERS for layer in stack[index + 1 :]
    )
    body = (
        _igmp_following_body_bytes(fields, stack, index)
        if body_is_in_following_layers
        else _igmp_inferred_body_bytes(fields)
    )
    header = _igmp_header_bytes(igmp_fields, body)
    return scapy_all.Raw(load=header if body_is_in_following_layers else header + body)


def _igmp_header_bytes(igmp_fields: Mapping[str, object], body: bytes) -> bytes:
    type_code = _igmp_type(
        _optional_field(igmp_fields, "type", "type_code"),
        default=0x11,
    )
    code = _igmp_code(igmp_fields, type_code)
    header = bytearray([type_code & 0xFF, code & 0xFF, 0, 0])
    if _igmp_base_header_len(igmp_fields, type_code) == 8:
        header.extend(_igmp_group_address_bytes(igmp_fields, type_code))

    checksum = _igmp_checksum(igmp_fields)
    if checksum is None:
        checksum = _internet_checksum(bytes(header) + body)
    header[2:4] = (checksum & 0xFFFF).to_bytes(2, "big")
    return bytes(header)


def _igmp_base_header_len(igmp_fields: Mapping[str, object], type_code: int) -> int:
    if type_code not in _IGMP_MRD_SHORT_TYPES:
        return 8
    if any(name in igmp_fields for name in ("group_address", "group", "gaddr")):
        return 8
    if any(name in igmp_fields for name in ("mrd_query_interval", "mrd_robustness_variable")):
        return 8
    return 4


def _igmp_inferred_body_bytes(fields: Mapping[str, JSONObject]) -> bytes:
    igmp_fields = _layer_fields(fields, "igmp")
    type_code = _igmp_type(_optional_field(igmp_fields, "type", "type_code"), default=0x11)

    raw_body = _optional_field(igmp_fields, "raw_body", "raw")
    if raw_body is not None:
        return _bytes_field(raw_body)

    body = b""
    if _igmp_has_query_body(fields, igmp_fields, type_code):
        body += _igmp_query_bytes(fields)
    elif _igmp_has_report_body(fields, igmp_fields, type_code):
        body += _igmp_report_bytes(fields)

    body += _igmp_extensions_bytes(fields)
    body += _igmp_raw_tail_bytes(igmp_fields)
    return body


def _igmp_following_body_bytes(
    fields: Mapping[str, JSONObject],
    stack: Sequence[str],
    index: int,
) -> bytes:
    body = b""
    for child_index in range(index + 1, len(stack)):
        layer = stack[child_index]
        if layer == "igmp_query":
            body += _igmp_query_bytes(fields)
        elif layer == "igmp_report":
            body += _igmp_report_bytes(fields)
        elif layer == "igmp_extension":
            body += _igmp_extension_layer_bytes(
                _layer_fields_for_stack_index(fields, stack, child_index)
            )
        elif layer == "payload":
            body += _payload_bytes(fields)
    return body


def _igmp_has_query_body(
    fields: Mapping[str, JSONObject],
    igmp_fields: Mapping[str, object],
    type_code: int,
) -> bool:
    if type_code != 0x11:
        return False
    if _layer_fields(fields, "igmp_query"):
        return True
    return any(
        name in igmp_fields
        for name in (
            "flags_qrv",
            "number_of_sources",
            "qqic",
            "query_flags",
            "raw_flags_qrv",
            "source_addresses",
        )
    )


def _igmp_has_report_body(
    fields: Mapping[str, JSONObject],
    igmp_fields: Mapping[str, object],
    type_code: int,
) -> bool:
    if type_code == 0x22:
        return True
    if _layer_fields(fields, "igmp_report"):
        return True
    return any(
        name in igmp_fields
        for name in (
            "group_records",
            "number_of_group_records",
            "number_of_records",
            "report_flags",
            "reserved_flags",
        )
    )


def _igmp_query_bytes(fields: Mapping[str, JSONObject]) -> bytes:
    igmp_fields = _layer_fields(fields, "igmp")
    query_fields = {**igmp_fields, **_layer_fields(fields, "igmp_query")}
    sources = _igmp_ipv4_list(_optional_field(query_fields, "source_addresses"))
    count = _int(
        _optional_field(query_fields, "number_of_sources"),
        len(sources),
    )
    return (
        bytes(
            [
                _igmp_query_flags(query_fields) & 0xFF,
                _int(_optional_field(query_fields, "qqic"), 0) & 0xFF,
            ]
        )
        + (count & 0xFFFF).to_bytes(2, "big")
        + b"".join(_ipv4_address_bytes(source) for source in sources)
    )


def _igmp_report_bytes(fields: Mapping[str, JSONObject]) -> bytes:
    igmp_fields = _layer_fields(fields, "igmp")
    report_fields = {**igmp_fields, **_layer_fields(fields, "igmp_report")}
    records = _igmp_group_records(report_fields)
    count = _int(
        _optional_field(report_fields, "number_of_group_records", "number_of_records"),
        len(records),
    )
    body = bytearray()
    body.extend((_igmp_report_flags(report_fields) & 0xFFFF).to_bytes(2, "big"))
    body.extend((count & 0xFFFF).to_bytes(2, "big"))
    for record in records:
        body.extend(_igmp_group_record_bytes(record))
    return bytes(body)


def _igmp_group_records(report_fields: Mapping[str, object]) -> list[Mapping[str, object]]:
    value = _optional_field(report_fields, "group_records", "records")
    if value is None:
        return []
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError("IGMP group_records materialization requires a record list")
    records: list[Mapping[str, object]] = []
    for record in value:
        if not isinstance(record, Mapping):
            raise ValueError(f"IGMP group record must be an object, got {record!r}")
        records.append(record)
    return records


def _igmp_group_record_bytes(record: Mapping[str, object]) -> bytes:
    sources = _igmp_ipv4_list(
        _optional_field(record, "source_addresses", "record_source_addresses")
    )
    auxiliary = _igmp_bytes_value(_optional_field(record, "auxiliary_data"))
    aux_len = _int(
        _optional_field(record, "auxiliary_data_len", "aux_data_len"),
        (len(auxiliary) + 3) // 4,
    )
    wire_aux_len = aux_len * 4
    if wire_aux_len > len(auxiliary) and _optional_field(record, "auxiliary_data_len", "aux_data_len") is not None:
        raise ValueError(
            "IGMP group record auxiliary_data_len exceeds supplied auxiliary_data bytes"
        )
    auxiliary = (auxiliary + b"\x00" * wire_aux_len)[:wire_aux_len]
    count = _int(
        _optional_field(record, "number_of_sources", "record_number_of_sources"),
        len(sources),
    )
    raw = bytearray(
        [
            _igmp_record_type(_optional_field(record, "record_type", "type")) & 0xFF,
            aux_len & 0xFF,
        ]
    )
    raw.extend((count & 0xFFFF).to_bytes(2, "big"))
    raw.extend(
        _ipv4_address_bytes(
            _optional_field(record, "multicast_address", "group_address", "group"),
            "0.0.0.0",
        )
    )
    for source in sources:
        raw.extend(_ipv4_address_bytes(source))
    raw.extend(auxiliary)
    return bytes(raw)


def _igmp_extensions_bytes(fields: Mapping[str, JSONObject]) -> bytes:
    igmp_fields = _layer_fields(fields, "igmp")
    value = _optional_field(igmp_fields, "extension_tlvs", "extensions")
    if value is not None:
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
            raise ValueError("IGMP extension_tlvs materialization requires a TLV list")
        raw = b""
        for item in value:
            if not isinstance(item, Mapping):
                raise ValueError(f"IGMP extension TLV must be an object, got {item!r}")
            raw += _igmp_extension_layer_bytes(item)
        return raw

    extension_fields = _layer_fields(fields, "igmp_extension")
    if extension_fields:
        return _igmp_extension_layer_bytes(extension_fields)
    return b""


def _igmp_extension_layer_bytes(fields: Mapping[str, object]) -> bytes:
    value = _igmp_bytes_value(_optional_field(fields, "extension_value", "value", "value_hex"))
    length = _int(_optional_field(fields, "extension_length", "length"), len(value))
    if length > len(value):
        raise ValueError("IGMP extension_length exceeds supplied extension_value bytes")
    return (
        (_igmp_extension_type(_optional_field(fields, "extension_type", "type")) & 0xFFFF).to_bytes(2, "big")
        + (length & 0xFFFF).to_bytes(2, "big")
        + value[:length]
    )


def _igmp_group_address_bytes(igmp_fields: Mapping[str, object], type_code: int) -> bytes:
    group_address = _optional_field(igmp_fields, "group_address", "group", "gaddr")
    if group_address is not None:
        return _ipv4_address_bytes(group_address, "0.0.0.0")
    if type_code == 0x30:
        query_interval = _int(_optional_field(igmp_fields, "mrd_query_interval"), 0)
        robustness = _int(_optional_field(igmp_fields, "mrd_robustness_variable"), 0)
        return (query_interval & 0xFFFF).to_bytes(2, "big") + (
            robustness & 0xFFFF
        ).to_bytes(2, "big")
    return b"\x00\x00\x00\x00"


def _igmp_code(igmp_fields: Mapping[str, object], type_code: int) -> int:
    value = _optional_field(
        igmp_fields,
        "code",
        "max_response_code",
        "max_response_time_tenths",
        "v2_max_response_time_tenths",
        "mrd_advertisement_interval",
        "mrd_reserved",
    )
    if value is None:
        return 0
    if isinstance(value, str):
        normalized = value.lower().replace(" ", "_").replace("-", "_")
        mapping = {
            "v1_query_zero": 0,
            "zero": 0,
            "reserved_zero": 0,
            "mrd_reserved": 0,
            "v2_max_response_time": 100,
            "v3_max_response_code": 100,
            "mrd_advertisement_interval": 20,
        }
        if normalized in mapping:
            return mapping[normalized]
        return int(normalized, 0)
    return _int(value, 0)


def _igmp_checksum(igmp_fields: Mapping[str, object]) -> int | None:
    value = _optional_field(igmp_fields, "checksum", "chksum")
    if value is None:
        return None
    if isinstance(value, str):
        normalized = value.lower().replace("-", "_")
        if normalized in {"derived", "auto"}:
            return None
        if normalized in {"explicit", "explicit_invalid"}:
            return 0x1234
        if normalized == "boundary":
            return 0xFFFF
        return int(normalized, 0)
    return _int(value, 0)


def _igmp_type(value: object, *, default: int = 0x11) -> int:
    if value is None:
        return default
    if isinstance(value, str):
        normalized = value.lower().replace(" ", "-")
        if normalized in _IGMP_TYPE_CODES:
            return _IGMP_TYPE_CODES[normalized]
        normalized = normalized.replace("-", "_")
        if normalized in _IGMP_TYPE_CODES:
            return _IGMP_TYPE_CODES[normalized]
        return int(normalized, 0)
    return _int(value, default)


def _igmp_record_type(value: object) -> int:
    if value is None:
        return 1
    if isinstance(value, str):
        normalized = value.lower().replace(" ", "-")
        if normalized in _IGMP_RECORD_TYPES:
            return _IGMP_RECORD_TYPES[normalized]
        normalized = normalized.replace("-", "_")
        if normalized in _IGMP_RECORD_TYPES:
            return _IGMP_RECORD_TYPES[normalized]
        return int(normalized, 0)
    return _int(value, 1)


def _igmp_extension_type(value: object) -> int:
    if value is None:
        return 0
    if isinstance(value, str):
        normalized = value.lower().replace(" ", "-")
        if normalized in _IGMP_EXTENSION_TYPES:
            return _IGMP_EXTENSION_TYPES[normalized]
        normalized = normalized.replace("-", "_")
        if normalized in _IGMP_EXTENSION_TYPES:
            return _IGMP_EXTENSION_TYPES[normalized]
        return int(normalized, 0)
    return _int(value, 0)


def _igmp_query_flags(fields: Mapping[str, object]) -> int:
    raw = _optional_field(fields, "raw_flags_qrv", "flags_qrv")
    if raw is not None:
        return _int(raw, 0)
    flags = _igmp_flags_value(_optional_field(fields, "query_flags"), _IGMP_QUERY_FLAG_BITS)
    suppress = _optional_field(fields, "suppress_router_side_processing", "s")
    if suppress is not None:
        if _bool_int(suppress, 0):
            flags |= 0x08
        else:
            flags &= ~0x08
    qrv = _optional_field(fields, "qrv", "querier_robustness_variable")
    if qrv is not None:
        flags = (flags & ~0x07) | (_int(qrv, 0) & 0x07)
    return flags


def _igmp_report_flags(fields: Mapping[str, object]) -> int:
    raw = _optional_field(fields, "reserved_flags")
    if raw is not None:
        return _int(raw, 0)
    return _igmp_flags_value(_optional_field(fields, "report_flags"), _IGMP_REPORT_FLAG_BITS)


def _igmp_flags_value(value: object, mapping: Mapping[str, int]) -> int:
    if value is None:
        return 0
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    items = value if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)) else [value]
    flags = 0
    for item in items:
        if isinstance(item, int) and not isinstance(item, bool):
            flags |= item
            continue
        if isinstance(item, str):
            normalized = item.lower().replace(" ", "_").replace("-", "_")
            flags |= mapping.get(normalized, int(normalized, 0) if normalized.startswith("0") else 0)
    return flags


def _igmp_ipv4_list(value: object) -> list[object]:
    if value is None:
        return []
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError("IGMP IPv4 address list requires a list")
    addresses: list[object] = []
    for item in value:
        if isinstance(item, Mapping):
            addresses.append(_optional_field(item, "address", "ip", "value"))
        else:
            addresses.append(item)
    return addresses


def _igmp_raw_tail_bytes(igmp_fields: Mapping[str, object]) -> bytes:
    value = _optional_field(igmp_fields, "raw_tail", "tail", "payload")
    if value is None:
        return b""
    return _igmp_bytes_value(value)


def _igmp_bytes_value(value: object) -> bytes:
    if value is None:
        return b""
    return _bytes_field(value)


register(
    ScapyProtocol(
        layer="igmp",
        scapy_class="Raw",
        supported_fields=_SUPPORTED_FIELDS,
        build=_build_igmp,
    )
)
