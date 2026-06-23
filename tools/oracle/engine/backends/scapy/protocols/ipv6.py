"""Scapy-stage encode + decode for the IPv6 base layer and extension headers.

Moves the ``_ipv6`` (IPv6) builder and the base-IPv6 decode normalization verbatim
out of :mod:`..packets` and :mod:`..normalize` and registers them through the
:class:`~.base.ScapyProtocol` contract; only the dispatch moves out of the legacy
if/elif. Behavior must stay byte-identical.

The IPv6 extension headers
(``ipv6_hop_by_hop``/``ipv6_destination_options``/``ipv6_fragment``/``ipv6_routing``)
are co-located here too: their encode builders and decode normalizers are moved
into this module byte-identically. They are *not* registered as separate
:class:`~.base.ScapyProtocol` plugins because they are not top-level oracle spec
layers — they are declared as ``extension_layers`` inside ``specs/layers/ipv6.yaml``
and never appear in ``OracleSpecs.layers``, so registering them under their own
names would trip the strict ``test_protocol_plugin_coverage`` "registrations are spec
layers" guard. Instead the ext-header builders/normalizers live here and are
re-imported by :mod:`..packets` / :mod:`..normalize`, whose legacy per-layer dispatch
still routes ``ipv6_hop_by_hop``/``ipv6_destination_options``/``ipv6_fragment``/
``ipv6_routing`` to them (the same pattern step 14 used for ``linux_cooked`` which
decodes under the non-spec name ``linux_sll``). The shared option-region capture in
``normalize._packet_layers`` and the ``_normalize_fields`` dispatch are orchestrator
wiring and stay in ``normalize``.

Base IPv6 has no dedicated ``if layer_name == "ipv6"`` decode block beyond the
``_normalize_ipv6_fields`` post-hoc tweak: it decoded through the generic alias
path plus the ``traffic_class`` -> ``dscp``/``ecn`` derivation. The plugin's
``_normalize`` reproduces that path exactly: each native Scapy field name is renamed
through the IPv6 field aliases (the former ``normalize._LAYER_FIELD_ALIASES["ipv6"]``
merged over the global ``normalize._FIELD_ALIASES`` table, with the layer-specific
names taking precedence — the same lookup order ``_normalize_field_name`` used), the
generic ``_normalize_field_value`` rules are applied, and ``_normalize_ipv6_fields``
(moved here) derives ``dscp``/``ecn`` from ``traffic_class``.

Shared primitives come from the helper modules so this plugin does not depend on the
``packets``/``normalize`` orchestrators (which would create a circular import).
``_IPV6_NEXT_HEADERS`` lives in :mod:`..encode_helpers` because the IPv6
extension-header builders and the IPv6 raw-bytes path in ``packets`` still use it.
Relative imports only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from typing import Any

from ....model import JSONObject, JSONValue
from ..decode_helpers import _int_or_zero, _normalize_flags
from ..encode_helpers import (
    _IPV6_NEXT_HEADERS,
    _bytes_field,
    _int,
    _layer_fields,
    _optional_field,
    _protocol_value,
    _required_field,
    _text,
)
from .base import ScapyProtocol, register


# Encode-side field allowlist for ``_validate_layer_fields`` — the canonical field
# names plus every Scapy/oracle alias the IPv6 builder accepts. Mirrors the former
# ``packets._SUPPORTED_FIELDS_BY_LAYER["ipv6"]`` entry exactly.
_SUPPORTED_FIELDS = frozenset(
    {
        "dst",
        "fl",
        "flow_label",
        "hlim",
        "hop_limit",
        "next_header",
        "nh",
        "src",
        "tc",
        "traffic_class",
    }
)

# Decode-side native-name aliases the IPv6 layer owns. ``layer_aliases`` maps the
# Scapy class name to the oracle layer name (the former ``normalize._LAYER_ALIASES``
# entry); ``field_aliases`` records the IPv6-specific field renames (the former
# ``normalize._LAYER_FIELD_ALIASES["ipv6"]`` entry).
_LAYER_ALIASES = (("IPv6", "ipv6"),)
_FIELD_ALIASES = (
    ("fl", "flow_label"),
    ("plen", "payload_length"),
    ("tc", "traffic_class"),
    ("version", "version"),
)

# Global cross-layer field aliases the legacy ``_normalize_field_name`` consulted as
# a fallback after the layer-specific map (mirrors ``normalize._FIELD_ALIASES``). The
# IPv6 layer only exercises ``nh``/``hlim``; the rest never appear on a decoded IPv6
# layer, so carrying the full map is harmless and keeps the lookup byte-identical to
# the legacy generic path.
_GLOBAL_FIELD_ALIASES: dict[str, str] = {
    "chksum": "checksum",
    "dataofs": "data_offset",
    "dport": "dst_port",
    "frag": "fragment_offset",
    "hlim": "hop_limit",
    "len": "length",
    "nh": "next_header",
    "proto": "protocol",
    "sport": "src_port",
    "urgptr": "urgent_pointer",
}
# Effective IPv6 field-name map: global aliases overlaid by the IPv6-specific ones,
# exactly the precedence ``_normalize_field_name("ipv6", ...)`` applied.
_IPV6_FIELD_NAME_MAP: dict[str, str] = {**_GLOBAL_FIELD_ALIASES, **dict(_FIELD_ALIASES)}


# ---------------------------------------------------------------------------
# Encode
# ---------------------------------------------------------------------------


def _build(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    ipv6_fields = _layer_fields(fields, "ipv6")
    kwargs: dict[str, Any] = {
        "src": _text(_required_field(ipv6_fields, "ipv6", "src"), ""),
        "dst": _text(_required_field(ipv6_fields, "ipv6", "dst"), ""),
        "hlim": _int(_required_field(ipv6_fields, "ipv6", "hop_limit", "hlim"), 0),
        "nh": _protocol_value(
            _required_field(ipv6_fields, "ipv6", "next_header", "nh"),
            _IPV6_NEXT_HEADERS,
        ),
    }
    if "traffic_class" in ipv6_fields or "tc" in ipv6_fields:
        kwargs["tc"] = _int(_optional_field(ipv6_fields, "traffic_class", "tc"), 0)
    if "flow_label" in ipv6_fields or "fl" in ipv6_fields:
        kwargs["fl"] = _int(_optional_field(ipv6_fields, "flow_label", "fl"), 0)
    return scapy_all.IPv6(**kwargs)


# ---------------------------------------------------------------------------
# Decode
# ---------------------------------------------------------------------------


def _normalize(fields: JSONObject) -> JSONObject:
    """Normalize a decoded Scapy IPv6 layer to the comparable oracle shape.

    Byte-identical to the legacy generic ``_normalize_fields`` path for ipv6: each
    native field name is renamed via the IPv6 field-name map (the lookup order
    ``_normalize_field_name`` applied), the generic ``_normalize_field_value`` rules
    are applied, and ``_normalize_ipv6_fields`` derives ``dscp``/``ecn`` from
    ``traffic_class``.
    """

    output: JSONObject = {}
    for native_name, value in fields.items():
        normalized_name = _IPV6_FIELD_NAME_MAP.get(native_name, native_name)
        output[normalized_name] = _normalize_field_value(normalized_name, value)
    _normalize_ipv6_fields(output)
    return output


def _normalize_field_value(field_name: str, value: JSONValue) -> JSONValue:
    if field_name == "flags":
        return _normalize_flags(value)
    if field_name == "is_response" and isinstance(value, int):
        return bool(value)
    if field_name == "more_fragments" and isinstance(value, int):
        return bool(value)
    return value


def _normalize_ipv6_fields(fields: JSONObject) -> None:
    traffic_class = fields.get("traffic_class")
    if isinstance(traffic_class, int):
        fields["dscp"] = traffic_class >> 2
        fields["ecn"] = traffic_class & 0x03


register(
    ScapyProtocol(
        layer="ipv6",
        scapy_class="IPv6",
        supported_fields=_SUPPORTED_FIELDS,
        build=_build,
        normalize=_normalize,
        layer_aliases=_LAYER_ALIASES,
        field_aliases=_FIELD_ALIASES,
    )
)


# ===========================================================================
# IPv6 extension headers (ipv6_hop_by_hop / ipv6_destination_options /
# ipv6_fragment / ipv6_routing)
#
# These are sub-layers of the ``ipv6`` spec, not separate spec layers, so they
# are NOT registered through ``ScapyProtocol``; the builders and normalizers below
# are re-imported by ``..packets`` / ``..normalize``, which keep the legacy
# per-layer dispatch for them. The code is moved here byte-identically.
# ===========================================================================


# Sentinel field key the decoder uses to smuggle the raw IPv6 option-region bytes
# from the orchestrator (``normalize._packet_layers``) into
# ``_normalize_ipv6_options_header_fields``; moved here with the normalizer that
# consumes it. ``normalize`` re-imports it for the producing side.
_IPV6_OPTION_REGION_KEY = "__ipv6_option_region_hex__"


# ---------------------------------------------------------------------------
# Extension-header encode builders
# ---------------------------------------------------------------------------


def _ipv6_hop_by_hop(
    fields: Mapping[str, JSONObject],
    stack: list[str],
    index: int,
    scapy_all: Any,
) -> Any:
    return _ipv6_options_header(
        fields,
        layer="ipv6_hop_by_hop",
        factory=scapy_all.IPv6ExtHdrHopByHop,
        scapy_all=scapy_all,
    )


def _ipv6_destination_options(
    fields: Mapping[str, JSONObject],
    stack: list[str],
    index: int,
    scapy_all: Any,
) -> Any:
    return _ipv6_options_header(
        fields,
        layer="ipv6_destination_options",
        factory=scapy_all.IPv6ExtHdrDestOpt,
        scapy_all=scapy_all,
    )


def _ipv6_options_header(
    fields: Mapping[str, JSONObject],
    *,
    layer: str,
    factory: Any,
    scapy_all: Any,
) -> Any:
    option_fields = _layer_fields(fields, layer)
    kwargs: dict[str, Any] = {
        "nh": _protocol_value(
            _required_field(option_fields, layer, "next_header", "nh"),
            _IPV6_NEXT_HEADERS,
        ),
        # Scapy aligns some known options by inserting PadN ahead of them. The
        # oracle model is byte-preserving, so plans carry any required padding
        # explicitly and Scapy's alignment autopad must stay disabled.
        "autopad": 0,
        "options": _ipv6_options(_required_field(option_fields, layer, "options"), scapy_all),
    }
    if "header_ext_len" in option_fields or "len" in option_fields:
        kwargs["len"] = _int(_optional_field(option_fields, "header_ext_len", "len"), 0)
    return factory(**kwargs)


def _ipv6_options(value: object, scapy_all: Any) -> list[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError("IPv6 options materialization requires an option list")
    return [_ipv6_option(item, scapy_all) for item in value]


def _ipv6_option(item: object, scapy_all: Any) -> Any:
    if not isinstance(item, Mapping):
        raise ValueError(f"IPv6 option entry must be an object, got {item!r}")
    kind = _ipv6_option_kind(item)
    if kind == "pad1":
        return scapy_all.Pad1()
    if kind == "padn":
        return scapy_all.PadN(optdata=_ipv6_padn_data(item))
    if kind == "router_alert":
        return scapy_all.RouterAlert(value=_int(_required_field(item, "ipv6 option", "value"), 0))
    if kind == "jumbo_payload":
        length = _required_field(item, "ipv6 option", "length", "jumbo_payload_length")
        return scapy_all.Jumbo(jumboplen=_int(length, 0))
    if kind == "home_address":
        address = _required_field(item, "ipv6 option", "address", "home_address")
        return scapy_all.HAO(hoa=_text(address, "::"))
    option_type = _int(
        _required_field(item, "ipv6 option", "option_type", "type", "kind"),
        0,
    )
    return scapy_all.HBHOptUnknown(
        otype=option_type,
        optdata=_ipv6_option_data(item),
    )


def _ipv6_option_kind(item: Mapping[str, object]) -> str:
    value = _optional_field(item, "kind", "name")
    if isinstance(value, str):
        normalized = value.lower().replace("-", "_")
        if normalized in {
            "pad1",
            "padn",
            "router_alert",
            "jumbo_payload",
            "home_address",
            "unknown",
            "generic",
        }:
            return normalized
    option_type = _optional_field(item, "option_type", "type")
    if option_type is None:
        return "unknown"
    option_type_int = _int(option_type, 0)
    if option_type_int == 0:
        return "pad1"
    if option_type_int == 1:
        return "padn"
    if option_type_int == 5 and "value" in item:
        return "router_alert"
    if option_type_int == 0xC2 and ("length" in item or "jumbo_payload_length" in item):
        return "jumbo_payload"
    if option_type_int == 0xC9 and ("address" in item or "home_address" in item):
        return "home_address"
    return "unknown"


def _ipv6_padn_data(item: Mapping[str, object]) -> bytes:
    data = _ipv6_option_data(item)
    if data:
        return data
    total_length = _optional_field(item, "total_length", "length")
    if total_length is None:
        return b""
    total = _int(total_length, 0)
    if total < 2:
        raise ValueError(f"PadN total length must be at least 2 bytes, got {total}")
    return b"\x00" * (total - 2)


def _ipv6_option_data(item: Mapping[str, object]) -> bytes:
    data = _optional_field(item, "data", "bytes", "value_hex", "hex")
    if data is None:
        return b""
    return _bytes_field(data)


def _ipv6_fragment(
    fields: Mapping[str, JSONObject],
    stack: list[str],
    index: int,
    scapy_all: Any,
) -> Any:
    fragment_fields = _layer_fields(fields, "ipv6_fragment")
    kwargs: dict[str, Any] = {
        "nh": _protocol_value(
            _required_field(fragment_fields, "ipv6_fragment", "next_header", "nh"),
            _IPV6_NEXT_HEADERS,
        ),
        "id": _int(_required_field(fragment_fields, "ipv6_fragment", "identification", "id"), 0),
        "offset": _int(
            _required_field(fragment_fields, "ipv6_fragment", "fragment_offset", "offset"),
            0,
        ),
        "m": _int(_required_field(fragment_fields, "ipv6_fragment", "more_fragments", "m"), 0),
    }
    if "reserved" in fragment_fields:
        kwargs["res1"] = _int(fragment_fields.get("reserved"), 0)
    return scapy_all.IPv6ExtHdrFragment(**kwargs)


def _ipv6_routing(
    fields: Mapping[str, JSONObject],
    stack: list[str],
    index: int,
    scapy_all: Any,
) -> Any:
    routing_fields = _layer_fields(fields, "ipv6_routing")
    kwargs: dict[str, Any] = {
        "nh": _protocol_value(
            _required_field(routing_fields, "ipv6_routing", "next_header", "nh"),
            _IPV6_NEXT_HEADERS,
        ),
        "type": _int(_required_field(routing_fields, "ipv6_routing", "type", "routing_type"), 0),
        "segleft": _int(
            _required_field(routing_fields, "ipv6_routing", "segments_left", "segleft"),
            0,
        ),
    }
    addresses = routing_fields.get("addresses")
    if isinstance(addresses, list):
        kwargs["addresses"] = addresses
    return scapy_all.IPv6ExtHdrRouting(**kwargs)


# ---------------------------------------------------------------------------
# Extension-header decode normalizers
# ---------------------------------------------------------------------------


def _normalize_ipv6_options_header_fields(fields: JSONObject) -> None:
    fields.pop("autopad", None)
    option_region_hex = fields.pop(_IPV6_OPTION_REGION_KEY, None)
    if "header_ext_len" in fields and "length" not in fields:
        fields["length"] = fields["header_ext_len"]
    if "length" in fields and "header_ext_len" not in fields:
        fields["header_ext_len"] = fields["length"]

    options = None
    if isinstance(option_region_hex, str):
        options = _decode_ipv6_option_tlvs(option_region_hex)
    if options is not None:
        fields["options"] = options
        fields["option_count"] = len(options)
        fields["options_raw_hex"] = option_region_hex
    elif isinstance(fields.get("options"), list):
        fields["option_count"] = len(fields["options"])


def _decode_ipv6_option_tlvs(option_region_hex: str) -> list[JSONObject] | None:
    try:
        raw = bytes.fromhex(option_region_hex)
    except ValueError:
        return None

    options: list[JSONObject] = []
    index = 0
    while index < len(raw):
        option_type = raw[index]
        index += 1
        if option_type == 0:
            options.append(_ipv6_option_item(option_type, b"", encoded_len=1))
            continue
        if index >= len(raw):
            return None
        option_length = raw[index]
        index += 1
        if index + option_length > len(raw):
            return None
        data = raw[index : index + option_length]
        index += option_length
        options.append(_ipv6_option_item(option_type, data, encoded_len=option_length + 2))
    return options


def _ipv6_option_item(option_type: int, data: bytes, *, encoded_len: int) -> JSONObject:
    item: JSONObject = {
        "option_type": option_type,
        "kind": _ipv6_decode_option_kind(option_type),
        "length": encoded_len,
        "data_hex": data.hex(),
        "action": option_type >> 6,
        "change_en_route": bool(option_type & 0x20),
    }
    if option_type == 5 and len(data) == 2:
        item["value"] = int.from_bytes(data, "big")
    elif option_type == 0xC2 and len(data) == 4:
        item["jumbo_payload_length"] = int.from_bytes(data, "big")
    elif option_type == 0xC9 and len(data) == 16:
        item["address"] = str(ipaddress.IPv6Address(data))
    return item


def _ipv6_decode_option_kind(option_type: int) -> str:
    if option_type == 0:
        return "pad1"
    if option_type == 1:
        return "padn"
    if option_type == 5:
        return "router_alert"
    if option_type == 0xC2:
        return "jumbo_payload"
    if option_type == 0xC9:
        return "home_address"
    return "unknown"


def _normalize_ipv6_fragment_fields(fields: JSONObject) -> None:
    aliases = {
        "id": "identification",
        "offset": "fragment_offset",
        "m": "more_fragments",
        "res1": "reserved",
        "res2": "res",
    }
    for old, new in aliases.items():
        if old in fields and new not in fields:
            fields[new] = fields.pop(old)
    if isinstance(fields.get("more_fragments"), int):
        fields["more_fragments"] = bool(fields["more_fragments"])
    offset = fields.get("fragment_offset")
    if isinstance(offset, int):
        fields["fragment_offset_bytes"] = offset * 8
    more_fragments = fields.get("more_fragments")
    if isinstance(offset, int) and isinstance(more_fragments, bool):
        fields["fragment_status"] = _ipv6_fragment_status(offset, more_fragments)


def _normalize_ipv6_routing_fields(fields: JSONObject) -> None:
    if "segleft" in fields and "segments_left" not in fields:
        fields["segments_left"] = fields.pop("segleft")
    if "lastentry" in fields and "last_entry" not in fields:
        fields["last_entry"] = fields.pop("lastentry")
    if "header_ext_len" in fields and "length" not in fields:
        fields["length"] = fields["header_ext_len"]
    if "length" in fields and "header_ext_len" not in fields:
        fields["header_ext_len"] = fields["length"]
    routing_type = fields.get("type")
    if isinstance(routing_type, int):
        fields["classification"] = _ipv6_routing_classification(routing_type)
    if (
        "segments" not in fields
        and isinstance(fields.get("addresses"), list)
        and fields["addresses"]
        and fields.get("type") == 4
    ):
        fields["segments"] = fields["addresses"]
    if "flags" not in fields:
        flags = _ipv6_segment_routing_flags(fields)
        if flags is not None:
            fields["flags"] = flags
    if fields.get("tlv_objects") == []:
        fields["raw_trailing_data"] = ""
    if (
        "type_data" not in fields
        and isinstance(fields.get("reserved"), int)
        and fields.get("type") not in {2, 4}
    ):
        fields["type_data"] = f"{fields['reserved']:08x}"
    if fields.get("reserved") == 0:
        fields["reserved"] = "00000000"
    if fields.get("addresses") == []:
        fields.pop("addresses", None)


def _ipv6_fragment_status(offset: int, more_fragments: bool) -> str:
    if offset == 0 and not more_fragments:
        return "atomic"
    if offset == 0:
        return "initial"
    return "non_initial"


def _ipv6_routing_classification(routing_type: int) -> str:
    if routing_type in {0, 1}:
        return "deprecated"
    if routing_type == 2:
        return "mobile"
    if routing_type == 4:
        return "segment_routing"
    if routing_type in {253, 254}:
        return "experimental"
    if routing_type == 255:
        return "reserved"
    return "unknown"


def _ipv6_segment_routing_flags(fields: JSONObject) -> int | None:
    names = ("unused1", "protected", "oam", "alert", "hmac", "unused2")
    if not any(isinstance(fields.get(name), int) for name in names):
        return None
    return (
        ((_int_or_zero(fields.get("unused1")) & 0x01) << 7)
        | ((_int_or_zero(fields.get("protected")) & 0x01) << 6)
        | ((_int_or_zero(fields.get("oam")) & 0x01) << 5)
        | ((_int_or_zero(fields.get("alert")) & 0x01) << 4)
        | ((_int_or_zero(fields.get("hmac")) & 0x01) << 3)
        | (_int_or_zero(fields.get("unused2")) & 0x07)
    )
