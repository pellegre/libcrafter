"""Wireshark-stage decode for the IPv6 base layer and extension headers.

Moves the ``_normalize_ipv6`` tshark normalizer and its tshark field aliases
verbatim out of :mod:`..normalize` and registers them through the
:class:`~.base.WiresharkProtocol` contract; only the dispatch moves out of the
legacy if/elif. Behavior must stay byte-identical.

The IPv6 extension-header normalizers
(``_normalize_ipv6_options_header``/``_normalize_ipv6_fragment``/
``_normalize_ipv6_routing``) and their TLV helpers are co-located here too, moved
byte-identically. They are *not* registered as separate
:class:`~.base.WiresharkProtocol` plugins because the ext-header names are sub-layers
of the ``ipv6`` spec (declared as ``extension_layers`` inside
``specs/layers/ipv6.yaml``) rather than top-level spec layers, so registering them
under their own names would trip the strict ``test_protocol_plugin_coverage``
"registrations are spec layers" guard. Instead they are re-imported by
:mod:`..normalize`, whose legacy per-layer dispatch still routes
``ipv6_hop_by_hop``/``ipv6_destination_options``/``ipv6_fragment``/``ipv6_routing``
to them (the same pattern step 14 used for ``linux_cooked`` which decodes under the
non-spec name ``linux_sll``). The ``ipv6.*`` tshark-protocol routing entries stay in
``normalize._PROTOCOL_LAYER_ALIASES`` (a root routing table left intact).

Shared primitives come from :mod:`..decode_helpers` so this plugin does not depend
on the ``normalize`` orchestrator (which would create a circular import). Relative
imports only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

import ipaddress

from ....model import JSONObject
from ..decode_helpers import (
    _field_list,
    _fields_from_aliases,
    _hex_bytes,
    _layer,
    _parse_int_fields,
)
from .base import WiresharkProtocol, register


# tshark field aliases the IPv6 layer owns: canonical oracle name -> the native
# tshark field names that carry it.
_IPV6_TSHARK_ALIASES: JSONObject = {
    "version": ("ipv6.version",),
    "traffic_class": ("ipv6.tclass",),
    "flow_label": ("ipv6.flow",),
    "payload_length": ("ipv6.plen",),
    "next_header": ("ipv6.nxt",),
    "hop_limit": ("ipv6.hlim",),
    "src": ("ipv6.src",),
    "dst": ("ipv6.dst",),
}


def _normalize_ipv6(layers: JSONObject, *, source_hex: str | None = None) -> JSONObject:
    layer = _layer(layers, "ipv6")
    output = _fields_from_aliases(layer, dict(_IPV6_TSHARK_ALIASES))
    _parse_int_fields(
        output,
        "version",
        "traffic_class",
        "flow_label",
        "payload_length",
        "next_header",
        "hop_limit",
    )
    traffic_class = output.get("traffic_class")
    if isinstance(traffic_class, int):
        output["dscp"] = traffic_class >> 2
        output["ecn"] = traffic_class & 0x03
    return output


register(
    WiresharkProtocol(
        layer="ipv6",
        normalize=_normalize_ipv6,
        tshark_aliases=dict(_IPV6_TSHARK_ALIASES),
    )
)


# ===========================================================================
# IPv6 extension headers (ipv6_hop_by_hop / ipv6_destination_options /
# ipv6_fragment / ipv6_routing)
#
# Sub-layers of the ``ipv6`` spec, not separate spec layers, so they are NOT
# registered through ``WiresharkProtocol``; the normalizers below are re-imported by
# ``..normalize``, which keeps the legacy per-layer dispatch for them. The code is
# moved here byte-identically.
# ===========================================================================


def _normalize_ipv6_options_header(layer: JSONObject, *, prefix: str) -> JSONObject:
    output = _fields_from_aliases(
        layer,
        {
            "next_header": (f"{prefix}.nxt", f"{prefix}.next", f"{prefix}.next_header"),
            "header_ext_len": (f"{prefix}.len", f"{prefix}.length", f"{prefix}.hdr_ext_len"),
            "options_raw_hex": (
                f"{prefix}.options_raw",
                f"{prefix}.options",
                f"{prefix}.option_bytes",
            ),
        },
    )
    _parse_int_fields(output, "next_header", "header_ext_len")
    if "header_ext_len" in output:
        output["length"] = output["header_ext_len"]

    raw_options = output.get("options_raw_hex")
    if isinstance(raw_options, str):
        raw_options = _hex_bytes(raw_options)
        options = _decode_ipv6_option_tlvs(raw_options)
        if options is not None:
            output["options_raw_hex"] = raw_options
            output["options"] = options
            output["option_count"] = len(options)
    return output


def _normalize_ipv6_fragment(layer: JSONObject) -> JSONObject:
    output = _fields_from_aliases(
        layer,
        {
            "next_header": (
                "ipv6.fragment.nxt",
                "ipv6.fraghdr.nxt",
                "ipv6.fragment.next_header",
            ),
            "reserved": ("ipv6.fragment.reserved", "ipv6.fraghdr.reserved"),
            "fragment_offset": (
                "ipv6.fragment.offset",
                "ipv6.fraghdr.offset",
                "ipv6.fragment.frag_offset",
            ),
            "more_fragments": (
                "ipv6.fragment.more",
                "ipv6.fragment.more_fragments",
                "ipv6.fraghdr.more",
            ),
            "identification": ("ipv6.fragment.id", "ipv6.fraghdr.id"),
        },
    )
    _parse_int_fields(
        output,
        "next_header",
        "reserved",
        "fragment_offset",
        "more_fragments",
        "identification",
    )
    if isinstance(output.get("more_fragments"), int):
        output["more_fragments"] = bool(output["more_fragments"])
    offset = output.get("fragment_offset")
    if isinstance(offset, int):
        output["fragment_offset_bytes"] = offset * 8
    more_fragments = output.get("more_fragments")
    if isinstance(offset, int) and isinstance(more_fragments, bool):
        output["fragment_status"] = _ipv6_fragment_status(offset, more_fragments)
    return output


def _normalize_ipv6_routing(layer: JSONObject) -> JSONObject:
    output = _fields_from_aliases(
        layer,
        {
            "next_header": ("ipv6.routing.nxt", "ipv6.routing.next_header"),
            "header_ext_len": (
                "ipv6.routing.len",
                "ipv6.routing.length",
                "ipv6.routing.hdr_ext_len",
            ),
            "type": ("ipv6.routing.type", "ipv6.routing.routing_type"),
            "segments_left": (
                "ipv6.routing.seg_left",
                "ipv6.routing.segleft",
                "ipv6.routing.segments_left",
            ),
            "last_entry": ("ipv6.routing.last_entry", "ipv6.routing.lastentry"),
            "flags": ("ipv6.routing.flags",),
            "tag": ("ipv6.routing.tag",),
            "raw_trailing_data": (
                "ipv6.routing.raw_trailing_data",
                "ipv6.routing.tlv_data",
            ),
            "type_data": ("ipv6.routing.type_data",),
        },
    )
    _parse_int_fields(
        output,
        "next_header",
        "header_ext_len",
        "type",
        "segments_left",
        "last_entry",
        "flags",
        "tag",
    )
    if "header_ext_len" in output:
        output["length"] = output["header_ext_len"]
    routing_type = output.get("type")
    if isinstance(routing_type, int):
        output["classification"] = _ipv6_routing_classification(routing_type)
    addresses = _field_list(layer, "ipv6.routing.address", "ipv6.routing.addresses")
    if addresses:
        output["addresses"] = [str(item) for item in addresses]
        if routing_type == 4:
            output["segments"] = list(output["addresses"])
    raw_trailing = output.get("raw_trailing_data")
    if isinstance(raw_trailing, str):
        output["raw_trailing_data"] = _hex_bytes(raw_trailing)
    type_data = output.get("type_data")
    if isinstance(type_data, str):
        output["type_data"] = _hex_bytes(type_data)
    return output


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
        "kind": _ipv6_option_kind(option_type),
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


def _ipv6_option_kind(option_type: int) -> str:
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
