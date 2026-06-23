"""Scapy-stage encode + decode plugin for the base IPv6 layer.

Moves the ``_ipv6`` (IPv6) builder and the base-IPv6 decode normalization verbatim
out of :mod:`..packets` and :mod:`..normalize` and registers them through the
:class:`~.base.ScapyProtocol` contract; only the dispatch moves out of the legacy
if/elif. Behavior must stay byte-identical. The IPv6 extension headers
(``ipv6_hop_by_hop``/``ipv6_destination_options``/``ipv6_fragment``/``ipv6_routing``)
stay on the legacy dispatch and migrate in a later step.

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

from collections.abc import Mapping
from typing import Any

from ....model import JSONObject, JSONValue
from ..decode_helpers import _normalize_flags
from ..encode_helpers import (
    _IPV6_NEXT_HEADERS,
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
