"""Scapy-stage encode + decode plugin for the BGP layer.

Moves the ``_bgp`` builder and its message/body helpers, the ``_BGP_MESSAGE_TYPES``
map, and the per-layer ``_normalize_bgp_fields`` normalizer verbatim out of
:mod:`..packets` and :mod:`..normalize` and registers them through the
:class:`~.base.ScapyProtocol` contract; only the dispatch moves out of the legacy
if/elif. Behavior must stay byte-identical.

BGP seeds only the header scalars during sampling; the message body bytes are
attached during the generator's behavior pass, so the builder routes on the BGP
message type and re-emits the planned body verbatim (``BGPHeader`` / ``Raw`` for
the common case, or the typed Scapy ``BGPOpen`` / ``BGPUpdate`` / ``BGPNotification``
/ ``BGPRouteRefresh`` sub-layers when no explicit body hex is present).

The per-layer ``_normalize`` reproduces the legacy ``_normalize_bgp_fields`` path
exactly: each native field name is renamed via the BGP field-name map (the former
``normalize._LAYER_FIELD_ALIASES["bgp"]`` overlaid on the global
``normalize._FIELD_ALIASES``, the same precedence ``_normalize_field_name("bgp",
...)`` applied), the ``flags`` value is normalized through ``_normalize_flags``
(none appears on a decoded BGP layer, carried only for byte-identity), an integer
``marker`` becomes its 16-octet hex form, an integer ``type`` resolves to its
message-type name, and any empty optional region collapses to ``{"hex": ""}``.

The whole-packet ``_canonicalize_bgp_from_wire`` pass and the ``BGP*`` body-layer
folding in ``normalize_packet`` operate on the assembled packet rather than a single
decoded layer, so — following the step-22/24 precedent — they stay in
:mod:`..normalize` and are not moved here. The decode-side ``layer_aliases`` this
plugin registers keep ``BGPHeader`` / ``BGPKeepAlive`` / ``BGPOpen`` / ``BGPUpdate``
/ ``BGPNotification`` / ``BGPRouteRefresh`` resolving to ``bgp`` so that whole-packet
pass continues to find the BGP layer.

Shared primitives come from the helper modules so this plugin does not depend on the
``packets``/``normalize`` orchestrators (which would create a circular import).
``import_scapy`` (for the Scapy BGP contrib classes) comes from :mod:`..bootstrap`.
Relative imports only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ....model import JSONObject, JSONValue
from ..bootstrap import import_scapy
from ..decode_helpers import _normalize_flags
from ..encode_helpers import (
    _bytes_exact,
    _bytes_field,
    _int,
    _ipv4_address_bytes,
    _layer_fields_for_stack_index,
    _optional_field,
    _required_field,
    _text,
)
from .base import ScapyProtocol, register


# Encode-side message-type name -> wire code, mirroring the former
# ``packets._BGP_MESSAGE_TYPES`` map.
_BGP_MESSAGE_TYPES: dict[str, int] = {
    "open": 1,
    "update": 2,
    "notification": 3,
    "keepalive": 4,
    "route-refresh": 5,
    "route_refresh": 5,
}

# Encode-side field allowlist for ``_validate_layer_fields`` — the canonical field
# names plus every Scapy/oracle alias the BGP builder accepts. Mirrors the former
# ``packets._SUPPORTED_FIELDS_BY_LAYER["bgp"]`` entry exactly.
_SUPPORTED_FIELDS = frozenset(
    {
        "afi",
        "asn",
        "bgp_id",
        "bgp_identifier",
        "body",
        "body_hex",
        "capabilities",
        "code",
        "data",
        "error_code",
        "error_subcode",
        "hold_time",
        "len",
        "length",
        "marker",
        "message_type",
        "my_as",
        "nlri",
        "nlri_hex",
        "opt_param_len",
        "opt_params",
        "optional_parameters",
        "optional_parameters_hex",
        "orf_data",
        "path_attr",
        "path_attr_len",
        "path_attributes",
        "path_attributes_hex",
        "raw",
        "raw_body",
        "safi",
        "subcode",
        "subtype",
        "type",
        "version",
        "withdrawn_routes",
        "withdrawn_routes_hex",
        "withdrawn_routes_len",
    }
)

# Decode-side native-name aliases the BGP layer owns. ``layer_aliases`` maps each
# Scapy BGP class name to the oracle layer name (the former
# ``normalize._LAYER_ALIASES`` entries); ``field_aliases`` records the BGP-specific
# field renames (the former ``normalize._LAYER_FIELD_ALIASES["bgp"]`` entry).
_LAYER_ALIASES = (
    ("BGPHeader", "bgp"),
    ("BGPKeepAlive", "bgp"),
    ("BGPNotification", "bgp"),
    ("BGPOpen", "bgp"),
    ("BGPRouteRefresh", "bgp"),
    ("BGPUpdate", "bgp"),
)
_FIELD_ALIASES = (
    ("bgp_id", "bgp_identifier"),
    ("len", "length"),
    ("my_as", "asn"),
    ("opt_params", "optional_parameters"),
    ("path_attr", "path_attributes"),
)

# Global cross-layer field aliases the legacy ``_normalize_field_name`` consulted as
# a fallback after the layer-specific map (mirrors ``normalize._FIELD_ALIASES``). BGP
# only exercises ``len`` (overridden by its layer-specific entry); the rest never
# appear on a decoded BGP layer, so carrying the full map is harmless and keeps the
# lookup byte-identical to the legacy generic path.
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
# Effective BGP field-name map: global aliases overlaid by the BGP-specific ones,
# exactly the precedence ``_normalize_field_name("bgp", ...)`` applied.
_BGP_FIELD_NAME_MAP: dict[str, str] = {**_GLOBAL_FIELD_ALIASES, **dict(_FIELD_ALIASES)}

# Decode-side message-type code -> name, mirroring the former
# ``normalize._BGP_MESSAGE_TYPE_NAMES`` map.
_BGP_MESSAGE_TYPE_NAMES: dict[int, str] = {
    1: "open",
    2: "update",
    3: "notification",
    4: "keepalive",
    5: "route_refresh",
}


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
    return _bgp(fields, stack, index, scapy_all)


def _bgp(
    fields: Mapping[str, JSONObject],
    stack: Sequence[str],
    index: int,
    scapy_all: Any,
) -> Any:
    scapy_bgp = import_scapy()["bgp"]
    bgp_fields = _layer_fields_for_stack_index(fields, stack, index)
    message_type = _bgp_message_type(
        _required_field(bgp_fields, "bgp", "message_type", "type")
    )
    header_kwargs = _bgp_header_kwargs(bgp_fields)

    if message_type == 4:
        return scapy_bgp.BGPKeepAlive(**header_kwargs)

    body = _bgp_raw_body(bgp_fields)
    if body is not None:
        return scapy_bgp.BGPHeader(type=message_type, **header_kwargs) / scapy_all.Raw(
            load=body
        )

    if message_type == 1:
        body = _bgp_open_raw_body(bgp_fields)
        if body is not None:
            return scapy_bgp.BGPHeader(type=message_type, **header_kwargs) / scapy_all.Raw(
                load=body
            )
        return scapy_bgp.BGPHeader(type=message_type, **header_kwargs) / scapy_bgp.BGPOpen(
            version=_int(_optional_field(bgp_fields, "version"), 4),
            my_as=_int(_optional_field(bgp_fields, "my_as", "asn"), 0),
            hold_time=_int(_optional_field(bgp_fields, "hold_time"), 0),
            bgp_id=_text(
                _optional_field(bgp_fields, "bgp_id", "bgp_identifier"),
                "0.0.0.0",
            ),
        )

    if message_type == 2:
        body = _bgp_update_raw_body(bgp_fields)
        if body is not None:
            return scapy_bgp.BGPHeader(type=message_type, **header_kwargs) / scapy_all.Raw(
                load=body
            )
        return scapy_bgp.BGPHeader(type=message_type, **header_kwargs) / scapy_bgp.BGPUpdate()

    if message_type == 3:
        kwargs: dict[str, Any] = {
            "error_code": _int(_optional_field(bgp_fields, "error_code", "code"), 0),
            "error_subcode": _int(
                _optional_field(bgp_fields, "error_subcode", "subcode"),
                0,
            ),
        }
        data = _optional_field(bgp_fields, "data")
        if data is not None:
            kwargs["data"] = _bytes_field(data)
        return (
            scapy_bgp.BGPHeader(type=message_type, **header_kwargs)
            / scapy_bgp.BGPNotification(**kwargs)
        )

    if message_type == 5:
        kwargs = {
            "afi": _bgp_afi(_optional_field(bgp_fields, "afi")),
            "subtype": _int(_optional_field(bgp_fields, "subtype"), 0),
            "safi": _bgp_safi(_optional_field(bgp_fields, "safi")),
        }
        orf_data = _optional_field(bgp_fields, "orf_data")
        if orf_data is not None:
            kwargs["orf_data"] = _bytes_field(orf_data)
        return (
            scapy_bgp.BGPHeader(type=message_type, **header_kwargs)
            / scapy_bgp.BGPRouteRefresh(**kwargs)
        )

    return scapy_bgp.BGPHeader(type=message_type, **header_kwargs)


def _bgp_header_kwargs(fields: Mapping[str, object]) -> dict[str, Any]:
    kwargs: dict[str, Any] = {}
    if "marker" in fields:
        kwargs["marker"] = _bgp_marker(fields["marker"])
    if "length" in fields or "len" in fields:
        kwargs["len"] = _int(_optional_field(fields, "length", "len"), 0)
    return kwargs


def _bgp_message_type(value: object) -> int:
    if isinstance(value, str):
        normalized = value.lower().replace("_", "-")
        if normalized in _BGP_MESSAGE_TYPES:
            return _BGP_MESSAGE_TYPES[normalized]
        return int(normalized, 0)
    return _int(value, 0)


def _bgp_marker(value: object) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return int.from_bytes(_bytes_exact(value, 16), "big")


def _bgp_raw_body(fields: Mapping[str, object]) -> bytes | None:
    value = _optional_field(fields, "body", "body_hex", "raw_body", "raw")
    if value is None:
        return None
    return _bytes_field(value)


def _bgp_open_raw_body(fields: Mapping[str, object]) -> bytes | None:
    optional_parameters = _optional_field(
        fields,
        "optional_parameters",
        "optional_parameters_hex",
        "opt_params",
        "capabilities",
    )
    if optional_parameters is None:
        return None
    parameters = _bytes_field(optional_parameters)
    param_len = _int(_optional_field(fields, "opt_param_len"), len(parameters))
    return (
        bytes([_int(_optional_field(fields, "version"), 4) & 0xFF])
        + _int(_optional_field(fields, "my_as", "asn"), 0).to_bytes(2, "big")
        + _int(_optional_field(fields, "hold_time"), 0).to_bytes(2, "big")
        + _ipv4_address_bytes(
            _optional_field(fields, "bgp_id", "bgp_identifier"),
            "0.0.0.0",
        )
        + bytes([param_len & 0xFF])
        + parameters
    )


def _bgp_update_raw_body(fields: Mapping[str, object]) -> bytes | None:
    withdrawn = _optional_field(fields, "withdrawn_routes", "withdrawn_routes_hex")
    path_attrs = _optional_field(
        fields,
        "path_attributes",
        "path_attributes_hex",
        "path_attr",
    )
    nlri = _optional_field(fields, "nlri", "nlri_hex")
    if withdrawn is None and path_attrs is None and nlri is None:
        return None
    withdrawn_bytes = _bytes_field(withdrawn) if withdrawn is not None else b""
    path_attr_bytes = _bytes_field(path_attrs) if path_attrs is not None else b""
    nlri_bytes = _bytes_field(nlri) if nlri is not None else b""
    withdrawn_len = _int(
        _optional_field(fields, "withdrawn_routes_len"),
        len(withdrawn_bytes),
    )
    path_attr_len = _int(_optional_field(fields, "path_attr_len"), len(path_attr_bytes))
    return (
        withdrawn_len.to_bytes(2, "big")
        + withdrawn_bytes
        + path_attr_len.to_bytes(2, "big")
        + path_attr_bytes
        + nlri_bytes
    )


def _bgp_afi(value: object) -> int:
    if isinstance(value, str):
        normalized = value.lower().replace("_", "-")
        mapping = {"ipv4": 1, "ip": 1, "ipv6": 2}
        if normalized in mapping:
            return mapping[normalized]
        return int(normalized, 0)
    return _int(value, 1)


def _bgp_safi(value: object) -> int:
    if isinstance(value, str):
        normalized = value.lower().replace("_", "-")
        mapping = {
            "unicast": 1,
            "multicast": 2,
            "nlri-unicast": 1,
        }
        if normalized in mapping:
            return mapping[normalized]
        return int(normalized, 0)
    return _int(value, 1)


# ---------------------------------------------------------------------------
# Decode
# ---------------------------------------------------------------------------


def _normalize(fields: JSONObject) -> JSONObject:
    """Normalize a decoded Scapy BGP layer to the comparable oracle shape.

    Byte-identical to the legacy ``_normalize_bgp_fields``: each native field name is
    renamed via the BGP field-name map (the lookup order ``_normalize_field_name``
    applied), the ``flags`` value is normalized through ``_normalize_flags`` (the
    former ``_normalize_field_value`` rule, with ``is_response``/``more_fragments``
    ints reduced to bools), an integer ``marker`` becomes its 16-octet hex form, an
    integer ``type`` resolves to its message-type name, and any empty optional region
    collapses to ``{"hex": ""}``.
    """

    output: JSONObject = {}
    for native_name, value in fields.items():
        normalized_name = _BGP_FIELD_NAME_MAP.get(native_name, native_name)
        output[normalized_name] = _normalize_field_value(normalized_name, value)

    marker = output.get("marker")
    if isinstance(marker, int) and not isinstance(marker, bool):
        output["marker"] = {"hex": marker.to_bytes(16, "big").hex()}

    message_type = output.get("type")
    if isinstance(message_type, int) and not isinstance(message_type, bool):
        output["message_type"] = _BGP_MESSAGE_TYPE_NAMES.get(message_type, message_type)

    for name in ("optional_parameters", "withdrawn_routes", "path_attributes", "nlri"):
        if output.get(name) == []:
            output[name] = {"hex": ""}
    return output


def _normalize_field_value(field_name: str, value: JSONValue) -> JSONValue:
    if field_name == "flags":
        return _normalize_flags(value)
    if field_name == "is_response" and isinstance(value, int):
        return bool(value)
    if field_name == "more_fragments" and isinstance(value, int):
        return bool(value)
    return value


register(
    ScapyProtocol(
        # ``scapy_class`` mirrors the former ``packets._SCAPY_LAYER_BY_LAYER["bgp"]``
        # value (``"BGPHeader"``, the BGP header class), which drives
        # ``_scapy_layer_name`` and the ``scapy_stack`` encode metadata. It must stay
        # ``BGPHeader`` (not the contrib module ``BGP``) so that metadata is
        # byte-identical to the legacy mapping (the same precedent as the IGMP
        # plugin's ``scapy_class="Raw"``).
        layer="bgp",
        scapy_class="BGPHeader",
        supported_fields=_SUPPORTED_FIELDS,
        build=_build,
        normalize=_normalize,
        layer_aliases=_LAYER_ALIASES,
        field_aliases=_FIELD_ALIASES,
    )
)
