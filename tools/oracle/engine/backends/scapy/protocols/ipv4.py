"""Scapy-stage encode + decode plugin for the IPv4 layer.

Moves the ``_ipv4`` (IP) builder and the IPv4 decode normalization verbatim out of
:mod:`..packets` and :mod:`..normalize` and registers them through the
:class:`~.base.ScapyProtocol` contract; only the dispatch moves out of the legacy
if/elif. Behavior must stay byte-identical.

IPv4 has no dedicated ``if layer_name == "ipv4"`` block in the legacy
``_normalize_fields``; it decoded through the generic alias path plus the
``flags`` value rule. The plugin's ``_normalize`` reproduces that path exactly:
each native Scapy field name is renamed through the IPv4 field aliases (the
former ``normalize._LAYER_FIELD_ALIASES["ipv4"]`` merged over the global
``normalize._FIELD_ALIASES`` table, with the layer-specific names taking
precedence — the same lookup order ``_normalize_field_name`` used), and the
``flags`` value is normalized through ``_normalize_ipv4_flags`` (moved here);
``more_fragments`` ints become bools, matching the legacy value rule.

Shared primitives come from the helper modules so this plugin does not depend on
the ``packets``/``normalize`` orchestrators (which would create a circular
import). Relative imports only so the package resolves under both the ``engine.*``
(CLI) and ``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ....model import JSONObject, JSONValue
from ..decode_helpers import _normalize_flags
from ..encode_helpers import (
    _IP_PROTOCOLS,
    _int,
    _ipv4_flags,
    _layer_fields,
    _option_bytes,
    _optional_field,
    _protocol_value,
    _required_field,
    _text,
)
from .base import ScapyProtocol, register


# Encode-side field allowlist for ``_validate_layer_fields`` — the canonical
# field names plus every Scapy/oracle alias the IPv4 builder accepts. Mirrors the
# former ``packets._SUPPORTED_FIELDS_BY_LAYER["ipv4"]`` entry exactly.
_SUPPORTED_FIELDS = frozenset(
    {
        "dst",
        "ds_field",
        "flags",
        "frag",
        "fragment_offset",
        "id",
        "identification",
        "options",
        "protocol",
        "proto",
        "src",
        "tos",
        "ttl",
    }
)

# Decode-side native-name aliases the IPv4 layer owns. ``layer_aliases`` maps the
# Scapy class name to the oracle layer name (the former ``normalize._LAYER_ALIASES``
# entry); ``field_aliases`` records the IPv4-specific field renames (the former
# ``normalize._LAYER_FIELD_ALIASES["ipv4"]`` entry).
_LAYER_ALIASES = (("IP", "ipv4"),)
_FIELD_ALIASES = (
    ("id", "identification"),
    ("ihl", "header_length"),
)

# Global cross-layer field aliases the legacy ``_normalize_field_name`` consulted
# as a fallback after the layer-specific map (mirrors ``normalize._FIELD_ALIASES``).
# IPv4 only exercises a few of these (``frag``/``proto``/``len``/``chksum``); the
# rest never appear on a decoded IP layer, so carrying the full map is harmless and
# keeps the lookup byte-identical to the legacy generic path.
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
# Effective IPv4 field-name map: global aliases overlaid by the IPv4-specific ones,
# exactly the precedence ``_normalize_field_name("ipv4", ...)`` applied.
_IPV4_FIELD_NAME_MAP: dict[str, str] = {**_GLOBAL_FIELD_ALIASES, **dict(_FIELD_ALIASES)}


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
    ipv4_fields = _layer_fields(fields, "ipv4")
    kwargs: dict[str, Any] = {
        "src": _text(_required_field(ipv4_fields, "ipv4", "src"), ""),
        "dst": _text(_required_field(ipv4_fields, "ipv4", "dst"), ""),
        "id": _int(_required_field(ipv4_fields, "ipv4", "identification", "id"), 0),
        "ttl": _int(_required_field(ipv4_fields, "ipv4", "ttl"), 0),
        "flags": _ipv4_flags(_required_field(ipv4_fields, "ipv4", "flags")),
        "proto": _protocol_value(
            _required_field(ipv4_fields, "ipv4", "protocol", "proto"), _IP_PROTOCOLS
        ),
    }
    if "tos" in ipv4_fields:
        kwargs["tos"] = _int(ipv4_fields.get("tos"), 0)
    if "ds_field" in ipv4_fields:
        kwargs["tos"] = _int(ipv4_fields.get("ds_field"), 0)
    if "fragment_offset" in ipv4_fields or "frag" in ipv4_fields:
        kwargs["frag"] = _int(_optional_field(ipv4_fields, "fragment_offset", "frag"), 0)
    if "options" in ipv4_fields:
        kwargs["options"] = _ipv4_options(ipv4_fields["options"], scapy_all)
    return scapy_all.IP(**kwargs)


def _ipv4_options(value: object, scapy_all: Any) -> object:
    raw = _option_bytes(value)
    if raw is not None:
        if not raw:
            return []
        return [scapy_all.IPOption(raw)]
    return value


# ---------------------------------------------------------------------------
# Decode
# ---------------------------------------------------------------------------


def _normalize(fields: JSONObject) -> JSONObject:
    """Normalize a decoded Scapy IP layer to the comparable oracle shape.

    Byte-identical to the legacy generic ``_normalize_fields`` path for ipv4: each
    native field name is renamed via the IPv4 field-name map (the lookup order
    ``_normalize_field_name`` applied), and the ``flags`` value is normalized
    through ``_normalize_ipv4_flags`` (the former ``_normalize_field_value`` rule),
    with ``more_fragments`` ints reduced to bools.
    """

    output: JSONObject = {}
    for native_name, value in fields.items():
        normalized_name = _IPV4_FIELD_NAME_MAP.get(native_name, native_name)
        output[normalized_name] = _normalize_field_value(normalized_name, value)
    return output


def _normalize_field_value(field_name: str, value: JSONValue) -> JSONValue:
    if field_name == "flags":
        return _normalize_ipv4_flags(value)
    if field_name == "is_response" and isinstance(value, int):
        return bool(value)
    if field_name == "more_fragments" and isinstance(value, int):
        return bool(value)
    return value


def _normalize_ipv4_flags(value: JSONValue) -> JSONValue:
    normalized = _normalize_flags(value)
    if isinstance(normalized, str):
        tokens = [
            "reserved" if token == "evil" else token for token in normalized.split("|")
        ]
        return "|".join(tokens)
    return normalized


register(
    ScapyProtocol(
        layer="ipv4",
        scapy_class="IP",
        supported_fields=_SUPPORTED_FIELDS,
        build=_build,
        normalize=_normalize,
        layer_aliases=_LAYER_ALIASES,
        field_aliases=_FIELD_ALIASES,
    )
)
