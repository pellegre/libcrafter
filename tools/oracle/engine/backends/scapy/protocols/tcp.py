"""Scapy-stage encode + decode plugin for the TCP layer.

Moves the ``_tcp`` (TCP) builder and its option/flag helpers, plus the TCP decode
normalization, verbatim out of :mod:`..packets` and :mod:`..normalize` and registers
them through the :class:`~.base.ScapyProtocol` contract; only the dispatch moves out
of the legacy if/elif. Behavior must stay byte-identical.

TCP has no dedicated ``if layer_name == "tcp"`` block in the legacy
``_normalize_fields``; it decoded through the generic alias path plus the ``flags``
value rule. The plugin's ``_normalize`` reproduces that path exactly: each native
Scapy field name is renamed through the TCP field aliases (the former
``normalize._LAYER_FIELD_ALIASES["tcp"]`` merged over the global
``normalize._FIELD_ALIASES`` table, with the layer-specific names taking precedence
— the same lookup order ``_normalize_field_name`` used), and the ``flags`` value is
normalized through ``_normalize_tcp_flags`` (moved here); ``is_response`` and
``more_fragments`` ints become bools, matching the legacy value rules (neither
appears on a decoded TCP layer, so they are carried only for byte-identity).

Shared primitives come from the helper modules so this plugin does not depend on the
``packets``/``normalize`` orchestrators (which would create a circular import).
Relative imports only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ....model import JSONObject, JSONValue
from ..encode_helpers import (
    _int,
    _layer_fields,
    _option_bytes,
    _optional_field,
    _required_field,
)
from .base import ScapyProtocol, register


# Encode-side field allowlist for ``_validate_layer_fields`` — the canonical field
# names plus every Scapy/oracle alias the TCP builder accepts. Mirrors the former
# ``packets._SUPPORTED_FIELDS_BY_LAYER["tcp"]`` entry exactly.
_SUPPORTED_FIELDS = frozenset(
    {
        "ack",
        "acknowledgement",
        "checksum",
        "chksum",
        "data_offset",
        "dataofs",
        "dport",
        "dst_port",
        "flags",
        "options",
        "reserved",
        "seq",
        "sequence",
        "sport",
        "src_port",
        "urgent_pointer",
        "urgptr",
        "window",
    }
)

# Decode-side native-name aliases the TCP layer owns. ``layer_aliases`` maps the
# Scapy class name to the oracle layer name (the former ``normalize._LAYER_ALIASES``
# entry); ``field_aliases`` records the TCP-specific field renames (the former
# ``normalize._LAYER_FIELD_ALIASES["tcp"]`` entry).
_LAYER_ALIASES = (("TCP", "tcp"),)
_FIELD_ALIASES = (
    ("ack", "acknowledgement"),
    ("seq", "sequence"),
)

# Global cross-layer field aliases the legacy ``_normalize_field_name`` consulted as
# a fallback after the layer-specific map (mirrors ``normalize._FIELD_ALIASES``). TCP
# only exercises a few of these (``sport``/``dport``/``chksum``/``dataofs``/
# ``urgptr``); the rest never appear on a decoded TCP layer, so carrying the full map
# is harmless and keeps the lookup byte-identical to the legacy generic path.
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
# Effective TCP field-name map: global aliases overlaid by the TCP-specific ones,
# exactly the precedence ``_normalize_field_name("tcp", ...)`` applied.
_TCP_FIELD_NAME_MAP: dict[str, str] = {**_GLOBAL_FIELD_ALIASES, **dict(_FIELD_ALIASES)}


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
    tcp_fields = _layer_fields(fields, "tcp")
    kwargs: dict[str, Any] = {
        "sport": _int(_required_field(tcp_fields, "tcp", "src_port", "sport"), 0),
        "dport": _int(_required_field(tcp_fields, "tcp", "dst_port", "dport"), 0),
        "flags": _tcp_flags(_required_field(tcp_fields, "tcp", "flags")),
        "seq": _int(_required_field(tcp_fields, "tcp", "sequence", "seq"), 0),
        "ack": _int(_required_field(tcp_fields, "tcp", "acknowledgement", "ack"), 0),
        "window": _int(_required_field(tcp_fields, "tcp", "window"), 0),
        "reserved": _int(_required_field(tcp_fields, "tcp", "reserved"), 0),
        "urgptr": _int(_optional_field(tcp_fields, "urgent_pointer", "urgptr"), 0),
    }
    if "checksum" in tcp_fields or "chksum" in tcp_fields:
        kwargs["chksum"] = _int(_optional_field(tcp_fields, "checksum", "chksum"), 0)
    if "data_offset" in tcp_fields or "dataofs" in tcp_fields:
        kwargs["dataofs"] = _int(_optional_field(tcp_fields, "data_offset", "dataofs"), 0)
    if "options" in tcp_fields:
        kwargs["options"] = _tcp_options(tcp_fields["options"])
    return scapy_all.TCP(**kwargs)


def _tcp_options(value: object) -> object:
    raw = _option_bytes(value)
    if raw is None:
        return value
    return _tcp_option_tuples(raw)


def _tcp_option_tuples(raw: bytes) -> list[object]:
    options: list[object] = []
    index = 0
    while index < len(raw):
        kind = raw[index]
        if kind == 0:
            options.append(("EOL", None))
            index += 1
            continue
        if kind == 1:
            options.append(("NOP", None))
            index += 1
            continue
        if index + 1 >= len(raw):
            options.append((kind, b""))
            break
        length = raw[index + 1]
        if length < 2 or index + length > len(raw):
            options.append((kind, raw[index + 2 :]))
            break
        data = raw[index + 2 : index + length]
        if kind == 2 and len(data) == 2:
            options.append(("MSS", int.from_bytes(data, "big")))
        elif kind == 3 and len(data) == 1:
            options.append(("WScale", data[0]))
        elif kind in {4, 5}:
            options.append((kind, data))
        elif kind == 8 and len(data) == 8:
            options.append(
                (
                    "Timestamp",
                    (
                        int.from_bytes(data[0:4], "big"),
                        int.from_bytes(data[4:8], "big"),
                    ),
                )
            )
        else:
            options.append((kind, data))
        index += length
    return options


def _tcp_flags(value: object) -> object:
    flag_names = {
        "fin": "F",
        "syn": "S",
        "rst": "R",
        "psh": "P",
        "ack": "A",
        "urg": "U",
        "ece": "E",
        "cwr": "C",
    }
    if isinstance(value, str):
        lowered = value.lower()
        if lowered == "all":
            return 0x1FF
        return flag_names.get(lowered, value)
    if isinstance(value, list):
        output = ""
        for item in value:
            if not isinstance(item, str):
                return value
            lowered = item.lower()
            if lowered == "all":
                return 0x1FF
            output += flag_names.get(lowered, item)
        return output
    return value


# ---------------------------------------------------------------------------
# Decode
# ---------------------------------------------------------------------------


def _normalize(fields: JSONObject) -> JSONObject:
    """Normalize a decoded Scapy TCP layer to the comparable oracle shape.

    Byte-identical to the legacy generic ``_normalize_fields`` path for tcp: each
    native field name is renamed via the TCP field-name map (the lookup order
    ``_normalize_field_name`` applied), and the ``flags`` value is normalized
    through ``_normalize_tcp_flags`` (the former ``_normalize_field_value`` rule),
    with ``is_response``/``more_fragments`` ints reduced to bools.
    """

    output: JSONObject = {}
    for native_name, value in fields.items():
        normalized_name = _TCP_FIELD_NAME_MAP.get(native_name, native_name)
        output[normalized_name] = _normalize_field_value(normalized_name, value)
    return output


def _normalize_field_value(field_name: str, value: JSONValue) -> JSONValue:
    if field_name == "flags":
        return _normalize_tcp_flags(value)
    if field_name == "is_response" and isinstance(value, int):
        return bool(value)
    if field_name == "more_fragments" and isinstance(value, int):
        return bool(value)
    return value


def _normalize_tcp_flags(value: JSONValue) -> JSONValue:
    if not isinstance(value, str):
        return value
    if not value:
        return "none"
    names = {
        "F": "fin",
        "S": "syn",
        "R": "rst",
        "P": "psh",
        "A": "ack",
        "U": "urg",
        "E": "ece",
        "C": "cwr",
        "N": "ns",
    }
    if all(char in names for char in value):
        return "|".join(names[char] for char in value)
    return value.lower().replace("+", "|").replace(" ", "_")


register(
    ScapyProtocol(
        layer="tcp",
        scapy_class="TCP",
        supported_fields=_SUPPORTED_FIELDS,
        build=_build,
        normalize=_normalize,
        layer_aliases=_LAYER_ALIASES,
        field_aliases=_FIELD_ALIASES,
    )
)
