"""Scapy-stage encode + decode plugin for the OSPF layer.

Moves the ``_ospf`` builder and its per-type body helpers, the
``_OSPF_PACKET_TYPES`` / ``_OSPF_AUTYPES`` maps, and the per-layer
``_normalize_ospf_fields`` normalizer verbatim out of :mod:`..packets` and
:mod:`..normalize` and registers them through the :class:`~.base.ScapyProtocol`
contract; only the dispatch moves out of the legacy if/elif. Behavior must stay
byte-identical.

OSPF seeds only the common-header scalars during sampling; the per-type body fields
are attached during the generator's smoke-case pass, so the builder routes on the
RFC 2328 packet type and materializes the matching
``OSPF_Hello``/``OSPF_DBDesc``/``OSPF_LSReq``/``OSPF_LSUpd``/``OSPF_LSAck`` body —
or re-emits an explicit raw ``body`` after the common header for unknown types so
it round-trips without Scapy re-interpreting it.

The per-layer ``_normalize`` reproduces the legacy ``_normalize_fields("ospf",
...)`` path exactly: each native field name is renamed via the OSPF field-name map
(the former ``normalize._LAYER_FIELD_ALIASES["ospf"]`` overlaid on the global
``normalize._FIELD_ALIASES``, the same precedence ``_normalize_field_name("ospf",
...)`` applied), each value is reduced via ``_normalize_field_value`` (the generic
``flags``/``is_response``/``more_fragments`` rules), and then the OSPF-specific
``_normalize_ospf_fields`` tweaks collapse the ``type``/``autype`` enums to the
oracle-neutral domain names, render the 64-bit ``authentication`` as raw hex, and
add ``lsa_header_count``.

The whole-packet ``OSPF_*`` body-layer folding in ``normalize_packet`` (the
``_is_ospf_body_layer`` pass) operates on the assembled packet rather than a single
decoded layer, so — following the step-22/24/25 precedent — it stays in
:mod:`..normalize` and is not moved here. The decode-side ``layer_aliases`` this
plugin registers keep ``OSPF_Hdr`` / ``OSPF_Hello`` / ``OSPF_DBDesc`` /
``OSPF_LSReq`` / ``OSPF_LSUpd`` / ``OSPF_LSAck`` resolving to ``ospf`` so that
whole-packet pass continues to find the OSPF layer.

Shared primitives come from the helper modules so this plugin does not depend on the
``packets``/``normalize`` orchestrators (which would create a circular import).
``import_scapy`` (for the Scapy OSPF contrib classes) comes from :mod:`..bootstrap`.
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
    _bytes_field,
    _int,
    _layer_fields_for_stack_index,
    _optional_field,
    _required_field,
    _text,
)
from .base import ScapyProtocol, register


# Oracle-neutral OSPFv2 packet-type domain names (specs/layers/ospf.yaml) mapped
# to the RFC 2328 type codes the OSPF_Hdr type field carries. Mirrors the former
# ``packets._OSPF_PACKET_TYPES`` map.
_OSPF_PACKET_TYPES: dict[str, int] = {
    "hello": 1,
    "database_description": 2,
    "database-description": 2,
    "link_state_request": 3,
    "link-state-request": 3,
    "link_state_update": 4,
    "link-state-update": 4,
    "link_state_ack": 5,
    "link-state-ack": 5,
}
# Oracle-neutral OSPF AuType domain names mapped to the AuType codes. Mirrors the
# former ``packets._OSPF_AUTYPES`` map.
_OSPF_AUTYPES: dict[str, int] = {
    "null": 0,
    "simple": 1,
    "simple_password": 1,
    "cryptographic": 2,
}

# Encode-side field allowlist for ``_validate_layer_fields`` — the canonical field
# names plus every Scapy/oracle alias the OSPF builder accepts. Mirrors the former
# ``packets._SUPPORTED_FIELDS_BY_LAYER["ospf"]`` entry exactly.
_SUPPORTED_FIELDS = frozenset(
    {
        # Oracle-neutral OSPFv2 common-header fields from specs/layers/ospf.yaml.
        "version",
        "type",
        "packet_length",
        "length",
        "len",
        "router_id",
        "area_id",
        "checksum",
        "autype",
        "authentication",
        # Per-type OSPFv2 body fields (Hello / DD / LSR / LSU / LSAck). The
        # reference layer types these; unknown packet types or an explicit raw
        # body fall back to opaque OSPF bytes.
        "network_mask",
        "hello_interval",
        "options",
        "router_priority",
        "router_dead_interval",
        "designated_router",
        "backup_designated_router",
        "neighbors",
        "interface_mtu",
        "dd_flags",
        "dd_sequence_number",
        "lsa_headers",
        "requests",
        "lsas",
        "num_lsas",
        "body",
        "body_hex",
        "raw",
        "raw_body",
    }
)

# Decode-side native-name aliases the OSPF layer owns. ``layer_aliases`` maps each
# Scapy OSPF class name to the oracle layer name (the former
# ``normalize._LAYER_ALIASES`` entries); ``field_aliases`` records the OSPF-specific
# field renames (the former ``normalize._LAYER_FIELD_ALIASES["ospf"]`` entry).
_LAYER_ALIASES = (
    ("OSPF_Hdr", "ospf"),
    ("OSPF_Hello", "ospf"),
    ("OSPF_DBDesc", "ospf"),
    ("OSPF_LSReq", "ospf"),
    ("OSPF_LSUpd", "ospf"),
    ("OSPF_LSAck", "ospf"),
)
_FIELD_ALIASES = (
    # OSPF_Hdr common-header fields mapped to the oracle-neutral names declared in
    # specs/layers/ospf.yaml.
    ("len", "packet_length"),
    ("src", "router_id"),
    ("area", "area_id"),
    ("chksum", "checksum"),
    ("authtype", "autype"),
    ("authdata", "authentication"),
    # OSPF_Hello / OSPF_DBDesc body fields.
    ("mask", "network_mask"),
    ("hellointerval", "hello_interval"),
    ("prio", "router_priority"),
    ("deadinterval", "router_dead_interval"),
    ("router", "designated_router"),
    ("backup", "backup_designated_router"),
    ("mtu", "interface_mtu"),
    ("dbdescr", "dd_flags"),
    ("ddseq", "dd_sequence_number"),
    ("lsaheaders", "lsa_headers"),
)

# Global cross-layer field aliases the legacy ``_normalize_field_name`` consulted as
# a fallback after the layer-specific map (mirrors ``normalize._FIELD_ALIASES``). The
# OSPF-specific map overrides ``len`` and ``chksum``; the rest never appear on a
# decoded OSPF layer, so carrying the full map is harmless and keeps the lookup
# byte-identical to the legacy generic path.
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
# Effective OSPF field-name map: global aliases overlaid by the OSPF-specific ones,
# exactly the precedence ``_normalize_field_name("ospf", ...)`` applied.
_OSPF_FIELD_NAME_MAP: dict[str, str] = {**_GLOBAL_FIELD_ALIASES, **dict(_FIELD_ALIASES)}

# OSPF_Hdr type codes (RFC 2328) rendered by Scapy's ShortEnumField as descriptive
# strings; collapse them onto the oracle-neutral packet-type domain names from
# specs/layers/ospf.yaml so a decoded type compares against the plan. Mirrors the
# former ``normalize._OSPF_TYPE_NAMES`` map.
_OSPF_TYPE_NAMES: dict[int, str] = {
    1: "hello",
    2: "database_description",
    3: "link_state_request",
    4: "link_state_update",
    5: "link_state_ack",
}
# OSPF AuType codes mapped to the oracle-neutral autype domain names. Mirrors the
# former ``normalize._OSPF_AUTYPE_NAMES`` map.
_OSPF_AUTYPE_NAMES: dict[int, str] = {
    0: "null",
    1: "simple",
    2: "cryptographic",
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
    return _ospf(fields, stack, index, scapy_all)


def _ospf(
    fields: Mapping[str, JSONObject],
    stack: Sequence[str],
    index: int,
    scapy_all: Any,
) -> Any:
    """Materialize an OSPFv2 packet for the ``[ipv4, ospf, payload]`` stack.

    The oracle-neutral common-header field names from ``specs/layers/ospf.yaml``
    map to the ``scapy.contrib.ospf`` ``OSPF_Hdr`` fields (version/type/len/src/
    area/chksum/authtype/authdata); the per-type body fields map to the matching
    ``OSPF_Hello``/``OSPF_DBDesc``/``OSPF_LSReq``/``OSPF_LSUpd``/``OSPF_LSAck``
    bodies. Unknown packet types or an explicit raw ``body`` fall back to opaque
    OSPF bytes after the common header so they round-trip without Scapy
    re-interpreting them.
    """

    scapy_ospf = import_scapy()["ospf"]
    ospf_fields = _layer_fields_for_stack_index(fields, stack, index)
    packet_type = _ospf_packet_type(_required_field(ospf_fields, "ospf", "type"))
    header_kwargs = _ospf_header_kwargs(ospf_fields, packet_type)
    header = scapy_ospf.OSPF_Hdr(type=packet_type, **header_kwargs)

    body = _ospf_raw_body(ospf_fields)
    if body is not None:
        return header / scapy_all.Raw(load=body)

    if packet_type == 1:
        return header / _ospf_hello(ospf_fields, scapy_ospf)
    if packet_type == 2:
        return header / _ospf_database_description(ospf_fields, scapy_ospf)
    if packet_type == 3:
        return header / _ospf_link_state_request(ospf_fields, scapy_ospf)
    if packet_type == 4:
        return header / _ospf_link_state_update(ospf_fields, scapy_ospf)
    if packet_type == 5:
        return header / _ospf_link_state_ack(ospf_fields, scapy_ospf)
    return header


def _ospf_header_kwargs(fields: Mapping[str, object], packet_type: int) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "version": _int(_optional_field(fields, "version"), 2),
    }
    router_id = _optional_field(fields, "router_id")
    if router_id is not None:
        kwargs["src"] = _text(router_id, "0.0.0.0")
    area_id = _optional_field(fields, "area_id")
    if area_id is not None:
        kwargs["area"] = _text(area_id, "0.0.0.0")
    if _optional_field(fields, "packet_length", "length", "len") is not None:
        kwargs["len"] = _int(_optional_field(fields, "packet_length", "length", "len"), 0)
    if _optional_field(fields, "checksum") is not None:
        kwargs["chksum"] = _int(_optional_field(fields, "checksum"), 0)
    if _optional_field(fields, "autype") is not None:
        kwargs["authtype"] = _ospf_autype(_optional_field(fields, "autype"))
    authentication = _optional_field(fields, "authentication")
    if authentication is not None:
        kwargs["authdata"] = int.from_bytes(_bytes_field(authentication, pad_to=8)[:8], "big")
    return kwargs


def _ospf_packet_type(value: object) -> int:
    if isinstance(value, str):
        normalized = value.lower().replace("-", "_")
        if normalized in _OSPF_PACKET_TYPES:
            return _OSPF_PACKET_TYPES[normalized]
        return int(normalized, 0)
    return _int(value, 0)


def _ospf_autype(value: object) -> int:
    if isinstance(value, str):
        normalized = value.lower().replace("-", "_")
        if normalized in _OSPF_AUTYPES:
            return _OSPF_AUTYPES[normalized]
        return int(normalized, 0)
    return _int(value, 0)


def _ospf_raw_body(fields: Mapping[str, object]) -> bytes | None:
    value = _optional_field(fields, "body", "body_hex", "raw_body", "raw")
    if value is None:
        return None
    return _bytes_field(value)


def _ospf_neighbors(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (str, bytes, bytearray)):
        return [_text(value, "0.0.0.0")]
    if isinstance(value, Sequence):
        return [_text(item, "0.0.0.0") for item in value]
    return []


def _ospf_hello(fields: Mapping[str, object], scapy_ospf: Any) -> Any:
    kwargs: dict[str, Any] = {
        "neighbors": _ospf_neighbors(_optional_field(fields, "neighbors")),
    }
    if _optional_field(fields, "network_mask") is not None:
        kwargs["mask"] = _text(_optional_field(fields, "network_mask"), "0.0.0.0")
    if _optional_field(fields, "hello_interval") is not None:
        kwargs["hellointerval"] = _int(_optional_field(fields, "hello_interval"), 0)
    if _optional_field(fields, "options") is not None:
        kwargs["options"] = _int(_optional_field(fields, "options"), 0)
    if _optional_field(fields, "router_priority") is not None:
        kwargs["prio"] = _int(_optional_field(fields, "router_priority"), 0)
    if _optional_field(fields, "router_dead_interval") is not None:
        kwargs["deadinterval"] = _int(_optional_field(fields, "router_dead_interval"), 0)
    if _optional_field(fields, "designated_router") is not None:
        kwargs["router"] = _text(_optional_field(fields, "designated_router"), "0.0.0.0")
    if _optional_field(fields, "backup_designated_router") is not None:
        kwargs["backup"] = _text(_optional_field(fields, "backup_designated_router"), "0.0.0.0")
    return scapy_ospf.OSPF_Hello(**kwargs)


def _ospf_database_description(fields: Mapping[str, object], scapy_ospf: Any) -> Any:
    kwargs: dict[str, Any] = {
        "lsaheaders": _ospf_lsa_headers(_optional_field(fields, "lsa_headers"), scapy_ospf),
    }
    if _optional_field(fields, "interface_mtu") is not None:
        kwargs["mtu"] = _int(_optional_field(fields, "interface_mtu"), 0)
    if _optional_field(fields, "options") is not None:
        kwargs["options"] = _int(_optional_field(fields, "options"), 0)
    if _optional_field(fields, "dd_flags") is not None:
        kwargs["dbdescr"] = _int(_optional_field(fields, "dd_flags"), 0)
    if _optional_field(fields, "dd_sequence_number") is not None:
        kwargs["ddseq"] = _int(_optional_field(fields, "dd_sequence_number"), 0)
    return scapy_ospf.OSPF_DBDesc(**kwargs)


def _ospf_link_state_request(fields: Mapping[str, object], scapy_ospf: Any) -> Any:
    requests = _optional_field(fields, "requests")
    items: list[Any] = []
    if isinstance(requests, Sequence) and not isinstance(requests, (str, bytes, bytearray)):
        for entry in requests:
            if not isinstance(entry, Mapping):
                continue
            items.append(
                scapy_ospf.OSPF_LSReq_Item(
                    type=_int(_optional_field(entry, "ls_type", "type"), 0),
                    id=_text(_optional_field(entry, "link_state_id", "id"), "0.0.0.0"),
                    adrouter=_text(
                        _optional_field(entry, "advertising_router", "adrouter"),
                        "0.0.0.0",
                    ),
                )
            )
    return scapy_ospf.OSPF_LSReq(requests=items)


def _ospf_link_state_update(fields: Mapping[str, object], scapy_ospf: Any) -> Any:
    kwargs: dict[str, Any] = {
        "lsalist": _ospf_lsa_list(_optional_field(fields, "lsas"), scapy_ospf),
    }
    if _optional_field(fields, "num_lsas") is not None:
        kwargs["lsacount"] = _int(_optional_field(fields, "num_lsas"), 0)
    return scapy_ospf.OSPF_LSUpd(**kwargs)


def _ospf_link_state_ack(fields: Mapping[str, object], scapy_ospf: Any) -> Any:
    return scapy_ospf.OSPF_LSAck(
        lsaheaders=_ospf_lsa_headers(_optional_field(fields, "lsa_headers"), scapy_ospf)
    )


def _ospf_lsa_headers(value: object, scapy_ospf: Any) -> list[Any]:
    headers: list[Any] = []
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for entry in value:
            if not isinstance(entry, Mapping):
                continue
            headers.append(_ospf_lsa_header(entry, scapy_ospf))
    return headers


def _ospf_lsa_header(entry: Mapping[str, object], scapy_ospf: Any) -> Any:
    kwargs: dict[str, Any] = {
        "age": _int(_optional_field(entry, "ls_age", "age"), 0),
        "options": _int(_optional_field(entry, "options"), 0),
        "type": _int(_optional_field(entry, "ls_type", "type"), 0),
        "id": _text(_optional_field(entry, "link_state_id", "id"), "0.0.0.0"),
        "adrouter": _text(
            _optional_field(entry, "advertising_router", "adrouter"),
            "0.0.0.0",
        ),
        "seq": _int(_optional_field(entry, "ls_sequence_number", "seq"), 0x80000001),
    }
    if _optional_field(entry, "ls_checksum", "chksum") is not None:
        kwargs["chksum"] = _int(_optional_field(entry, "ls_checksum", "chksum"), 0)
    if _optional_field(entry, "length", "len") is not None:
        kwargs["len"] = _int(_optional_field(entry, "length", "len"), 0)
    return scapy_ospf.OSPF_LSA_Hdr(**kwargs)


def _ospf_lsa_list(value: object, scapy_ospf: Any) -> list[Any]:
    lsas: list[Any] = []
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for entry in value:
            if not isinstance(entry, Mapping):
                continue
            header = _ospf_lsa_header(entry, scapy_ospf)
            body = _optional_field(entry, "body", "body_hex", "raw")
            if body is not None:
                lsas.append(header / import_scapy()["all"].Raw(load=_bytes_field(body)))
            else:
                lsas.append(header)
    return lsas


# ---------------------------------------------------------------------------
# Decode
# ---------------------------------------------------------------------------


def _normalize(fields: JSONObject) -> JSONObject:
    """Normalize a decoded Scapy OSPF layer to the comparable oracle shape.

    Byte-identical to the legacy ``_normalize_fields("ospf", ...)`` path: each
    native field name is renamed via the OSPF field-name map (the lookup order
    ``_normalize_field_name`` applied), each value is reduced via
    ``_normalize_field_value`` (the generic ``flags``/``is_response``/
    ``more_fragments`` rules), and then ``_normalize_ospf_fields`` collapses the
    ``type``/``autype`` enums to the oracle-neutral domain names, renders the 64-bit
    ``authentication`` as raw hex, and adds ``lsa_header_count``.
    """

    output: JSONObject = {}
    for native_name, value in fields.items():
        normalized_name = _OSPF_FIELD_NAME_MAP.get(native_name, native_name)
        output[normalized_name] = _normalize_field_value(normalized_name, value)
    _normalize_ospf_fields(output)
    return output


def _normalize_field_value(field_name: str, value: JSONValue) -> JSONValue:
    if field_name == "flags":
        return _normalize_flags(value)
    if field_name == "is_response" and isinstance(value, int):
        return bool(value)
    if field_name == "more_fragments" and isinstance(value, int):
        return bool(value)
    return value


def _normalize_ospf_fields(fields: JSONObject) -> None:
    """Normalize decoded OSPFv2 fields into the backend-neutral oracle shape.

    The common-header field names are already aliased (len->packet_length,
    src->router_id, area->area_id, chksum->checksum, authtype->autype,
    authdata->authentication). This reduces the remaining Scapy-typed values to
    comparable forms: the packet ``type`` and ``autype`` enum strings collapse to
    the oracle-neutral domain names, and the 64-bit authentication field is
    rendered as raw hex bytes so both backends compare byte-for-byte.
    """

    type_value = fields.get("type")
    if isinstance(type_value, int) and not isinstance(type_value, bool):
        fields["type"] = _OSPF_TYPE_NAMES.get(type_value, type_value)
    elif isinstance(type_value, str):
        fields["type"] = _ospf_enum_token(type_value)

    autype_value = fields.get("autype")
    if isinstance(autype_value, int) and not isinstance(autype_value, bool):
        fields["autype"] = _OSPF_AUTYPE_NAMES.get(autype_value, autype_value)
    elif isinstance(autype_value, str):
        fields["autype"] = _ospf_enum_token(autype_value)

    authentication = fields.get("authentication")
    if isinstance(authentication, int) and not isinstance(authentication, bool):
        fields["authentication"] = {"hex": authentication.to_bytes(8, "big").hex()}

    lsa_headers = fields.get("lsa_headers")
    if isinstance(lsa_headers, list):
        fields["lsa_header_count"] = len(lsa_headers)


def _ospf_enum_token(value: str) -> str:
    return value.strip().lower().replace(" ", "_").replace("-", "_")


register(
    ScapyProtocol(
        # ``scapy_class`` mirrors the former ``packets._SCAPY_LAYER_BY_LAYER["ospf"]``
        # value (``"OSPF_Hdr"``, the OSPF common-header class), which drives
        # ``_scapy_layer_name`` and the ``scapy_stack`` encode metadata. It must stay
        # ``OSPF_Hdr`` so that metadata is byte-identical to the legacy mapping.
        layer="ospf",
        scapy_class="OSPF_Hdr",
        supported_fields=_SUPPORTED_FIELDS,
        build=_build,
        normalize=_normalize,
        layer_aliases=_LAYER_ALIASES,
        field_aliases=_FIELD_ALIASES,
    )
)
