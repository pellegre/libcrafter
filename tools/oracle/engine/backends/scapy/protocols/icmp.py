"""Scapy-stage encode + decode plugin for the ICMPv4 and ICMPv6 layers.

Moves the ``_icmp`` (ICMPv4) and ``_icmpv6`` (ICMPv6*) builders, their rest-of-header
/ body / type-mapping helpers, the ``_ICMP_ID_SEQ_TYPES`` table, and the per-layer
ICMP decode normalization verbatim out of :mod:`..packets` and :mod:`..normalize`
and registers them through the :class:`~.base.ScapyProtocol` contract; only the
dispatch moves out of the legacy if/elif. Behavior must stay byte-identical.

Two layers are registered. ``icmp`` materializes Scapy's ``ICMP`` class (or opaque
raw bytes for rest-of-header shapes the reference layer cannot type); ``icmpv6``
materializes the per-type ``ICMPv6*`` class selected by ``_icmpv6_class_name``. The
decode side reproduces the legacy generic ``_normalize_fields`` path for each layer:
each native field name is renamed through the layer field aliases (the former
``normalize._LAYER_FIELD_ALIASES["icmp"]``/``["icmpv6"]`` merged over the global
``normalize._FIELD_ALIASES`` table, with the layer-specific names taking precedence —
the lookup order ``_normalize_field_name`` used), the ``type`` value is collapsed
onto the spec domain name, and the icmp post-pass (drop ``unused``/empty ``data``,
fill ``rest_of_header``; and for icmpv6 the rest-of-header derivation) runs exactly
as the legacy ``layer_name in {"icmp", "icmpv6"}`` block did.

The whole-packet ICMPv4 canonicalization pass (``_canonicalize_icmpv4``) and the
central ``_normalize_layer_name`` ``ICMPv6`` prefix special-case are whole-packet
post-passes / root routing, not per-layer normalize, so they stay in
:mod:`..normalize` (the established pattern for whole-stack passes).

Shared primitives come from the helper modules so this plugin does not depend on the
``packets``/``normalize`` orchestrators (which would create a circular import).
Relative imports only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ....model import JSONObject, JSONValue
from ..encode_helpers import (
    _int,
    _internet_checksum,
    _ipv4_address_bytes,
    _layer_fields,
    _option_bytes,
    _optional_field,
    _payload_bytes,
    _required_field,
    _text,
)
from .base import ScapyProtocol, register


# Encode-side field allowlists for ``_validate_layer_fields`` — the canonical field
# names plus every Scapy/oracle alias each builder accepts. Mirror the former
# ``packets._SUPPORTED_FIELDS_BY_LAYER["icmp"]``/``["icmpv6"]`` entries exactly.
_ICMP_SUPPORTED_FIELDS = frozenset(
    {
        "checksum",
        "chksum",
        "code",
        "id",
        "identifier",
        "seq",
        "sequence",
        "type",
        # ICMPv4 live-matrix rest-of-header and type-specific body fields. These
        # carry the oracle-normalized names the generator emits; the Scapy
        # materializer translates them to Scapy-native ICMP fields where the
        # reference layer types them, or to deterministic raw rest-of-header /
        # payload bytes for the raw-compatible cases.
        "rest_of_header",
        "gateway",
        "pointer",
        "next_hop_mtu",
        "originate_timestamp",
        "receive_timestamp",
        "transmit_timestamp",
        "address_mask",
        "router_addresses",
        "router_address_entry_size",
        "router_lifetime",
        "extension_bytes",
        "embedded_header",
    }
)
_ICMPV6_SUPPORTED_FIELDS = frozenset(
    {"checksum", "cksum", "code", "id", "identifier", "seq", "sequence", "type"}
)

# Decode-side native-name aliases each layer owns. ``layer_aliases`` maps the Scapy
# class name to the oracle layer name (the former ``normalize._LAYER_ALIASES``
# entry); ``field_aliases`` records the layer-specific field renames (the former
# ``normalize._LAYER_FIELD_ALIASES["icmp"]``/``["icmpv6"]`` entries). The ICMPv6
# native classes (``ICMPv6EchoRequest``, ``ICMPv6DestUnreach`` …) are mapped to
# ``icmpv6`` by the central ``_normalize_layer_name`` ``startswith("ICMPv6")`` rule
# (a whole-family routing rule that stays in ``normalize``), so the icmpv6 plugin
# carries no per-class ``layer_aliases``.
_ICMP_LAYER_ALIASES = (("ICMP", "icmp"),)
_ICMP_FIELD_ALIASES = (
    ("id", "identifier"),
    ("seq", "sequence"),
)
_ICMPV6_LAYER_ALIASES: tuple[tuple[str, str], ...] = ()
_ICMPV6_FIELD_ALIASES = (
    ("cksum", "checksum"),
    ("id", "identifier"),
    ("seq", "sequence"),
)

# Global cross-layer field aliases the legacy ``_normalize_field_name`` consulted as
# a fallback after the layer-specific map (mirrors ``normalize._FIELD_ALIASES``). The
# ICMP layers only exercise ``chksum``; the rest never appear on a decoded ICMP layer,
# so carrying the full map is harmless and keeps the lookup byte-identical to the
# legacy generic path.
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
# Effective field-name maps: global aliases overlaid by the layer-specific ones,
# exactly the precedence ``_normalize_field_name(<layer>, ...)`` applied.
_ICMP_FIELD_NAME_MAP: dict[str, str] = {
    **_GLOBAL_FIELD_ALIASES,
    **dict(_ICMP_FIELD_ALIASES),
}
_ICMPV6_FIELD_NAME_MAP: dict[str, str] = {
    **_GLOBAL_FIELD_ALIASES,
    **dict(_ICMPV6_FIELD_ALIASES),
}


# ===========================================================================
# Encode
# ===========================================================================

# ICMPv4 types whose rest-of-header Scapy's ICMP layer exposes via the id/seq
# pair (echo, timestamp, information, address-mask, and the deprecated query
# families that reuse the identifier/sequence layout).
_ICMP_ID_SEQ_TYPES = frozenset(
    {
        "echo-reply",
        "echo-request",
        "timestamp-request",
        "timestamp-reply",
        "information-request",
        "information-response",
        "address-mask-request",
        "address-mask-reply",
    }
)

# ICMPv4 type names the generator emits, mapped to the Scapy ICMP type-field
# name (or numeric type for shapes the reference ICMP layer does not enumerate).
# The reference enum names some types differently (information-response,
# timestamp-request) and does not list extended-echo (42/43), so these are mapped
# explicitly to keep materialization byte-correct.
_ICMP_TYPE_ALIASES: dict[str, object] = {
    "echo-reply": "echo-reply",
    "echo-request": "echo-request",
    "destination-unreachable": "dest-unreach",
    "dest-unreach": "dest-unreach",
    "source-quench": "source-quench",
    "redirect": "redirect",
    "router-advertisement": "router-advertisement",
    "router-solicitation": "router-solicitation",
    "time-exceeded": "time-exceeded",
    "parameter-problem": "parameter-problem",
    "timestamp": "timestamp-request",
    "timestamp-request": "timestamp-request",
    "timestamp-reply": "timestamp-reply",
    "information-request": "information-request",
    "information-reply": "information-response",
    "information-response": "information-response",
    "address-mask-request": "address-mask-request",
    "address-mask-reply": "address-mask-reply",
    "traceroute": "traceroute",
    "datagram-conversion-error": "datagram-conversion-error",
    "mobile-host-redirect": "mobile-host-redirect",
    "domain-name-request": "domain-name-request",
    "domain-name-reply": "domain-name-reply",
    "photuris": "photuris",
    # ICMPv4 types the reference ICMP type field does not enumerate; emit the
    # numeric type so the byte stays correct (raw-compatible).
    "extended-echo-request": 42,
    "extended-echo-reply": 43,
}

# Mapping table from the normalized ICMPv6 `type` domain to the native Scapy
# class that materializes it. Echo + the four RFC 4443 errors are live today;
# the NDP (RFC 4861) and MLD (RFC 2710 / RFC 3810) kinds below are scaffolding —
# Scapy has native classes for them, but libcrafter does not emit these wire
# bytes yet, so no smoke coverage_case references them. The per-message steps
# that add the bytes attach their cases and extend the body materialization
# (target/dest addresses, NDP option lists) on top of this entry point.
_ICMPV6_CLASS_NAMES: dict[str, str] = {
    "dest-unreach": "ICMPv6DestUnreach",
    "destination-unreachable": "ICMPv6DestUnreach",
    "echo-reply": "ICMPv6EchoReply",
    "echo-request": "ICMPv6EchoRequest",
    "packet-too-big": "ICMPv6PacketTooBig",
    "parameter-problem": "ICMPv6ParamProblem",
    "time-exceeded": "ICMPv6TimeExceeded",
    # NDP (RFC 4861) — scaffolded for later steps.
    "router-solicitation": "ICMPv6ND_RS",
    "router-advertisement": "ICMPv6ND_RA",
    "neighbor-solicitation": "ICMPv6ND_NS",
    "neighbor-advertisement": "ICMPv6ND_NA",
    "redirect": "ICMPv6ND_Redirect",
    # MLD (RFC 2710 / RFC 3810 / RFC 9777) — scaffolded for later steps. The
    # type-130 query is MLDv1; the MLDv2 query (ICMPv6MLQuery2) shares the type
    # and is selected by the per-message materializer when records are present.
    "mld-query": "ICMPv6MLQuery",
    "mld-report": "ICMPv6MLReport",
    "mld-done": "ICMPv6MLDone",
    "mldv2-report": "ICMPv6MLReport2",
    # Extended echo (RFC 8335, types 160/161) has no native Scapy ICMPv6 class;
    # the per-message materializer emits the numeric type (raw-compatible),
    # mirroring the ICMPv4 extended-echo path, so it is intentionally absent
    # from this native-class table.
}


def _icmp_type(value: object) -> object:
    if isinstance(value, str):
        lowered = value.lower().replace("_", "-")
        return _ICMP_TYPE_ALIASES.get(lowered, lowered)
    return value


def _icmpv6_class_name(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError(f"unsupported Scapy icmpv6 type materialization: {value!r}")
    lowered = value.lower().replace("_", "-")
    class_name = _ICMPV6_CLASS_NAMES.get(lowered)
    if class_name is None:
        raise ValueError(f"unsupported Scapy icmpv6 type materialization: {value!r}")
    return class_name


def _build_icmp(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    return _icmp(fields, scapy_all)


def _build_icmpv6(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    return _icmpv6(fields, list(stack), scapy_all)


def _icmp(fields: Mapping[str, JSONObject], scapy_all: Any) -> Any:
    icmp_fields = _layer_fields(fields, "icmp")
    scapy_type = _icmp_type(_required_field(icmp_fields, "icmp", "type"))
    icmp_type_int = _icmp_type_number(scapy_type, scapy_all)
    code = _int(_required_field(icmp_fields, "icmp", "code"), 0)
    type_name = scapy_type if isinstance(scapy_type, str) else None

    body = _icmp_body_bytes(icmp_fields)
    explicit_rest = icmp_fields.get("rest_of_header")

    # Types whose four-byte rest-of-header the reference ICMP layer cannot type
    # (router solicitation, legacy/deprecated families, extended echo) carry an
    # explicit rest_of_header. Build opaque ICMP bytes so those four bytes land
    # in the real rest-of-header rather than as trailing payload; parsing them
    # back through Scapy can trigger type-specific body expectations.
    if explicit_rest is not None:
        rest_bytes = _icmp_rest_of_header_bytes(explicit_rest)
        if "checksum" in icmp_fields or "chksum" in icmp_fields:
            checksum = _int(_optional_field(icmp_fields, "checksum", "chksum"), 0)
        else:
            checksum = _internet_checksum(
                bytes([icmp_type_int & 0xFF, code & 0xFF, 0, 0]) + rest_bytes + body
            )
        header = bytes([icmp_type_int & 0xFF, code & 0xFF])
        header += checksum.to_bytes(2, "big") + rest_bytes
        return scapy_all.Raw(load=header + body)

    kwargs: dict[str, Any] = {"type": scapy_type, "code": code}

    # id/seq map to the Scapy ICMP rest-of-header only for the query families that
    # the reference layer types with the identifier/sequence pair.
    if type_name in _ICMP_ID_SEQ_TYPES:
        if "id" in icmp_fields or "identifier" in icmp_fields:
            kwargs["id"] = _int(_optional_field(icmp_fields, "id", "identifier"), 0)
        if "seq" in icmp_fields or "sequence" in icmp_fields:
            kwargs["seq"] = _int(_optional_field(icmp_fields, "seq", "sequence"), 0)

    # Scapy-native typed rest-of-header fields.
    if "gateway" in icmp_fields:
        kwargs["gw"] = _text(icmp_fields.get("gateway"), "0.0.0.0")
    if "pointer" in icmp_fields:
        kwargs["ptr"] = _int(icmp_fields.get("pointer"), 0)
    if "next_hop_mtu" in icmp_fields:
        kwargs["nexthopmtu"] = _int(icmp_fields.get("next_hop_mtu"), 0)
    if "address_mask" in icmp_fields:
        kwargs["addr_mask"] = _text(icmp_fields.get("address_mask"), "0.0.0.0")
    if "originate_timestamp" in icmp_fields:
        kwargs["ts_ori"] = _int(icmp_fields.get("originate_timestamp"), 0)
    if "receive_timestamp" in icmp_fields:
        kwargs["ts_rx"] = _int(icmp_fields.get("receive_timestamp"), 0)
    if "transmit_timestamp" in icmp_fields:
        kwargs["ts_tx"] = _int(icmp_fields.get("transmit_timestamp"), 0)

    if "checksum" in icmp_fields or "chksum" in icmp_fields:
        kwargs["chksum"] = _int(_optional_field(icmp_fields, "checksum", "chksum"), 0)

    icmp = scapy_all.ICMP(**kwargs)
    if body:
        return icmp / scapy_all.Raw(load=body)
    return icmp


def _icmp_type_number(scapy_type: object, scapy_all: Any) -> int:
    """Resolve an ICMP type to its numeric value for raw-header construction."""

    if isinstance(scapy_type, int):
        return scapy_type
    if isinstance(scapy_type, str):
        type_field = next(
            field for field in scapy_all.ICMP.fields_desc if field.name == "type"
        )
        for number, name in getattr(type_field, "i2s", {}).items():
            if name == scapy_type:
                return number
        return int(scapy_type, 0)
    raise ValueError(f"unsupported ICMP type for materialization: {scapy_type!r}")


def _icmp_rest_of_header_bytes(value: object) -> bytes:
    rest = _icmp_hex_bytes(value)
    if len(rest) != 4:
        raise ValueError(
            f"ICMP rest_of_header must be exactly four bytes, got {len(rest)}"
        )
    return rest


def _icmp_body_bytes(icmp_fields: Mapping[str, JSONObject]) -> bytes:
    """Deterministic raw bytes that follow the ICMP four-byte rest-of-header.

    Covers ICMP shapes the reference ICMP layer does not type natively: the
    quoted (embedded) original IPv4 datagram carried by RFC 792 error messages,
    the RFC 1256 router-advertisement address list, and the RFC 4884/4950
    extension framing blobs. The quoted datagram comes first (immediately after
    the rest-of-header), then any extension objects, matching RFC 4884 framing.
    Both backends emit and parse these bytes identically.
    """

    body = b""

    embedded = icmp_fields.get("embedded_header")
    embedded_bytes = _icmp_hex_bytes(embedded)
    if embedded_bytes:
        body += embedded_bytes

    routers = icmp_fields.get("router_addresses")
    if isinstance(routers, list) and routers:
        body += _icmp_router_address_bytes(routers)

    extension = icmp_fields.get("extension_bytes")
    extension_bytes = _icmp_hex_bytes(extension)
    if extension_bytes:
        body += extension_bytes

    return body


def _icmp_router_address_bytes(routers: Sequence[object]) -> bytes:
    raw = b""
    for entry in routers:
        if not isinstance(entry, Mapping):
            continue
        address = _text(entry.get("address"), "0.0.0.0")
        preference = _int(entry.get("preference"), 0)
        raw += _ipv4_address_bytes(address)
        raw += preference.to_bytes(4, "big")
    return raw


def _icmp_hex_bytes(value: object) -> bytes:
    if value is None:
        return b""
    raw = _option_bytes(value)
    if raw is None:
        raise ValueError(f"ICMP rest-of-header/extension bytes must be hex, got {value!r}")
    return raw


def _icmpv6(fields: Mapping[str, JSONObject], stack: list[str], scapy_all: Any) -> Any:
    icmpv6_fields = _layer_fields(fields, "icmpv6")
    icmp_type = _icmp_type(_required_field(icmpv6_fields, "icmpv6", "type"))
    class_name = _icmpv6_class_name(icmp_type)
    layer_factory = getattr(scapy_all, class_name, None)
    if layer_factory is None:
        raise ValueError(f"Scapy layer is unavailable for icmpv6 type {icmp_type!r}: {class_name}")

    kwargs: dict[str, Any] = {}
    if "code" in icmpv6_fields:
        kwargs["code"] = _int(icmpv6_fields.get("code"), 0)
    if "checksum" in icmpv6_fields or "cksum" in icmpv6_fields:
        kwargs["cksum"] = _int(_optional_field(icmpv6_fields, "checksum", "cksum"), 0)
    if class_name in {"ICMPv6EchoReply", "ICMPv6EchoRequest"}:
        if "id" in icmpv6_fields or "identifier" in icmpv6_fields:
            kwargs["id"] = _int(_optional_field(icmpv6_fields, "id", "identifier"), 0)
        if "seq" in icmpv6_fields or "sequence" in icmpv6_fields:
            kwargs["seq"] = _int(_optional_field(icmpv6_fields, "seq", "sequence"), 0)
    if "payload" not in stack:
        payload = _payload_bytes(fields)
        if payload:
            kwargs["data"] = payload
    return layer_factory(**kwargs)


# ===========================================================================
# Decode
# ===========================================================================


def _normalize_icmp(fields: JSONObject) -> JSONObject:
    """Normalize a decoded Scapy ICMPv4 layer to the comparable oracle shape.

    Byte-identical to the legacy generic ``_normalize_fields`` path for icmp: each
    native field name is renamed via the ICMP field-name map (the lookup order
    ``_normalize_field_name`` applied), the ``type`` value is collapsed onto the spec
    domain via ``_normalize_icmpv4_type``, and the icmp post-pass drops the synthetic
    ``unused``/empty ``data`` fields and fills ``rest_of_header``.
    """

    output: JSONObject = {}
    for native_name, value in fields.items():
        normalized_name = _ICMP_FIELD_NAME_MAP.get(native_name, native_name)
        output[normalized_name] = _normalize_icmp_field_value(normalized_name, value)
    _icmp_rest_of_header_post_pass(output)
    return output


def _normalize_icmpv6(fields: JSONObject) -> JSONObject:
    """Normalize a decoded Scapy ICMPv6 layer to the comparable oracle shape.

    Byte-identical to the legacy generic ``_normalize_fields`` path for icmpv6: each
    native field name is renamed via the ICMPv6 field-name map, the ``type`` value is
    collapsed onto the spec domain via ``_normalize_icmpv6_type``, and the icmp
    post-pass (shared with icmpv4) plus ``_normalize_icmpv6_rest_of_header`` run.
    """

    output: JSONObject = {}
    for native_name, value in fields.items():
        normalized_name = _ICMPV6_FIELD_NAME_MAP.get(native_name, native_name)
        output[normalized_name] = _normalize_icmpv6_field_value(normalized_name, value)
    _icmp_rest_of_header_post_pass(output)
    _normalize_icmpv6_rest_of_header(output)
    return output


def _icmp_rest_of_header_post_pass(output: JSONObject) -> None:
    """Shared icmp/icmpv6 post-pass from the legacy ``_normalize_fields`` block."""

    output.pop("unused", None)
    if output.get("data") == {"hex": "", "ascii": ""}:
        output.pop("data", None)
    _fill_icmp_rest_of_header(output)


def _normalize_icmp_field_value(field_name: str, value: JSONValue) -> JSONValue:
    if field_name == "type" and isinstance(value, str):
        return _normalize_icmpv4_type(value)
    if field_name == "is_response" and isinstance(value, int):
        return bool(value)
    if field_name == "more_fragments" and isinstance(value, int):
        return bool(value)
    return value


def _normalize_icmpv6_field_value(field_name: str, value: JSONValue) -> JSONValue:
    if field_name == "type" and isinstance(value, str):
        return _normalize_icmpv6_type(value)
    if field_name == "is_response" and isinstance(value, int):
        return bool(value)
    if field_name == "more_fragments" and isinstance(value, int):
        return bool(value)
    return value


def _normalize_icmpv6_type(value: str) -> str:
    lowered = value.lower().replace(" ", "_").replace("-", "_")
    aliases = {
        "echo_reply": "echo_reply",
        "echo_request": "echo_request",
        "destination_unreachable": "destination_unreachable",
        "packet_too_big": "packet_too_big",
        "parameter_problem": "parameter_problem",
        "time_exceeded": "time_exceeded",
        # NDP (RFC 4861). Scapy's ND classes report descriptive type strings
        # (e.g. "Neighbor Solicitation"); collapse them onto the spec domain
        # names so decoded NDP/MLD/extended-echo kinds compare cleanly once the
        # per-message coverage cases land. Scaffolding for later steps.
        "router_solicitation": "router_solicitation",
        "router_advertisement": "router_advertisement",
        "neighbor_solicitation": "neighbor_solicitation",
        "neighbor_advertisement": "neighbor_advertisement",
        "redirect": "redirect",
        "redirect_message": "redirect",
        # MLD (RFC 2710 / RFC 3810 / RFC 9777).
        "mld_query": "mld_query",
        "multicast_listener_query": "mld_query",
        "mld_report": "mld_report",
        "multicast_listener_report": "mld_report",
        "mld_done": "mld_done",
        "multicast_listener_done": "mld_done",
        "mldv2_report": "mldv2_report",
        "version_2_multicast_listener_report": "mldv2_report",
        # Extended echo (RFC 8335, types 160/161).
        "extended_echo_request": "extended_echo_request",
        "extended_echo_reply": "extended_echo_reply",
    }
    return aliases.get(lowered, lowered)


def _normalize_icmpv4_type(value: str) -> str:
    lowered = value.lower().replace(" ", "_").replace("-", "_")
    aliases = {
        "dest_unreach": "destination_unreachable",
        "destination_unreachable": "destination_unreachable",
        "echo_reply": "echo_reply",
        "echo_request": "echo_request",
        "parameter_problem": "parameter_problem",
        "redirect": "redirect",
        "time_exceeded": "time_exceeded",
    }
    return aliases.get(lowered, lowered)


def _fill_icmp_rest_of_header(fields: JSONObject) -> None:
    if "rest_of_header" in fields:
        return
    identifier = fields.get("identifier")
    sequence = fields.get("sequence")
    if isinstance(identifier, int) and isinstance(sequence, int):
        fields["rest_of_header"] = f"{identifier:04x}{sequence:04x}"


def _normalize_icmpv6_rest_of_header(fields: JSONObject) -> None:
    icmp_type = fields.get("type")
    if icmp_type in {2, "packet_too_big"} and isinstance(fields.get("mtu"), int):
        fields["rest_of_header"] = f"{fields.pop('mtu'):08x}"
    elif icmp_type in {4, "parameter_problem"} and isinstance(fields.get("ptr"), int):
        fields["rest_of_header"] = f"{fields.pop('ptr'):08x}"
    elif icmp_type in {1, 3, "destination_unreachable", "time_exceeded"}:
        fields.setdefault("rest_of_header", "00000000")

    if fields.get("ext") is None:
        fields.pop("ext", None)
    if fields.get("extpad") == {"hex": "", "ascii": ""}:
        fields.pop("extpad", None)


register(
    ScapyProtocol(
        layer="icmp",
        scapy_class="ICMP",
        supported_fields=_ICMP_SUPPORTED_FIELDS,
        build=_build_icmp,
        normalize=_normalize_icmp,
        layer_aliases=_ICMP_LAYER_ALIASES,
        field_aliases=_ICMP_FIELD_ALIASES,
    )
)

register(
    ScapyProtocol(
        layer="icmpv6",
        scapy_class="ICMPv6EchoRequest",
        supported_fields=_ICMPV6_SUPPORTED_FIELDS,
        build=_build_icmpv6,
        normalize=_normalize_icmpv6,
        layer_aliases=_ICMPV6_LAYER_ALIASES,
        field_aliases=_ICMPV6_FIELD_ALIASES,
    )
)
