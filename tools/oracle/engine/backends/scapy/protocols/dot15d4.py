"""Scapy-stage encode + decode plugin for the IEEE 802.15.4 / Zigbee layers.

Owns the four spec layers of the 802.15.4 family — ``dot15d4`` (MAC frame),
``dot15d4_radio`` (the IEEE 802.15.4 TAP / DLT 283 pseudo-header), ``zigbee_nwk``
(Zigbee NWK), and ``zigbee_aps`` (Zigbee APS) — mirroring how the crate groups the
Zigbee sublayers under ``protocols/link/dot15d4``. The builders map the
libcrafter-neutral plan fields onto scapy's native ``Dot15d4FCS`` / ``Dot15d4Data``
MAC layers and the ``ZigbeeNWK`` / ``ZigbeeAppDataPayload`` layers
(``scapy.layers.dot15d4`` / ``scapy.layers.zigbee``, loaded by
``bootstrap.import_scapy`` which pins ``conf.dot15d4_protocol="zigbee"``); the
emitted bytes match libcrafter's wire encoding, and the trailing CRC-16/CCITT FCS
is produced by scapy's ``Dot15d4FCS`` makeFCS, which matches libcrafter's reflected
FCS. The TAP pseudo-header has no native scapy dissector, so ``dot15d4_radio`` is a
Raw passthrough (the BLE LL-with-PHDR precedent): libcrafter's ``Dot15d4Radio`` owns
the TAP descriptor decode, so the radio layer carries no strict-byte descriptor
fields here and the following MAC frame provides the wire bytes.

Each layer registers a :class:`~.base.ScapyProtocol`. ``scapy_class`` drives the
``scapy_stack`` metadata, ``_scapy_layer_name`` and ``_is_materialized_layer``;
``supported_fields`` is the encode-side field allowlist (canonical names plus the
scapy/oracle aliases the builders accept), moved out of the former
``packets._SUPPORTED_FIELDS_BY_LAYER`` entries. ``layer_aliases`` carries the
decode-side native-name map (``Dot15d4FCS`` / ``Dot15d4Data`` -> ``dot15d4``,
``ZigbeeNWK`` -> ``zigbee_nwk``, ``ZigbeeAppDataPayload`` -> ``zigbee_aps``) that
``normalize._normalize_layer_name`` resolves from ``_registered_layer_aliases``; the
whole-packet ``normalize._canonicalize_dot15d4_zigbee`` pass then collapses the
``Dot15d4FCS`` + ``Dot15d4Data`` run into a single ``Dot15d4`` MAC layer and renames
the Zigbee sublayers to the libcrafter names, so neither layer needs a per-layer
``normalize`` hook.

Shared primitives come from :mod:`..encode_helpers` so this plugin does not depend
on the ``packets`` orchestrator (which would create a circular import). Relative
imports only so the package resolves under both the ``engine.*`` (CLI) and
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
    _layer_fields,
    _optional_field,
    _payload_bytes,
)
from .base import ScapyProtocol, register


# spec frame_type -> scapy fcf_frametype codepoint.
_DOT15D4_FRAME_TYPES: dict[str, int] = {
    "beacon": 0,
    "data": 1,
    "ack": 2,
    "acknowledgement": 2,
    "command": 3,
    "mac_command": 3,
}
# spec addressing mode -> scapy fcf_*addrmode codepoint.
_DOT15D4_ADDR_MODES: dict[str, int] = {
    "none": 0,
    "absent": 0,
    "short_16": 2,
    "short": 2,
    "extended_64": 3,
    "extended": 3,
    "long": 3,
}
# spec zigbee NWK frame_type -> scapy frametype codepoint.
_ZIGBEE_NWK_FRAME_TYPES: dict[str, int] = {
    "data": 0,
    "command": 1,
    "inter_pan": 3,
    "inter-pan": 3,
}
# spec zigbee APS frame_type -> scapy aps_frametype codepoint.
_ZIGBEE_APS_FRAME_TYPES: dict[str, int] = {
    "data": 0,
    "command": 1,
    "ack": 2,
    "acknowledgement": 2,
}
# spec zigbee APS delivery_mode -> scapy delivery_mode codepoint.
_ZIGBEE_APS_DELIVERY_MODES: dict[str, int] = {
    "unicast": 0,
    "indirect": 1,
    "broadcast": 2,
    "group": 3,
    "group_addressing": 3,
}


# Encode-side field allowlists for ``_validate_layer_fields`` — the canonical field
# names plus every scapy/oracle alias the builders accept. Mirror the former
# ``packets._SUPPORTED_FIELDS_BY_LAYER`` entries exactly.
_DOT15D4_SUPPORTED_FIELDS = frozenset(
    {
        "ack_request",
        "dest_addr",
        "dest_addr_mode",
        "dest_extended",
        "dest_pan",
        "dest_short",
        "fcs",
        "frame_pending",
        "frame_type",
        "frame_version",
        "pan_id_compression",
        "payload",
        "payload_hex",
        "security_enabled",
        "seq",
        "sequence_number",
        "src_addr",
        "src_addr_mode",
        "src_extended",
        "src_pan",
        "src_short",
    }
)
_DOT15D4_RADIO_SUPPORTED_FIELDS = frozenset(
    {
        "channel",
        "fcs_type",
        "fcs_valid",
        "lqi",
        "rssi",
    }
)
_ZIGBEE_NWK_SUPPORTED_FIELDS = frozenset(
    {
        "dest",
        "frame_type",
        "payload",
        "payload_hex",
        "protocol_version",
        "radius",
        "seq",
        "src",
    }
)
_ZIGBEE_APS_SUPPORTED_FIELDS = frozenset(
    {
        "cluster",
        "counter",
        "delivery_mode",
        "dest_endpoint",
        "frame_type",
        "payload",
        "payload_hex",
        "profile",
        "src_endpoint",
    }
)


# Decode-side native-name aliases each layer owns: the scapy class names mapped to
# the oracle layer names (the former ``normalize._LAYER_ALIASES`` dot15d4/zigbee
# entries). ``_normalize_layer_name`` resolves them from ``_registered_layer_aliases``.
# Scapy splits the MAC header into ``Dot15d4FCS`` + ``Dot15d4Data`` (both -> dot15d4);
# the whole-packet ``_canonicalize_dot15d4_zigbee`` pass then collapses the run.
_DOT15D4_LAYER_ALIASES = (
    ("Dot15d4", "dot15d4"),
    ("Dot15d4FCS", "dot15d4"),
    ("Dot15d4Data", "dot15d4"),
)
_ZIGBEE_NWK_LAYER_ALIASES = (("ZigbeeNWK", "zigbee_nwk"),)
_ZIGBEE_APS_LAYER_ALIASES = (("ZigbeeAppDataPayload", "zigbee_aps"),)


# ---------------------------------------------------------------------------
# Encode helpers
# ---------------------------------------------------------------------------


def _dot15d4_enum(value: object, table: Mapping[str, int], default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        key = value.lower().replace("-", "_")
        if key in table:
            return table[key]
        return int(value, 0)
    raise ValueError(f"unsupported IEEE 802.15.4/Zigbee enum value: {value!r}")


def _has_child_layer(stack: Sequence[str], index: int) -> bool:
    """Return True when a non-payload protocol layer follows ``index``.

    dot15d4/zigbee plans carry the upper protocol as a stacked layer (zigbee_nwk
    inside dot15d4, zigbee_aps inside zigbee_nwk). When such a child exists the
    builder must not append its own ``payload`` field, because the composed child
    layer is the real payload; only the terminal layer materializes its declared
    opaque payload bytes.
    """

    return any(layer != "payload" and layer != "raw" for layer in stack[index + 1 :])


def _layer_opaque_payload(
    fields: Mapping[str, JSONObject],
    stack: Sequence[str],
    index: int,
    layer_fields: Mapping[str, object],
) -> bytes:
    """Resolve the trailing opaque payload bytes for a dot15d4/zigbee layer.

    The bytes come from the layer's own ``payload``/``payload_hex`` field, or from a
    following ``payload`` stack entry, and are only emitted when no protocol child
    layer follows this one in the stack.
    """

    if _has_child_layer(stack, index):
        return b""
    payload_field = _optional_field(layer_fields, "payload", "payload_hex")
    if payload_field is not None:
        return _opaque_bytes(payload_field)
    # Fall back to a following payload/raw stack entry, if present.
    for following in stack[index + 1 :]:
        if following in ("payload", "raw"):
            return _payload_bytes(fields)
    return b""


def _opaque_bytes(value: object) -> bytes:
    if value is None:
        return b""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return bytes.fromhex(value)
    if isinstance(value, Mapping):
        return _bytes_field(value)
    raise ValueError(f"unsupported IEEE 802.15.4/Zigbee payload value: {value!r}")


# ---------------------------------------------------------------------------
# Encode builders (uniform ``build(plan, fields, stack, index, scapy_all)`` shape)
# ---------------------------------------------------------------------------


def _build_dot15d4_radio(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    """Materialize the IEEE 802.15.4 TAP (DLT 283) pseudo-header.

    Scapy 2.7 has no native Dot15d4 TAP dissector. libcrafter's Dot15d4Radio owns
    the TAP descriptor decode, so the radio layer carries no strict-byte descriptor
    fields here and is emitted as an empty Raw passthrough (the BLE LL-with-PHDR
    precedent); the following MAC frame provides the wire bytes.
    """

    _ = _layer_fields(fields, "dot15d4_radio")
    return scapy_all.Raw(load=b"")


def _build_dot15d4(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: list[str],
    index: int,
    scapy_all: Any,
) -> Any:
    """Build an IEEE 802.15.4 MAC frame via scapy Dot15d4FCS / Dot15d4Data.

    The Dot15d4FCS header carries the frame-control field, sequence number, and the
    trailing CRC-16/CCITT FCS; Dot15d4Data carries the addressing fields when a
    destination or source addressing mode is present. PAN-ID compression, the
    addressing modes, and the address widths are all encoded by scapy from the
    frame-control codepoints, matching libcrafter's wire layout.
    """

    mac = _layer_fields(fields, "dot15d4")
    frame_type = _dot15d4_enum(
        _optional_field(mac, "frame_type"), _DOT15D4_FRAME_TYPES, 1
    )
    dest_mode = _dot15d4_enum(
        _optional_field(mac, "dest_addr_mode"), _DOT15D4_ADDR_MODES, 0
    )
    src_mode = _dot15d4_enum(
        _optional_field(mac, "src_addr_mode"), _DOT15D4_ADDR_MODES, 0
    )
    # When the plan omits explicit addressing modes but supplies addresses, infer
    # the mode from the address presence so the frame is self-consistent.
    if _optional_field(mac, "dest_addr_mode") is None:
        if _optional_field(mac, "dest_extended") is not None:
            dest_mode = 3
        elif _optional_field(mac, "dest_short", "dest_addr") is not None:
            dest_mode = 2
    if _optional_field(mac, "src_addr_mode") is None:
        if _optional_field(mac, "src_extended") is not None:
            src_mode = 3
        elif _optional_field(mac, "src_short", "src_addr") is not None:
            src_mode = 2

    fcf_kwargs: dict[str, Any] = {
        "fcf_frametype": frame_type,
        "fcf_destaddrmode": dest_mode,
        "fcf_srcaddrmode": src_mode,
        "fcf_panidcompress": _bool_int(_optional_field(mac, "pan_id_compression"), 0),
        "seqnum": _int(_optional_field(mac, "seq", "sequence_number"), 0),
    }
    if _optional_field(mac, "security_enabled") is not None:
        fcf_kwargs["fcf_security"] = _bool_int(mac.get("security_enabled"), 0)
    if _optional_field(mac, "frame_pending") is not None:
        fcf_kwargs["fcf_pending"] = _bool_int(mac.get("frame_pending"), 0)
    if _optional_field(mac, "ack_request") is not None:
        fcf_kwargs["fcf_ackreq"] = _bool_int(mac.get("ack_request"), 0)
    if _optional_field(mac, "frame_version") is not None:
        fcf_kwargs["fcf_framever"] = _int(mac.get("frame_version"), 0)
    if _optional_field(mac, "fcs") is not None:
        fcf_kwargs["fcs"] = _int(mac.get("fcs"), 0)

    packet = scapy_all.Dot15d4FCS(**fcf_kwargs)

    if dest_mode != 0 or src_mode != 0:
        data_kwargs: dict[str, Any] = {}
        if dest_mode != 0:
            data_kwargs["dest_panid"] = _int(_optional_field(mac, "dest_pan"), 0xFFFF)
            data_kwargs["dest_addr"] = _int(
                _optional_field(mac, "dest_extended", "dest_short", "dest_addr"), 0
            )
        if src_mode != 0:
            if _optional_field(mac, "src_pan") is not None:
                data_kwargs["src_panid"] = _int(mac.get("src_pan"), 0xFFFF)
            data_kwargs["src_addr"] = _int(
                _optional_field(mac, "src_extended", "src_short", "src_addr"), 0
            )
        packet = packet / scapy_all.Dot15d4Data(**data_kwargs)

    trailer = _layer_opaque_payload(fields, stack, index, mac)
    if trailer:
        packet = packet / scapy_all.Raw(load=trailer)
    return packet


def _build_zigbee_nwk(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: list[str],
    index: int,
    scapy_all: Any,
) -> Any:
    """Build a Zigbee NWK header via scapy ZigbeeNWK.

    Maps the libcrafter-neutral frame type, protocol version, 16-bit dest/src
    addresses, radius, and sequence number onto the scapy constructor.
    """

    nwk = _layer_fields(fields, "zigbee_nwk")
    kwargs: dict[str, Any] = {
        "frametype": _dot15d4_enum(
            _optional_field(nwk, "frame_type"), _ZIGBEE_NWK_FRAME_TYPES, 0
        ),
        "proto_version": _int(_optional_field(nwk, "protocol_version"), 2),
        "flags": 0,
        "discover_route": 0,
        "destination": _int(_optional_field(nwk, "dest"), 0),
        "source": _int(_optional_field(nwk, "src"), 0),
        "radius": _int(_optional_field(nwk, "radius"), 0),
        "seqnum": _int(_optional_field(nwk, "seq"), 0),
    }
    packet = scapy_all.ZigbeeNWK(**kwargs)
    trailer = _layer_opaque_payload(fields, stack, index, nwk)
    if trailer:
        packet = packet / scapy_all.Raw(load=trailer)
    return packet


def _build_zigbee_aps(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: list[str],
    index: int,
    scapy_all: Any,
) -> Any:
    """Build a Zigbee APS header via scapy ZigbeeAppDataPayload.

    Maps the libcrafter-neutral frame type, delivery mode, destination/source
    endpoints, cluster id, profile id, and APS counter onto the scapy constructor.
    dst_endpoint / cluster / profile / src_endpoint are conditional scapy fields
    driven by the frame type and delivery mode; the data frame / unicast delivery
    used by the spec stack carries all four.
    """

    aps = _layer_fields(fields, "zigbee_aps")
    kwargs: dict[str, Any] = {
        "aps_frametype": _dot15d4_enum(
            _optional_field(aps, "frame_type"), _ZIGBEE_APS_FRAME_TYPES, 0
        ),
        "delivery_mode": _dot15d4_enum(
            _optional_field(aps, "delivery_mode"), _ZIGBEE_APS_DELIVERY_MODES, 0
        ),
        "frame_control": 0,
        "counter": _int(_optional_field(aps, "counter"), 0),
    }
    if _optional_field(aps, "dest_endpoint") is not None:
        kwargs["dst_endpoint"] = _int(aps.get("dest_endpoint"), 0)
    if _optional_field(aps, "cluster") is not None:
        kwargs["cluster"] = _int(aps.get("cluster"), 0)
    if _optional_field(aps, "profile") is not None:
        kwargs["profile"] = _int(aps.get("profile"), 0)
    if _optional_field(aps, "src_endpoint") is not None:
        kwargs["src_endpoint"] = _int(aps.get("src_endpoint"), 0)
    packet = scapy_all.ZigbeeAppDataPayload(**kwargs)
    trailer = _layer_opaque_payload(fields, stack, index, aps)
    if trailer:
        packet = packet / scapy_all.Raw(load=trailer)
    return packet


register(
    ScapyProtocol(
        layer="dot15d4",
        scapy_class="Dot15d4",
        supported_fields=_DOT15D4_SUPPORTED_FIELDS,
        build=_build_dot15d4,
        normalize=None,
        layer_aliases=_DOT15D4_LAYER_ALIASES,
    )
)
register(
    ScapyProtocol(
        layer="dot15d4_radio",
        scapy_class="Raw",
        supported_fields=_DOT15D4_RADIO_SUPPORTED_FIELDS,
        build=_build_dot15d4_radio,
        normalize=None,
    )
)
register(
    ScapyProtocol(
        layer="zigbee_nwk",
        scapy_class="ZigbeeNWK",
        supported_fields=_ZIGBEE_NWK_SUPPORTED_FIELDS,
        build=_build_zigbee_nwk,
        normalize=None,
        layer_aliases=_ZIGBEE_NWK_LAYER_ALIASES,
    )
)
register(
    ScapyProtocol(
        layer="zigbee_aps",
        scapy_class="ZigbeeAppDataPayload",
        supported_fields=_ZIGBEE_APS_SUPPORTED_FIELDS,
        build=_build_zigbee_aps,
        normalize=None,
        layer_aliases=_ZIGBEE_APS_LAYER_ALIASES,
    )
)
