"""Scapy-stage encode + decode plugins for the simple framing/wrapper layers.

Covers ``payload``, ``null_loopback``, ``linux_cooked`` and ``llc_snap``. The
``payload``/``raw`` Raw build, the ``_linux_cooked`` (CookedLinux) and
``_null_loopback`` (Loopback) builders, and their decode-side class/field aliases
are moved verbatim out of :mod:`..packets` and :mod:`..normalize` and registered
through the :class:`~.base.ScapyProtocol` contract; only the dispatch moves out of
the legacy if/elif. Behavior must stay byte-identical.

``llc_snap`` only materializes through the Wi-Fi (Dot11 phase-1.5) raw-bytes path,
so it has no standalone per-layer Scapy builder — its ``build`` raises exactly as
the legacy ``_build_layer`` would have. Only its generic framing handling (the
``LLC/SNAP`` class name and the ``LLC``/``SNAP`` decode aliases) is migrated here;
the Wi-Fi composition (``_llc_snap_bytes`` encode and ``_decode_llc_or_payload``
decode) stays with the Wi-Fi steps.

Decode-name vs. spec-name note: a decoded ``CookedLinux`` layer normalizes under
the name ``linux_sll`` (not the spec layer name ``linux_cooked``). The registry is
keyed by the spec layer name, so the ``CookedLinux -> linux_sll`` class alias is
carried here (registry-derived, preserving the decoded name) while the per-field
``linux_sll`` decode aliases and value normalization stay in :mod:`..normalize`,
reached through the generic alias path under the non-spec name ``linux_sll``.

Shared primitives come from :mod:`..encode_helpers` so this plugin does not depend
on the ``packets``/``normalize`` orchestrators (which would create a circular
import). Relative imports only so the package resolves under both the ``engine.*``
(CLI) and ``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ....model import JSONObject, PacketPlan
from ..encode_helpers import (
    _bytes_field,
    _ethertype_value,
    _hardware_type_value,
    _int,
    _layer_fields,
    _payload_bytes,
    _required_field,
)
from .base import ScapyProtocol, register


# Encode-side field allowlists for ``_validate_layer_fields`` — mirror the former
# ``packets._SUPPORTED_FIELDS_BY_LAYER[...]`` entries exactly.
_PAYLOAD_SUPPORTED_FIELDS = frozenset({"bytes_hex", "hex", "length", "text", "value"})
_NULL_LOOPBACK_SUPPORTED_FIELDS = frozenset({"type"})
_LINUX_COOKED_SUPPORTED_FIELDS = frozenset(
    {
        "address_length",
        "address_type",
        "packet_type",
        "protocol",
        "source_address",
    }
)
_LLC_SNAP_SUPPORTED_FIELDS = frozenset(
    {
        "control",
        "dsap",
        "ethertype",
        "oui",
        "payload_length",
        "ssap",
    }
)

# Decode-side class aliases each layer owns: native Scapy class name -> oracle
# layer name (mirroring the former ``normalize._LAYER_ALIASES`` entries).
_PAYLOAD_LAYER_ALIASES = (("Raw", "payload"),)
_NULL_LOOPBACK_LAYER_ALIASES = (("Loopback", "null_loopback"),)
# CookedLinux decodes under the non-spec name ``linux_sll``; its per-field decode
# aliases stay in ``normalize`` and are reached via the generic alias path.
_LINUX_COOKED_LAYER_ALIASES = (("CookedLinux", "linux_sll"),)
_LLC_SNAP_LAYER_ALIASES = (("LLC", "llc_snap"), ("SNAP", "llc_snap"))

# Decode-side field aliases the ``payload`` layer owns (Raw's native ``load`` field).
_PAYLOAD_FIELD_ALIASES = (("load", "hex"),)


# ---------------------------------------------------------------------------
# Encode
# ---------------------------------------------------------------------------


def _build_payload(
    plan: PacketPlan,
    fields: JSONObject,
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    return scapy_all.Raw(load=_payload_bytes(fields))


def _build_linux_cooked(
    plan: PacketPlan,
    fields: JSONObject,
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    sll_fields = _layer_fields(fields, "linux_cooked")
    kwargs: dict[str, Any] = {
        "pkttype": _linux_sll_packet_type(
            _required_field(sll_fields, "linux_cooked", "packet_type")
        ),
        "lladdrtype": _hardware_type_value(
            _required_field(sll_fields, "linux_cooked", "address_type")
        ),
        "lladdrlen": _int(
            _required_field(sll_fields, "linux_cooked", "address_length"),
            6,
        ),
        "src": _bytes_field(
            _required_field(sll_fields, "linux_cooked", "source_address"),
            pad_to=8,
        ),
        "proto": _ethertype_value(
            _required_field(sll_fields, "linux_cooked", "protocol")
        ),
    }
    return scapy_all.CookedLinux(**kwargs)


def _build_null_loopback(
    plan: PacketPlan,
    fields: JSONObject,
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    null_fields = _layer_fields(fields, "null_loopback")
    kwargs = {
        "type": _address_family_value(
            _required_field(null_fields, "null_loopback", "type")
        )
    }
    return scapy_all.Loopback(**kwargs)


def _build_llc_snap(
    plan: PacketPlan,
    fields: JSONObject,
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    # ``llc_snap`` is only ever materialized through the Wi-Fi (Dot11 phase-1.5)
    # raw-bytes path, never as a standalone per-layer build. The legacy
    # ``_build_layer`` had no ``llc_snap`` branch, so reaching this build is the
    # same error the legacy code raised.
    raise ValueError("unsupported Scapy materialization layer: llc_snap")


def _linux_sll_packet_type(value: object) -> int:
    if isinstance(value, str):
        lowered = value.lower().replace("-", "_")
        mapping = {
            "host": 0,
            "broadcast": 1,
            "multicast": 2,
            "otherhost": 3,
            "outgoing": 4,
        }
        if lowered in mapping:
            return mapping[lowered]
        return int(lowered, 0)
    return _int(value, 0)


def _address_family_value(value: object) -> int:
    if isinstance(value, str):
        lowered = value.lower().replace("-", "_")
        mapping = {
            "ipv4": 2,
            "ip": 2,
            "ipv6": 24,
        }
        if lowered in mapping:
            return mapping[lowered]
        return int(lowered, 0)
    return _int(value, 2)


# ---------------------------------------------------------------------------
# Decode
# ---------------------------------------------------------------------------


def _normalize_payload(fields: JSONObject) -> JSONObject:
    load = fields.get("load")
    if isinstance(load, Mapping):
        hex_value = load.get("hex")
        ascii_value = load.get("ascii")
        if isinstance(hex_value, str):
            output: JSONObject = {
                "hex": hex_value,
                "length": len(bytes.fromhex(hex_value)),
            }
            if isinstance(ascii_value, str):
                output["ascii"] = ascii_value
            return output
    if isinstance(load, str):
        return {"hex": load, "length": len(bytes.fromhex(load))}
    return {}


register(
    ScapyProtocol(
        layer="payload",
        scapy_class="Raw",
        supported_fields=_PAYLOAD_SUPPORTED_FIELDS,
        build=_build_payload,
        normalize=_normalize_payload,
        layer_aliases=_PAYLOAD_LAYER_ALIASES,
        field_aliases=_PAYLOAD_FIELD_ALIASES,
    )
)

register(
    ScapyProtocol(
        layer="linux_cooked",
        scapy_class="CookedLinux",
        supported_fields=_LINUX_COOKED_SUPPORTED_FIELDS,
        build=_build_linux_cooked,
        layer_aliases=_LINUX_COOKED_LAYER_ALIASES,
    )
)

register(
    ScapyProtocol(
        layer="null_loopback",
        scapy_class="Loopback",
        supported_fields=_NULL_LOOPBACK_SUPPORTED_FIELDS,
        build=_build_null_loopback,
        layer_aliases=_NULL_LOOPBACK_LAYER_ALIASES,
    )
)

register(
    ScapyProtocol(
        layer="llc_snap",
        scapy_class="LLC/SNAP",
        supported_fields=_LLC_SNAP_SUPPORTED_FIELDS,
        build=_build_llc_snap,
        layer_aliases=_LLC_SNAP_LAYER_ALIASES,
    )
)
