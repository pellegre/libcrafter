"""Scapy-stage encode + decode plugin for the ``ethernet`` and ``vlan`` layers.

Moves the ``_ethernet`` (Ether) and ``_vlan`` (Dot1Q) builders verbatim out of
:mod:`..packets` and registers them through the :class:`~.base.ScapyProtocol`
contract; only the dispatch moves out of the legacy if/elif. Behavior must stay
byte-identical.

Neither layer has a custom Scapy decode normalizer — they decode through the
generic alias path — so each plugin carries the decode-side ``layer_aliases`` and
``field_aliases`` it owns and supplies a small ``normalize`` that applies those
field aliases (the byte-identical equivalent of the legacy
``_LAYER_FIELD_ALIASES`` lookup for these layers, whose native field names do not
collide with the global field-alias table).

Shared primitives come from :mod:`..encode_helpers` so this plugin does not depend
on the ``packets``/``normalize`` orchestrators (which would create a circular
import). Relative imports only so the package resolves under both the ``engine.*``
(CLI) and ``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from typing import Any

from ....model import JSONObject, PacketPlan
from ..encode_helpers import (
    _ethertype_value,
    _int,
    _layer_fields,
    _optional_field,
    _required_field,
    _text,
)
from .base import ScapyProtocol, register


# Encode-side field allowlists for ``_validate_layer_fields`` — the canonical
# field names plus every Scapy/oracle alias the builders accept. Mirror the former
# ``packets._SUPPORTED_FIELDS_BY_LAYER["ethernet"]`` / ``["vlan"]`` entries exactly.
_ETHERNET_SUPPORTED_FIELDS = frozenset({"dst", "ethertype", "src", "type"})
_VLAN_SUPPORTED_FIELDS = frozenset(
    {
        "dei",
        "drop_eligible",
        "ethertype",
        "id",
        "prio",
        "priority",
        "type",
        "vlan",
        "vlan_id",
    }
)

# Decode-side aliases each layer owns. ``layer_aliases`` maps the Scapy class name
# to the oracle layer name; ``field_aliases`` maps Scapy's native field names to
# the oracle-neutral names (mirroring the former ``normalize._LAYER_ALIASES`` and
# ``normalize._LAYER_FIELD_ALIASES`` entries).
_ETHERNET_LAYER_ALIASES = (("Ether", "ethernet"),)
_ETHERNET_FIELD_ALIASES = (("type", "ethertype"),)

_VLAN_LAYER_ALIASES = (("Dot1Q", "vlan"),)
_VLAN_FIELD_ALIASES = (
    ("dei", "drop_eligible"),
    ("prio", "priority"),
    ("type", "ethertype"),
    ("vlan", "vlan_id"),
)


# ---------------------------------------------------------------------------
# Encode
# ---------------------------------------------------------------------------


def _build_ethernet(
    plan: PacketPlan,
    fields: JSONObject,
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    eth_fields = _layer_fields(plan.fields, "ethernet")
    kwargs: dict[str, Any] = {
        "src": _text(_required_field(eth_fields, "ethernet", "src"), ""),
        "dst": _text(_required_field(eth_fields, "ethernet", "dst"), ""),
        "type": _ethertype_value(
            _required_field(eth_fields, "ethernet", "ethertype", "type")
        ),
    }
    return scapy_all.Ether(**kwargs)


def _build_vlan(
    plan: PacketPlan,
    fields: JSONObject,
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    vlan_fields = _layer_fields(plan.fields, "vlan")
    kwargs: dict[str, Any] = {
        "prio": _int(_required_field(vlan_fields, "vlan", "priority", "prio"), 0),
        "vlan": _int(_required_field(vlan_fields, "vlan", "vlan_id", "id", "vlan"), 0),
        "type": _ethertype_value(
            _required_field(vlan_fields, "vlan", "ethertype", "type")
        ),
        "dei": _int(_optional_field(vlan_fields, "drop_eligible", "dei"), 0),
    }
    return scapy_all.Dot1Q(**kwargs)


# ---------------------------------------------------------------------------
# Decode
# ---------------------------------------------------------------------------


def _normalize_with_aliases(
    fields: JSONObject, field_aliases: dict[str, str]
) -> JSONObject:
    """Apply this layer's field-name aliases to a decoded Scapy layer.

    Byte-identical to the legacy generic ``_normalize_fields`` path for these two
    layers: each native field name is renamed via the layer's alias map, and the
    value is passed through unchanged (neither layer needs value normalization,
    and their native field names never collide with the global field-alias table).
    """

    output: JSONObject = {}
    for native_name, value in fields.items():
        output[field_aliases.get(native_name, native_name)] = value
    return output


def _normalize_ethernet(fields: JSONObject) -> JSONObject:
    return _normalize_with_aliases(fields, dict(_ETHERNET_FIELD_ALIASES))


def _normalize_vlan(fields: JSONObject) -> JSONObject:
    return _normalize_with_aliases(fields, dict(_VLAN_FIELD_ALIASES))


register(
    ScapyProtocol(
        layer="ethernet",
        scapy_class="Ether",
        supported_fields=_ETHERNET_SUPPORTED_FIELDS,
        build=_build_ethernet,
        normalize=_normalize_ethernet,
        layer_aliases=_ETHERNET_LAYER_ALIASES,
        field_aliases=_ETHERNET_FIELD_ALIASES,
    )
)

register(
    ScapyProtocol(
        layer="vlan",
        scapy_class="Dot1Q",
        supported_fields=_VLAN_SUPPORTED_FIELDS,
        build=_build_vlan,
        normalize=_normalize_vlan,
        layer_aliases=_VLAN_LAYER_ALIASES,
        field_aliases=_VLAN_FIELD_ALIASES,
    )
)
