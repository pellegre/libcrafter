"""Wireshark-stage decode plugins for the ``ethernet`` and ``vlan`` layers.

Moves the ``_normalize_ethernet`` and ``_normalize_vlan`` tshark normalizers and
their field aliases verbatim out of :mod:`..normalize` and registers them through
the :class:`~.base.WiresharkProtocol` contract; only the dispatch moves out of the
legacy if/elif. Behavior must stay byte-identical.

Shared primitives come from :mod:`..decode_helpers` so this plugin does not depend
on the ``normalize`` orchestrator (which would create a circular import). Relative
imports only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from ....model import JSONObject
from ..decode_helpers import _fields_from_aliases, _layer, _parse_int_fields
from .base import WiresharkProtocol, register


# tshark field aliases each layer owns: canonical oracle name -> the native-tshark
# field names that carry it.
_ETHERNET_TSHARK_ALIASES: JSONObject = {
    "dst": ("eth.dst",),
    "src": ("eth.src",),
    "ethertype": ("eth.type",),
}
_VLAN_TSHARK_ALIASES: JSONObject = {
    "priority": ("vlan.priority",),
    "drop_eligible": ("vlan.dei",),
    "vlan_id": ("vlan.id",),
    "ethertype": ("vlan.etype", "vlan.type"),
}


def _normalize_ethernet(
    layers: JSONObject, *, source_hex: str | None = None
) -> JSONObject:
    output = _fields_from_aliases(_layer(layers, "eth"), dict(_ETHERNET_TSHARK_ALIASES))
    _parse_int_fields(output, "ethertype")
    return output


def _normalize_vlan(layers: JSONObject, *, source_hex: str | None = None) -> JSONObject:
    output = _fields_from_aliases(_layer(layers, "vlan"), dict(_VLAN_TSHARK_ALIASES))
    _parse_int_fields(output, "priority", "drop_eligible", "vlan_id", "ethertype")
    return output


register(
    WiresharkProtocol(
        layer="ethernet",
        normalize=_normalize_ethernet,
        tshark_aliases=dict(_ETHERNET_TSHARK_ALIASES),
    )
)

register(
    WiresharkProtocol(
        layer="vlan",
        normalize=_normalize_vlan,
        tshark_aliases=dict(_VLAN_TSHARK_ALIASES),
    )
)
