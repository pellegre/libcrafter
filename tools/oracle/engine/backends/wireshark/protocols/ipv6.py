"""Wireshark-stage decode plugin for the base IPv6 layer.

Moves the ``_normalize_ipv6`` tshark normalizer and its tshark field aliases
verbatim out of :mod:`..normalize` and registers them through the
:class:`~.base.WiresharkProtocol` contract; only the dispatch moves out of the
legacy if/elif. Behavior must stay byte-identical. The IPv6 extension-header
normalizers stay on the legacy dispatch and migrate in a later step.

Shared primitives come from :mod:`..decode_helpers` so this plugin does not depend
on the ``normalize`` orchestrator (which would create a circular import). Relative
imports only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from ....model import JSONObject
from ..decode_helpers import _fields_from_aliases, _layer, _parse_int_fields
from .base import WiresharkProtocol, register


# tshark field aliases the IPv6 layer owns: canonical oracle name -> the native
# tshark field names that carry it.
_IPV6_TSHARK_ALIASES: JSONObject = {
    "version": ("ipv6.version",),
    "traffic_class": ("ipv6.tclass",),
    "flow_label": ("ipv6.flow",),
    "payload_length": ("ipv6.plen",),
    "next_header": ("ipv6.nxt",),
    "hop_limit": ("ipv6.hlim",),
    "src": ("ipv6.src",),
    "dst": ("ipv6.dst",),
}


def _normalize_ipv6(layers: JSONObject, *, source_hex: str | None = None) -> JSONObject:
    layer = _layer(layers, "ipv6")
    output = _fields_from_aliases(layer, dict(_IPV6_TSHARK_ALIASES))
    _parse_int_fields(
        output,
        "version",
        "traffic_class",
        "flow_label",
        "payload_length",
        "next_header",
        "hop_limit",
    )
    traffic_class = output.get("traffic_class")
    if isinstance(traffic_class, int):
        output["dscp"] = traffic_class >> 2
        output["ecn"] = traffic_class & 0x03
    return output


register(
    WiresharkProtocol(
        layer="ipv6",
        normalize=_normalize_ipv6,
        tshark_aliases=dict(_IPV6_TSHARK_ALIASES),
    )
)
