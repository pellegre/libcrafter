"""Wireshark-stage decode plugin for the UDP layer.

Moves the ``_normalize_udp`` tshark normalizer and the UDP tshark field aliases
verbatim out of :mod:`..normalize` and registers them through the
:class:`~.base.WiresharkProtocol` contract; only the dispatch moves out of the
legacy if/elif. Behavior must stay byte-identical.

The plugin ``normalize`` takes the full tshark ``layers`` object (the uniform
registry signature) and pulls the ``udp`` layer before applying the alias map,
matching the legacy ``_normalize_udp(_layer(layers, "udp"))`` call exactly.

Shared primitives come from :mod:`..decode_helpers` so this plugin does not depend
on the ``normalize`` orchestrator (which would create a circular import). Relative
imports only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from ....model import JSONObject
from ..decode_helpers import _fields_from_aliases, _layer, _parse_int_fields
from .base import WiresharkProtocol, register


# tshark field aliases the UDP layer owns: canonical oracle name -> the native
# tshark field names that carry it.
_UDP_TSHARK_ALIASES: JSONObject = {
    "src_port": ("udp.srcport",),
    "dst_port": ("udp.dstport",),
    "length": ("udp.length",),
    "checksum": ("udp.checksum",),
}


def _normalize_udp(layers: JSONObject, *, source_hex: str | None = None) -> JSONObject:
    layer = _layer(layers, "udp")
    output = _fields_from_aliases(layer, dict(_UDP_TSHARK_ALIASES))
    _parse_int_fields(output, "src_port", "dst_port", "length", "checksum")
    return output


register(
    WiresharkProtocol(
        layer="udp",
        normalize=_normalize_udp,
        tshark_aliases=dict(_UDP_TSHARK_ALIASES),
    )
)
