"""Wireshark-stage decode plugin for the DNS layer.

The parser-only Wireshark backend never carried a DNS-specific normalizer: the
``dns`` layer fell through the legacy ``_normalize_protocol_fields`` if/elif to its
``return {}`` default, contributing no comparison-visible fields (the
comparison-visible ``dns`` surface is built by the Scapy backend's whole-packet
``_normalize_dns_message`` model). This plugin makes that ownership explicit by
registering a :class:`~.base.WiresharkProtocol` for ``dns`` whose ``normalize``
returns the same empty mapping, so the per-layer Wireshark decode stays
byte-identical while ``dns`` is now fully migrated across every stage.

There are accordingly no tshark field aliases for this layer (none ever existed),
and there is no legacy ``dns`` branch to remove from ``_normalize_protocol_fields``.

Relative imports only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from ....model import JSONObject
from .base import WiresharkProtocol, register


# The DNS layer owns no tshark field aliases: the parser-only backend has never
# decoded any comparison-visible ``dns`` field.
_DNS_TSHARK_ALIASES: JSONObject = {}


def _normalize(layers: JSONObject, *, source_hex: str | None = None) -> JSONObject:
    # Byte-identical to the legacy ``return {}`` default the ``dns`` layer hit in
    # ``_normalize_protocol_fields``: the Wireshark backend surfaces no per-layer
    # DNS fields.
    return {}


register(
    WiresharkProtocol(
        layer="dns",
        normalize=_normalize,
        tshark_aliases=dict(_DNS_TSHARK_ALIASES),
    )
)
