"""Wireshark-stage decode plugin for the ICMPv4 and ICMPv6 layers.

Moves the ``_normalize_icmp`` tshark normalizer and its field aliases verbatim out
of :mod:`..normalize` and registers them through the
:class:`~.base.WiresharkProtocol` contract; only the dispatch moves out of the
legacy if/elif. Behavior must stay byte-identical.

``icmp`` and ``icmpv6`` share one tshark normalizer: the legacy
``_normalize_protocol_fields`` dispatch called ``_normalize_icmp(_layer(layers,
"icmp"))`` for icmp and ``_normalize_icmp(_layer(layers, "icmpv6"))`` for icmpv6,
and the alias map already lists both ``icmp.*`` and ``icmpv6.*`` field names. Two
:class:`WiresharkProtocol` instances are registered, one per layer, each pulling its
native tshark layer (``icmp`` / ``icmpv6``) before applying the shared normalizer.

Shared primitives come from :mod:`..decode_helpers` so this plugin does not depend
on the ``normalize`` orchestrator (which would create a circular import). Relative
imports only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from ....model import JSONObject
from ..decode_helpers import _fields_from_aliases, _layer, _parse_int_fields
from .base import WiresharkProtocol, register


# tshark field aliases the ICMP layers own: canonical oracle name -> the native
# tshark field names that carry it (both the ICMPv4 ``icmp.*`` and the ICMPv6
# ``icmpv6.*`` reporting names, so the one normalizer serves both layers).
_ICMP_TSHARK_ALIASES: JSONObject = {
    "type": ("icmp.type", "icmpv6.type"),
    "code": ("icmp.code", "icmpv6.code"),
    "checksum": ("icmp.checksum", "icmpv6.checksum"),
    "identifier": ("icmp.ident", "icmpv6.echo.identifier"),
    "sequence": ("icmp.seq", "icmpv6.echo.sequence_number"),
}


def _normalize_icmp(layer: JSONObject) -> JSONObject:
    output = _fields_from_aliases(layer, dict(_ICMP_TSHARK_ALIASES))
    _parse_int_fields(output, "type", "code", "checksum", "identifier", "sequence")
    identifier = output.get("identifier")
    sequence = output.get("sequence")
    if isinstance(identifier, int) and isinstance(sequence, int):
        output["rest_of_header"] = f"{identifier:04x}{sequence:04x}"
    return output


def _normalize_icmp_layer(layers: JSONObject, *, source_hex: str | None = None) -> JSONObject:
    return _normalize_icmp(_layer(layers, "icmp"))


def _normalize_icmpv6_layer(layers: JSONObject, *, source_hex: str | None = None) -> JSONObject:
    return _normalize_icmp(_layer(layers, "icmpv6"))


register(
    WiresharkProtocol(
        layer="icmp",
        normalize=_normalize_icmp_layer,
        tshark_aliases=dict(_ICMP_TSHARK_ALIASES),
    )
)

register(
    WiresharkProtocol(
        layer="icmpv6",
        normalize=_normalize_icmpv6_layer,
        tshark_aliases=dict(_ICMP_TSHARK_ALIASES),
    )
)
