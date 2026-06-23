"""Wireshark-stage decode plugin for the IPv4 layer.

Moves the ``_normalize_ipv4`` tshark normalizer, the ``_ipv4_flags`` reducer, and
the IPv4 tshark field aliases verbatim out of :mod:`..normalize` and registers
them through the :class:`~.base.WiresharkProtocol` contract; only the dispatch
moves out of the legacy if/elif. Behavior must stay byte-identical.

Shared primitives come from :mod:`..decode_helpers` so this plugin does not depend
on the ``normalize`` orchestrator (which would create a circular import). Relative
imports only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from ....model import JSONObject
from ..decode_helpers import (
    _field,
    _fields_from_aliases,
    _layer,
    _parse_int,
    _parse_int_fields,
    _truthy_field,
)
from .base import WiresharkProtocol, register


# tshark field aliases the IPv4 layer owns: canonical oracle name -> the native
# tshark field names that carry it. ``flags`` is derived separately from the
# ``ip.flags*`` bit fields.
_IPV4_TSHARK_ALIASES: JSONObject = {
    "version": ("ip.version",),
    "header_length": ("ip.hdr_len",),
    "tos": ("ip.dsfield", "ip.tos"),
    "length": ("ip.len",),
    "identification": ("ip.id",),
    "fragment_offset": ("ip.frag_offset",),
    "ttl": ("ip.ttl",),
    "protocol": ("ip.proto",),
    "checksum": ("ip.checksum",),
    "src": ("ip.src",),
    "dst": ("ip.dst",),
}


def _normalize_ipv4(layers: JSONObject, *, source_hex: str | None = None) -> JSONObject:
    layer = _layer(layers, "ip")
    output = _fields_from_aliases(layer, dict(_IPV4_TSHARK_ALIASES))
    _parse_int_fields(
        output,
        "version",
        "header_length",
        "tos",
        "length",
        "identification",
        "fragment_offset",
        "ttl",
        "protocol",
        "checksum",
    )
    header_length = output.get("header_length")
    if isinstance(header_length, int) and header_length >= 20 and header_length % 4 == 0:
        output["header_length"] = header_length // 4
    output["flags"] = _ipv4_flags(layer)
    return output


def _ipv4_flags(layer: JSONObject) -> str:
    if _truthy_field(layer, "ip.flags.df"):
        return "df"
    if _truthy_field(layer, "ip.flags.mf"):
        return "mf"
    value = _parse_int(_field(layer, "ip.flags"))
    if value == 0:
        return "none"
    if value is None:
        return "none"
    flags: list[str] = []
    if value & 0x2:
        flags.append("df")
    if value & 0x1:
        flags.append("mf")
    return "|".join(flags) if flags else "none"


register(
    WiresharkProtocol(
        layer="ipv4",
        normalize=_normalize_ipv4,
        tshark_aliases=dict(_IPV4_TSHARK_ALIASES),
    )
)
