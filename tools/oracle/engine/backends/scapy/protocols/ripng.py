"""Scapy-stage encode plugin for the RIPng layer.

Moves the ``_ripng`` builder and its ``_ripng_rtes`` / ``_ripng_rte_bytes`` /
``_is_ripng_next_hop`` helpers, plus the ``_RIPNG_RTE_LEN`` /
``_RIPNG_NEXT_HOP_METRIC`` constants, verbatim out of :mod:`..packets` and
registers them through the :class:`~.base.ScapyProtocol` contract; only the
dispatch moves out of the legacy if/elif. Behavior must stay byte-identical.

Scapy has no native RIPng dissector, so a RIPng plan cannot be built from a
reference layer the way IPv4 RIP rides Scapy's RIP/RIPEntry/RIPAuth. The oracle
still needs reference RIPng bytes for the strict-byte cases, so the 4-octet header
(command, version, reserved) and the fixed 20-octet route table entries (16-octet
IPv6 prefix, 2-octet route tag, 1-octet prefix length, 1-octet metric) are
assembled manually and wrapped in a Scapy ``Raw`` layer (``scapy_class="Raw"``,
mirroring the former ``packets._SCAPY_LAYER_BY_LAYER["ripng"]`` value). The
``_rip_command`` symbolic-command resolver is shared with the RIP builder and is
imported from the co-located :mod:`.rip` plugin rather than duplicated.

RIPng decode is special: Scapy carries the RIPng message as an opaque ``Raw``
payload, so the generic layer loop emits ``ipv6 / udp / payload`` and the
whole-packet ``_canonicalize_ripng`` pass in :mod:`..normalize` reconstructs the
neutral ``ripng`` layer from the wire bytes. That pass operates on the assembled
packet rather than a single decoded layer, so — following the step-22/24/25/26/27
precedent for whole-packet canonicalizers (``_canonicalize_icmpv4`` /
``_canonicalize_igmp`` / ``_canonicalize_bgp_from_wire`` / ``_canonicalize_rip``) —
it stays in :mod:`..normalize` and is not moved here. This plugin therefore
registers no ``normalize`` hook and no decode aliases.

Shared primitives come from the helper modules so this plugin does not depend on the
``packets`` orchestrator (which would create a circular import). Relative imports
only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ....model import JSONObject
from ..encode_helpers import (
    _int,
    _ipv6_address_bytes,
    _layer_fields,
    _optional_field,
    _required_field,
)
from .base import ScapyProtocol, register
from .rip import _rip_command


# Encode-side field allowlist for ``_validate_layer_fields`` — mirrors the former
# ``packets._SUPPORTED_FIELDS_BY_LAYER["ripng"]`` entry exactly. RIPng (RFC 2080)
# header fields mirror the libcrafter Ripng accessor names; per-RTE fields
# (prefix/route_tag/prefix_len/metric) live under the "rtes" list. RIPng has no
# AFI/authentication fields of its own.
_SUPPORTED_FIELDS = frozenset(
    {
        "command",
        "version",
        "reserved",
        "rtes",
    }
)

_RIPNG_RTE_LEN = 20
# A next-hop RTE is signalled by metric 0xFF (RFC 2080 §2.1.1).
_RIPNG_NEXT_HOP_METRIC = 0xFF


def _build(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    return _ripng(fields, scapy_all)


def _ripng(fields: Mapping[str, JSONObject], scapy_all: Any) -> Any:
    """Materialize a RIPng plan as manually-built header + RTE bytes.

    Scapy has no native RIPng layer, so the 4-octet header and 20-octet route
    table entries are encoded directly and wrapped in a ``Raw`` layer.
    """

    ripng_fields = _layer_fields(fields, "ripng")
    command = _rip_command(_required_field(ripng_fields, "ripng", "command", "cmd"))
    version = _int(_optional_field(ripng_fields, "version"), 1)
    reserved = _int(_optional_field(ripng_fields, "reserved", "null"), 0)
    raw = bytes([command & 0xFF, version & 0xFF]) + (reserved & 0xFFFF).to_bytes(2, "big")
    for rte in _ripng_rtes(ripng_fields):
        raw += _ripng_rte_bytes(rte)
    return scapy_all.Raw(load=raw)


def _ripng_rtes(ripng_fields: Mapping[str, object]) -> list[Mapping[str, object]]:
    rtes = ripng_fields.get("rtes")
    if rtes is None:
        rtes = ripng_fields.get("entries")
    if rtes is None:
        return []
    if not isinstance(rtes, Sequence) or isinstance(rtes, (str, bytes, bytearray)):
        raise ValueError("RIPng RTE materialization requires an RTE list")
    result: list[Mapping[str, object]] = []
    for rte in rtes:
        if not isinstance(rte, Mapping):
            raise ValueError(f"RIPng RTE must be an object, got {rte!r}")
        result.append(rte)
    return result


def _ripng_rte_bytes(rte: Mapping[str, object]) -> bytes:
    """Encode one 20-octet RIPng route table entry (RFC 2080 §2.1).

    Layout: 16-octet IPv6 prefix, 2-octet route tag, 1-octet prefix length,
    1-octet metric. A next-hop RTE carries metric 0xFF with route tag and
    prefix length at zero.
    """

    prefix = _ipv6_address_bytes(_optional_field(rte, "prefix", "address", "addr"), "::")
    route_tag = _int(_optional_field(rte, "route_tag", "tag", "routetag"), 0)
    prefix_len = _int(_optional_field(rte, "prefix_len", "prefix_length", "plen"), 0)
    metric = _int(_optional_field(rte, "metric"), _RIPNG_NEXT_HOP_METRIC if _is_ripng_next_hop(rte) else 0)
    raw = (
        prefix
        + (route_tag & 0xFFFF).to_bytes(2, "big")
        + bytes([prefix_len & 0xFF, metric & 0xFF])
    )
    if len(raw) != _RIPNG_RTE_LEN:
        raise ValueError(f"RIPng RTE must encode to {_RIPNG_RTE_LEN} octets, got {len(raw)}")
    return raw


def _is_ripng_next_hop(rte: Mapping[str, object]) -> bool:
    flag = _optional_field(rte, "next_hop", "is_next_hop")
    if isinstance(flag, bool):
        return flag
    return False


register(
    ScapyProtocol(
        # ``scapy_class`` mirrors the former ``packets._SCAPY_LAYER_BY_LAYER["ripng"]``
        # value (``"Raw"``): Scapy has no native RIPng dissector, so the plan is
        # materialized as manually-built header + RTE octets wrapped in a ``Raw``
        # layer. This drives ``_scapy_layer_name`` and the ``scapy_stack`` metadata.
        layer="ripng",
        scapy_class="Raw",
        supported_fields=_SUPPORTED_FIELDS,
        build=_build,
        # RIPng decode uses the whole-packet ``_canonicalize_ripng`` pass in
        # ``normalize`` (reconstructed from wire bytes); no per-layer hook or aliases.
        normalize=None,
    )
)
