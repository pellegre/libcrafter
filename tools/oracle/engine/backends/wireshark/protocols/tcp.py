"""Wireshark-stage decode plugin for the TCP layer.

Moves the ``_normalize_tcp`` tshark normalizer, its ``_tcp_flags`` helper, and the
TCP tshark field aliases verbatim out of :mod:`..normalize` and registers them
through the :class:`~.base.WiresharkProtocol` contract; only the dispatch moves out
of the legacy if/elif. Behavior must stay byte-identical.

The plugin ``normalize`` takes the full tshark ``layers`` object (the uniform
registry signature) and pulls the ``tcp`` layer before applying the alias map,
matching the legacy ``_normalize_tcp(_layer(layers, "tcp"))`` call exactly. The
``flags`` field is rebuilt from the per-bit ``tcp.flags.*`` fields (falling back to
the packed ``tcp.flags`` value), and the ``data_offset`` is folded from tshark's
header-length-in-octets reporting back to the 5..15 word count when it is a valid
20+ octet multiple-of-four header.

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


# tshark field aliases the TCP layer owns: canonical oracle name -> the native
# tshark field names that carry it.
_TCP_TSHARK_ALIASES: JSONObject = {
    "src_port": ("tcp.srcport",),
    "dst_port": ("tcp.dstport",),
    "sequence": ("tcp.seq_raw", "tcp.seq"),
    "acknowledgement": ("tcp.ack_raw", "tcp.ack"),
    "data_offset": ("tcp.hdr_len",),
    "window": ("tcp.window_size_value", "tcp.window_size"),
    "checksum": ("tcp.checksum",),
    "urgent_pointer": ("tcp.urgent_pointer",),
}


def _normalize_tcp(layers: JSONObject, *, source_hex: str | None = None) -> JSONObject:
    layer = _layer(layers, "tcp")
    output = _fields_from_aliases(layer, dict(_TCP_TSHARK_ALIASES))
    _parse_int_fields(
        output,
        "src_port",
        "dst_port",
        "sequence",
        "acknowledgement",
        "data_offset",
        "window",
        "checksum",
        "urgent_pointer",
    )
    data_offset = output.get("data_offset")
    if isinstance(data_offset, int) and data_offset >= 20 and data_offset % 4 == 0:
        output["data_offset"] = data_offset // 4
    output["flags"] = _tcp_flags(layer)
    return output


def _tcp_flags(layer: JSONObject) -> str:
    names = [
        ("tcp.flags.fin", "fin"),
        ("tcp.flags.syn", "syn"),
        ("tcp.flags.reset", "rst"),
        ("tcp.flags.push", "psh"),
        ("tcp.flags.ack", "ack"),
        ("tcp.flags.urg", "urg"),
        ("tcp.flags.ece", "ece"),
        ("tcp.flags.cwr", "cwr"),
    ]
    enabled = [name for field, name in names if _truthy_field(layer, field)]
    if enabled:
        return "|".join(enabled)
    value = _parse_int(_field(layer, "tcp.flags"))
    if value is None or value == 0:
        return "none"
    raw_names = [
        (0x01, "fin"),
        (0x02, "syn"),
        (0x04, "rst"),
        (0x08, "psh"),
        (0x10, "ack"),
        (0x20, "urg"),
        (0x40, "ece"),
        (0x80, "cwr"),
    ]
    return "|".join(name for bit, name in raw_names if value & bit) or "none"


register(
    WiresharkProtocol(
        layer="tcp",
        normalize=_normalize_tcp,
        tshark_aliases=dict(_TCP_TSHARK_ALIASES),
    )
)
