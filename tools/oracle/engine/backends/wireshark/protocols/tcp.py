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
    reserved = _tcp_reserved_from_source(source_hex)
    if reserved is not None:
        output["reserved"] = reserved
    output["flags"] = _tcp_flags(layer)
    return output


def _tcp_reserved_from_source(source_hex: str | None) -> int | None:
    if not source_hex:
        return None
    try:
        raw = bytes.fromhex(source_hex)
    except ValueError:
        return None
    for offset in _l3_offsets(raw):
        value = _tcp_reserved_at_l3(raw, offset)
        if value is not None:
            return value
    return None


def _l3_offsets(raw: bytes) -> tuple[int, ...]:
    offsets: list[int] = []
    if raw:
        offsets.append(0)
    if len(raw) >= 14:
        ether_type = int.from_bytes(raw[12:14], "big")
        if ether_type in {0x0800, 0x86DD}:
            offsets.append(14)
    return tuple(dict.fromkeys(offsets))


def _tcp_reserved_at_l3(raw: bytes, offset: int) -> int | None:
    if offset >= len(raw):
        return None
    version = raw[offset] >> 4
    if version == 4:
        return _tcp_reserved_ipv4(raw, offset)
    if version == 6:
        return _tcp_reserved_ipv6(raw, offset)
    return None


def _tcp_reserved_ipv4(raw: bytes, offset: int) -> int | None:
    if offset + 20 > len(raw):
        return None
    ihl = (raw[offset] & 0x0F) * 4
    if ihl < 20 or offset + ihl > len(raw) or raw[offset + 9] != 6:
        return None
    total_length = int.from_bytes(raw[offset + 2 : offset + 4], "big")
    end = min(len(raw), offset + total_length) if total_length else len(raw)
    return _tcp_reserved_at_offset(raw, offset + ihl, end)


def _tcp_reserved_ipv6(raw: bytes, offset: int) -> int | None:
    if offset + 40 > len(raw) or raw[offset + 6] != 6:
        return None
    payload_length = int.from_bytes(raw[offset + 4 : offset + 6], "big")
    end = min(len(raw), offset + 40 + payload_length)
    return _tcp_reserved_at_offset(raw, offset + 40, end)


def _tcp_reserved_at_offset(raw: bytes, tcp_offset: int, end: int) -> int | None:
    if tcp_offset + 14 > end:
        return None
    data_offset_words = raw[tcp_offset + 12] >> 4
    header_length = data_offset_words * 4
    if data_offset_words < 5 or tcp_offset + header_length > end:
        return None
    return (raw[tcp_offset + 12] & 0x0E) >> 1


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
