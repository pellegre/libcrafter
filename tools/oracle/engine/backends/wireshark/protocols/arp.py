"""Wireshark-stage decode plugin for the ARP layer.

Reference vertical-slice migration for the parser-only Wireshark stage. The ARP
tshark normalizer and its field aliases are moved verbatim out of
:mod:`..normalize` and registered through the :class:`~.base.WiresharkProtocol`
contract; only the dispatch moves out of the legacy if/elif. Behavior must stay
byte-identical.

Shared primitives come from :mod:`..decode_helpers` so this plugin does not
depend on the ``normalize`` orchestrator (which would create a circular import).
Relative imports only so the package resolves under both the ``engine.*`` (CLI)
and ``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from ....model import JSONObject
from ..decode_helpers import (
    _fields_from_aliases,
    _hex_bytes,
    _layer,
    _parse_int_fields,
)
from .base import WiresharkProtocol, register


# tshark field aliases the ARP layer owns: canonical oracle name -> the
# native-tshark field names that carry it.
_TSHARK_ALIASES: JSONObject = {
    "hardware_type": ("arp.hw.type", "arp.hardware.type"),
    "protocol_type": ("arp.proto.type",),
    "hardware_length": ("arp.hw.size", "arp.hardware.size"),
    "protocol_length": ("arp.proto.size",),
    "opcode": ("arp.opcode",),
    "sender_hardware_address": ("arp.src.hw_mac", "arp.src.hw"),
    "sender_protocol_address": ("arp.src.proto_ipv4", "arp.src.proto"),
    "target_hardware_address": ("arp.dst.hw_mac", "arp.dst.hw"),
    "target_protocol_address": ("arp.dst.proto_ipv4", "arp.dst.proto"),
}

_ARP_HARDWARE_ADDRESS_FIELDS = (
    "sender_hardware_address",
    "target_hardware_address",
)
_ARP_PROTOCOL_ADDRESS_FIELDS = (
    "sender_protocol_address",
    "target_protocol_address",
)


def _normalize(layers: JSONObject, *, source_hex: str | None = None) -> JSONObject:
    """Normalize a tshark ARP layer to the shared canonical field names.

    The normalized names and comparable forms match the Scapy reference backend
    (``tools/oracle/engine/backends/scapy/normalize.py``) and the libcrafter
    decoder (``tools/oracle/adapters/src/bin/decode_vectors.rs``). The fixed
    header (``hardware_type``, ``protocol_type``, ``hardware_length``,
    ``protocol_length``, ``opcode``) is kept numeric so known and unknown
    codepoints stay raw-preserving. The four variable sender/target address
    fields keep their colon-formatted MAC / dotted IPv4 string form for standard
    Ethernet/IPv4 ARP, and reduce to a bare ``{"hex": ...}`` value carrying the
    raw octets for nonstandard hardware/protocol lengths or unknown address
    families. tshark exposes typed ``*.hw_mac`` / ``*.proto_ipv4`` fields for the
    standard forms and the generic ``*.hw`` / ``*.proto`` fields otherwise.
    """

    layer = _layer(layers, "arp")
    output = _fields_from_aliases(layer, dict(_TSHARK_ALIASES))
    _parse_int_fields(
        output,
        "hardware_type",
        "protocol_type",
        "hardware_length",
        "protocol_length",
        "opcode",
    )
    for name in _ARP_HARDWARE_ADDRESS_FIELDS:
        if name in output:
            output[name] = _normalize_arp_address(output[name], kind="hardware")
    for name in _ARP_PROTOCOL_ADDRESS_FIELDS:
        if name in output:
            output[name] = _normalize_arp_address(output[name], kind="protocol")
    return output


def _normalize_arp_address(value: object, *, kind: str) -> object:
    """Reduce one tshark ARP address to the shared comparable form.

    Standard Ethernet hardware addresses (a colon-separated MAC) and standard
    IPv4 protocol addresses (a dotted quad) keep their string form, matching the
    Scapy reference backend and libcrafter's decoded view. Any other form — a
    nonstandard-width hardware/protocol address or an unknown address family,
    which tshark renders as a colon-separated hex string — is reduced to a bare
    ``{"hex": ...}`` value carrying the raw octets, so the comparison stays
    byte-identical across backends regardless of tshark's textual rendering.
    """

    if not isinstance(value, str):
        return value
    if kind == "hardware" and _is_standard_mac(value):
        return value
    if kind == "protocol" and _is_standard_ipv4(value):
        return value
    return {"hex": _hex_bytes(value)}


def _is_standard_mac(value: str) -> bool:
    parts = value.split(":")
    if len(parts) != 6:
        return False
    for part in parts:
        if len(part) != 2:
            return False
        try:
            int(part, 16)
        except ValueError:
            return False
    return True


def _is_standard_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        if not 0 <= int(part) <= 255:
            return False
    return True


register(
    WiresharkProtocol(
        layer="arp",
        normalize=_normalize,
        tshark_aliases=dict(_TSHARK_ALIASES),
    )
)
