"""Scapy-stage encode + decode plugin for the ARP layer.

Reference vertical-slice migration for the Scapy stage. The ARP builder and the
ARP decode normalization are moved verbatim out of :mod:`..packets` and
:mod:`..normalize` and registered through the :class:`~.base.ScapyProtocol`
contract; only the dispatch moves out of the legacy if/elif. Behavior must stay
byte-identical.

Shared primitives come from the helper modules so this plugin does not depend on
the ``packets``/``normalize`` orchestrators (which would create a circular
import). Relative imports only so the package resolves under both the ``engine.*``
(CLI) and ``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ....model import JSONObject, JSONValue
from ..encode_helpers import (
    _ethertype_value,
    _hardware_type_value,
    _bytes_field,
    _int,
    _layer_fields,
    _optional_field,
    _required_field,
    _text,
)
from .base import ScapyProtocol, register


# Encode-side field allowlist for ``_validate_layer_fields`` — the canonical
# field names plus every Scapy/oracle alias the ARP builder accepts. Mirrors the
# former ``packets._SUPPORTED_FIELDS_BY_LAYER["arp"]`` entry exactly.
_SUPPORTED_FIELDS = frozenset(
    {
        "hardware_type",
        "hwtype",
        "protocol_type",
        "ptype",
        "hardware_length",
        "hwlen",
        "protocol_length",
        "plen",
        "opcode",
        "op",
        "operation",
        "sender_hardware_address",
        "sender_ip",
        "sender_protocol_address",
        "hwsrc",
        "psrc",
        "target_hardware_address",
        "target_ip",
        "target_protocol_address",
        "hwdst",
        "pdst",
    }
)

# Decode-side native-name aliases the ARP layer owns. ``layer_aliases`` maps the
# Scapy class name to the oracle layer name; ``field_aliases`` maps Scapy's native
# field names to the oracle-neutral names.
_LAYER_ALIASES = (("ARP", "arp"),)
_FIELD_ALIASES = (
    ("hwlen", "hardware_length"),
    ("hwtype", "hardware_type"),
    ("plen", "protocol_length"),
    ("hwsrc", "sender_hardware_address"),
    ("hwdst", "target_hardware_address"),
    ("op", "opcode"),
    ("pdst", "target_protocol_address"),
    ("psrc", "sender_protocol_address"),
    ("ptype", "protocol_type"),
)
_FIELD_ALIAS_MAP = dict(_FIELD_ALIASES)


# ---------------------------------------------------------------------------
# Encode
# ---------------------------------------------------------------------------

# Hardware/protocol address octet counts for the standard Ethernet/IPv4 ARP
# form. Scapy's ARP layer accepts a colon-MAC or dotted-IPv4 *string* for these
# standard widths and emits exact wire bytes, so the existing string path is
# preserved for them (and for the hwsrc/psrc/hwdst/pdst aliases). Any other
# address form — a raw ``bytes`` value, a ``{"hex": ...}`` object, or a hex
# string whose decoded width is not the standard one — is materialized as raw
# octets so variable-length and unknown-family ARP addresses round-trip without
# Scapy re-interpreting them as a MAC or IP string.
_ARP_STANDARD_HARDWARE_OCTETS = 6
_ARP_STANDARD_PROTOCOL_OCTETS = 4


def _build(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    arp_fields = _layer_fields(fields, "arp")
    kwargs: dict[str, Any] = {
        "op": _arp_op(_required_field(arp_fields, "arp", "opcode", "op", "operation")),
        "hwsrc": _arp_address(
            _required_field(arp_fields, "arp", "sender_hardware_address", "hwsrc"),
            kind="hardware",
        ),
        "psrc": _arp_address(
            _required_field(
                arp_fields,
                "arp",
                "sender_protocol_address",
                "sender_ip",
                "psrc",
            ),
            kind="protocol",
        ),
        "hwdst": _arp_address(
            _required_field(arp_fields, "arp", "target_hardware_address", "hwdst"),
            kind="hardware",
        ),
        "pdst": _arp_address(
            _required_field(
                arp_fields,
                "arp",
                "target_protocol_address",
                "target_ip",
                "pdst",
            ),
            kind="protocol",
        ),
        "hwtype": _hardware_type_value(
            _required_field(arp_fields, "arp", "hardware_type", "hwtype")
        ),
        "ptype": _ethertype_value(_required_field(arp_fields, "arp", "protocol_type", "ptype")),
    }
    if "hardware_length" in arp_fields or "hwlen" in arp_fields:
        kwargs["hwlen"] = _int(_optional_field(arp_fields, "hardware_length", "hwlen"), 0)
    if "protocol_length" in arp_fields or "plen" in arp_fields:
        kwargs["plen"] = _int(_optional_field(arp_fields, "protocol_length", "plen"), 0)
    return scapy_all.ARP(**kwargs)


def _arp_address(value: object, *, kind: str) -> object:
    """Coerce one ARP sender/target address into a Scapy-materializable value.

    Standard Ethernet/IPv4 forms (a colon-separated MAC for a hardware address,
    a dotted-quad IPv4 for a protocol address) pass through unchanged as the
    string Scapy expects, keeping the golden Ethernet/IPv4 ARP bytes stable.
    Raw byte forms — ``bytes``, ``{"hex": ...}``, or a non-standard-width hex
    string — are decoded to raw octets so nonstandard hardware/protocol address
    lengths and unknown address families materialize byte-for-byte.
    """

    standard_octets = (
        _ARP_STANDARD_HARDWARE_OCTETS
        if kind == "hardware"
        else _ARP_STANDARD_PROTOCOL_OCTETS
    )

    if isinstance(value, bytes):
        return value
    if isinstance(value, Mapping):
        return _bytes_field(value)
    if isinstance(value, str):
        if kind == "hardware" and _is_standard_mac(value):
            return value
        if kind == "protocol" and _is_standard_ipv4(value):
            return value
        raw = _arp_address_hex_bytes(value)
        if raw is None:
            # Unrecognized string form (e.g. a non-standard IPv4/MAC textual
            # form). Leave it to Scapy unchanged rather than silently rewriting
            # the address; an encode failure here surfaces as a backend
            # limitation in the oracle report.
            return value
        if len(raw) == standard_octets:
            # Standard-width hex with no separators: hand Scapy the native
            # string form so the standard golden bytes path is unchanged.
            if kind == "hardware":
                return ":".join(f"{octet:02x}" for octet in raw)
            return ".".join(str(octet) for octet in raw)
        return raw
    return _text(value, "")


def _is_standard_mac(value: str) -> bool:
    parts = value.split(":")
    if len(parts) != _ARP_STANDARD_HARDWARE_OCTETS:
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
    if len(parts) != _ARP_STANDARD_PROTOCOL_OCTETS:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        if not 0 <= int(part) <= 255:
            return False
    return True


def _arp_address_hex_bytes(value: str) -> bytes | None:
    cleaned = value.replace(":", "").replace("-", "").replace(" ", "")
    if cleaned == "":
        return b""
    if len(cleaned) % 2 != 0:
        return None
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return None


def _arp_op(value: object) -> int | str:
    if value is None:
        return 1
    if isinstance(value, str):
        lowered = value.lower()
        if lowered in {"who-has", "request"}:
            return 1
        if lowered in {"is-at", "reply"}:
            return 2
        return lowered
    return _int(value, 1)


# ---------------------------------------------------------------------------
# Decode
# ---------------------------------------------------------------------------

_ARP_ADDRESS_FIELDS = (
    "sender_hardware_address",
    "sender_protocol_address",
    "target_hardware_address",
    "target_protocol_address",
)


def _normalize(fields: JSONObject) -> JSONObject:
    """Normalize a decoded Scapy ARP layer to the comparable oracle shape.

    The fixed-header fields (hardware/protocol type, hardware/protocol length,
    and opcode) are already aliased and kept numeric so known and unknown
    codepoints stay raw-preserving and round-trippable. The four variable
    sender/target address fields are reduced to a stable comparable form:
    standard Ethernet/IPv4 ARP keeps the colon-formatted MAC and dotted IPv4
    strings (matching the current fixtures and the libcrafter decoded view),
    while nonstandard or unknown-family address byte vectors are reduced to a
    bare ``{"hex": ...}`` value carrying the raw octets without the Scapy
    ASCII rendering, which is not byte-comparable across backends.
    """

    output: JSONObject = {}
    for native_name, value in fields.items():
        normalized_name = _FIELD_ALIAS_MAP.get(native_name, native_name)
        output[normalized_name] = value
    for name in _ARP_ADDRESS_FIELDS:
        if name in output:
            output[name] = _normalize_arp_address(output[name])
    return output


def _normalize_arp_address(value: JSONValue) -> JSONValue:
    if isinstance(value, Mapping):
        hex_value = value.get("hex")
        if isinstance(hex_value, str):
            return {"hex": hex_value}
    return value


register(
    ScapyProtocol(
        layer="arp",
        scapy_class="ARP",
        supported_fields=_SUPPORTED_FIELDS,
        build=_build,
        normalize=_normalize,
        layer_aliases=_LAYER_ALIASES,
        field_aliases=_FIELD_ALIASES,
    )
)
