"""Wireshark-stage decode plugin for the DHCP layer.

Moves the ``_normalize_dhcp`` tshark normalizer and its DHCP helpers
(``_dhcp_flags``, ``_dhcp_options_from_source``, ``_decode_dhcp_option_tlvs``,
``_dhcp_layer``) and the DHCP option/cookie constants verbatim out of
:mod:`..normalize` and registers the ``dhcp`` layer through the
:class:`~.base.WiresharkProtocol` contract; only the dispatch moves out of the
legacy ``_normalize_protocol_fields`` if/elif. Behavior must stay byte-identical.

The plugin's :func:`_normalize` callback receives the full tshark ``layers`` object
and selects the BOOTP/DHCP sub-layer with :func:`_dhcp_layer` (Wireshark renamed the
dissector prefix from ``bootp.`` to ``dhcp.`` around 3.0, so both are accepted),
exactly as the legacy ``_normalize_dhcp(_dhcp_layer(layers), ...)`` call did.

Shared primitives come from :mod:`..decode_helpers` so this plugin does not depend on
the ``normalize`` orchestrator (which would create a circular import). Relative
imports only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from ....model import JSONObject
from ..decode_helpers import (
    _field,
    _fields_from_aliases,
    _hex_bytes,
    _layer,
    _parse_int,
    _parse_int_fields,
    _string_field,
    _truthy_field,
)
from .base import WiresharkProtocol, register


# DHCP magic cookie (RFC 2132) prefacing the option region.
_DHCP_MAGIC_COOKIE = 0x63825363
# Option codes that need no length octet and carry no payload.
_DHCP_OPTION_PAD = 0
_DHCP_OPTION_END = 255
# DHCP message type option (RFC 2132).
_DHCP_OPTION_MESSAGE_TYPE = 53

# tshark field aliases the DHCP layer owns: canonical oracle name -> the
# native-tshark field names that carry it. Wireshark renamed the dissector prefix
# from ``bootp.`` to ``dhcp.`` around 3.0, so both prefixes are accepted.
_TSHARK_ALIASES: JSONObject = {
    "opcode": ("dhcp.type", "bootp.type"),
    "hardware_type": ("dhcp.hw.type", "bootp.hw.type"),
    "hardware_length": ("dhcp.hw.len", "bootp.hw.len"),
    "hops": ("dhcp.hops", "bootp.hops"),
    "transaction_id": ("dhcp.id", "bootp.id"),
    "seconds": ("dhcp.secs", "bootp.secs"),
    "client_ip": ("dhcp.ip.client", "bootp.ip.client"),
    "your_ip": ("dhcp.ip.your", "bootp.ip.your"),
    "server_ip": ("dhcp.ip.server", "bootp.ip.server"),
    "relay_ip": ("dhcp.ip.relay", "bootp.ip.relay"),
    "magic_cookie": ("dhcp.cookie", "bootp.cookie"),
}


def _normalize(layers: JSONObject, *, source_hex: str | None = None) -> JSONObject:
    """Normalize a tshark BOOTP/DHCP layer to the shared oracle field names.

    The normalized names match the Scapy reference backend
    (``tools/oracle/engine/backends/scapy/normalize.py``) and the libcrafter
    decoder (``tools/oracle/adapters/src/bin/decode_vectors.rs``): ``opcode``,
    ``hardware_type``/``hardware_length``, ``hops``, ``transaction_id``,
    ``seconds``, integer ``flags``, the BOOTP IPv4 fields, ``magic_cookie``,
    ``client_hardware_address`` as ``{"hex": ...}``, plus backend-neutral
    ``options`` (``{code, payload_hex}`` TLVs), ``option_count`` and integer
    ``message_type``.
    """

    layer = _dhcp_layer(layers)
    output = _fields_from_aliases(layer, dict(_TSHARK_ALIASES))
    _parse_int_fields(
        output,
        "opcode",
        "hardware_type",
        "hardware_length",
        "hops",
        "transaction_id",
        "seconds",
    )
    magic = _parse_int(output.get("magic_cookie"))
    output["magic_cookie"] = magic if magic is not None else _DHCP_MAGIC_COOKIE

    chaddr = _string_field(layer, "dhcp.hw.mac_addr", "bootp.hw.mac_addr", "dhcp.hw.addr")
    if chaddr is not None:
        output["client_hardware_address"] = {"hex": _hex_bytes(chaddr)}

    output["flags"] = _dhcp_flags(layer)

    options = _dhcp_options_from_source(source_hex)
    if options is not None:
        output["options"] = options
        output["option_count"] = len(options)
        for option in options:
            if option["code"] == _DHCP_OPTION_MESSAGE_TYPE:
                payload = bytes.fromhex(option["payload_hex"])
                if len(payload) == 1:
                    output["message_type"] = payload[0]
                break
    else:
        message_type = _parse_int(
            _field(layer, "dhcp.option.dhcp", "bootp.option.dhcp")
        )
        if message_type is not None:
            output["message_type"] = message_type
    return output


def _dhcp_flags(layer: JSONObject) -> int:
    """Return DHCP flags as the shared integer view (broadcast bit 0x8000)."""

    value = _parse_int(_field(layer, "dhcp.flags", "bootp.flags"))
    if value is not None:
        return value
    if _truthy_field(layer, "dhcp.flags.bc") or _truthy_field(layer, "bootp.flags.bc"):
        return 0x8000
    return 0


def _dhcp_options_from_source(source_hex: str | None) -> list[JSONObject] | None:
    """Reconstruct backend-neutral DHCP option TLVs from the raw packet bytes.

    The option region begins right after the magic cookie. Parsing the raw bytes
    (rather than tshark's typed option views) keeps the ``{code, payload_hex}``
    list byte-identical to the Scapy and libcrafter decoders. A malformed or
    truncated region yields ``None`` so callers fall back to tshark's own
    message-type field.
    """

    if not source_hex:
        return None
    try:
        raw = bytes.fromhex(source_hex)
    except ValueError:
        return None
    cookie = _DHCP_MAGIC_COOKIE.to_bytes(4, "big")
    marker = raw.find(cookie)
    if marker < 0:
        return None
    return _decode_dhcp_option_tlvs(raw[marker + len(cookie) :])


def _decode_dhcp_option_tlvs(raw: bytes) -> list[JSONObject] | None:
    # Mirrors the Scapy reference parser
    # (tools/oracle/engine/backends/scapy/protocols/dhcp.py::_decode_dhcp_option_tlvs):
    # pad/end are single-octet options with empty payloads and END does not stop
    # parsing, so the ``option_count`` stays byte-identical across backends. The
    # wire bytes are identical for the offline strict-byte path, so the region
    # after the magic cookie matches the Scapy DHCP sub-layer region exactly.
    options: list[JSONObject] = []
    index = 0
    length = len(raw)
    while index < length:
        code = raw[index]
        index += 1
        if code in {_DHCP_OPTION_PAD, _DHCP_OPTION_END}:
            options.append({"code": code, "payload_hex": ""})
            continue
        if index >= length:
            return None
        option_length = raw[index]
        index += 1
        if index + option_length > length:
            return None
        payload = raw[index : index + option_length]
        index += option_length
        options.append({"code": code, "payload_hex": payload.hex()})
    return options if options else None


def _dhcp_layer(layers: JSONObject) -> JSONObject:
    layer = layers.get("dhcp")
    if isinstance(layer, dict):
        return layer
    return _layer(layers, "bootp")


register(
    WiresharkProtocol(
        layer="dhcp",
        normalize=_normalize,
        tshark_aliases=dict(_TSHARK_ALIASES),
    )
)
