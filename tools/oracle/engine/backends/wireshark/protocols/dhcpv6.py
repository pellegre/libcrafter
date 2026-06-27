"""Wireshark-stage decode plugin for the DHCPv6 layer."""

from __future__ import annotations

import ipaddress

from ....model import JSONObject
from ..decode_helpers import _fields_from_aliases, _layer, _parse_int_fields
from .base import WiresharkProtocol, register


_DHCPV6_RELAY_MESSAGE_TYPES = frozenset({12, 13})
_DHCPV6_RELAY_HEADER_LEN = 34
_DHCPV6_TRANSACTION_HEADER_LEN = 4
_IPV6_HEADER_LEN = 40
_UDP_HEADER_LEN = 8

_TSHARK_ALIASES: JSONObject = {
    "message_type": (
        "dhcpv6.msgtype",
        "dhcpv6.type",
        "dhcpv6.message_type",
    ),
    "transaction_id": (
        "dhcpv6.trid",
        "dhcpv6.xid",
        "dhcpv6.transaction_id",
        "dhcpv6.transactionid",
    ),
    "hop_count": (
        "dhcpv6.hopcount",
        "dhcpv6.hop_count",
    ),
    "link_address": (
        "dhcpv6.linkaddr",
        "dhcpv6.link_address",
    ),
    "peer_address": (
        "dhcpv6.peeraddr",
        "dhcpv6.peer_address",
    ),
}


def _normalize(layers: JSONObject, *, source_hex: str | None = None) -> JSONObject:
    """Normalize tshark DHCPv6 output to the shared oracle field names."""

    output = dhcpv6_fields_from_source(source_hex)
    if output is not None:
        return output

    layer = _layer(layers, "dhcpv6")
    output = _fields_from_aliases(layer, dict(_TSHARK_ALIASES))
    _parse_int_fields(output, "message_type", "transaction_id", "hop_count")
    _normalize_address_field(output, "link_address")
    _normalize_address_field(output, "peer_address")
    return output


def dhcpv6_fields_from_source(source_hex: str | None) -> JSONObject | None:
    payload = dhcpv6_payload_from_source(source_hex)
    if payload is None:
        return None
    return dhcpv6_fields_from_bytes(payload)


def dhcpv6_fields_from_bytes(payload: bytes) -> JSONObject | None:
    if len(payload) < _DHCPV6_TRANSACTION_HEADER_LEN:
        return None

    message_type = payload[0]
    output: JSONObject = {"message_type": message_type}
    if message_type in _DHCPV6_RELAY_MESSAGE_TYPES:
        if len(payload) < _DHCPV6_RELAY_HEADER_LEN:
            return None
        output["hop_count"] = payload[1]
        output["link_address"] = str(ipaddress.IPv6Address(payload[2:18]))
        output["peer_address"] = str(ipaddress.IPv6Address(payload[18:34]))
        options = _decode_dhcpv6_option_tlvs(payload[_DHCPV6_RELAY_HEADER_LEN:])
    else:
        output["transaction_id"] = int.from_bytes(payload[1:4], "big")
        options = _decode_dhcpv6_option_tlvs(payload[_DHCPV6_TRANSACTION_HEADER_LEN:])

    if options is not None:
        output["options"] = options
        output["option_count"] = len(options)
    return output


def dhcpv6_payload_from_source(source_hex: str | None) -> bytes | None:
    if not source_hex:
        return None
    try:
        raw = bytes.fromhex(source_hex)
    except ValueError:
        return None

    ipv6_offset = _ipv6_offset(raw)
    if ipv6_offset is None:
        return None
    if len(raw) < ipv6_offset + _IPV6_HEADER_LEN + _UDP_HEADER_LEN:
        return None
    if raw[ipv6_offset + 6] != 17:
        return None

    payload_length = int.from_bytes(raw[ipv6_offset + 4 : ipv6_offset + 6], "big")
    ipv6_end = ipv6_offset + _IPV6_HEADER_LEN + payload_length
    if ipv6_end > len(raw):
        return None
    udp_offset = ipv6_offset + _IPV6_HEADER_LEN
    udp_length = int.from_bytes(raw[udp_offset + 4 : udp_offset + 6], "big")
    if udp_length < _UDP_HEADER_LEN or udp_offset + udp_length > ipv6_end:
        return None
    return raw[udp_offset + _UDP_HEADER_LEN : udp_offset + udp_length]


def _ipv6_offset(raw: bytes) -> int | None:
    if len(raw) >= 14 and raw[12:14] == b"\x86\xdd":
        return 14
    if raw and raw[0] >> 4 == 6:
        return 0
    return None


def _decode_dhcpv6_option_tlvs(raw: bytes) -> list[JSONObject] | None:
    options: list[JSONObject] = []
    index = 0
    while index < len(raw):
        if index + 4 > len(raw):
            return None
        code = int.from_bytes(raw[index : index + 2], "big")
        option_length = int.from_bytes(raw[index + 2 : index + 4], "big")
        index += 4
        if index + option_length > len(raw):
            return None
        payload = raw[index : index + option_length]
        index += option_length
        options.append({"code": code, "payload_hex": payload.hex()})
    return options


def _normalize_address_field(output: JSONObject, name: str) -> None:
    value = output.get(name)
    if isinstance(value, str):
        try:
            output[name] = str(ipaddress.IPv6Address(value))
        except ValueError:
            pass


register(
    WiresharkProtocol(
        layer="dhcpv6",
        normalize=_normalize,
        tshark_aliases=dict(_TSHARK_ALIASES),
    )
)
