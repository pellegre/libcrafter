"""Scapy-stage encode + decode plugin for the DHCPv6 layer."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from typing import Any

from ....model import JSONObject, JSONValue
from ..encode_helpers import _int, _layer_fields, _optional_field, _required_field, _text
from .base import ScapyProtocol, register


_SUPPORTED_FIELDS = frozenset(
    {
        "hop_count",
        "link_address",
        "message_type",
        "options",
        "peer_address",
        "transaction_id",
    }
)

_MESSAGE_TYPES: dict[str, int] = {
    "solicit": 1,
    "advertise": 2,
    "request": 3,
    "confirm": 4,
    "renew": 5,
    "rebind": 6,
    "reply": 7,
    "release": 8,
    "decline": 9,
    "reconfigure": 10,
    "information-request": 11,
    "information_request": 11,
    "relay-forward": 12,
    "relay_forward": 12,
    "relay-forw": 12,
    "relay_forw": 12,
    "relay-reply": 13,
    "relay_reply": 13,
    "relay-repl": 13,
    "relay_repl": 13,
}
_MESSAGE_CLASS_BY_CODE: dict[int, str] = {
    1: "DHCP6_Solicit",
    2: "DHCP6_Advertise",
    3: "DHCP6_Request",
    4: "DHCP6_Confirm",
    5: "DHCP6_Renew",
    6: "DHCP6_Rebind",
    7: "DHCP6_Reply",
    8: "DHCP6_Release",
    9: "DHCP6_Decline",
    10: "DHCP6_Reconf",
    11: "DHCP6_InfoRequest",
    12: "DHCP6_RelayForward",
    13: "DHCP6_RelayReply",
}
_DHCPV6_RELAY_MESSAGE_TYPES = frozenset({12, 13})

_STATUS_CODES: dict[str, int] = {
    "success": 0,
    "unspec_fail": 1,
    "unspec-fail": 1,
    "no_addrs_avail": 2,
    "no-addrs-avail": 2,
    "no_binding": 3,
    "no-binding": 3,
    "not_on_link": 4,
    "not-on-link": 4,
    "use_multicast": 5,
    "use-multicast": 5,
    "no_prefix_avail": 6,
    "no-prefix-avail": 6,
}

_DHCPV6_OPTION_REGION_KEY = "__dhcpv6_option_region_hex__"

_LAYER_ALIASES = (
    ("DHCP6", "dhcpv6"),
    ("DHCP6_Solicit", "dhcpv6"),
    ("DHCP6_Advertise", "dhcpv6"),
    ("DHCP6_Request", "dhcpv6"),
    ("DHCP6_Confirm", "dhcpv6"),
    ("DHCP6_Renew", "dhcpv6"),
    ("DHCP6_Rebind", "dhcpv6"),
    ("DHCP6_Reply", "dhcpv6"),
    ("DHCP6_Release", "dhcpv6"),
    ("DHCP6_Decline", "dhcpv6"),
    ("DHCP6_Reconf", "dhcpv6"),
    ("DHCP6_InfoRequest", "dhcpv6"),
    ("DHCP6_RelayForward", "dhcpv6"),
    ("DHCP6_RelayReply", "dhcpv6"),
    ("DHCP6_AddrRegInform", "dhcpv6"),
    ("DHCP6_AddrRegReply", "dhcpv6"),
)
_FIELD_ALIASES = (
    ("hopcount", "hop_count"),
    ("linkaddr", "link_address"),
    ("msgtype", "message_type"),
    ("peeraddr", "peer_address"),
    ("trid", "transaction_id"),
)


def _build(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    return _dhcpv6(_layer_fields(fields, "dhcpv6"), scapy_all)


def _dhcpv6(fields: Mapping[str, object], scapy_all: Any) -> Any:
    message_type = _message_type_code(
        _required_field(fields, "dhcpv6", "message_type")
    )
    if message_type in _DHCPV6_RELAY_MESSAGE_TYPES:
        cls = getattr(scapy_all, _MESSAGE_CLASS_BY_CODE[message_type])
        message = cls(
            hopcount=_int(_optional_field(fields, "hop_count"), 0),
            linkaddr=_text(_required_field(fields, "dhcpv6", "link_address"), "::"),
            peeraddr=_text(_required_field(fields, "dhcpv6", "peer_address"), "::"),
        )
    else:
        cls_name = _MESSAGE_CLASS_BY_CODE.get(message_type, "DHCP6")
        cls = getattr(scapy_all, cls_name)
        message = cls(trid=_int(_optional_field(fields, "transaction_id"), 0))
        if cls_name == "DHCP6":
            message.msgtype = message_type

    for option in _dhcpv6_options(_required_field(fields, "dhcpv6", "options"), scapy_all):
        message = message / option
    return message


def _dhcpv6_options(value: object, scapy_all: Any) -> list[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError("dhcpv6 options must be an array")
    return [_dhcpv6_option(item, scapy_all) for item in value]


def _dhcpv6_option(value: object, scapy_all: Any) -> Any:
    if not isinstance(value, Mapping):
        raise ValueError(f"dhcpv6 option must be an object, got {value!r}")
    name = _text(_required_field(value, "dhcpv6.option", "name"), "")
    normalized = name.lower().replace("-", "_")
    if normalized == "client_id":
        return scapy_all.DHCP6OptClientId(duid=_hex_field(value, "duid"))
    if normalized == "server_id":
        return scapy_all.DHCP6OptServerId(duid=_hex_field(value, "duid"))
    if normalized == "oro":
        codes = _required_field(value, "dhcpv6.option.oro", "codes")
        if not isinstance(codes, Sequence) or isinstance(codes, (str, bytes, bytearray)):
            raise ValueError("dhcpv6 ORO codes must be an array")
        return scapy_all.DHCP6OptOptReq(reqopts=[_int(code, 0) for code in codes])
    if normalized == "elapsed_time":
        return scapy_all.DHCP6OptElapsedTime(
            elapsedtime=_int(_required_field(value, "dhcpv6.option.elapsed_time", "centiseconds"), 0)
        )
    if normalized == "status_code":
        return scapy_all.DHCP6OptStatusCode(
            statuscode=_status_code(_required_field(value, "dhcpv6.option.status_code", "status")),
            statusmsg=_option_text_or_bytes(value.get("message")),
        )
    if normalized == "dns_servers":
        servers = _required_field(value, "dhcpv6.option.dns_servers", "servers")
        if not isinstance(servers, Sequence) or isinstance(servers, (str, bytes, bytearray)):
            raise ValueError("dhcpv6 DNS servers must be an array")
        return scapy_all.DHCP6OptDNSServers(dnsservers=[str(server) for server in servers])
    if normalized == "domain_list":
        domains = _required_field(value, "dhcpv6.option.domain_list", "domains")
        if not isinstance(domains, Sequence) or isinstance(domains, (str, bytes, bytearray)):
            raise ValueError("dhcpv6 domain list must be an array")
        return scapy_all.DHCP6OptDNSDomains(dnsdomains=[_dns_name(str(domain)) for domain in domains])
    if normalized == "ia_na":
        return scapy_all.DHCP6OptIA_NA(
            iaid=_int(_required_field(value, "dhcpv6.option.ia_na", "iaid"), 0),
            T1=_int(_optional_field(value, "t1"), 0),
            T2=_int(_optional_field(value, "t2"), 0),
            ianaopts=_nested_options(value, scapy_all),
        )
    if normalized == "ia_addr":
        return scapy_all.DHCP6OptIAAddress(
            addr=_text(_required_field(value, "dhcpv6.option.ia_addr", "address"), "::"),
            preflft=_int(_required_field(value, "dhcpv6.option.ia_addr", "preferred_lifetime"), 0),
            validlft=_int(_required_field(value, "dhcpv6.option.ia_addr", "valid_lifetime"), 0),
            iaaddropts=_nested_options(value, scapy_all),
        )
    if normalized == "ia_pd":
        return scapy_all.DHCP6OptIA_PD(
            iaid=_int(_required_field(value, "dhcpv6.option.ia_pd", "iaid"), 0),
            T1=_int(_optional_field(value, "t1"), 0),
            T2=_int(_optional_field(value, "t2"), 0),
            iapdopt=_nested_options(value, scapy_all),
        )
    if normalized == "ia_prefix":
        return scapy_all.DHCP6OptIAPrefix(
            preflft=_int(_required_field(value, "dhcpv6.option.ia_prefix", "preferred_lifetime"), 0),
            validlft=_int(_required_field(value, "dhcpv6.option.ia_prefix", "valid_lifetime"), 0),
            plen=_int(_required_field(value, "dhcpv6.option.ia_prefix", "prefix_length"), 0),
            prefix=_text(_required_field(value, "dhcpv6.option.ia_prefix", "prefix"), "::"),
            iaprefopts=_nested_options(value, scapy_all),
        )
    if normalized == "interface_id":
        return scapy_all.DHCP6OptIfaceId(ifaceid=_payload_hex(value))
    if normalized == "relay_msg":
        if "payload_hex" in value:
            payload = _payload_hex(value)
        else:
            nested_message = _required_field(value, "dhcpv6.option.relay_msg", "message")
            if not isinstance(nested_message, Mapping):
                raise ValueError("dhcpv6 relay_msg.message must be an object")
            payload = _dhcpv6(nested_message, scapy_all)
        return scapy_all.DHCP6OptRelayMsg(message=payload)
    if normalized in {"unknown", "raw"}:
        return scapy_all.DHCP6OptUnknown(
            optcode=_int(_required_field(value, "dhcpv6.option.unknown", "code"), 0),
            data=_payload_hex(value),
        )
    raise ValueError(f"unsupported dhcpv6 option kind: {name!r}")


def _nested_options(value: Mapping[str, object], scapy_all: Any) -> list[Any]:
    options = value.get("options", [])
    return _dhcpv6_options(options, scapy_all)


def _message_type_code(value: object) -> int:
    if isinstance(value, str):
        normalized = value.lower().replace("-", "_")
        if normalized in _MESSAGE_TYPES:
            return _MESSAGE_TYPES[normalized]
        return int(normalized, 0)
    return _int(value, 1)


def _status_code(value: object) -> int:
    if isinstance(value, str):
        normalized = value.lower().replace("-", "_")
        if normalized in _STATUS_CODES:
            return _STATUS_CODES[normalized]
        return int(normalized, 0)
    return _int(value, 0)


def _hex_field(value: Mapping[str, object], name: str) -> bytes:
    raw = _required_field(value, f"dhcpv6.option.{name}", name)
    if not isinstance(raw, str):
        raise ValueError(f"dhcpv6 option field {name} must be hex text")
    return bytes.fromhex(raw)


def _payload_hex(value: Mapping[str, object]) -> bytes:
    raw = _required_field(value, "dhcpv6.option.payload", "payload_hex")
    if not isinstance(raw, str):
        raise ValueError("dhcpv6 option payload_hex must be hex text")
    return bytes.fromhex(raw)


def _option_text_or_bytes(value: object) -> bytes:
    if value is None:
        return b""
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, Mapping):
        raw = value.get("hex")
        if isinstance(raw, str):
            return bytes.fromhex(raw)
    raise ValueError(f"unsupported dhcpv6 option text/bytes value: {value!r}")


def _dns_name(value: str) -> str:
    return value if value.endswith(".") else f"{value}."


def _normalize(fields: JSONObject) -> JSONObject:
    option_region_hex = fields.get(_DHCPV6_OPTION_REGION_KEY)
    output: JSONObject = {}
    message_type = fields.get("msgtype")
    if isinstance(message_type, int):
        output["message_type"] = message_type
    transaction_id = fields.get("trid")
    if isinstance(transaction_id, int):
        output["transaction_id"] = transaction_id
    hop_count = fields.get("hopcount")
    if isinstance(hop_count, int):
        output["hop_count"] = hop_count
    link_address = fields.get("linkaddr")
    if isinstance(link_address, str):
        output["link_address"] = str(ipaddress.IPv6Address(link_address))
    peer_address = fields.get("peeraddr")
    if isinstance(peer_address, str):
        output["peer_address"] = str(ipaddress.IPv6Address(peer_address))
    if isinstance(option_region_hex, str):
        _apply_dhcpv6_option_details(output, option_region_hex)
    return output


def _apply_dhcpv6_option_details(output: JSONObject, option_region_hex: str) -> None:
    options = _decode_dhcpv6_option_tlvs(option_region_hex)
    if options is None:
        return
    output["options"] = options
    output["option_count"] = len(options)


def _decode_dhcpv6_option_tlvs(option_region_hex: str) -> list[JSONObject] | None:
    try:
        raw = bytes.fromhex(option_region_hex)
    except ValueError:
        return None
    options: list[JSONObject] = []
    index = 0
    length = len(raw)
    while index < length:
        if index + 4 > length:
            return None
        code = int.from_bytes(raw[index : index + 2], "big")
        option_length = int.from_bytes(raw[index + 2 : index + 4], "big")
        index += 4
        if index + option_length > length:
            return None
        payload = raw[index : index + option_length]
        index += option_length
        options.append({"code": code, "payload_hex": payload.hex()})
    return options


register(
    ScapyProtocol(
        layer="dhcpv6",
        scapy_class="DHCP6",
        supported_fields=_SUPPORTED_FIELDS,
        build=_build,
        normalize=_normalize,
        layer_aliases=_LAYER_ALIASES,
        field_aliases=_FIELD_ALIASES,
    )
)
