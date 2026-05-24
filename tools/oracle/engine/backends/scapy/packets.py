"""Scapy raw packet materialization for oracle packet plans."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ...model import EncodedVector, JSONObject, PacketPlan
from ..registry import BackendCapabilities, BackendRegistration, get_backend
from .bootstrap import import_scapy


BACKEND_NAME = "scapy"

_ETHERTYPES: dict[str, int] = {
    "arp": 0x0806,
    "experimental": 0x9000,
    "ipv4": 0x0800,
    "ip": 0x0800,
    "ipv6": 0x86DD,
    "unknown": 0x9000,
    "vlan": 0x8100,
}
_IP_PROTOCOLS: dict[str, int] = {
    "icmp": 1,
    "tcp": 6,
    "unknown": 253,
    "udp": 17,
}
_IPV6_NEXT_HEADERS: dict[str, int] = {
    "fragment": 44,
    "routing": 43,
    "icmpv6": 58,
    "payload": 253,
    "raw": 253,
    "tcp": 6,
    "unknown": 253,
    "udp": 17,
}
_SCAPY_LAYER_BY_LAYER: dict[str, str] = {
    "arp": "ARP",
    "dhcp": "DHCP",
    "dns": "DNS",
    "ethernet": "Ether",
    "icmp": "ICMP",
    "icmpv6": "ICMPv6EchoRequest",
    "ipv6_fragment": "IPv6ExtHdrFragment",
    "ipv6_routing": "IPv6ExtHdrRouting",
    "ipv4": "IP",
    "ipv6": "IPv6",
    "linux_cooked": "CookedLinux",
    "null_loopback": "Loopback",
    "payload": "Raw",
    "raw": "Raw",
    "tcp": "TCP",
    "udp": "UDP",
    "vlan": "Dot1Q",
}
_SCAPY_DECODER_BY_ROOT: dict[str, str] = {
    "link:ethernet": "Ether",
    "link:linux-cooked": "CookedLinux",
    "link:linux-sll": "CookedLinux",
    "link:null-loopback": "Loopback",
    "link:raw": "Raw",
    "l3:ipv4": "IP",
    "l3:ipv6": "IPv6",
}
_ROOT_FIRST_LAYERS: dict[str, set[str]] = {
    "link:ethernet": {"ethernet"},
    "link:linux-cooked": {"linux_cooked"},
    "link:linux-sll": {"linux_cooked"},
    "link:null-loopback": {"null_loopback"},
    "link:raw": {"payload"},
    "l3:ipv4": {"ipv4"},
    "l3:ipv6": {"ipv6"},
}
_SCAPY_MATERIALIZED_LAYERS = frozenset(_SCAPY_LAYER_BY_LAYER)
_SUPPORTED_FEATURES = {
    "dhcp_behavior",
    "dns_behavior",
    "icmpv4_errors",
    "icmpv6_errors",
    "ipv4_options",
    "ipv6_fragment_routing",
    "pcap_contracts",
    "pcap_link_types",
    "tcp_options",
}
_SUPPORTED_FIELDS_BY_LAYER: dict[str, set[str]] = {
    "arp": {
        "hardware_type",
        "hwtype",
        "protocol_type",
        "ptype",
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
    },
    "dhcp": {
        "op",
        "hardware_type",
        "htype",
        "hardware_length",
        "hlen",
        "transaction_id",
        "xid",
        "flags",
        "client_ip",
        "ciaddr",
        "your_ip",
        "yiaddr",
        "client_hardware_address",
        "chaddr",
        "options",
    },
    "dns": {
        "answers",
        "flags",
        "id",
        "is_response",
        "opcode",
        "qname",
        "qtype",
        "questions",
        "query",
        "response_code",
        "transaction_id",
    },
    "ethernet": {"dst", "ethertype", "src", "type"},
    "icmp": {"checksum", "chksum", "code", "id", "identifier", "seq", "sequence", "type"},
    "icmpv6": {"checksum", "cksum", "code", "id", "identifier", "seq", "sequence", "type"},
    "ipv4": {
        "dst",
        "flags",
        "frag",
        "fragment_offset",
        "id",
        "identification",
        "options",
        "protocol",
        "proto",
        "src",
        "tos",
        "ttl",
    },
    "ipv6": {
        "dst",
        "fl",
        "flow_label",
        "hlim",
        "hop_limit",
        "next_header",
        "nh",
        "src",
        "tc",
        "traffic_class",
    },
    "ipv6_fragment": {
        "fragment_offset",
        "identification",
        "id",
        "m",
        "more_fragments",
        "next_header",
        "nh",
        "offset",
        "reserved",
    },
    "ipv6_routing": {
        "addresses",
        "next_header",
        "nh",
        "routing_type",
        "segments_left",
        "segleft",
        "type",
    },
    "linux_cooked": {
        "address_length",
        "address_type",
        "packet_type",
        "protocol",
        "source_address",
    },
    "null_loopback": {"type"},
    "payload": {"bytes_hex", "hex", "length", "text", "value"},
    "tcp": {
        "ack",
        "acknowledgement",
        "checksum",
        "chksum",
        "data_offset",
        "dataofs",
        "dport",
        "dst_port",
        "flags",
        "options",
        "reserved",
        "seq",
        "sequence",
        "sport",
        "src_port",
        "urgent_pointer",
        "urgptr",
        "window",
    },
    "udp": {"checksum", "chksum", "dport", "dst_port", "len", "length", "sport", "src_port"},
    "vlan": {
        "dei",
        "drop_eligible",
        "ethertype",
        "id",
        "prio",
        "priority",
        "type",
        "vlan",
        "vlan_id",
    },
}


def encode_packet_plan(
    plan: PacketPlan,
    *,
    capabilities: BackendCapabilities | BackendRegistration | None = None,
) -> EncodedVector:
    """Materialize one backend-neutral packet plan as Scapy-generated bytes."""

    _require_encode_capability(capabilities)
    scapy = import_scapy()
    scapy_all = scapy["all"]
    scapy_version = _string(scapy["version"], "unknown")
    raw = scapy_all.raw

    stack = _canonical_stack(plan.stack)
    if not stack:
        raise ValueError("packet plan stack must contain at least one layer")
    root = _plan_root(plan)
    _validate_plan_contract(plan, stack, root)

    packet = None
    for index, layer in enumerate(stack):
        piece = _build_layer(plan, stack, index, scapy_all)
        packet = piece if packet is None else packet / piece

    if packet is None:
        raise ValueError("packet plan did not produce a packet")

    raw_bytes = bytes(raw(packet))
    return EncodedVector.from_bytes(
        plan=plan,
        backend=BACKEND_NAME,
        raw=raw_bytes,
        root=root,
        decoder=_scapy_decoder(root),
        metadata={
            "backend": BACKEND_NAME,
            "feature_tags": list(plan.feature_tags),
            "scapy_version": scapy_version,
            "root_decoder": root,
            "stack_tags": list(plan.feature_tags),
            "strict_bytes": plan.strict_bytes,
            "scapy_stack": [_scapy_layer_name(layer) for layer in stack],
            "length": len(raw_bytes),
        },
    )


def encode_packet_plans(
    plans: list[PacketPlan],
    *,
    capabilities: BackendCapabilities | BackendRegistration | None = None,
) -> list[EncodedVector]:
    """Materialize packet plans in order."""

    _require_encode_capability(capabilities)
    return [encode_packet_plan(plan, capabilities=capabilities) for plan in plans]


def _build_layer(plan: PacketPlan, stack: list[str], index: int, scapy_all: Any) -> Any:
    layer = stack[index]
    fields = plan.fields

    if layer == "payload" or layer == "raw":
        return scapy_all.Raw(load=_payload_bytes(fields))
    if layer == "ethernet":
        return _ethernet(plan, scapy_all)
    if layer == "linux_cooked":
        return _linux_cooked(plan.fields, scapy_all)
    if layer == "null_loopback":
        return _null_loopback(plan.fields, scapy_all)
    if layer == "vlan":
        return _vlan(plan, scapy_all)
    if layer == "arp":
        return _arp(fields, scapy_all)
    if layer == "ipv4":
        return _ipv4(fields, stack, index, scapy_all)
    if layer == "ipv6":
        return _ipv6(fields, stack, index, scapy_all)
    if layer == "ipv6_fragment":
        return _ipv6_fragment(fields, stack, index, scapy_all)
    if layer == "ipv6_routing":
        return _ipv6_routing(fields, stack, index, scapy_all)
    if layer == "icmp":
        return _icmp(fields, scapy_all)
    if layer == "icmpv6":
        return _icmpv6(fields, stack, scapy_all)
    if layer == "udp":
        return _udp(fields, stack, scapy_all)
    if layer == "tcp":
        return _tcp(fields, scapy_all)
    if layer == "dns":
        return _dns(fields, scapy_all)
    if layer == "dhcp":
        return _dhcp(fields, scapy_all)

    raise ValueError(f"unsupported Scapy materialization layer: {layer}")


def _ethernet(plan: PacketPlan, scapy_all: Any) -> Any:
    fields = _layer_fields(plan.fields, "ethernet")
    kwargs: dict[str, Any] = {
        "src": _text(_required_field(fields, "ethernet", "src"), ""),
        "dst": _text(_required_field(fields, "ethernet", "dst"), ""),
        "type": _ethertype_value(_required_field(fields, "ethernet", "ethertype", "type")),
    }
    return scapy_all.Ether(**kwargs)


def _vlan(plan: PacketPlan, scapy_all: Any) -> Any:
    fields = _layer_fields(plan.fields, "vlan")
    kwargs: dict[str, Any] = {
        "prio": _int(_required_field(fields, "vlan", "priority", "prio"), 0),
        "vlan": _int(_required_field(fields, "vlan", "vlan_id", "id", "vlan"), 0),
        "type": _ethertype_value(_required_field(fields, "vlan", "ethertype", "type")),
        "dei": _int(_required_field(fields, "vlan", "drop_eligible", "dei"), 0),
    }
    return scapy_all.Dot1Q(**kwargs)


def _linux_cooked(fields: Mapping[str, JSONObject], scapy_all: Any) -> Any:
    sll_fields = _layer_fields(fields, "linux_cooked")
    kwargs: dict[str, Any] = {
        "pkttype": _linux_sll_packet_type(
            _required_field(sll_fields, "linux_cooked", "packet_type")
        ),
        "lladdrtype": _hardware_type_value(
            _required_field(sll_fields, "linux_cooked", "address_type")
        ),
        "lladdrlen": _int(
            _required_field(sll_fields, "linux_cooked", "address_length"),
            6,
        ),
        "src": _bytes_field(
            _required_field(sll_fields, "linux_cooked", "source_address"),
            pad_to=8,
        ),
        "proto": _ethertype_value(
            _required_field(sll_fields, "linux_cooked", "protocol")
        ),
    }
    return scapy_all.CookedLinux(**kwargs)


def _null_loopback(fields: Mapping[str, JSONObject], scapy_all: Any) -> Any:
    null_fields = _layer_fields(fields, "null_loopback")
    kwargs = {
        "type": _address_family_value(
            _required_field(null_fields, "null_loopback", "type")
        )
    }
    return scapy_all.Loopback(**kwargs)


def _arp(fields: Mapping[str, JSONObject], scapy_all: Any) -> Any:
    arp_fields = _layer_fields(fields, "arp")
    kwargs: dict[str, Any] = {
        "op": _arp_op(_required_field(arp_fields, "arp", "opcode", "op", "operation")),
        "hwsrc": _text(
            _required_field(arp_fields, "arp", "sender_hardware_address", "hwsrc"),
            "",
        ),
        "psrc": _text(
            _required_field(
                arp_fields,
                "arp",
                "sender_protocol_address",
                "sender_ip",
                "psrc",
            ),
            "",
        ),
        "hwdst": _text(
            _required_field(arp_fields, "arp", "target_hardware_address", "hwdst"),
            "",
        ),
        "pdst": _text(
            _required_field(
                arp_fields,
                "arp",
                "target_protocol_address",
                "target_ip",
                "pdst",
            ),
            "",
        ),
        "hwtype": _hardware_type_value(
            _required_field(arp_fields, "arp", "hardware_type", "hwtype")
        ),
        "ptype": _ethertype_value(_required_field(arp_fields, "arp", "protocol_type", "ptype")),
    }
    return scapy_all.ARP(**kwargs)


def _ipv4(fields: Mapping[str, JSONObject], stack: list[str], index: int, scapy_all: Any) -> Any:
    ipv4_fields = _layer_fields(fields, "ipv4")
    kwargs: dict[str, Any] = {
        "src": _text(_required_field(ipv4_fields, "ipv4", "src"), ""),
        "dst": _text(_required_field(ipv4_fields, "ipv4", "dst"), ""),
        "id": _int(_required_field(ipv4_fields, "ipv4", "identification", "id"), 0),
        "ttl": _int(_required_field(ipv4_fields, "ipv4", "ttl"), 0),
        "flags": _ipv4_flags(_required_field(ipv4_fields, "ipv4", "flags")),
        "proto": _protocol_value(_required_field(ipv4_fields, "ipv4", "protocol", "proto"), _IP_PROTOCOLS),
    }
    if "tos" in ipv4_fields:
        kwargs["tos"] = _int(ipv4_fields.get("tos"), 0)
    if "fragment_offset" in ipv4_fields or "frag" in ipv4_fields:
        kwargs["frag"] = _int(_optional_field(ipv4_fields, "fragment_offset", "frag"), 0)
    if "options" in ipv4_fields:
        kwargs["options"] = _ipv4_options(ipv4_fields["options"], scapy_all)
    return scapy_all.IP(**kwargs)


def _ipv6(fields: Mapping[str, JSONObject], stack: list[str], index: int, scapy_all: Any) -> Any:
    ipv6_fields = _layer_fields(fields, "ipv6")
    kwargs: dict[str, Any] = {
        "src": _text(_required_field(ipv6_fields, "ipv6", "src"), ""),
        "dst": _text(_required_field(ipv6_fields, "ipv6", "dst"), ""),
        "hlim": _int(_required_field(ipv6_fields, "ipv6", "hop_limit", "hlim"), 0),
        "nh": _protocol_value(
            _required_field(ipv6_fields, "ipv6", "next_header", "nh"),
            _IPV6_NEXT_HEADERS,
        ),
    }
    if "traffic_class" in ipv6_fields or "tc" in ipv6_fields:
        kwargs["tc"] = _int(_optional_field(ipv6_fields, "traffic_class", "tc"), 0)
    if "flow_label" in ipv6_fields or "fl" in ipv6_fields:
        kwargs["fl"] = _int(_optional_field(ipv6_fields, "flow_label", "fl"), 0)
    return scapy_all.IPv6(**kwargs)


def _ipv6_fragment(
    fields: Mapping[str, JSONObject],
    stack: list[str],
    index: int,
    scapy_all: Any,
) -> Any:
    fragment_fields = _layer_fields(fields, "ipv6_fragment")
    kwargs: dict[str, Any] = {
        "nh": _protocol_value(
            _required_field(fragment_fields, "ipv6_fragment", "next_header", "nh"),
            _IPV6_NEXT_HEADERS,
        ),
        "id": _int(_required_field(fragment_fields, "ipv6_fragment", "identification", "id"), 0),
        "offset": _int(
            _required_field(fragment_fields, "ipv6_fragment", "fragment_offset", "offset"),
            0,
        ),
        "m": _int(_required_field(fragment_fields, "ipv6_fragment", "more_fragments", "m"), 0),
    }
    if "reserved" in fragment_fields:
        kwargs["res1"] = _int(fragment_fields.get("reserved"), 0)
    return scapy_all.IPv6ExtHdrFragment(**kwargs)


def _ipv6_routing(
    fields: Mapping[str, JSONObject],
    stack: list[str],
    index: int,
    scapy_all: Any,
) -> Any:
    routing_fields = _layer_fields(fields, "ipv6_routing")
    kwargs: dict[str, Any] = {
        "nh": _protocol_value(
            _required_field(routing_fields, "ipv6_routing", "next_header", "nh"),
            _IPV6_NEXT_HEADERS,
        ),
        "type": _int(_required_field(routing_fields, "ipv6_routing", "type", "routing_type"), 0),
        "segleft": _int(
            _required_field(routing_fields, "ipv6_routing", "segments_left", "segleft"),
            0,
        ),
    }
    addresses = routing_fields.get("addresses")
    if isinstance(addresses, list):
        kwargs["addresses"] = addresses
    return scapy_all.IPv6ExtHdrRouting(**kwargs)


def _icmp(fields: Mapping[str, JSONObject], scapy_all: Any) -> Any:
    icmp_fields = _layer_fields(fields, "icmp")
    kwargs: dict[str, Any] = {
        "type": _icmp_type(_required_field(icmp_fields, "icmp", "type")),
        "code": _int(_required_field(icmp_fields, "icmp", "code"), 0),
    }
    if "id" in icmp_fields or "identifier" in icmp_fields:
        kwargs["id"] = _int(_optional_field(icmp_fields, "id", "identifier"), 0)
    if "seq" in icmp_fields or "sequence" in icmp_fields:
        kwargs["seq"] = _int(_optional_field(icmp_fields, "seq", "sequence"), 0)
    if "checksum" in icmp_fields or "chksum" in icmp_fields:
        kwargs["chksum"] = _int(_optional_field(icmp_fields, "checksum", "chksum"), 0)
    return scapy_all.ICMP(**kwargs)


def _icmpv6(fields: Mapping[str, JSONObject], stack: list[str], scapy_all: Any) -> Any:
    icmpv6_fields = _layer_fields(fields, "icmpv6")
    icmp_type = _icmp_type(_required_field(icmpv6_fields, "icmpv6", "type"))
    class_name = _icmpv6_class_name(icmp_type)
    layer_factory = getattr(scapy_all, class_name, None)
    if layer_factory is None:
        raise ValueError(f"Scapy layer is unavailable for icmpv6 type {icmp_type!r}: {class_name}")

    kwargs: dict[str, Any] = {}
    if "code" in icmpv6_fields:
        kwargs["code"] = _int(icmpv6_fields.get("code"), 0)
    if "checksum" in icmpv6_fields or "cksum" in icmpv6_fields:
        kwargs["cksum"] = _int(_optional_field(icmpv6_fields, "checksum", "cksum"), 0)
    if class_name in {"ICMPv6EchoReply", "ICMPv6EchoRequest"}:
        if "id" in icmpv6_fields or "identifier" in icmpv6_fields:
            kwargs["id"] = _int(_optional_field(icmpv6_fields, "id", "identifier"), 0)
        if "seq" in icmpv6_fields or "sequence" in icmpv6_fields:
            kwargs["seq"] = _int(_optional_field(icmpv6_fields, "seq", "sequence"), 0)
    if "payload" not in stack:
        payload = _payload_bytes(fields)
        if payload:
            kwargs["data"] = payload
    return layer_factory(**kwargs)


def _udp(fields: Mapping[str, JSONObject], stack: list[str], scapy_all: Any) -> Any:
    udp_fields = _layer_fields(fields, "udp")
    kwargs: dict[str, Any] = {
        "sport": _int(_required_field(udp_fields, "udp", "src_port", "sport"), 0),
        "dport": _int(_required_field(udp_fields, "udp", "dst_port", "dport"), 0),
    }
    if "checksum" in udp_fields or "chksum" in udp_fields:
        kwargs["chksum"] = _int(_optional_field(udp_fields, "checksum", "chksum"), 0)
    if "length" in udp_fields or "len" in udp_fields:
        kwargs["len"] = _int(_optional_field(udp_fields, "length", "len"), 0)
    return scapy_all.UDP(**kwargs)


def _tcp(fields: Mapping[str, JSONObject], scapy_all: Any) -> Any:
    tcp_fields = _layer_fields(fields, "tcp")
    kwargs: dict[str, Any] = {
        "sport": _int(_required_field(tcp_fields, "tcp", "src_port", "sport"), 0),
        "dport": _int(_required_field(tcp_fields, "tcp", "dst_port", "dport"), 0),
        "flags": _tcp_flags(_required_field(tcp_fields, "tcp", "flags")),
        "seq": _int(_required_field(tcp_fields, "tcp", "sequence", "seq"), 0),
        "ack": _int(_required_field(tcp_fields, "tcp", "acknowledgement", "ack"), 0),
        "window": _int(_required_field(tcp_fields, "tcp", "window"), 0),
        "reserved": _int(_required_field(tcp_fields, "tcp", "reserved"), 0),
        "urgptr": _int(_optional_field(tcp_fields, "urgent_pointer", "urgptr"), 0),
    }
    if "checksum" in tcp_fields or "chksum" in tcp_fields:
        kwargs["chksum"] = _int(_optional_field(tcp_fields, "checksum", "chksum"), 0)
    if "data_offset" in tcp_fields or "dataofs" in tcp_fields:
        kwargs["dataofs"] = _int(_optional_field(tcp_fields, "data_offset", "dataofs"), 0)
    if "options" in tcp_fields:
        kwargs["options"] = _tcp_options(tcp_fields["options"])
    return scapy_all.TCP(**kwargs)


def _dns(fields: Mapping[str, JSONObject], scapy_all: Any) -> Any:
    dns_fields = _layer_fields(fields, "dns")
    questions_value = _required_field(dns_fields, "dns", "questions")
    if not isinstance(questions_value, list) or not questions_value:
        raise ValueError("dns materialization requires at least one question")
    question = _first_question(dns_fields)
    qname = _text(question.get("qname"), "")
    if not qname.endswith("."):
        qname = f"{qname}."
    flags = _dns_flags(_optional_field(dns_fields, "flags"))
    questions = _dns_questions(dns_fields, scapy_all)
    answers = _dns_answers(dns_fields, scapy_all)
    return scapy_all.DNS(
        id=_int(_optional_field(dns_fields, "transaction_id", "id"), 0),
        qr=_bool_int(_optional_field(dns_fields, "is_response"), 0),
        opcode=_dns_opcode(_optional_field(dns_fields, "opcode")),
        qdcount=_dns_count(dns_fields.get("questions"), 1),
        ancount=_dns_count(dns_fields.get("answers"), 0),
        aa=flags["aa"],
        tc=flags["tc"],
        rd=flags["rd"],
        rcode=_dns_response_code(_optional_field(dns_fields, "response_code")),
        qd=questions
        or scapy_all.DNSQR(
            qname=qname,
            qtype=_text(dns_fields.get("qtype", question.get("qtype")), "A"),
        ),
        an=answers,
    )


def _dhcp(fields: Mapping[str, JSONObject], scapy_all: Any) -> Any:
    dhcp_fields = _layer_fields(fields, "dhcp")
    bootp = scapy_all.BOOTP(
        op=_dhcp_op(_required_field(dhcp_fields, "dhcp", "op")),
        htype=_hardware_type_value(_required_field(dhcp_fields, "dhcp", "hardware_type", "htype")),
        hlen=_int(_required_field(dhcp_fields, "dhcp", "hardware_length", "hlen"), 0),
        xid=_int(_required_field(dhcp_fields, "dhcp", "transaction_id", "xid"), 0),
        flags=_dhcp_flags(_required_field(dhcp_fields, "dhcp", "flags")),
        ciaddr=_text(_required_field(dhcp_fields, "dhcp", "client_ip", "ciaddr"), ""),
        yiaddr=_text(_required_field(dhcp_fields, "dhcp", "your_ip", "yiaddr"), ""),
        chaddr=_dhcp_chaddr(
            _required_field(dhcp_fields, "dhcp", "client_hardware_address", "chaddr")
        ),
    )
    return bootp / scapy_all.DHCP(
        options=_dhcp_options(_required_field(dhcp_fields, "dhcp", "options"))
    )


def _canonical_stack(stack: list[str]) -> list[str]:
    aliases = {
        "dot1q": "vlan",
        "ether": "ethernet",
        "ip": "ipv4",
        "raw": "payload",
    }
    return [aliases.get(layer.lower(), layer.lower()) for layer in stack]


def _validate_plan_contract(plan: PacketPlan, stack: list[str], root: str) -> None:
    supported_roots = _ROOT_FIRST_LAYERS.get(root)
    if supported_roots is None:
        raise ValueError(f"unsupported Scapy materialization root: {root!r}")
    if stack[0] not in supported_roots:
        raise ValueError(
            f"packet plan root/stack mismatch for Scapy materialization: "
            f"root={root!r} first_layer={stack[0]!r}"
        )

    feature = plan.metadata.get("feature")
    if feature is not None:
        if not isinstance(feature, str):
            raise ValueError("packet plan metadata.feature must be a string when present")
        if feature not in _SUPPORTED_FEATURES:
            raise ValueError(
                f"unsupported Scapy feature materialization: {feature!r}; "
                f"supported features: {', '.join(sorted(_SUPPORTED_FEATURES))}"
            )

    for layer in stack:
        if layer not in _SCAPY_MATERIALIZED_LAYERS:
            raise ValueError(f"unsupported Scapy materialization layer: {layer}")
        fields = _layer_fields(plan.fields, layer)
        _validate_layer_fields(layer, fields)
        if layer == "payload":
            if not fields:
                raise ValueError("payload materialization requires payload fields")
            _payload_bytes(plan.fields)


def _validate_layer_fields(layer: str, fields: Mapping[str, object]) -> None:
    supported = _SUPPORTED_FIELDS_BY_LAYER.get(layer)
    if supported is None:
        raise ValueError(f"unsupported Scapy materialization layer: {layer}")
    unknown = sorted(set(fields) - supported)
    if unknown:
        raise ValueError(
            f"unsupported Scapy materialization fields for {layer}: {', '.join(unknown)}"
        )


def _plan_root(plan: PacketPlan) -> str:
    root = plan.metadata.get("root_decoder", plan.metadata.get("root"))
    if not isinstance(root, str) or not root:
        raise ValueError("packet plan metadata must include root_decoder or root")
    return root


def _layer_fields(fields: Mapping[str, JSONObject], layer: str) -> JSONObject:
    value = fields.get(layer)
    if value is None and layer == "ipv4":
        value = fields.get("ip")
    if value is None and layer == "payload":
        value = fields.get("raw")
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"{layer} fields must be an object")
    return dict(value)


def _payload_bytes(fields: Mapping[str, JSONObject]) -> bytes:
    payload = _layer_fields(fields, "payload")
    if not payload:
        return b""
    if "hex" in payload:
        raw = bytes.fromhex(_text(payload.get("hex"), ""))
        _validate_payload_length(payload, raw)
        return raw
    if "bytes_hex" in payload:
        raw = bytes.fromhex(_text(payload.get("bytes_hex"), ""))
        _validate_payload_length(payload, raw)
        return raw
    if "text" in payload:
        raw = _text(payload.get("text"), "").encode("utf-8")
        _validate_payload_length(payload, raw)
        return raw
    if "value" in payload:
        raw = _text(payload.get("value"), "").encode("utf-8")
        _validate_payload_length(payload, raw)
        return raw
    raise ValueError("payload materialization requires bytes in hex, bytes_hex, text, or value")


def _validate_payload_length(payload: Mapping[str, object], raw: bytes) -> None:
    if "length" not in payload:
        return
    length = _int(payload.get("length"), 0)
    if length != len(raw):
        raise ValueError(
            f"payload length mismatch: declared={length} materialized={len(raw)}"
        )


def _required_field(fields: Mapping[str, object], layer: str, *names: str) -> object:
    value = _optional_field(fields, *names)
    if value is None:
        joined = "/".join(names)
        raise ValueError(f"{layer} materialization requires field {joined}")
    return value


def _optional_field(fields: Mapping[str, object], *names: str) -> object | None:
    for name in names:
        if name in fields:
            return fields[name]
    return None


def _ipv4_options(value: object, scapy_all: Any) -> object:
    raw = _option_bytes(value)
    if raw is not None:
        if not raw:
            return []
        return [scapy_all.IPOption(raw)]
    return value


def _tcp_options(value: object) -> object:
    raw = _option_bytes(value)
    if raw is None:
        return value
    return _tcp_option_tuples(raw)


def _option_bytes(value: object) -> bytes | None:
    if isinstance(value, bytes):
        return value
    if isinstance(value, Mapping):
        hex_value = value.get("hex")
        if isinstance(hex_value, str):
            return bytes.fromhex(hex_value)
    if isinstance(value, str):
        return bytes.fromhex(value)
    return None


def _tcp_option_tuples(raw: bytes) -> list[object]:
    options: list[object] = []
    index = 0
    while index < len(raw):
        kind = raw[index]
        if kind == 0:
            options.append(("EOL", None))
            index += 1
            continue
        if kind == 1:
            options.append(("NOP", None))
            index += 1
            continue
        if index + 1 >= len(raw):
            options.append((kind, b""))
            break
        length = raw[index + 1]
        if length < 2 or index + length > len(raw):
            options.append((kind, raw[index + 2 :]))
            break
        data = raw[index + 2 : index + length]
        if kind == 2 and len(data) == 2:
            options.append(("MSS", int.from_bytes(data, "big")))
        elif kind == 3 and len(data) == 1:
            options.append(("WScale", data[0]))
        elif kind in {4, 5}:
            options.append((kind, data))
        elif kind == 8 and len(data) == 8:
            options.append(
                (
                    "Timestamp",
                    (
                        int.from_bytes(data[0:4], "big"),
                        int.from_bytes(data[4:8], "big"),
                    ),
                )
            )
        else:
            options.append((kind, data))
        index += length
    return options


def _require_encode_capability(
    capabilities: BackendCapabilities | BackendRegistration | None,
) -> None:
    resolved = _capability_contract(capabilities)
    if not resolved.encode:
        raise ValueError("unsupported backend capability: Scapy packet materialization requires encode")


def _capability_contract(
    capabilities: BackendCapabilities | BackendRegistration | None,
) -> BackendCapabilities:
    if capabilities is None:
        return get_backend(BACKEND_NAME).capabilities
    if isinstance(capabilities, BackendRegistration):
        return capabilities.capabilities
    return capabilities


def _ethertype_value(value: object) -> int:
    if isinstance(value, str):
        lowered = value.lower()
        if lowered in _ETHERTYPES:
            return _ETHERTYPES[lowered]
        return int(lowered, 0)
    return _int(value, 0x9000)


def _hardware_type_value(value: object) -> int:
    if isinstance(value, str):
        lowered = value.lower()
        if lowered in {"ether", "ethernet"}:
            return 1
        return int(lowered, 0)
    return _int(value, 1)


def _linux_sll_packet_type(value: object) -> int:
    if isinstance(value, str):
        lowered = value.lower().replace("-", "_")
        mapping = {
            "host": 0,
            "broadcast": 1,
            "multicast": 2,
            "otherhost": 3,
            "outgoing": 4,
        }
        if lowered in mapping:
            return mapping[lowered]
        return int(lowered, 0)
    return _int(value, 0)


def _address_family_value(value: object) -> int:
    if isinstance(value, str):
        lowered = value.lower().replace("-", "_")
        mapping = {
            "ipv4": 2,
            "ip": 2,
            "ipv6": 24,
        }
        if lowered in mapping:
            return mapping[lowered]
        return int(lowered, 0)
    return _int(value, 2)


def _bytes_field(value: object, *, pad_to: int | None = None) -> bytes:
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, Mapping):
        hex_value = value.get("hex")
        if not isinstance(hex_value, str):
            raise ValueError(f"bytes field object requires hex, got {value!r}")
        raw = bytes.fromhex(hex_value)
    elif isinstance(value, str):
        cleaned = value.replace(":", "").replace("-", "")
        raw = bytes.fromhex(cleaned)
    else:
        raise ValueError(f"expected bytes-compatible value, got {value!r}")
    if pad_to is not None and len(raw) < pad_to:
        raw = raw + (b"\x00" * (pad_to - len(raw)))
    return raw


def _protocol_value(value: object, mapping: Mapping[str, int]) -> int:
    if isinstance(value, str):
        lowered = value.lower()
        if lowered in mapping:
            return mapping[lowered]
        return int(lowered, 0)
    return _int(value, 0)


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


def _ipv4_flags(value: object) -> object:
    if isinstance(value, str):
        lowered = value.lower().replace("_", "-")
        if lowered in {"none", "0"}:
            return 0
        if lowered in {"df", "dont-fragment"}:
            return "DF"
        if lowered in {"mf", "more-fragments"}:
            return "MF"
    return value


def _icmp_type(value: object) -> object:
    if isinstance(value, str):
        lowered = value.lower().replace("_", "-")
        aliases = {
            "destination-unreachable": "dest-unreach",
            "echo-reply": "echo-reply",
            "echo-request": "echo-request",
            "parameter-problem": "parameter-problem",
            "time-exceeded": "time-exceeded",
        }
        return aliases.get(lowered, lowered)
    return value


def _icmpv6_class_name(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError(f"unsupported Scapy icmpv6 type materialization: {value!r}")
    class_names = {
        "dest-unreach": "ICMPv6DestUnreach",
        "destination-unreachable": "ICMPv6DestUnreach",
        "echo-reply": "ICMPv6EchoReply",
        "echo-request": "ICMPv6EchoRequest",
        "packet-too-big": "ICMPv6PacketTooBig",
        "parameter-problem": "ICMPv6ParamProblem",
        "time-exceeded": "ICMPv6TimeExceeded",
    }
    class_name = class_names.get(value)
    if class_name is None:
        raise ValueError(f"unsupported Scapy icmpv6 type materialization: {value!r}")
    return class_name


def _tcp_flags(value: object) -> object:
    flag_names = {
        "fin": "F",
        "syn": "S",
        "rst": "R",
        "psh": "P",
        "ack": "A",
        "urg": "U",
        "ece": "E",
        "cwr": "C",
    }
    if isinstance(value, str):
        lowered = value.lower()
        if lowered == "all":
            return 0x1FF
        return flag_names.get(lowered, value)
    if isinstance(value, list):
        output = ""
        for item in value:
            if not isinstance(item, str):
                return value
            lowered = item.lower()
            if lowered == "all":
                return 0x1FF
            output += flag_names.get(lowered, item)
        return output
    return value


def _dhcp_op(value: object) -> int:
    if isinstance(value, str):
        lowered = value.lower().replace("_", "-")
        if lowered in {"bootrequest", "request"}:
            return 1
        if lowered in {"bootreply", "reply"}:
            return 2
    return _int(value, 1)


def _dhcp_flags(value: object) -> int:
    if isinstance(value, str):
        lowered = value.lower().replace("_", "-")
        if lowered in {"broadcast", "b"}:
            return 0x8000
        if lowered in {"none", "0"}:
            return 0
    return _int(value, 0)


def _dhcp_chaddr(value: object) -> bytes:
    mac = _text(value, "00:00:5e:00:53:01")
    raw = bytes.fromhex(mac.replace(":", ""))
    return raw.ljust(16, b"\x00")


def _dhcp_options(value: object) -> list[object]:
    if not isinstance(value, list):
        return [("message-type", "discover"), "end"]
    options: list[object] = []
    for item in value:
        if isinstance(item, str):
            if item == "end":
                options.append("end")
                continue
            if "=" in item:
                name, raw_value = item.split("=", 1)
                options.append((name, raw_value))
                continue
        options.append(item)
    if not options or options[-1] != "end":
        options.append("end")
    return options


def _bool_int(value: object, default: int) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, str):
        lowered = value.lower().replace("_", "-")
        if lowered in {"true", "yes", "response"}:
            return 1
        if lowered in {"false", "no", "query"}:
            return 0
    return _int(value, default)


def _dns_opcode(value: object) -> int:
    if isinstance(value, str):
        lowered = value.lower().replace("_", "-")
        if lowered == "query":
            return 0
        return int(lowered, 0)
    return _int(value, 0)


def _dns_response_code(value: object) -> int:
    if isinstance(value, str):
        lowered = value.lower().replace("_", "-")
        aliases = {
            "no-error": 0,
            "server-failure": 2,
            "name-error": 3,
        }
        if lowered in aliases:
            return aliases[lowered]
        return int(lowered, 0)
    return _int(value, 0)


def _dns_flags(value: object) -> dict[str, int]:
    flags = {"aa": 0, "tc": 0, "rd": 1}
    if value is None:
        return flags
    values = value if isinstance(value, list) else [value]
    flags = {"aa": 0, "tc": 0, "rd": 0}
    for item in values:
        if not isinstance(item, str):
            continue
        lowered = item.lower().replace("-", "_")
        if lowered == "authoritative":
            flags["aa"] = 1
        elif lowered == "truncated":
            flags["tc"] = 1
        elif lowered == "recursion_desired":
            flags["rd"] = 1
    return flags


def _first_question(dns_fields: Mapping[str, object]) -> JSONObject:
    questions = dns_fields.get("questions")
    if isinstance(questions, list) and questions:
        first = questions[0]
        if isinstance(first, Mapping):
            return dict(first)  # type: ignore[arg-type, return-value]
        if isinstance(first, str):
            return {"qname": first}
    return {}


def _dns_questions(dns_fields: Mapping[str, object], scapy_all: Any) -> object | None:
    questions = dns_fields.get("questions")
    if not isinstance(questions, list) or not questions:
        return None
    chain = None
    for question in questions:
        if isinstance(question, Mapping):
            qname = _text(question.get("qname", question.get("name")), "example.com.")
            qtype = _text(question.get("qtype", question.get("type")), "A")
        else:
            qname = _text(question, "example.com.")
            qtype = "A"
        if not qname.endswith("."):
            qname = f"{qname}."
        entry = scapy_all.DNSQR(qname=qname, qtype=qtype)
        chain = entry if chain is None else chain / entry
    return chain


def _dns_answers(dns_fields: Mapping[str, object], scapy_all: Any) -> object | None:
    answers = dns_fields.get("answers")
    if not isinstance(answers, list) or not answers:
        return None
    chain = None
    for answer in answers:
        if not isinstance(answer, Mapping):
            continue
        rr_type = _text(answer.get("type"), "A").upper()
        name = _text(answer.get("name", answer.get("rrname")), "example.com.")
        if not name.endswith("."):
            name = f"{name}."
        if rr_type == "CNAME":
            rdata = _text(answer.get("target", answer.get("rdata")), "alias.example.com.")
        else:
            rdata = _text(answer.get("address", answer.get("rdata")), "192.0.2.53")
        entry = scapy_all.DNSRR(
            rrname=name,
            type=rr_type,
            ttl=_int(answer.get("ttl"), 60),
            rdata=rdata,
        )
        chain = entry if chain is None else chain / entry
    return chain


def _dns_count(value: object, default: int) -> int:
    if isinstance(value, list):
        return len(value)
    return default


def _scapy_decoder(root: str) -> str:
    decoder = _SCAPY_DECODER_BY_ROOT.get(root)
    if decoder is None:
        raise ValueError(f"unsupported Scapy root decoder: {root!r}")
    return decoder


def _scapy_layer_name(layer: str) -> str:
    return _SCAPY_LAYER_BY_LAYER.get(layer, layer)


def _int(value: object, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError(f"expected integer-compatible value, got {value!r}")


def _text(value: object, default: str) -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value
    return str(value)


def _string(value: object, default: str) -> str:
    if isinstance(value, str):
        return value
    return default
