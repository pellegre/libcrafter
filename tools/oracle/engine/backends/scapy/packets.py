"""Scapy raw packet materialization for oracle packet plans."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ...model import EncodedVector, JSONObject, PacketPlan
from ..registry import BackendCapabilities, BackendRegistration, get_backend
from . import dns_raw
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
    "l2:ipv4": "IP",
    "l3:ipv4": "IP",
    "l3:ipv6": "IPv6",
}
_ROOT_FIRST_LAYERS: dict[str, set[str]] = {
    "link:ethernet": {"ethernet"},
    "link:linux-cooked": {"linux_cooked"},
    "link:linux-sll": {"linux_cooked"},
    "link:null-loopback": {"null_loopback"},
    "link:raw": {"payload"},
    "l2:ipv4": {"ipv4"},
    "l3:ipv4": {"ipv4"},
    "l3:ipv6": {"ipv6"},
}
_SCAPY_MATERIALIZED_LAYERS = frozenset(_SCAPY_LAYER_BY_LAYER)
_SUPPORTED_FEATURES = {
    "dhcp_behavior",
    "dns_behavior",
    "icmpv4_errors",
    "icmpv4_live",
    "icmpv6_errors",
    "ipv4_options",
    "ipv6_fragment_routing",
    "pcap_contracts",
    "pcap_link_types",
    "tcp_header",
    "tcp_options",
    "udp_options",
}
_SUPPORTED_FIELDS_BY_LAYER: dict[str, set[str]] = {
    "arp": {
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
        "additional",
        "answers",
        "authority",
        "dns_raw",
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
    "icmp": {
        "checksum",
        "chksum",
        "code",
        "id",
        "identifier",
        "seq",
        "sequence",
        "type",
        # ICMPv4 live-matrix rest-of-header and type-specific body fields. These
        # carry the oracle-normalized names the generator emits; the Scapy
        # materializer translates them to Scapy-native ICMP fields where the
        # reference layer types them, or to deterministic raw rest-of-header /
        # payload bytes for the raw-compatible cases.
        "rest_of_header",
        "gateway",
        "pointer",
        "next_hop_mtu",
        "originate_timestamp",
        "receive_timestamp",
        "transmit_timestamp",
        "address_mask",
        "router_addresses",
        "router_address_entry_size",
        "router_lifetime",
        "extension_bytes",
        "embedded_header",
    },
    "icmpv6": {"checksum", "cksum", "code", "id", "identifier", "seq", "sequence", "type"},
    "ipv4": {
        "dst",
        "ds_field",
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
    "udp": {
        "checksum",
        "chksum",
        "dport",
        "dst_port",
        "len",
        "length",
        "options",
        "sport",
        "src_port",
    },
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
    raw_bytes, udp_options_metadata = _materialize_udp_options(plan, root, raw_bytes)
    metadata: JSONObject = {
        "backend": BACKEND_NAME,
        "feature_tags": list(plan.feature_tags),
        "scapy_version": scapy_version,
        "root_decoder": root,
        "stack_tags": list(plan.feature_tags),
        "strict_bytes": plan.strict_bytes,
        "scapy_stack": [_scapy_layer_name(layer) for layer in stack],
        "length": len(raw_bytes),
    }
    if udp_options_metadata is not None:
        metadata["udp_options_materialization"] = udp_options_metadata
    return EncodedVector.from_bytes(
        plan=plan,
        backend=BACKEND_NAME,
        raw=raw_bytes,
        root=root,
        decoder=_scapy_decoder(root),
        metadata=metadata,
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
        "dei": _int(_optional_field(fields, "drop_eligible", "dei"), 0),
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
    if "ds_field" in ipv4_fields:
        kwargs["tos"] = _int(ipv4_fields.get("ds_field"), 0)
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


# ICMPv4 types whose rest-of-header Scapy's ICMP layer exposes via the id/seq
# pair (echo, timestamp, information, address-mask, and the deprecated query
# families that reuse the identifier/sequence layout).
_ICMP_ID_SEQ_TYPES = frozenset(
    {
        "echo-reply",
        "echo-request",
        "timestamp-request",
        "timestamp-reply",
        "information-request",
        "information-response",
        "address-mask-request",
        "address-mask-reply",
    }
)


def _icmp(fields: Mapping[str, JSONObject], scapy_all: Any) -> Any:
    icmp_fields = _layer_fields(fields, "icmp")
    scapy_type = _icmp_type(_required_field(icmp_fields, "icmp", "type"))
    icmp_type_int = _icmp_type_number(scapy_type, scapy_all)
    code = _int(_required_field(icmp_fields, "icmp", "code"), 0)
    type_name = scapy_type if isinstance(scapy_type, str) else None

    body = _icmp_body_bytes(icmp_fields)
    explicit_rest = icmp_fields.get("rest_of_header")

    # Types whose four-byte rest-of-header the reference ICMP layer cannot type
    # (router solicitation, legacy/deprecated families, extended echo) carry an
    # explicit rest_of_header. Build opaque ICMP bytes so those four bytes land
    # in the real rest-of-header rather than as trailing payload; parsing them
    # back through Scapy can trigger type-specific body expectations.
    if explicit_rest is not None:
        rest_bytes = _icmp_rest_of_header_bytes(explicit_rest)
        if "checksum" in icmp_fields or "chksum" in icmp_fields:
            checksum = _int(_optional_field(icmp_fields, "checksum", "chksum"), 0)
        else:
            checksum = _internet_checksum(
                bytes([icmp_type_int & 0xFF, code & 0xFF, 0, 0]) + rest_bytes + body
            )
        header = bytes([icmp_type_int & 0xFF, code & 0xFF])
        header += checksum.to_bytes(2, "big") + rest_bytes
        return scapy_all.Raw(load=header + body)

    kwargs: dict[str, Any] = {"type": scapy_type, "code": code}

    # id/seq map to the Scapy ICMP rest-of-header only for the query families that
    # the reference layer types with the identifier/sequence pair.
    if type_name in _ICMP_ID_SEQ_TYPES:
        if "id" in icmp_fields or "identifier" in icmp_fields:
            kwargs["id"] = _int(_optional_field(icmp_fields, "id", "identifier"), 0)
        if "seq" in icmp_fields or "sequence" in icmp_fields:
            kwargs["seq"] = _int(_optional_field(icmp_fields, "seq", "sequence"), 0)

    # Scapy-native typed rest-of-header fields.
    if "gateway" in icmp_fields:
        kwargs["gw"] = _text(icmp_fields.get("gateway"), "0.0.0.0")
    if "pointer" in icmp_fields:
        kwargs["ptr"] = _int(icmp_fields.get("pointer"), 0)
    if "next_hop_mtu" in icmp_fields:
        kwargs["nexthopmtu"] = _int(icmp_fields.get("next_hop_mtu"), 0)
    if "address_mask" in icmp_fields:
        kwargs["addr_mask"] = _text(icmp_fields.get("address_mask"), "0.0.0.0")
    if "originate_timestamp" in icmp_fields:
        kwargs["ts_ori"] = _int(icmp_fields.get("originate_timestamp"), 0)
    if "receive_timestamp" in icmp_fields:
        kwargs["ts_rx"] = _int(icmp_fields.get("receive_timestamp"), 0)
    if "transmit_timestamp" in icmp_fields:
        kwargs["ts_tx"] = _int(icmp_fields.get("transmit_timestamp"), 0)

    if "checksum" in icmp_fields or "chksum" in icmp_fields:
        kwargs["chksum"] = _int(_optional_field(icmp_fields, "checksum", "chksum"), 0)

    icmp = scapy_all.ICMP(**kwargs)
    if body:
        return icmp / scapy_all.Raw(load=body)
    return icmp


def _icmp_type_number(scapy_type: object, scapy_all: Any) -> int:
    """Resolve an ICMP type to its numeric value for raw-header construction."""

    if isinstance(scapy_type, int):
        return scapy_type
    if isinstance(scapy_type, str):
        type_field = next(
            field for field in scapy_all.ICMP.fields_desc if field.name == "type"
        )
        for number, name in getattr(type_field, "i2s", {}).items():
            if name == scapy_type:
                return number
        return int(scapy_type, 0)
    raise ValueError(f"unsupported ICMP type for materialization: {scapy_type!r}")


def _icmp_rest_of_header_bytes(value: object) -> bytes:
    rest = _icmp_hex_bytes(value)
    if len(rest) != 4:
        raise ValueError(
            f"ICMP rest_of_header must be exactly four bytes, got {len(rest)}"
        )
    return rest


def _internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(
        int.from_bytes(data[index : index + 2], "big")
        for index in range(0, len(data), 2)
    )
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _icmp_body_bytes(icmp_fields: Mapping[str, JSONObject]) -> bytes:
    """Deterministic raw bytes that follow the ICMP four-byte rest-of-header.

    Covers ICMP shapes the reference ICMP layer does not type natively: the
    quoted (embedded) original IPv4 datagram carried by RFC 792 error messages,
    the RFC 1256 router-advertisement address list, and the RFC 4884/4950
    extension framing blobs. The quoted datagram comes first (immediately after
    the rest-of-header), then any extension objects, matching RFC 4884 framing.
    Both backends emit and parse these bytes identically.
    """

    body = b""

    embedded = icmp_fields.get("embedded_header")
    embedded_bytes = _icmp_hex_bytes(embedded)
    if embedded_bytes:
        body += embedded_bytes

    routers = icmp_fields.get("router_addresses")
    if isinstance(routers, list) and routers:
        body += _icmp_router_address_bytes(routers)

    extension = icmp_fields.get("extension_bytes")
    extension_bytes = _icmp_hex_bytes(extension)
    if extension_bytes:
        body += extension_bytes

    return body


def _icmp_router_address_bytes(routers: Sequence[object]) -> bytes:
    raw = b""
    for entry in routers:
        if not isinstance(entry, Mapping):
            continue
        address = _text(entry.get("address"), "0.0.0.0")
        preference = _int(entry.get("preference"), 0)
        raw += _ipv4_address_bytes(address)
        raw += preference.to_bytes(4, "big")
    return raw


def _ipv4_address_bytes(address: str) -> bytes:
    parts = address.split(".")
    if len(parts) != 4:
        raise ValueError(f"invalid IPv4 address for ICMP router entry: {address!r}")
    return bytes(int(part) for part in parts)


def _icmp_hex_bytes(value: object) -> bytes:
    if value is None:
        return b""
    raw = _option_bytes(value)
    if raw is None:
        raise ValueError(f"ICMP rest-of-header/extension bytes must be hex, got {value!r}")
    return raw


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
    raw_spec = dns_fields.get("dns_raw")
    if dns_raw.is_raw_dns_spec(raw_spec):
        return dns_raw.materialize_raw_dns(raw_spec, scapy_all)
    questions_value = dns_fields.get("questions")
    flags = _dns_flags(_optional_field(dns_fields, "flags"))
    questions = _dns_questions(dns_fields, scapy_all)
    if questions is None:
        questions = _dns_default_question(dns_fields, scapy_all)
    answers = _dns_records(dns_fields.get("answers"), scapy_all)
    authority = _dns_records(dns_fields.get("authority"), scapy_all)
    additional = _dns_records(dns_fields.get("additional"), scapy_all)
    return scapy_all.DNS(
        id=_int(_optional_field(dns_fields, "transaction_id", "id"), 0),
        qr=_bool_int(_optional_field(dns_fields, "is_response"), 0),
        opcode=_dns_opcode(_optional_field(dns_fields, "opcode")),
        qdcount=_dns_count(questions_value, 1),
        ancount=_dns_count(dns_fields.get("answers"), 0),
        nscount=_dns_count(dns_fields.get("authority"), 0),
        arcount=_dns_count(dns_fields.get("additional"), 0),
        aa=flags["aa"],
        tc=flags["tc"],
        rd=flags["rd"],
        ra=flags["ra"],
        ad=flags["ad"],
        cd=flags["cd"],
        z=flags["z"],
        rcode=_dns_response_code(_optional_field(dns_fields, "response_code")),
        qd=questions,
        an=answers,
        ns=authority,
        ar=additional,
    )


def _dns_default_question(dns_fields: Mapping[str, object], scapy_all: Any) -> Any:
    question = _first_question(dns_fields)
    qname = _dns_normalized_name(_text(question.get("qname"), "example.com."))
    return scapy_all.DNSQR(
        qname=qname,
        qtype=_dns_qtype(question.get("qtype", dns_fields.get("qtype"))),
    )


def _dhcp(fields: Mapping[str, JSONObject], scapy_all: Any) -> Any:
    dhcp_fields = _layer_fields(fields, "dhcp")
    bootp = scapy_all.BOOTP(
        op=_dhcp_op(_required_field(dhcp_fields, "dhcp", "op")),
        htype=_hardware_type_value(_required_field(dhcp_fields, "dhcp", "hardware_type", "htype")),
        hlen=_int(_required_field(dhcp_fields, "dhcp", "hardware_length", "hlen"), 0),
        xid=_int(_optional_field(dhcp_fields, "transaction_id", "xid"), 0),
        flags=_dhcp_flags(_required_field(dhcp_fields, "dhcp", "flags")),
        ciaddr=_text(_optional_field(dhcp_fields, "client_ip", "ciaddr"), "0.0.0.0"),
        yiaddr=_text(_optional_field(dhcp_fields, "your_ip", "yiaddr"), "0.0.0.0"),
        chaddr=_dhcp_chaddr(
            _optional_field(dhcp_fields, "client_hardware_address", "chaddr")
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


def _materialize_udp_options(
    plan: PacketPlan,
    root: str,
    raw: bytes,
) -> tuple[bytes, JSONObject | None]:
    udp_fields = _layer_fields(plan.fields, "udp")
    options = udp_fields.get("options")
    if not isinstance(options, Mapping):
        return raw, None
    if options.get("format") != "udp_surplus_options":
        raise ValueError("udp.options format must be udp_surplus_options")

    layout = _udp_layout(root, raw)
    payload = raw[layout["udp_payload_start"] : layout["udp_payload_end"]]
    declared_payload = _udp_options_application_payload(options)
    if declared_payload is not None and declared_payload != payload:
        raise ValueError(
            "udp.options application payload does not match materialized UDP payload"
        )

    option_bytes = _udp_surplus_option_bytes(options, payload)
    if not option_bytes and _udp_options_checksum_mode(options) == "absent":
        return raw, None

    l3_relative_surplus_start = layout["surplus_start"] - layout["l3_start"]
    alignment = b"\x00" * (l3_relative_surplus_start & 1)
    option_checksum = _udp_option_checksum_value(
        options,
        alignment=alignment,
        option_bytes=option_bytes,
        udp_checksum=int.from_bytes(
            raw[layout["udp_start"] + 6 : layout["udp_start"] + 8],
            "big",
        ),
    )
    surplus = alignment + option_checksum.to_bytes(2, "big") + option_bytes
    materialized = raw[: layout["surplus_start"]] + surplus + raw[layout["surplus_start"] :]
    materialized = _patch_ip_payload_length(materialized, layout, len(surplus))

    return materialized, {
        "format": "udp_surplus_options",
        "native_scapy_support": False,
        "materialization": "udp_payload_bytes_plus_explicit_surplus",
        "application_payload_hex": payload.hex(),
        "udp_length": layout["udp_length"],
        "udp_checksum": int.from_bytes(
            materialized[layout["udp_start"] + 6 : layout["udp_start"] + 8],
            "big",
        ),
        "surplus_hex": surplus.hex(),
        "surplus_length": len(surplus),
        "surplus_start": layout["surplus_start"],
        "option_checksum": option_checksum,
        "option_bytes_hex": option_bytes.hex(),
        "alignment_hex": alignment.hex(),
        "placement": "after_udp_length",
    }


def _udp_options_application_payload(options: Mapping[str, object]) -> bytes | None:
    value = options.get("application_payload")
    if not isinstance(value, Mapping):
        return None
    hex_value = value.get("hex")
    if not isinstance(hex_value, str):
        return None
    payload = bytes.fromhex(hex_value)
    length = value.get("length")
    if isinstance(length, int) and length != len(payload):
        raise ValueError(
            f"udp.options application payload length mismatch: "
            f"declared={length} actual={len(payload)}"
        )
    return payload


def _udp_surplus_option_bytes(options: Mapping[str, object], payload: bytes) -> bytes:
    items = options.get("items")
    if not isinstance(items, list):
        raise ValueError("udp.options.items must be a list")
    output = bytearray()
    for item in items:
        if not isinstance(item, Mapping):
            raise ValueError("udp.options.items entries must be objects")
        output.extend(_udp_surplus_option_item_bytes(item, payload))
    return bytes(output)


def _udp_surplus_option_item_bytes(item: Mapping[str, object], payload: bytes) -> bytes:
    kind = _int(_required_field(item, "udp.options", "kind"), 0)
    if kind in {0, 1}:
        return bytes([kind])

    declared_length = _int(_required_field(item, "udp.options", "length"), 0)
    data = _udp_surplus_option_item_data(kind, item, payload)
    actual_length = 2 + len(data)
    if declared_length != actual_length:
        raise ValueError(
            f"udp option length mismatch for kind {kind}: "
            f"declared={declared_length} materialized={actual_length}"
        )
    if not 2 <= declared_length <= 255:
        raise ValueError(f"udp option length must fit one byte: {declared_length}")
    return bytes([kind, declared_length]) + data


def _udp_surplus_option_item_data(
    kind: int,
    item: Mapping[str, object],
    payload: bytes,
) -> bytes:
    data_hex = item.get("data_hex")
    if isinstance(data_hex, str):
        return bytes.fromhex(data_hex)

    if kind == 2:
        checksum = item.get("checksum")
        if checksum == "auto_crc32c_application_payload":
            return _crc32c(payload).to_bytes(4, "big")
        if isinstance(checksum, int):
            return checksum.to_bytes(4, "big")
    if kind == 4:
        return _int(
            _required_field(item, "udp.options", "max_datagram_size"),
            0,
        ).to_bytes(2, "big")
    if kind == 5:
        return (
            _int(
                _required_field(item, "udp.options", "max_reassembled_size"),
                0,
            ).to_bytes(2, "big")
            + bytes(
                [
                    _int(
                        _required_field(item, "udp.options", "segment_count"),
                        0,
                    )
                ]
            )
        )
    if kind in {6, 7}:
        return _int(_required_field(item, "udp.options", "token"), 0).to_bytes(4, "big")
    if kind == 8:
        return (
            _int(_required_field(item, "udp.options", "tsval"), 0).to_bytes(4, "big")
            + _int(_required_field(item, "udp.options", "tsecr"), 0).to_bytes(4, "big")
        )

    declared_length = _int(_required_field(item, "udp.options", "length"), 0)
    return b"\x00" * max(0, declared_length - 2)


def _udp_options_checksum_mode(options: Mapping[str, object]) -> str:
    checksum = options.get("option_checksum")
    if isinstance(checksum, Mapping):
        mode = checksum.get("mode")
        if isinstance(mode, str):
            return mode
    return "auto_internet_checksum"


def _udp_option_checksum_value(
    options: Mapping[str, object],
    *,
    alignment: bytes,
    option_bytes: bytes,
    udp_checksum: int,
) -> int:
    checksum = options.get("option_checksum")
    if isinstance(checksum, Mapping):
        value = checksum.get("value")
        if isinstance(value, int):
            return value
        mode = checksum.get("mode")
        if mode == "absent":
            return 0
        if mode == "zero_allowed_when_udp_checksum_zero" and udp_checksum == 0:
            return 0

    surplus_len = len(alignment) + 2 + len(option_bytes)
    if surplus_len > 0xFFFF:
        raise ValueError("udp options surplus length must fit in two bytes")
    checksum_value = _internet_checksum(
        surplus_len.to_bytes(2, "big") + b"\x00\x00" + option_bytes
    )
    return 0xFFFF if checksum_value == 0 else checksum_value


def _udp_layout(root: str, raw: bytes) -> dict[str, int]:
    l3_start = _l3_start_offset(root, raw)
    if l3_start >= len(raw):
        raise ValueError(f"packet is too short for root {root!r}")
    version = raw[l3_start] >> 4
    if version == 4:
        ihl = (raw[l3_start] & 0x0F) * 4
        if ihl < 20 or l3_start + ihl + 8 > len(raw):
            raise ValueError("IPv4 packet is too short to locate UDP header")
        protocol = raw[l3_start + 9]
        if protocol != 17:
            raise ValueError(f"IPv4 next protocol is not UDP: {protocol}")
        ip_end = l3_start + int.from_bytes(raw[l3_start + 2 : l3_start + 4], "big")
        udp_start = l3_start + ihl
    elif version == 6:
        if l3_start + 48 > len(raw):
            raise ValueError("IPv6 packet is too short to locate UDP header")
        payload_len = int.from_bytes(raw[l3_start + 4 : l3_start + 6], "big")
        ip_end = l3_start + 40 + payload_len
        udp_start = _ipv6_udp_start(raw, l3_start)
    else:
        raise ValueError(f"unsupported IP version for UDP options: {version}")

    if udp_start + 8 > len(raw):
        raise ValueError("packet is too short for UDP header")
    udp_length = int.from_bytes(raw[udp_start + 4 : udp_start + 6], "big")
    if udp_length < 8:
        raise ValueError(f"UDP length is too short: {udp_length}")
    udp_payload_start = udp_start + 8
    udp_payload_end = udp_start + udp_length
    if udp_payload_end > len(raw) or udp_payload_end > ip_end:
        raise ValueError(
            f"UDP length exceeds materialized packet: udp_end={udp_payload_end} ip_end={ip_end}"
        )
    return {
        "ip_version": version,
        "l3_start": l3_start,
        "ip_end": ip_end,
        "udp_start": udp_start,
        "udp_length": udp_length,
        "udp_payload_start": udp_payload_start,
        "udp_payload_end": udp_payload_end,
        "surplus_start": udp_payload_end,
    }


def _l3_start_offset(root: str, raw: bytes) -> int:
    if root in {"l3:ipv4", "l3:ipv6", "IP", "IPv6"}:
        return 0
    if root in {"link:linux-cooked", "link:linux-sll", "CookedLinux"}:
        return 16
    if root in {"link:null-loopback", "Loopback"}:
        return 4
    if root in {"link:ethernet", "Ether"}:
        offset = 14
        while len(raw) >= offset + 4:
            ethertype = int.from_bytes(raw[offset - 2 : offset], "big")
            if ethertype not in {0x8100, 0x88A8, 0x9100}:
                return offset
            offset += 4
        return offset
    raise ValueError(f"unsupported UDP option materialization root: {root!r}")


def _ipv6_udp_start(raw: bytes, l3_start: int) -> int:
    next_header = raw[l3_start + 6]
    cursor = l3_start + 40
    while next_header != 17:
        if cursor + 8 > len(raw):
            raise ValueError("IPv6 extension header chain is truncated before UDP")
        if next_header == 44:
            next_header = raw[cursor]
            cursor += 8
            continue
        if next_header in {0, 43, 60}:
            header_len = (raw[cursor + 1] + 1) * 8
            next_header = raw[cursor]
            cursor += header_len
            continue
        raise ValueError(f"IPv6 next header is not UDP: {next_header}")
    return cursor


def _patch_ip_payload_length(raw: bytes, layout: Mapping[str, int], added_len: int) -> bytes:
    if added_len == 0:
        return raw
    output = bytearray(raw)
    l3_start = layout["l3_start"]
    if layout["ip_version"] == 4:
        total_length = int.from_bytes(output[l3_start + 2 : l3_start + 4], "big")
        total_length += added_len
        if total_length > 0xFFFF:
            raise ValueError("IPv4 total length must fit in two bytes")
        output[l3_start + 2 : l3_start + 4] = total_length.to_bytes(2, "big")
        output[l3_start + 10 : l3_start + 12] = b"\x00\x00"
        ihl = (output[l3_start] & 0x0F) * 4
        checksum = _internet_checksum(bytes(output[l3_start : l3_start + ihl]))
        output[l3_start + 10 : l3_start + 12] = checksum.to_bytes(2, "big")
    else:
        payload_length = int.from_bytes(output[l3_start + 4 : l3_start + 6], "big")
        payload_length += added_len
        if payload_length > 0xFFFF:
            raise ValueError("IPv6 payload length must fit in two bytes")
        output[l3_start + 4 : l3_start + 6] = payload_length.to_bytes(2, "big")
    return bytes(output)


def _internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += int.from_bytes(data[index : index + 2], "big")
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _crc32c(data: bytes) -> int:
    crc = 0xFFFF_FFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x82F6_3B78
            else:
                crc >>= 1
    return (~crc) & 0xFFFF_FFFF


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


# ICMPv4 type names the generator emits, mapped to the Scapy ICMP type-field
# name (or numeric type for shapes the reference ICMP layer does not enumerate).
# The reference enum names some types differently (information-response,
# timestamp-request) and does not list extended-echo (42/43), so these are mapped
# explicitly to keep materialization byte-correct.
_ICMP_TYPE_ALIASES: dict[str, object] = {
    "echo-reply": "echo-reply",
    "echo-request": "echo-request",
    "destination-unreachable": "dest-unreach",
    "dest-unreach": "dest-unreach",
    "source-quench": "source-quench",
    "redirect": "redirect",
    "router-advertisement": "router-advertisement",
    "router-solicitation": "router-solicitation",
    "time-exceeded": "time-exceeded",
    "parameter-problem": "parameter-problem",
    "timestamp": "timestamp-request",
    "timestamp-request": "timestamp-request",
    "timestamp-reply": "timestamp-reply",
    "information-request": "information-request",
    "information-reply": "information-response",
    "information-response": "information-response",
    "address-mask-request": "address-mask-request",
    "address-mask-reply": "address-mask-reply",
    "traceroute": "traceroute",
    "datagram-conversion-error": "datagram-conversion-error",
    "mobile-host-redirect": "mobile-host-redirect",
    "domain-name-request": "domain-name-request",
    "domain-name-reply": "domain-name-reply",
    "photuris": "photuris",
    # ICMPv4 types the reference ICMP type field does not enumerate; emit the
    # numeric type so the byte stays correct (raw-compatible).
    "extended-echo-request": 42,
    "extended-echo-reply": 43,
}


def _icmp_type(value: object) -> object:
    if isinstance(value, str):
        lowered = value.lower().replace("_", "-")
        return _ICMP_TYPE_ALIASES.get(lowered, lowered)
    return value


def _icmpv6_class_name(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError(f"unsupported Scapy icmpv6 type materialization: {value!r}")
    lowered = value.lower().replace("_", "-")
    class_name = _ICMPV6_CLASS_NAMES.get(lowered)
    if class_name is None:
        raise ValueError(f"unsupported Scapy icmpv6 type materialization: {value!r}")
    return class_name


# Mapping table from the normalized ICMPv6 `type` domain to the native Scapy
# class that materializes it. Echo + the four RFC 4443 errors are live today;
# the NDP (RFC 4861) and MLD (RFC 2710 / RFC 3810) kinds below are scaffolding —
# Scapy has native classes for them, but libcrafter does not emit these wire
# bytes yet, so no smoke coverage_case references them. The per-message steps
# that add the bytes attach their cases and extend the body materialization
# (target/dest addresses, NDP option lists) on top of this entry point.
_ICMPV6_CLASS_NAMES: dict[str, str] = {
    "dest-unreach": "ICMPv6DestUnreach",
    "destination-unreachable": "ICMPv6DestUnreach",
    "echo-reply": "ICMPv6EchoReply",
    "echo-request": "ICMPv6EchoRequest",
    "packet-too-big": "ICMPv6PacketTooBig",
    "parameter-problem": "ICMPv6ParamProblem",
    "time-exceeded": "ICMPv6TimeExceeded",
    # NDP (RFC 4861) — scaffolded for later steps.
    "router-solicitation": "ICMPv6ND_RS",
    "router-advertisement": "ICMPv6ND_RA",
    "neighbor-solicitation": "ICMPv6ND_NS",
    "neighbor-advertisement": "ICMPv6ND_NA",
    "redirect": "ICMPv6ND_Redirect",
    # MLD (RFC 2710 / RFC 3810 / RFC 9777) — scaffolded for later steps. The
    # type-130 query is MLDv1; the MLDv2 query (ICMPv6MLQuery2) shares the type
    # and is selected by the per-message materializer when records are present.
    "mld-query": "ICMPv6MLQuery",
    "mld-report": "ICMPv6MLReport",
    "mld-done": "ICMPv6MLDone",
    "mldv2-report": "ICMPv6MLReport2",
    # Extended echo (RFC 8335, types 160/161) has no native Scapy ICMPv6 class;
    # the per-message materializer emits the numeric type (raw-compatible),
    # mirroring the ICMPv4 extended-echo path, so it is intentionally absent
    # from this native-class table.
}


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


# Scapy DHCP option names differ from the backend-neutral / libcrafter option
# names for several byte-identical options. Mapping the neutral name to the
# Scapy field name lets the same ``name=value`` option string materialize to
# identical option bytes through both backends; an unmapped name passes through
# unchanged so Scapy still recognizes its own native option names.
_DHCP_OPTION_NAME_TO_SCAPY: dict[str, str] = {
    "message_type": "message-type",
    "host_name": "hostname",
    "domain_name": "domain",
    "requested_ip": "requested_addr",
    "requested_ip_address": "requested_addr",
    "server_identifier": "server_id",
    "dns": "name_server",
    "domain_name_server": "name_server",
}
# Options whose Scapy field is an integer; the generator carries the value as a
# JSON string, so it must be coerced back to int before Scapy serializes it.
_DHCP_INTEGER_OPTIONS = frozenset({"lease_time", "renewal_time", "rebinding_time"})


def _dhcp_options(value: object) -> list[object]:
    if not isinstance(value, list):
        return [("message-type", "discover"), "end"]
    options: list[object] = []
    for item in value:
        if isinstance(item, str):
            if item in {"end", "pad"}:
                options.append(item)
                continue
            if "=" in item:
                name, raw_value = item.split("=", 1)
                options.append(_dhcp_name_value_option(name, raw_value))
                continue
        if isinstance(item, (list, tuple)) and len(item) == 2 and isinstance(item[0], str):
            options.append((item[0], _dhcp_option_value(item[1])))
            continue
        options.append(item)
    if not options or options[-1] != "end":
        options.append("end")
    return options


def _dhcp_name_value_option(name: str, raw_value: str) -> tuple[str, object]:
    """Translate a ``name=value`` option string into a Scapy option tuple.

    The option name is normalized to the Scapy field name for the byte-safe
    option set so the neutral/libcrafter option names round-trip strict-bytes,
    and integer-valued options are coerced from their JSON string form.
    """

    scapy_name = _DHCP_OPTION_NAME_TO_SCAPY.get(name, name)
    if name in _DHCP_INTEGER_OPTIONS:
        return scapy_name, int(raw_value, 0)
    return scapy_name, raw_value


def _dhcp_option_value(value: object) -> object:
    """Translate a JSON-safe option value into a Scapy option payload.

    A string value is interpreted as raw option bytes encoded as hex so byte
    payloads (client identifiers, raw relay-agent option 82, vendor class data)
    survive JSON transport. List values pass through for Scapy fields that take
    lists, such as the parameter request list and classless static routes.
    """

    if isinstance(value, str):
        return bytes.fromhex(value)
    if isinstance(value, (list, tuple)):
        return list(value)
    return value


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
        aliases = {
            "query": 0,
            "iquery": 1,
            "inverse-query": 1,
            "status": 2,
            "notify": 4,
            "update": 5,
        }
        if lowered in aliases:
            return aliases[lowered]
        if lowered == "unknown":
            return 14
        return int(lowered, 0)
    return _int(value, 0)


def _dns_response_code(value: object) -> int:
    if isinstance(value, str):
        lowered = value.lower().replace("_", "-")
        aliases = {
            "no-error": 0,
            "format-error": 1,
            "server-failure": 2,
            "name-error": 3,
            "nxdomain": 3,
            "not-implemented": 4,
            "refused": 5,
        }
        if lowered in aliases:
            return aliases[lowered]
        if lowered == "unknown":
            return 11
        return int(lowered, 0)
    return _int(value, 0)


def _dns_flags(value: object) -> dict[str, int]:
    flags = {"aa": 0, "tc": 0, "rd": 1, "ra": 0, "ad": 0, "cd": 0, "z": 0}
    if value is None:
        return flags
    if isinstance(value, Mapping):
        return _dns_flags_mapping(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return _dns_flags_word(value)
    values = value if isinstance(value, list) else [value]
    flags = {"aa": 0, "tc": 0, "rd": 0, "ra": 0, "ad": 0, "cd": 0, "z": 0}
    for item in values:
        if isinstance(item, int) and not isinstance(item, bool):
            return _dns_flags_word(item)
        if not isinstance(item, str):
            continue
        lowered = item.lower().replace("-", "_")
        if lowered in {"raw", "reserved_z", "z"}:
            flags["z"] = 1
        elif lowered in _DNS_FLAG_NAMES:
            flags[_DNS_FLAG_NAMES[lowered]] = 1
    return flags


def _dns_flags_mapping(value: Mapping[str, object]) -> dict[str, int]:
    flags = {"aa": 0, "tc": 0, "rd": 0, "ra": 0, "ad": 0, "cd": 0, "z": 0}
    for name, slot in {
        "authoritative": "aa",
        "aa": "aa",
        "truncated": "tc",
        "tc": "tc",
        "recursion_desired": "rd",
        "rd": "rd",
        "recursion_available": "ra",
        "ra": "ra",
        "authentic_data": "ad",
        "ad": "ad",
        "checking_disabled": "cd",
        "cd": "cd",
        "reserved_z": "z",
        "z": "z",
    }.items():
        if name in value:
            flags[slot] = _bool_int(value[name], 0)
    return flags


def _dns_flags_word(value: int) -> dict[str, int]:
    return {
        "aa": (value >> 10) & 0x1,
        "tc": (value >> 9) & 0x1,
        "rd": (value >> 8) & 0x1,
        "ra": (value >> 7) & 0x1,
        "z": (value >> 6) & 0x1,
        "ad": (value >> 5) & 0x1,
        "cd": (value >> 4) & 0x1,
    }


_DNS_FLAG_NAMES: dict[str, str] = {
    "authoritative": "aa",
    "truncated": "tc",
    "recursion_desired": "rd",
    "recursion_available": "ra",
    "authentic_data": "ad",
    "checking_disabled": "cd",
}


def _dns_normalized_name(value: object) -> str:
    name = _text(value, "")
    if name in {"", "."}:
        return "."
    if not name.endswith("."):
        return f"{name}."
    return name


# QTYPE/QCLASS codepoint maps used to feed Scapy unambiguous numeric values.
#
# Scapy's DNSQR qtype/qclass enums use their own spellings (for example CHAOS
# rather than CH) and omit several IANA names (such as QCLASS NONE), so passing
# a canonical IANA name string can raise a KeyError. Resolving the canonical
# name to its numeric codepoint here keeps Scapy as the reference encoder while
# accepting the same symbolic names libcrafter uses. The maps reuse the raw
# helper's code tables; QTYPE ANY (the query-only meta-type) shares codepoint
# 255 with QCLASS ANY and is added explicitly.
_QTYPE_CODES: dict[str, int] = {**dns_raw._TYPE_CODES, "ANY": 255}
_QCLASS_CODES: dict[str, int] = dict(dns_raw._CLASS_CODES)


def _dns_qtype(value: object) -> object:
    if value is None:
        return "A"
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return int(text)
        return _QTYPE_CODES.get(text.upper(), text.upper())
    return _text(value, "A")


def _dns_qclass(value: object) -> object:
    if value is None:
        return "IN"
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return int(text)
        return _QCLASS_CODES.get(text.upper(), text.upper())
    return "IN"


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
            qname = _dns_normalized_name(question.get("qname", question.get("name")))
            qtype = _dns_qtype(question.get("qtype", question.get("type")))
            qclass = _dns_qclass(question.get("qclass", question.get("record_class")))
        else:
            qname = _dns_normalized_name(question)
            qtype = "A"
            qclass = "IN"
        entry = scapy_all.DNSQR(qname=qname, qtype=qtype, qclass=qclass)
        chain = entry if chain is None else chain / entry
    return chain


def _dns_records(value: object, scapy_all: Any) -> object | None:
    if not isinstance(value, list) or not value:
        return None
    chain = None
    for record in value:
        if not isinstance(record, Mapping):
            continue
        entry = _dns_record_entry(record, scapy_all)
        chain = entry if chain is None else chain / entry
    return chain


def _dns_record_entry(record: Mapping[str, object], scapy_all: Any) -> Any:
    rr_type = _dns_record_type_token(record)
    name = _dns_normalized_name(record.get("name", record.get("rrname")))
    ttl = _int(record.get("ttl"), 60)
    builder = _DNS_RECORD_BUILDERS.get(rr_type)
    if builder is not None:
        return builder(record, scapy_all, name=name, ttl=ttl)
    if rr_type == "OPT":
        return _dns_record_opt(record, scapy_all, name=name, ttl=ttl)
    return _dns_record_raw(record, scapy_all, name=name, ttl=ttl, rr_type=rr_type)


def _dns_record_type_token(record: Mapping[str, object]) -> str:
    raw = record.get("type", record.get("record_type"))
    if isinstance(raw, int) and not isinstance(raw, bool):
        return str(raw)
    text = _text(raw, "A").strip()
    if text.isdigit():
        return text
    return text.upper()


def _dns_record_class(value: object) -> object:
    if value is None:
        return "IN"
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    text = _text(value, "IN").strip()
    if text.isdigit():
        return int(text)
    return text.upper()


def _dns_rr_common(record: Mapping[str, object], *, name: str, ttl: int) -> dict[str, Any]:
    return {
        "rrname": name,
        "ttl": ttl,
        "rclass": _dns_record_class(record.get("record_class", record.get("rclass"))),
    }


def _dns_record_a(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
    address = _text(record.get("address", record.get("rdata")), "192.0.2.53")
    return scapy_all.DNSRR(type="A", rdata=address, **_dns_rr_common(record, name=name, ttl=ttl))


def _dns_record_aaaa(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
    address = _text(record.get("address", record.get("rdata")), "2001:db8::53")
    return scapy_all.DNSRR(type="AAAA", rdata=address, **_dns_rr_common(record, name=name, ttl=ttl))


def _dns_record_name_target(
    rr_type: str,
    default: str,
) -> Any:
    def builder(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
        target = _dns_normalized_name(
            record.get("target", record.get("rdata", default)),
        )
        return scapy_all.DNSRR(
            type=rr_type,
            rdata=target,
            **_dns_rr_common(record, name=name, ttl=ttl),
        )

    return builder


def _dns_record_mx(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
    return scapy_all.DNSRRMX(
        preference=_int(record.get("preference"), 10),
        exchange=_dns_normalized_name(record.get("exchange", record.get("target"))),
        **_dns_rr_common(record, name=name, ttl=ttl),
    )


def _dns_record_txt(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
    strings = record.get("strings", record.get("rdata"))
    if isinstance(strings, list):
        rdata = [_dns_text_string(item) for item in strings]
    elif strings is None:
        rdata = [b""]
    else:
        rdata = [_dns_text_string(strings)]
    return scapy_all.DNSRR(type="TXT", rdata=rdata, **_dns_rr_common(record, name=name, ttl=ttl))


def _dns_record_soa(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
    return scapy_all.DNSRRSOA(
        mname=_dns_normalized_name(record.get("primary_name", record.get("mname"))),
        rname=_dns_normalized_name(record.get("responsible_name", record.get("rname"))),
        serial=_int(record.get("serial"), 0),
        refresh=_int(record.get("refresh"), 0),
        retry=_int(record.get("retry"), 0),
        expire=_int(record.get("expire"), 0),
        minimum=_int(record.get("minimum"), 0),
        **_dns_rr_common(record, name=name, ttl=ttl),
    )


def _dns_record_srv(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
    return scapy_all.DNSRRSRV(
        priority=_int(record.get("priority"), 0),
        weight=_int(record.get("weight"), 0),
        port=_int(record.get("port"), 0),
        target=_dns_normalized_name(record.get("target")),
        **_dns_rr_common(record, name=name, ttl=ttl),
    )


def _dns_record_ds(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
    return scapy_all.DNSRRDS(
        keytag=_int(record.get("key_tag", record.get("keytag")), 0),
        algorithm=_int(record.get("algorithm"), 0),
        digesttype=_int(record.get("digest_type", record.get("digesttype")), 0),
        digest=_dns_blob(record.get("digest")),
        **_dns_rr_common(record, name=name, ttl=ttl),
    )


def _dns_record_dnskey(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
    return scapy_all.DNSRRDNSKEY(
        flags=_int(record.get("flags"), 0),
        protocol=_int(record.get("protocol"), 3),
        algorithm=_int(record.get("algorithm"), 0),
        publickey=_dns_blob(record.get("public_key", record.get("publickey"))),
        **_dns_rr_common(record, name=name, ttl=ttl),
    )


def _dns_record_rrsig(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
    return scapy_all.DNSRRRSIG(
        typecovered=_dns_qtype(record.get("type_covered", record.get("typecovered"))),
        algorithm=_int(record.get("algorithm"), 0),
        labels=_int(record.get("labels"), 0),
        originalttl=_int(record.get("original_ttl", record.get("originalttl")), 0),
        expiration=_int(record.get("signature_expiration", record.get("expiration")), 0),
        inception=_int(record.get("signature_inception", record.get("inception")), 0),
        keytag=_int(record.get("key_tag", record.get("keytag")), 0),
        signersname=_dns_normalized_name(record.get("signer_name", record.get("signersname"))),
        signature=_dns_blob(record.get("signature")),
        **_dns_rr_common(record, name=name, ttl=ttl),
    )


def _dns_record_nsec(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
    return scapy_all.DNSRRNSEC(
        nextname=_dns_normalized_name(record.get("next_name", record.get("nextname"))),
        typebitmaps=_dns_type_bitmaps(
            record.get("type_bitmaps", record.get("typebitmaps")), scapy_all
        ),
        **_dns_rr_common(record, name=name, ttl=ttl),
    )


def _dns_record_nsec3(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
    # Scapy 2.7's DNSRRNSEC3 FieldLenField does not reliably auto-compute the
    # Salt Length / Hash Length octets from a raw bytes salt or next hashed
    # owner name, so the length prefixes are passed explicitly. Both fields stay
    # raw bytes (RFC 5155 Section 3.2), never reinterpreted as text.
    salt = _dns_blob(record.get("salt"))
    next_hashed_owner = _dns_blob(
        record.get("next_hashed_owner", record.get("nexthashedownername"))
    )
    return scapy_all.DNSRRNSEC3(
        hashalg=_int(record.get("hash_algorithm", record.get("hashalg")), 1),
        flags=_int(record.get("flags"), 0),
        iterations=_int(record.get("iterations"), 0),
        saltlength=len(salt),
        salt=salt,
        hashlength=len(next_hashed_owner),
        nexthashedownername=next_hashed_owner,
        typebitmaps=_dns_type_bitmaps(
            record.get("type_bitmaps", record.get("typebitmaps")), scapy_all
        ),
        **_dns_rr_common(record, name=name, ttl=ttl),
    )


def _dns_record_svcb(rr_type: str) -> Any:
    def builder(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
        # Scapy's high-level DNSRRSVCB/DNSRRHTTPS SvcParam field re-interprets and
        # re-encodes the per-key SvcParamValue (for example it length-prefixes the
        # alpn id list and rejects raw port/ipvNhint bytes), so it cannot carry the
        # SvcParamValue verbatim the way libcrafter and the wire format require.
        # The oracle contract compares SvcParam values as opaque bytes, so this
        # builder owns the exact RDATA octets and hands them to Scapy as a generic
        # DNSRR (TYPE 64/65) whose rdata is preserved verbatim. Scapy still
        # re-dissects the bytes as SVCB/HTTPS on decode; the byte image is the
        # reference boundary either way.
        rdata = _dns_svcb_rdata_bytes(record)
        return scapy_all.DNSRR(
            type=_dns_record_type_int(rr_type),
            rdata=rdata,
            **_dns_rr_common(record, name=name, ttl=ttl),
        )

    return builder


def _dns_svcb_rdata_bytes(record: Mapping[str, object]) -> bytes:
    """Build SVCB/HTTPS RDATA verbatim: SvcPriority, uncompressed TargetName, then
    SvcParams in strictly increasing SvcParamKey order with opaque values.

    The TargetName is uncompressed (RFC 9460 Section 2.2) and may be the root
    name ``.``. Each SvcParam is a {SvcParamKey, length, value} tuple whose value
    bytes are carried exactly as given so the encoding matches libcrafter's
    byte-for-byte. Params are sorted by ascending key to mirror the libcrafter
    SvcParams ordering rule.
    """

    priority = _int(record.get("priority", record.get("svc_priority")), 0)
    target = dns_raw.dns_name_bytes(record.get("target", record.get("target_name")))
    params = _dns_svcb_param_tuples(record.get("params", record.get("svc_params")))
    params.sort(key=lambda pair: pair[0])
    body = bytearray()
    body += int(priority & 0xFFFF).to_bytes(2, "big")
    body += target
    for key, value in params:
        body += int(key & 0xFFFF).to_bytes(2, "big")
        body += int(len(value) & 0xFFFF).to_bytes(2, "big")
        body += value
    return bytes(body)


def _dns_svcb_param_tuples(value: object) -> list[tuple[int, bytes]]:
    if not isinstance(value, list):
        return []
    params: list[tuple[int, bytes]] = []
    for param in value:
        if not isinstance(param, Mapping):
            continue
        key = _dns_svc_param_key_code(param.get("key"))
        param_value = _dns_blob(param.get("value"))
        params.append((key, param_value))
    return params


def _dns_svc_param_key_code(value: object) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    text = _text(value, "0").strip()
    if text.isdigit():
        return int(text)
    lowered = text.lower().replace("_", "-")
    code = _SVCB_PARAM_KEY_CODES.get(lowered)
    if code is not None:
        return code
    return int(text, 0)


# SvcParamKey mnemonic -> numeric codepoint (IANA DNS SVCB SvcParamKeys, RFC
# 9460 / RFC 9461). Mirrors the libcrafter dns_svc_param_key mapping so a case
# may give either a named or a numeric key.
_SVCB_PARAM_KEY_CODES: dict[str, int] = {
    "mandatory": 0,
    "alpn": 1,
    "no-default-alpn": 2,
    "port": 3,
    "ipv4hint": 4,
    "ech": 5,
    "ipv6hint": 6,
    "dohpath": 7,
}


def _dns_record_opt(record: Mapping[str, object], scapy_all: Any, *, name: str, ttl: int) -> Any:
    rclass = _int(record.get("udp_payload_size", record.get("rclass")), 4096)
    extrcode = _int(record.get("extended_rcode", record.get("extrcode")), 0)
    version = _int(record.get("version"), 0)
    z = 0x8000 if _bool_int(record.get("dnssec_ok"), 0) else 0
    z |= _int(record.get("z_bits", record.get("z")), 0) & 0x7FFF
    return scapy_all.DNSRROPT(
        rrname=_dns_normalized_name(record.get("name", record.get("rrname", "."))),
        rclass=rclass,
        extrcode=extrcode,
        version=version,
        z=z,
        rdata=_dns_edns_options(record.get("options"), scapy_all),
    )


def _dns_record_raw(
    record: Mapping[str, object],
    scapy_all: Any,
    *,
    name: str,
    ttl: int,
    rr_type: str,
) -> Any:
    rdata = _dns_blob(record.get("data", record.get("rdata")))
    return scapy_all.DNSRR(
        type=_dns_record_type_int(rr_type),
        rdata=rdata,
        **_dns_rr_common(record, name=name, ttl=ttl),
    )


def _dns_record_type_int(rr_type: str) -> object:
    if rr_type.isdigit():
        return int(rr_type)
    return rr_type


def _dns_text_string(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, Mapping):
        hex_value = value.get("hex")
        if isinstance(hex_value, str):
            return bytes.fromhex(hex_value)
    return _text(value, "").encode("utf-8")


def _dns_blob(value: object) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, Mapping):
        hex_value = value.get("hex")
        if isinstance(hex_value, str):
            return bytes.fromhex(hex_value)
        raise ValueError(f"dns blob object requires hex, got {value!r}")
    if isinstance(value, str):
        return bytes.fromhex(value)
    raise ValueError(f"expected blob-compatible dns value, got {value!r}")


def _dns_type_bitmaps(value: object, scapy_all: Any) -> list[int]:
    if value is None:
        return []
    record_types = value
    if isinstance(value, Mapping):
        record_types = value.get("record_types", [])
    if not isinstance(record_types, list):
        return []
    return [_dns_type_code(item, scapy_all) for item in record_types]


def _dns_type_code(value: object, scapy_all: Any) -> int:
    if isinstance(value, bool):
        raise ValueError(f"dns type bitmap entry must not be a boolean: {value!r}")
    if isinstance(value, int):
        return value
    text = _text(value, "").strip()
    if text.isdigit():
        return int(text)
    reverse = _dns_type_name_to_code(scapy_all)
    code = reverse.get(text.upper())
    if code is None:
        raise ValueError(f"unsupported dns type bitmap entry: {value!r}")
    return code


def _dns_type_name_to_code(scapy_all: Any) -> dict[str, int]:
    from scapy.layers import dns as scapy_dns  # type: ignore[import-untyped]

    return {name: code for code, name in scapy_dns.dnstypes.items()}


def _dns_edns_options(value: object, scapy_all: Any) -> list[object]:
    if not isinstance(value, list):
        return []
    options: list[object] = []
    for option in value:
        if not isinstance(option, Mapping):
            continue
        optcode = _int(option.get("option_code", option.get("optcode")), 0)
        optdata = _dns_blob(option.get("option_data", option.get("optdata")))
        options.append(scapy_all.EDNS0TLV(optcode=optcode, optdata=optdata))
    return options


def _dns_svc_params(value: object, scapy_all: Any) -> list[object]:
    if not isinstance(value, list):
        return []
    params: list[object] = []
    for param in value:
        if not isinstance(param, Mapping):
            continue
        key = _dns_svc_param_key(param.get("key"))
        param_value = _dns_blob(param.get("value"))
        params.append(scapy_all.SvcParam(key=key, value=param_value))
    return params


def _dns_svc_param_key(value: object) -> object:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    text = _text(value, "0").strip()
    if text.isdigit():
        return int(text)
    return text


_DNS_RECORD_BUILDERS: dict[str, Any] = {
    "A": _dns_record_a,
    "AAAA": _dns_record_aaaa,
    "NS": _dns_record_name_target("NS", "ns.example.com."),
    "CNAME": _dns_record_name_target("CNAME", "alias.example.com."),
    "PTR": _dns_record_name_target("PTR", "host.example.com."),
    "MX": _dns_record_mx,
    "TXT": _dns_record_txt,
    "SOA": _dns_record_soa,
    "SRV": _dns_record_srv,
    "DS": _dns_record_ds,
    "DNSKEY": _dns_record_dnskey,
    "RRSIG": _dns_record_rrsig,
    "NSEC": _dns_record_nsec,
    "NSEC3": _dns_record_nsec3,
    "SVCB": _dns_record_svcb("SVCB"),
    "HTTPS": _dns_record_svcb("HTTPS"),
}


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
