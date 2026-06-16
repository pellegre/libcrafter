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
    "eapol": 0x888E,
    "experimental": 0x9000,
    "ipv4": 0x0800,
    "ip": 0x0800,
    "ipv6": 0x86DD,
    "unknown": 0x9000,
    "vlan": 0x8100,
}
_IP_PROTOCOLS: dict[str, int] = {
    "ah": 51,
    "esp": 50,
    "icmp": 1,
    "tcp": 6,
    "unknown": 253,
    "udp": 17,
}
_BGP_MESSAGE_TYPES: dict[str, int] = {
    "open": 1,
    "update": 2,
    "notification": 3,
    "keepalive": 4,
    "route-refresh": 5,
    "route_refresh": 5,
}
_IPV6_NEXT_HEADERS: dict[str, int] = {
    "destination-options": 60,
    "destination_options": 60,
    "dstopts": 60,
    "fragment": 44,
    "hop-by-hop": 0,
    "hop-by-hop-options": 0,
    "hop_by_hop": 0,
    "hop_by_hop_options": 0,
    "hopopts": 0,
    "routing": 43,
    "icmpv6": 58,
    "no-next": 59,
    "no_next": 59,
    "payload": 253,
    "raw": 253,
    "tcp": 6,
    "unknown": 253,
    "udp": 17,
}
_SCAPY_LAYER_BY_LAYER: dict[str, str] = {
    "ah": "AH",
    "arp": "ARP",
    "bgp": "BGPHeader",
    "dhcp": "DHCP",
    "dns": "DNS",
    "dot11": "Dot11",
    "eapol": "EAPOL",
    "esp": "ESP",
    "ethernet": "Ether",
    "icmp": "ICMP",
    "ikev2": "ISAKMP",
    "icmpv6": "ICMPv6EchoRequest",
    "ipv6_destination_options": "IPv6ExtHdrDestOpt",
    "ipv6_fragment": "IPv6ExtHdrFragment",
    "ipv6_hop_by_hop": "IPv6ExtHdrHopByHop",
    "ipv6_routing": "IPv6ExtHdrRouting",
    "ipv4": "IP",
    "ipv6": "IPv6",
    "linux_cooked": "CookedLinux",
    "llc_snap": "LLC/SNAP",
    "null_loopback": "Loopback",
    "payload": "Raw",
    "radiotap": "RadioTap",
    "raw": "Raw",
    "rip": "RIP",
    # Scapy has no native RIPng dissector, so a RIPng plan is materialized as
    # manually-built header + RTE octets wrapped in a Scapy ``Raw`` layer; the
    # parser (wireshark/tshark) backend supplies the cross-validation decode.
    "ripng": "Raw",
    "rsn": "Dot11EltRSN",
    "tcp": "TCP",
    "udp": "UDP",
    "vlan": "Dot1Q",
}
_SCAPY_DECODER_BY_ROOT: dict[str, str] = {
    "link:ethernet": "Ether",
    "link:dot11": "Dot11",
    "link:ieee80211": "Dot11",
    "link:linux-cooked": "CookedLinux",
    "link:linux-sll": "CookedLinux",
    "link:null-loopback": "Loopback",
    "link:radiotap": "RadioTap",
    "link:raw": "Raw",
    "l2:ipv4": "IP",
    "l3:ipv4": "IP",
    "l3:ipv6": "IPv6",
}
_ROOT_FIRST_LAYERS: dict[str, set[str]] = {
    "link:dot11": {"dot11"},
    "link:ethernet": {"ethernet"},
    "link:ieee80211": {"dot11"},
    "link:linux-cooked": {"linux_cooked"},
    "link:linux-sll": {"linux_cooked"},
    "link:null-loopback": {"null_loopback"},
    "link:radiotap": {"radiotap"},
    "link:raw": {"payload"},
    "l2:ipv4": {"ipv4"},
    "l3:ipv4": {"ipv4"},
    "l3:ipv6": {"ipv6"},
}
_SCAPY_MATERIALIZED_LAYERS = frozenset(_SCAPY_LAYER_BY_LAYER)
_SUPPORTED_FEATURES = {
    "ah_integrity",
    "bgp_communities",
    "bgp_keepalive",
    "bgp_mp_reach",
    "bgp_notification",
    "bgp_open",
    "bgp_route_refresh",
    "bgp_update",
    "dhcp_behavior",
    "dns_behavior",
    "dot11_basic",
    "dot11_data_llc",
    "dot11_pcap_link_types",
    "eapol_basic",
    "esp_aead",
    "esp_cbc",
    "icmpv4_errors",
    "icmpv4_live",
    "icmpv6_errors",
    "ikev2_header",
    "ikev2_payloads",
    "ip_fragment_transforms",
    "ipv4_options",
    "ipv6_fragment_routing",
    "pcap_contracts",
    "pcap_link_types",
    "radiotap_basic",
    "rsn_foundations",
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
    "bgp": {
        "afi",
        "asn",
        "bgp_id",
        "bgp_identifier",
        "body",
        "body_hex",
        "capabilities",
        "code",
        "data",
        "error_code",
        "error_subcode",
        "hold_time",
        "len",
        "length",
        "marker",
        "message_type",
        "my_as",
        "nlri",
        "nlri_hex",
        "opt_param_len",
        "opt_params",
        "optional_parameters",
        "optional_parameters_hex",
        "orf_data",
        "path_attr",
        "path_attr_len",
        "path_attributes",
        "path_attributes_hex",
        "raw",
        "raw_body",
        "safi",
        "subcode",
        "subtype",
        "type",
        "version",
        "withdrawn_routes",
        "withdrawn_routes_hex",
        "withdrawn_routes_len",
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
    "dot11": {
        "addr1",
        "addr2",
        "addr3",
        "addr4",
        "duration_id",
        "frame_control",
        "frame_type",
        "from_ds",
        "ht_control",
        "management_fixed_fields",
        "more_data",
        "more_fragments",
        "order",
        "payload",
        "power_management",
        "protected",
        "protocol_version",
        "qos_control",
        "retry",
        "sequence_control",
        "subtype",
        "tagged_parameters",
        "to_ds",
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
    "eapol": {
        "body_length",
        "descriptor_type",
        "key_data",
        "key_data_length",
        "key_id",
        "key_information",
        "key_iv",
        "key_length",
        "key_mic",
        "key_nonce",
        "key_rsc",
        "packet_type",
        "replay_counter",
        "version",
    },
    "esp": {
        # The pinned key/salt/IV crypto context (see the generator determinism
        # seam) is consumed by the SecurityAssociation materializer.
        "crypto",
        "icv",
        "iv",
        "next_header",
        "pad_length",
        "sequence",
        "spi",
    },
    "ah": {
        "crypto",
        "icv",
        "next_header",
        "payload_len",
        "reserved",
        "sequence",
        "spi",
    },
    "ikev2": {
        "crypto",
        "exchange_type",
        "flags",
        "initiator_spi",
        "length",
        "message_id",
        "next_payload",
        "responder_spi",
        "version",
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
    "ipv6_destination_options": {
        "header_ext_len",
        "len",
        "next_header",
        "nh",
        "options",
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
    "ipv6_hop_by_hop": {
        "header_ext_len",
        "len",
        "next_header",
        "nh",
        "options",
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
    "llc_snap": {
        "control",
        "dsap",
        "ethertype",
        "oui",
        "payload_length",
        "ssap",
    },
    "null_loopback": {"type"},
    "payload": {"bytes_hex", "hex", "length", "text", "value"},
    "radiotap": {
        "antenna",
        "channel_flags",
        "channel_frequency",
        "dbm_antenna_signal",
        "fcs_status",
        "flags",
        "length",
        "pad",
        "present_words",
        "rate",
        "rx_flags",
        "tx_flags",
        "unknown_fields",
        "version",
    },
    "rip": {
        # RIP (RFC 1058 / RFC 2453) header fields mirror the libcrafter
        # accessor names; per-entry fields live under the "entries" list, and
        # the AFI 0xFFFF authentication entry lives under "auth".
        "command",
        "version",
        "reserved",
        "entries",
        "auth",
    },
    "ripng": {
        # RIPng (RFC 2080) header fields mirror the libcrafter Ripng accessor
        # names; per-RTE fields (prefix/route_tag/prefix_len/metric) live under
        # the "rtes" list. RIPng has no AFI/authentication fields of its own.
        "command",
        "version",
        "reserved",
        "rtes",
    },
    "rsn": {
        "akm_suites",
        "capabilities",
        "element_id",
        "group_cipher_suite",
        "group_management_cipher_suite",
        "length",
        "pairwise_cipher_suites",
        "pmkid_list",
        "trailing_bytes",
        "version",
    },
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
    stack = _canonical_stack(plan.stack)
    if not stack:
        raise ValueError("packet plan stack must contain at least one layer")
    root = _plan_root(plan)
    _validate_plan_contract(plan, stack, root)

    wifi_materialization = _is_dot11_phase15_stack(stack)
    needs_scapy = not wifi_materialization
    scapy_all = None
    scapy_version = "not-required"
    raw = None
    if needs_scapy:
        scapy = import_scapy()
        scapy_all = scapy["all"]
        scapy_version = _string(scapy["version"], "unknown")
        raw = scapy_all.raw

    ipsec_sa_metadata = None
    if wifi_materialization:
        raw_bytes = _dot11_phase15_bytes(plan, stack, scapy_all)
        udp_options_metadata = None
    elif _is_ipsec_sa_stack(plan, stack):
        if raw is None:
            raise ValueError("Scapy raw materializer was not initialized")
        raw_bytes, ipsec_sa_metadata = _materialize_ipsec_sa_packet(
            plan, stack, scapy_all
        )
        raw_bytes, udp_options_metadata = _materialize_udp_options(plan, root, raw_bytes)
    else:
        packet = None
        for index, layer in enumerate(stack):
            piece = _build_layer(plan, stack, index, scapy_all)
            packet = piece if packet is None else packet / piece

        if packet is None:
            raise ValueError("packet plan did not produce a packet")

        if raw is None:
            raise ValueError("Scapy raw materializer was not initialized")
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
    if ipsec_sa_metadata is not None:
        metadata["ipsec_sa_materialization"] = ipsec_sa_metadata
    if wifi_materialization:
        metadata["dot11_phase15_materialization"] = {
            "native_scapy_support": False,
            "materialization": "deterministic_wire_bytes",
        }
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
    if layer == "bgp":
        return _bgp(fields, stack, index, scapy_all)
    if layer == "ipv4":
        return _ipv4(fields, stack, index, scapy_all)
    if layer == "ipv6":
        return _ipv6(fields, stack, index, scapy_all)
    if layer == "ipv6_hop_by_hop":
        return _ipv6_hop_by_hop(fields, stack, index, scapy_all)
    if layer == "ipv6_destination_options":
        return _ipv6_destination_options(fields, stack, index, scapy_all)
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
    if layer == "rip":
        return _rip(fields, scapy_all)
    if layer == "ripng":
        return _ripng(fields, scapy_all)
    if layer == "esp":
        return _esp(fields, scapy_all)
    if layer == "ah":
        return _ah(fields, scapy_all)
    if layer == "ikev2":
        return _ikev2(fields, scapy_all)

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


def _bgp(
    fields: Mapping[str, JSONObject],
    stack: Sequence[str],
    index: int,
    scapy_all: Any,
) -> Any:
    scapy_bgp = import_scapy()["bgp"]
    bgp_fields = _layer_fields_for_stack_index(fields, stack, index)
    message_type = _bgp_message_type(
        _required_field(bgp_fields, "bgp", "message_type", "type")
    )
    header_kwargs = _bgp_header_kwargs(bgp_fields)

    if message_type == 4:
        return scapy_bgp.BGPKeepAlive(**header_kwargs)

    body = _bgp_raw_body(bgp_fields)
    if body is not None:
        return scapy_bgp.BGPHeader(type=message_type, **header_kwargs) / scapy_all.Raw(
            load=body
        )

    if message_type == 1:
        body = _bgp_open_raw_body(bgp_fields)
        if body is not None:
            return scapy_bgp.BGPHeader(type=message_type, **header_kwargs) / scapy_all.Raw(
                load=body
            )
        return scapy_bgp.BGPHeader(type=message_type, **header_kwargs) / scapy_bgp.BGPOpen(
            version=_int(_optional_field(bgp_fields, "version"), 4),
            my_as=_int(_optional_field(bgp_fields, "my_as", "asn"), 0),
            hold_time=_int(_optional_field(bgp_fields, "hold_time"), 0),
            bgp_id=_text(
                _optional_field(bgp_fields, "bgp_id", "bgp_identifier"),
                "0.0.0.0",
            ),
        )

    if message_type == 2:
        body = _bgp_update_raw_body(bgp_fields)
        if body is not None:
            return scapy_bgp.BGPHeader(type=message_type, **header_kwargs) / scapy_all.Raw(
                load=body
            )
        return scapy_bgp.BGPHeader(type=message_type, **header_kwargs) / scapy_bgp.BGPUpdate()

    if message_type == 3:
        kwargs: dict[str, Any] = {
            "error_code": _int(_optional_field(bgp_fields, "error_code", "code"), 0),
            "error_subcode": _int(
                _optional_field(bgp_fields, "error_subcode", "subcode"),
                0,
            ),
        }
        data = _optional_field(bgp_fields, "data")
        if data is not None:
            kwargs["data"] = _bytes_field(data)
        return (
            scapy_bgp.BGPHeader(type=message_type, **header_kwargs)
            / scapy_bgp.BGPNotification(**kwargs)
        )

    if message_type == 5:
        kwargs = {
            "afi": _bgp_afi(_optional_field(bgp_fields, "afi")),
            "subtype": _int(_optional_field(bgp_fields, "subtype"), 0),
            "safi": _bgp_safi(_optional_field(bgp_fields, "safi")),
        }
        orf_data = _optional_field(bgp_fields, "orf_data")
        if orf_data is not None:
            kwargs["orf_data"] = _bytes_field(orf_data)
        return (
            scapy_bgp.BGPHeader(type=message_type, **header_kwargs)
            / scapy_bgp.BGPRouteRefresh(**kwargs)
        )

    return scapy_bgp.BGPHeader(type=message_type, **header_kwargs)


def _bgp_header_kwargs(fields: Mapping[str, object]) -> dict[str, Any]:
    kwargs: dict[str, Any] = {}
    if "marker" in fields:
        kwargs["marker"] = _bgp_marker(fields["marker"])
    if "length" in fields or "len" in fields:
        kwargs["len"] = _int(_optional_field(fields, "length", "len"), 0)
    return kwargs


def _bgp_message_type(value: object) -> int:
    if isinstance(value, str):
        normalized = value.lower().replace("_", "-")
        if normalized in _BGP_MESSAGE_TYPES:
            return _BGP_MESSAGE_TYPES[normalized]
        return int(normalized, 0)
    return _int(value, 0)


def _bgp_marker(value: object) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return int.from_bytes(_bytes_exact(value, 16), "big")


def _bgp_raw_body(fields: Mapping[str, object]) -> bytes | None:
    value = _optional_field(fields, "body", "body_hex", "raw_body", "raw")
    if value is None:
        return None
    return _bytes_field(value)


def _bgp_open_raw_body(fields: Mapping[str, object]) -> bytes | None:
    optional_parameters = _optional_field(
        fields,
        "optional_parameters",
        "optional_parameters_hex",
        "opt_params",
        "capabilities",
    )
    if optional_parameters is None:
        return None
    parameters = _bytes_field(optional_parameters)
    param_len = _int(_optional_field(fields, "opt_param_len"), len(parameters))
    return (
        bytes([_int(_optional_field(fields, "version"), 4) & 0xFF])
        + _int(_optional_field(fields, "my_as", "asn"), 0).to_bytes(2, "big")
        + _int(_optional_field(fields, "hold_time"), 0).to_bytes(2, "big")
        + _ipv4_address_bytes(
            _optional_field(fields, "bgp_id", "bgp_identifier"),
            "0.0.0.0",
        )
        + bytes([param_len & 0xFF])
        + parameters
    )


def _bgp_update_raw_body(fields: Mapping[str, object]) -> bytes | None:
    withdrawn = _optional_field(fields, "withdrawn_routes", "withdrawn_routes_hex")
    path_attrs = _optional_field(
        fields,
        "path_attributes",
        "path_attributes_hex",
        "path_attr",
    )
    nlri = _optional_field(fields, "nlri", "nlri_hex")
    if withdrawn is None and path_attrs is None and nlri is None:
        return None
    withdrawn_bytes = _bytes_field(withdrawn) if withdrawn is not None else b""
    path_attr_bytes = _bytes_field(path_attrs) if path_attrs is not None else b""
    nlri_bytes = _bytes_field(nlri) if nlri is not None else b""
    withdrawn_len = _int(
        _optional_field(fields, "withdrawn_routes_len"),
        len(withdrawn_bytes),
    )
    path_attr_len = _int(_optional_field(fields, "path_attr_len"), len(path_attr_bytes))
    return (
        withdrawn_len.to_bytes(2, "big")
        + withdrawn_bytes
        + path_attr_len.to_bytes(2, "big")
        + path_attr_bytes
        + nlri_bytes
    )


def _bgp_afi(value: object) -> int:
    if isinstance(value, str):
        normalized = value.lower().replace("_", "-")
        mapping = {"ipv4": 1, "ip": 1, "ipv6": 2}
        if normalized in mapping:
            return mapping[normalized]
        return int(normalized, 0)
    return _int(value, 1)


def _bgp_safi(value: object) -> int:
    if isinstance(value, str):
        normalized = value.lower().replace("_", "-")
        mapping = {
            "unicast": 1,
            "multicast": 2,
            "nlri-unicast": 1,
        }
        if normalized in mapping:
            return mapping[normalized]
        return int(normalized, 0)
    return _int(value, 1)


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


def _ipv6_hop_by_hop(
    fields: Mapping[str, JSONObject],
    stack: list[str],
    index: int,
    scapy_all: Any,
) -> Any:
    return _ipv6_options_header(
        fields,
        layer="ipv6_hop_by_hop",
        factory=scapy_all.IPv6ExtHdrHopByHop,
        scapy_all=scapy_all,
    )


def _ipv6_destination_options(
    fields: Mapping[str, JSONObject],
    stack: list[str],
    index: int,
    scapy_all: Any,
) -> Any:
    return _ipv6_options_header(
        fields,
        layer="ipv6_destination_options",
        factory=scapy_all.IPv6ExtHdrDestOpt,
        scapy_all=scapy_all,
    )


def _ipv6_options_header(
    fields: Mapping[str, JSONObject],
    *,
    layer: str,
    factory: Any,
    scapy_all: Any,
) -> Any:
    option_fields = _layer_fields(fields, layer)
    kwargs: dict[str, Any] = {
        "nh": _protocol_value(
            _required_field(option_fields, layer, "next_header", "nh"),
            _IPV6_NEXT_HEADERS,
        ),
        # Scapy aligns some known options by inserting PadN ahead of them. The
        # oracle model is byte-preserving, so plans carry any required padding
        # explicitly and Scapy's alignment autopad must stay disabled.
        "autopad": 0,
        "options": _ipv6_options(_required_field(option_fields, layer, "options"), scapy_all),
    }
    if "header_ext_len" in option_fields or "len" in option_fields:
        kwargs["len"] = _int(_optional_field(option_fields, "header_ext_len", "len"), 0)
    return factory(**kwargs)


def _ipv6_options(value: object, scapy_all: Any) -> list[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError("IPv6 options materialization requires an option list")
    return [_ipv6_option(item, scapy_all) for item in value]


def _ipv6_option(item: object, scapy_all: Any) -> Any:
    if not isinstance(item, Mapping):
        raise ValueError(f"IPv6 option entry must be an object, got {item!r}")
    kind = _ipv6_option_kind(item)
    if kind == "pad1":
        return scapy_all.Pad1()
    if kind == "padn":
        return scapy_all.PadN(optdata=_ipv6_padn_data(item))
    if kind == "router_alert":
        return scapy_all.RouterAlert(value=_int(_required_field(item, "ipv6 option", "value"), 0))
    if kind == "jumbo_payload":
        length = _required_field(item, "ipv6 option", "length", "jumbo_payload_length")
        return scapy_all.Jumbo(jumboplen=_int(length, 0))
    if kind == "home_address":
        address = _required_field(item, "ipv6 option", "address", "home_address")
        return scapy_all.HAO(hoa=_text(address, "::"))
    option_type = _int(
        _required_field(item, "ipv6 option", "option_type", "type", "kind"),
        0,
    )
    return scapy_all.HBHOptUnknown(
        otype=option_type,
        optdata=_ipv6_option_data(item),
    )


def _ipv6_option_kind(item: Mapping[str, object]) -> str:
    value = _optional_field(item, "kind", "name")
    if isinstance(value, str):
        normalized = value.lower().replace("-", "_")
        if normalized in {
            "pad1",
            "padn",
            "router_alert",
            "jumbo_payload",
            "home_address",
            "unknown",
            "generic",
        }:
            return normalized
    option_type = _optional_field(item, "option_type", "type")
    if option_type is None:
        return "unknown"
    option_type_int = _int(option_type, 0)
    if option_type_int == 0:
        return "pad1"
    if option_type_int == 1:
        return "padn"
    if option_type_int == 5 and "value" in item:
        return "router_alert"
    if option_type_int == 0xC2 and ("length" in item or "jumbo_payload_length" in item):
        return "jumbo_payload"
    if option_type_int == 0xC9 and ("address" in item or "home_address" in item):
        return "home_address"
    return "unknown"


def _ipv6_padn_data(item: Mapping[str, object]) -> bytes:
    data = _ipv6_option_data(item)
    if data:
        return data
    total_length = _optional_field(item, "total_length", "length")
    if total_length is None:
        return b""
    total = _int(total_length, 0)
    if total < 2:
        raise ValueError(f"PadN total length must be at least 2 bytes, got {total}")
    return b"\x00" * (total - 2)


def _ipv6_option_data(item: Mapping[str, object]) -> bytes:
    data = _optional_field(item, "data", "bytes", "value_hex", "hex")
    if data is None:
        return b""
    return _bytes_field(data)


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


# --------------------------------------------------------------------------
# RIP (RFC 1058 / RFC 2453) materialization.
#
# Scapy ships a native RIP layer (scapy.layers.rip): RIP carries the 4-octet
# header (cmd, version, null), RIPEntry carries a 20-octet route entry (AF,
# RouteTag, addr, mask, nextHop, metric), and RIPAuth carries the AFI 0xFFFF
# authentication entry. The oracle field names mirror the libcrafter accessor
# names (command/version/reserved + per-entry address_family/route_tag/address/
# subnet_mask/next_hop/metric) so cross-backend normalization aligns. The plan
# carries the route entries under "entries" and an optional leading AFI 0xFFFF
# authentication entry under "auth".

# Named RIP command codes (RFC 1058 / RFC 2453 / RFC 2091) for plans that carry
# a symbolic command instead of a numeric one.
_RIP_COMMANDS: dict[str, int] = {
    "request": 1,
    "response": 2,
    "traceon": 3,
    "traceoff": 4,
    "sun": 5,
    "update-request": 9,
    "update_request": 9,
    "update-response": 10,
    "update_response": 10,
    "update-ack": 11,
    "update_acknowledge": 11,
    "update_ack": 11,
}
_RIP_AFI_IP = 2
_RIP_AFI_AUTH = 0xFFFF


def _rip(fields: Mapping[str, JSONObject], scapy_all: Any) -> Any:
    scapy_rip = import_scapy()["rip"]
    rip_fields = _layer_fields(fields, "rip")
    rip = scapy_rip.RIP(
        cmd=_rip_command(_required_field(rip_fields, "rip", "command", "cmd")),
        version=_int(_optional_field(rip_fields, "version"), 2),
        null=_int(_optional_field(rip_fields, "reserved", "null"), 0),
    )

    packet = rip
    auth = _optional_field(rip_fields, "auth")
    if auth is not None:
        packet = packet / _rip_auth(auth, scapy_rip)
    for entry in _rip_entries(rip_fields):
        packet = packet / _rip_entry(entry, scapy_rip)
    return packet


def _rip_command(value: object) -> int:
    if isinstance(value, str):
        normalized = value.lower().replace(" ", "-")
        if normalized in _RIP_COMMANDS:
            return _RIP_COMMANDS[normalized]
        return int(normalized, 0)
    return _int(value, 0)


def _rip_entries(rip_fields: Mapping[str, object]) -> list[Mapping[str, object]]:
    entries = rip_fields.get("entries")
    if entries is None:
        return []
    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes, bytearray)):
        raise ValueError("RIP entries materialization requires an entry list")
    result: list[Mapping[str, object]] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise ValueError(f"RIP entry must be an object, got {entry!r}")
        result.append(entry)
    return result


def _rip_entry(entry: Mapping[str, object], scapy_rip: Any) -> Any:
    return scapy_rip.RIPEntry(
        AF=_int(_optional_field(entry, "address_family", "af"), _RIP_AFI_IP),
        RouteTag=_int(_optional_field(entry, "route_tag", "tag", "routetag"), 0),
        addr=_text(_optional_field(entry, "address", "addr"), "0.0.0.0"),
        mask=_text(_optional_field(entry, "subnet_mask", "mask"), "0.0.0.0"),
        nextHop=_text(_optional_field(entry, "next_hop", "nexthop"), "0.0.0.0"),
        metric=_int(_optional_field(entry, "metric"), 0),
    )


def _rip_auth(auth: object, scapy_rip: Any) -> Any:
    if not isinstance(auth, Mapping):
        raise ValueError(f"RIP auth entry must be an object, got {auth!r}")
    auth_type = _int(_optional_field(auth, "type", "authtype", "auth_type"), 2)
    if auth_type == 2:
        # Simple password (RFC 2453 §4.1): up to 16 octets of cleartext password
        # carried in the AFI 0xFFFF entry.
        password = _rip_password_bytes(
            _optional_field(auth, "simple_password", "password", "secret")
        )
        return scapy_rip.RIPAuth(authtype=2, password=password)
    # Keyed message digest (RFC 2082 / RFC 4822): the AFI 0xFFFF leading entry
    # is a digest header. Scapy's RIPAuth carries the digest-header region; the
    # pinned key id / sequence map onto the header fields.
    kwargs: dict[str, Any] = {"authtype": auth_type}
    if _optional_field(auth, "digest_offset", "digestoffset") is not None:
        kwargs["digestoffset"] = _int(
            _optional_field(auth, "digest_offset", "digestoffset"), 0
        )
    if _optional_field(auth, "key_id", "keyid") is not None:
        kwargs["keyid"] = _int(_optional_field(auth, "key_id", "keyid"), 0)
    if _optional_field(auth, "auth_data_len", "authdatalen") is not None:
        kwargs["authdatalen"] = _int(
            _optional_field(auth, "auth_data_len", "authdatalen"), 0
        )
    if _optional_field(auth, "sequence", "seqnum") is not None:
        kwargs["seqnum"] = _int(_optional_field(auth, "sequence", "seqnum"), 0)
    return scapy_rip.RIPAuth(**kwargs)


def _rip_password_bytes(value: object) -> bytes:
    if value is None:
        return b"\x00" * 16
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, Mapping):
        raw = _bytes_field(value)
    elif isinstance(value, str):
        raw = value.encode("utf-8")
    else:
        raise ValueError(f"RIP simple password must be bytes or str, got {value!r}")
    return (raw + b"\x00" * 16)[:16]


# --------------------------------------------------------------------------
# RIPng (RFC 2080) manual materialization.
#
# Scapy has no native RIPng dissector, so a RIPng plan cannot be built from a
# reference layer the way IPv4 RIP rides Scapy's RIP/RIPEntry/RIPAuth. The
# oracle still needs reference RIPng bytes for the strict-byte cases, so the
# 4-octet header (command, version, reserved) and the fixed 20-octet route
# table entries (16-octet IPv6 prefix, 2-octet route tag, 1-octet prefix
# length, 1-octet metric) are assembled manually and wrapped in a Scapy ``Raw``
# layer. Cross-validation decode falls back to the wireshark/tshark parser
# backend plus the libcrafter internal round-trip, the way DNS records its
# Scapy gaps. The plan field names mirror the libcrafter Ripng/RipngRte
# accessor names so the parser-backend normalization aligns.

# RIPng over UDP port 521 (RFC 2080 §2).
_RIPNG_RTE_LEN = 20
# A next-hop RTE is signalled by metric 0xFF (RFC 2080 §2.1.1).
_RIPNG_NEXT_HOP_METRIC = 0xFF


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


# --------------------------------------------------------------------------
# IPSec (ESP / AH / IKEv2) materialization.
#
# ESP and AH byte-parity is driven by scapy.layers.ipsec.SecurityAssociation:
# the SA seals the cleartext IP packet (transport: the upper-layer data;
# tunnel: the inner IP datagram) with the algorithm, key, salt, and explicit IV
# pinned by the generator's determinism seam, so the emitted
# SPI || Seq || IV || ciphertext || ICV (ESP) or AH header + ICV (AH) matches
# libcrafter octet-for-octet. The ESP-null/opaque case and IKEv2 (ISAKMP) do not
# need an SA and are built as raw layers in the normal chain.
#
# The crypto suite is keyed off the plan's feature/feature_behavior metadata
# (esp_aead -> AES-GCM-16; esp_cbc cbc-hmac -> AES-CBC + HMAC-SHA2-256-128;
# esp_cbc null-opaque -> ENCR_NULL opaque; ah_integrity -> HMAC-SHA2-256-128),
# matching the feature specs and RFC 4106 / RFC 3602 / RFC 4302 placement.

# libcrafter EncryptionAlgorithm / IntegrityAlgorithm names mapped to scapy's
# SecurityAssociation crypt_algo / auth_algo identifiers.
_IPSEC_CRYPT_ALGO_BY_NAME: dict[str, str] = {
    "aes-gcm-16": "AES-GCM",
    "encr_aes_gcm_16": "AES-GCM",
    "aes-cbc": "AES-CBC",
    "encr_aes_cbc": "AES-CBC",
    "aes-ctr": "AES-CTR",
    "encr_aes_ctr": "AES-CTR",
    "null": "NULL",
    "encr_null": "NULL",
}
_IPSEC_AUTH_ALGO_BY_NAME: dict[str, str] = {
    "hmac-sha2-256-128": "SHA2-256-128",
    "auth_hmac_sha2_256_128": "SHA2-256-128",
    "hmac-sha2-384-192": "SHA2-384-192",
    "auth_hmac_sha2_384_192": "SHA2-384-192",
    "hmac-sha2-512-256": "SHA2-512-256",
    "auth_hmac_sha2_512_256": "SHA2-512-256",
    "hmac-sha1-96": "HMAC-SHA1-96",
    "auth_hmac_sha1_96": "HMAC-SHA1-96",
    "aes-xcbc-96": "AES-CMAC-96",
    "auth_aes_xcbc_96": "AES-CMAC-96",
}
# AEAD ICV (tag) length in octets, by suite. AES-GCM-16 is the MUST suite.
_IPSEC_AEAD_ICV_LEN: dict[str, int] = {
    "AES-GCM": 16,
    "AES-CCM": 8,
    "CHACHA20-POLY1305": 16,
}
# IP next-header derived from the plan ESP/AH next_header value for transport
# mode (tunnel mode dispatches an inner IP layer instead).
_IPSEC_TRANSPORT_PROTO: dict[str, int] = {
    "tcp": 6,
    "udp": 17,
    "icmp": 1,
    "payload": 253,
    "raw": 253,
}


def _is_ipsec_sa_stack(plan: PacketPlan, stack: Sequence[str]) -> bool:
    """True when an ESP/AH stack must be sealed with a SecurityAssociation.

    The ESP null/opaque case carries no SA (the body is preserved verbatim) and
    is materialized through the normal chain as a raw ESP layer; every other
    ESP/AH stack is sealed/signed by ``SecurityAssociation`` so the ciphertext
    and ICV are byte-reproducible.
    """

    if "esp" not in stack and "ah" not in stack:
        return False
    if _ipsec_feature_behavior(plan) == "null-opaque":
        return False
    return True


def _ipsec_feature(plan: PacketPlan) -> str:
    feature = plan.metadata.get("feature")
    return feature if isinstance(feature, str) else ""


def _ipsec_feature_behavior(plan: PacketPlan) -> str:
    behavior = plan.metadata.get("feature_behavior")
    return behavior if isinstance(behavior, str) else ""


def _ipsec_crypto_block(layer_fields: Mapping[str, object]) -> Mapping[str, object]:
    crypto = layer_fields.get("crypto")
    if not isinstance(crypto, Mapping):
        raise ValueError("IPSec ESP/AH materialization requires a pinned crypto block")
    return crypto


def _ipsec_crypto_bytes(crypto: Mapping[str, object], *names: str) -> bytes:
    for name in names:
        value = crypto.get(name)
        if value is not None:
            return _bytes_field(value)
    joined = "/".join(names)
    raise ValueError(f"IPSec crypto block requires field {joined}")


def _esp_suite(plan: PacketPlan) -> tuple[str, str | None]:
    """Resolve the (crypt_algo, auth_algo) scapy names for an ESP plan."""

    feature = _ipsec_feature(plan)
    if feature == "esp_aead":
        return "AES-GCM", None
    if feature == "esp_cbc":
        return "AES-CBC", "SHA2-256-128"
    # Default to the MUST AEAD suite so an unkeyed feature still seals.
    return "AES-GCM", None


def _materialize_ipsec_sa_packet(
    plan: PacketPlan,
    stack: Sequence[str],
    scapy_all: Any,
) -> tuple[bytes, JSONObject]:
    if "esp" in stack:
        return _materialize_esp_sa_packet(plan, stack, scapy_all)
    return _materialize_ah_sa_packet(plan, stack, scapy_all)


def _materialize_esp_sa_packet(
    plan: PacketPlan,
    stack: Sequence[str],
    scapy_all: Any,
) -> tuple[bytes, JSONObject]:
    esp_index = stack.index("esp")
    esp_fields = _layer_fields(plan.fields, "esp")
    crypto = _ipsec_crypto_block(esp_fields)
    crypt_algo, auth_algo = _esp_suite(plan)

    if crypt_algo == "AES-GCM":
        crypt_key = _ipsec_crypto_bytes(crypto, "encryption_key") + _ipsec_crypto_bytes(
            crypto, "salt"
        )
        explicit_iv = _ipsec_explicit_iv(esp_fields, crypto, aead=True)
    else:
        crypt_key = _ipsec_crypto_bytes(crypto, "encryption_key")
        explicit_iv = _ipsec_explicit_iv(esp_fields, crypto, aead=False)

    sa_kwargs: dict[str, Any] = {
        "spi": _int(_optional_field(esp_fields, "spi"), 0),
        "crypt_algo": crypt_algo,
        "crypt_key": crypt_key,
    }
    if crypt_algo in _IPSEC_AEAD_ICV_LEN:
        sa_kwargs["crypt_icv_size"] = _IPSEC_AEAD_ICV_LEN[crypt_algo]
    if auth_algo is not None:
        sa_kwargs["auth_algo"] = auth_algo
        sa_kwargs["auth_key"] = _ipsec_crypto_bytes(crypto, "integrity_key")

    tunnel, nat_t, outer, inner = _ipsec_inner_packet(plan, stack, esp_index, scapy_all)
    if tunnel is not None:
        sa_kwargs["tunnel_header"] = tunnel
    if nat_t is not None:
        sa_kwargs["nat_t_header"] = nat_t

    sa = scapy_all.SecurityAssociation(scapy_all.ESP, **sa_kwargs)
    seq = _int(_optional_field(esp_fields, "sequence"), 1)
    sealed = sa.encrypt(inner, seq_num=seq, iv=explicit_iv)
    raw_bytes = bytes(scapy_all.raw(sealed))
    return raw_bytes, {
        "layer": "esp",
        "crypt_algo": crypt_algo,
        "auth_algo": auth_algo,
        "mode": "tunnel" if tunnel is not None else "transport",
        "nat_traversal": nat_t is not None,
        "spi": sa_kwargs["spi"],
        "sequence": seq,
        "explicit_iv_hex": explicit_iv.hex(),
        "native_scapy_support": True,
    }


def _materialize_ah_sa_packet(
    plan: PacketPlan,
    stack: Sequence[str],
    scapy_all: Any,
) -> tuple[bytes, JSONObject]:
    ah_index = stack.index("ah")
    ah_fields = _layer_fields(plan.fields, "ah")
    crypto = _ipsec_crypto_block(ah_fields)
    auth_algo = "SHA2-256-128"

    sa_kwargs: dict[str, Any] = {
        "spi": _int(_optional_field(ah_fields, "spi"), 0),
        "auth_algo": auth_algo,
        "auth_key": _ipsec_crypto_bytes(crypto, "integrity_key"),
    }
    tunnel, nat_t, outer, inner = _ipsec_inner_packet(plan, stack, ah_index, scapy_all)
    if tunnel is not None:
        sa_kwargs["tunnel_header"] = tunnel
    if nat_t is not None:
        sa_kwargs["nat_t_header"] = nat_t

    sa = scapy_all.SecurityAssociation(scapy_all.AH, **sa_kwargs)
    seq = _int(_optional_field(ah_fields, "sequence"), 1)
    signed = sa.encrypt(inner, seq_num=seq)
    raw_bytes = bytes(scapy_all.raw(signed))
    return raw_bytes, {
        "layer": "ah",
        "auth_algo": auth_algo,
        "mode": "tunnel" if tunnel is not None else "transport",
        "nat_traversal": nat_t is not None,
        "spi": sa_kwargs["spi"],
        "sequence": seq,
        "native_scapy_support": True,
    }


def _ipsec_explicit_iv(
    layer_fields: Mapping[str, object],
    crypto: Mapping[str, object],
    *,
    aead: bool,
) -> bytes:
    """Resolve the pinned explicit IV for an ESP datagram.

    AEAD (RFC 4106): the 8-octet explicit IV. A per-layer ``iv`` override wins
    (the generator pins it, including the all-zero ``zero`` domain) so the
    explicit IV || ciphertext is reproducible. CBC (RFC 3602) uses the 16-octet
    ``cbc_iv`` from the pinned crypto block; the ESP ``iv`` field carries only
    the 8-octet AEAD IV, so it is not used for the CBC IV.
    """

    if aead:
        override = layer_fields.get("iv")
        if override is not None:
            return _bytes_field(override)
        return _ipsec_crypto_bytes(crypto, "iv", "aead_iv")
    return _ipsec_crypto_bytes(crypto, "cbc_iv")


def _ipsec_inner_packet(
    plan: PacketPlan,
    stack: Sequence[str],
    sec_index: int,
    scapy_all: Any,
) -> tuple[Any | None, Any | None, Any, Any]:
    """Build (tunnel_header, nat_t_header, outer_ip, cleartext_inner).

    Transport mode: the outer IP carries the upper-layer data directly, so the
    inner packet is ``outer_ip / upper_layers`` and there is no tunnel header.
    Tunnel mode: the ESP/AH next-header is an inner IP datagram, so the outer IP
    becomes the tunnel header and the inner packet is the inner IP datagram and
    everything after it. NAT-T (RFC 3948): when a UDP layer sits between the IP
    header and ESP, the UDP layer becomes the SecurityAssociation NAT-T header so
    scapy emits IP / UDP / ESP.
    """

    nat_t_index = sec_index - 1
    if nat_t_index >= 0 and stack[nat_t_index] == "udp":
        nat_t = _build_layer(plan, list(stack), nat_t_index, scapy_all)
        outer_index = nat_t_index - 1
    else:
        nat_t = None
        outer_index = sec_index - 1

    if outer_index < 0 or stack[outer_index] not in {"ipv4", "ipv6"}:
        raise ValueError("ESP/AH materialization requires a preceding IP layer")
    outer_ip = _build_layer(plan, list(stack), outer_index, scapy_all)

    inner_layers = stack[sec_index + 1 :]
    if inner_layers and inner_layers[0] in {"ipv4", "ipv6"}:
        # Tunnel mode: outer IP is the tunnel header; the inner IP datagram (and
        # any following upper layers) is the cleartext that gets sealed.
        inner = _chain_layers(plan, stack, sec_index + 1, len(stack), scapy_all)
        return outer_ip, nat_t, outer_ip, inner

    # Transport mode: the upper-layer data is carried directly under the outer IP.
    inner = outer_ip
    for index in range(sec_index + 1, len(stack)):
        inner = inner / _build_layer(plan, list(stack), index, scapy_all)
    return None, nat_t, outer_ip, inner


def _chain_layers(
    plan: PacketPlan,
    stack: Sequence[str],
    start: int,
    end: int,
    scapy_all: Any,
) -> Any:
    packet = None
    for index in range(start, end):
        piece = _build_layer(plan, list(stack), index, scapy_all)
        packet = piece if packet is None else packet / piece
    if packet is None:
        raise ValueError("IPSec inner packet did not produce any layers")
    return packet


def _esp(fields: Mapping[str, JSONObject], scapy_all: Any) -> Any:
    """Build a raw ESP layer for the opaque (no-SA) case.

    The null/opaque case preserves the ESP body verbatim, so the layer carries
    SPI || Seq and the following layer's bytes become the opaque ``data``.
    """

    esp_fields = _layer_fields(fields, "esp")
    kwargs: dict[str, Any] = {
        "spi": _int(_optional_field(esp_fields, "spi"), 0),
        "seq": _int(_optional_field(esp_fields, "sequence"), 1),
    }
    return scapy_all.ESP(**kwargs)


def _ah(fields: Mapping[str, JSONObject], scapy_all: Any) -> Any:
    """Build a raw AH header (used when no SA seals the stack)."""

    ah_fields = _layer_fields(fields, "ah")
    kwargs: dict[str, Any] = {
        "spi": _int(_optional_field(ah_fields, "spi"), 0),
        "seq": _int(_optional_field(ah_fields, "sequence"), 1),
    }
    if "reserved" in ah_fields:
        kwargs["reserved"] = _int(ah_fields.get("reserved"), 0)
    if "payload_len" in ah_fields:
        kwargs["payloadlen"] = _int(ah_fields.get("payload_len"), 0)
    if "icv" in ah_fields:
        kwargs["icv"] = _bytes_field(ah_fields["icv"])
    return scapy_all.AH(**kwargs)


def _ikev2(fields: Mapping[str, JSONObject], scapy_all: Any) -> Any:
    """Build an IKEv2 (ISAKMP) message header via scapy.layers.isakmp.

    The initiator/responder SPIs map to the ISAKMP init/resp cookies, and the
    next-payload, version, exchange type, flags, and message id round-trip. The
    payload chain itself is carried as the following Raw layer in the stack, so
    this builder materializes the 28-byte header only; compile() / the generic
    payload chain belongs to the libcrafter side and later parity steps.
    """

    ike_fields = _layer_fields(fields, "ikev2")
    kwargs: dict[str, Any] = {
        "next_payload": _ikev2_next_payload(_optional_field(ike_fields, "next_payload")),
        "exch_type": _ikev2_exchange_type(_optional_field(ike_fields, "exchange_type")),
        "id": _int(_optional_field(ike_fields, "message_id"), 0),
        "flags": _ikev2_flags(_optional_field(ike_fields, "flags")),
    }
    if "initiator_spi" in ike_fields:
        kwargs["init_cookie"] = _bytes_field(ike_fields["initiator_spi"])
    if "responder_spi" in ike_fields:
        kwargs["resp_cookie"] = _bytes_field(ike_fields["responder_spi"])
    if "version" in ike_fields:
        kwargs["version"] = _int(ike_fields.get("version"), 0x20)
    if "length" in ike_fields:
        kwargs["length"] = _int(ike_fields.get("length"), 0)
    return scapy_all.ISAKMP(**kwargs)


# IKEv2 next-payload codepoints (RFC 7296 §3.2). The plan carries libcrafter
# payload-type layer names; map them to the wire codepoint scapy stores.
_IKEV2_NEXT_PAYLOAD_CODE: dict[str, int] = {
    "none": 0,
    "ikesapayload": 33,
    "sa": 33,
    "ikekepayload": 34,
    "ke": 34,
    "ikeidipayload": 35,
    "ikeidrpayload": 36,
    "ikecertpayload": 37,
    "ikecertreqpayload": 38,
    "ikeauthpayload": 39,
    "auth": 39,
    "ikenoncepayload": 40,
    "nonce": 40,
    "ikenotifypayload": 41,
    "notify": 41,
    "ikedeletepayload": 42,
    "delete": 42,
    "ikevendorpayload": 43,
    "iketsipayload": 44,
    "iketsrpayload": 45,
    "ikeencryptedpayload": 46,
    "encrypted": 46,
    "ikeconfigpayload": 47,
    "ikeeappayload": 48,
}
_IKEV2_EXCHANGE_TYPE_CODE: dict[str, int] = {
    "ike_sa_init": 34,
    "ike_auth": 35,
    "create_child_sa": 36,
    "informational": 37,
}
_IKEV2_FLAG_BIT: dict[str, int] = {
    "initiator": 0x08,
    "version": 0x10,
    "response": 0x20,
}


def _ikev2_next_payload(value: object) -> int:
    if value is None:
        return 0
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.lower().replace("-", "_")
        if lowered in _IKEV2_NEXT_PAYLOAD_CODE:
            return _IKEV2_NEXT_PAYLOAD_CODE[lowered]
        return int(lowered, 0)
    return _int(value, 0)


def _ikev2_exchange_type(value: object) -> int:
    if value is None:
        return 34
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.lower().replace("-", "_")
        if lowered in _IKEV2_EXCHANGE_TYPE_CODE:
            return _IKEV2_EXCHANGE_TYPE_CODE[lowered]
        return int(lowered, 0)
    return _int(value, 34)


def _ikev2_flags(value: object) -> int:
    if value is None:
        return 0
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    items = value if isinstance(value, (list, tuple)) else [value]
    flags = 0
    for item in items:
        if isinstance(item, int) and not isinstance(item, bool):
            flags |= item
            continue
        if isinstance(item, str):
            lowered = item.lower().replace("-", "_")
            if lowered in _IKEV2_FLAG_BIT:
                flags |= _IKEV2_FLAG_BIT[lowered]
    return flags


def _canonical_stack(stack: list[str]) -> list[str]:
    aliases = {
        "dot1q": "vlan",
        "ether": "ethernet",
        "hop-by-hop": "ipv6_hop_by_hop",
        "hop-by-hop-options": "ipv6_hop_by_hop",
        "hop_by_hop": "ipv6_hop_by_hop",
        "hop_by_hop_options": "ipv6_hop_by_hop",
        "ip": "ipv4",
        "ipv6-destination-options": "ipv6_destination_options",
        "ipv6-hop-by-hop": "ipv6_hop_by_hop",
        "ipv6-hop-by-hop-options": "ipv6_hop_by_hop",
        "destination-options": "ipv6_destination_options",
        "destination_options": "ipv6_destination_options",
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

    for index, layer in enumerate(stack):
        if layer not in _SCAPY_MATERIALIZED_LAYERS:
            raise ValueError(f"unsupported Scapy materialization layer: {layer}")
        fields = _layer_fields_for_stack_index(plan.fields, stack, index)
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


def _layer_fields_for_stack_index(
    fields: Mapping[str, JSONObject],
    stack: Sequence[str],
    index: int,
) -> JSONObject:
    layer = stack[index]
    occurrence = sum(1 for item in stack[: index + 1] if item == layer)
    if occurrence > 1:
        value = fields.get(f"{layer}#{occurrence}")
        if value is not None:
            if not isinstance(value, Mapping):
                raise ValueError(f"{layer}#{occurrence} fields must be an object")
            return dict(value)
    return _layer_fields(fields, layer)


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


_DOT11_PHASE15_LAYERS = frozenset({"radiotap", "dot11", "llc_snap", "eapol", "rsn"})
_DOT11_CONVENTIONAL_CHILDREN = frozenset({"arp", "ipv4", "ipv6"})


def _is_dot11_phase15_stack(stack: Sequence[str]) -> bool:
    return any(layer in _DOT11_PHASE15_LAYERS for layer in stack)


def _dot11_phase15_bytes(plan: PacketPlan, stack: list[str], scapy_all: Any) -> bytes:
    output = bytearray()
    index = 0
    while index < len(stack):
        layer = stack[index]
        if layer == "radiotap":
            output.extend(_radiotap_bytes(plan.fields))
        elif layer == "dot11":
            output.extend(_dot11_bytes(plan.fields))
        elif layer == "llc_snap":
            output.extend(_llc_snap_bytes(plan.fields, stack))
        elif layer == "eapol":
            output.extend(_eapol_bytes(plan.fields, stack, index))
        elif layer == "rsn":
            output.extend(_rsn_element_bytes(plan.fields))
        elif layer in {"payload", "raw"}:
            output.extend(_payload_bytes(plan.fields))
        elif layer in _DOT11_CONVENTIONAL_CHILDREN:
            output.extend(_dot11_conventional_child_bytes(plan.fields, layer))
        else:
            raise ValueError(f"unsupported Dot11 phase 1.5 materialization layer: {layer}")
        index += 1
    return bytes(output)


def _radiotap_bytes(fields: Mapping[str, JSONObject]) -> bytes:
    radiotap = _layer_fields(fields, "radiotap")
    field_entries: list[tuple[int, int, bytes]] = []
    if "flags" in radiotap or "fcs_status" in radiotap:
        field_entries.append((1, 1, bytes([_radiotap_flags(radiotap)])))
    if "rate" in radiotap:
        field_entries.append((2, 1, bytes([_int(radiotap.get("rate"), 2) & 0xFF])))
    if "channel_frequency" in radiotap or "channel_flags" in radiotap:
        field_entries.append(
            (
                3,
                2,
                _int(radiotap.get("channel_frequency"), 2412).to_bytes(2, "little")
                + _radiotap_channel_flags(radiotap.get("channel_flags")).to_bytes(2, "little"),
            )
        )
    if "dbm_antenna_signal" in radiotap:
        signal = _int(radiotap.get("dbm_antenna_signal"), -42)
        field_entries.append((5, 1, int(signal).to_bytes(1, "little", signed=True)))
    if "antenna" in radiotap:
        field_entries.append((11, 1, bytes([_int(radiotap.get("antenna"), 0) & 0xFF])))
    if "rx_flags" in radiotap:
        field_entries.append((14, 2, _int(radiotap.get("rx_flags"), 0).to_bytes(2, "little")))
    if "tx_flags" in radiotap:
        field_entries.append((15, 2, _int(radiotap.get("tx_flags"), 0).to_bytes(2, "little")))

    present = 0
    for bit, _, _ in field_entries:
        present |= 1 << bit
    body = bytearray()
    offset = 8
    for _, alignment, value in sorted(field_entries, key=lambda item: item[0]):
        pad = _radiotap_padding(offset, alignment)
        body.extend(b"\x00" * pad)
        offset += pad
        body.extend(value)
        offset += len(value)

    version = _int(radiotap.get("version"), 0) & 0xFF
    pad_byte = _int(radiotap.get("pad"), 0) & 0xFF
    length = 8 + len(body)
    return (
        bytes([version, pad_byte])
        + length.to_bytes(2, "little")
        + present.to_bytes(4, "little")
        + bytes(body)
    )


def _radiotap_padding(offset: int, alignment: int) -> int:
    if alignment <= 1:
        return 0
    remainder = offset % alignment
    return 0 if remainder == 0 else alignment - remainder


def _radiotap_flags(fields: Mapping[str, object]) -> int:
    value = 0
    raw_flags = fields.get("flags")
    raw_status = fields.get("fcs_status")
    tokens = {str(item).lower().replace("-", "_") for item in (raw_flags, raw_status) if item is not None}
    if raw_flags is not None and not isinstance(raw_flags, str):
        value |= _int(raw_flags, 0)
    if "fcs_present" in tokens or "present" in tokens or "present_failed" in tokens:
        value |= 0x10
    if "failed_fcs" in tokens or "failed" in tokens or "present_failed" in tokens:
        value |= 0x40
    return value


def _radiotap_channel_flags(value: object) -> int:
    if value is None:
        return 0x00A0
    if not isinstance(value, str):
        return _int(value, 0)
    normalized = value.lower().replace("-", "_")
    mapping = {
        "two_ghz_cck": 0x00A0,
        "two_ghz_ofdm": 0x00C0,
        "five_ghz_ofdm": 0x0140,
    }
    if normalized in mapping:
        return mapping[normalized]
    return _int(value, 0)


def _dot11_bytes(fields: Mapping[str, JSONObject]) -> bytes:
    dot11 = _layer_fields(fields, "dot11")
    frame_control = _dot11_frame_control(dot11)
    frame_type = (frame_control >> 2) & 0x3
    subtype = (frame_control >> 4) & 0xF
    output = bytearray()
    output.extend(frame_control.to_bytes(2, "little"))
    output.extend(_int(dot11.get("duration_id"), 0).to_bytes(2, "little"))
    output.extend(_mac_bytes(dot11.get("addr1"), "00:00:5e:00:53:01"))

    if frame_type == 1:
        if subtype not in {12, 13}:
            output.extend(_mac_bytes(dot11.get("addr2"), "00:00:5e:00:53:02"))
        return bytes(output)

    output.extend(_mac_bytes(dot11.get("addr2"), "00:00:5e:00:53:02"))
    output.extend(_mac_bytes(dot11.get("addr3"), "00:00:5e:00:53:03"))
    output.extend(_int(dot11.get("sequence_control"), 0).to_bytes(2, "little"))
    if frame_type == 2 and (frame_control & 0x0300) == 0x0300:
        output.extend(_mac_bytes(dot11.get("addr4"), "00:00:5e:00:53:04"))
    if frame_type == 2 and (subtype & 0x8):
        output.extend(_int(dot11.get("qos_control"), 0).to_bytes(2, "little"))
    if frame_control & 0x8000 and "ht_control" in dot11:
        output.extend(_int(dot11.get("ht_control"), 0).to_bytes(4, "little"))
    if frame_type == 0:
        output.extend(_bytes_optional(dot11.get("management_fixed_fields")))
        output.extend(_tagged_parameters_bytes(dot11.get("tagged_parameters")))
    return bytes(output)


def _dot11_frame_control(fields: Mapping[str, object]) -> int:
    if "frame_control" in fields:
        return _int(fields.get("frame_control"), 0)
    value = (_int(fields.get("protocol_version"), 0) & 0x3)
    value |= (_dot11_frame_type_value(fields.get("frame_type")) & 0x3) << 2
    value |= (_dot11_subtype_value(fields.get("subtype")) & 0xF) << 4
    for name, mask in (
        ("to_ds", 0x0100),
        ("from_ds", 0x0200),
        ("more_fragments", 0x0400),
        ("retry", 0x0800),
        ("power_management", 0x1000),
        ("more_data", 0x2000),
        ("protected", 0x4000),
        ("order", 0x8000),
    ):
        if bool(fields.get(name)):
            value |= mask
    return value


def _dot11_frame_type_value(value: object) -> int:
    if not isinstance(value, str):
        return _int(value, 2)
    mapping = {"management": 0, "control": 1, "data": 2, "extension": 3}
    normalized = value.lower().replace("-", "_")
    if normalized in mapping:
        return mapping[normalized]
    return _int(value, 2)


def _dot11_subtype_value(value: object) -> int:
    if not isinstance(value, str):
        return _int(value, 0)
    mapping = {
        "association_request": 0,
        "probe_request": 4,
        "beacon": 8,
        "authentication": 11,
        "deauthentication": 12,
        "rts": 11,
        "cts": 12,
        "ack": 13,
        "data": 0,
        "qos_data": 8,
        "unknown": 15,
    }
    normalized = value.lower().replace("-", "_")
    if normalized in mapping:
        return mapping[normalized]
    return _int(value, 0)


def _tagged_parameters_bytes(value: object) -> bytes:
    if value is None:
        return b""
    if isinstance(value, Mapping):
        value = [value]
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return _bytes_optional(value)
    output = bytearray()
    for item in value:
        if not isinstance(item, Mapping):
            continue
        tag = _int(item.get("id", item.get("tag", item.get("element_id"))), 0)
        data = _bytes_optional(item.get("value", item.get("data", item.get("bytes"))))
        output.extend(bytes([tag & 0xFF, len(data) & 0xFF]))
        output.extend(data)
    return bytes(output)


def _llc_snap_bytes(fields: Mapping[str, JSONObject], stack: Sequence[str]) -> bytes:
    llc = _layer_fields(fields, "llc_snap")
    return bytes(
        [
            _int(llc.get("dsap"), 0xAA) & 0xFF,
            _int(llc.get("ssap"), 0xAA) & 0xFF,
            _int(llc.get("control"), 0x03) & 0xFF,
        ]
    ) + _oui_bytes(llc.get("oui")) + _ethertype_value(
        llc.get("ethertype", _llc_snap_ethertype_for_stack(stack))
    ).to_bytes(2, "big")


def _dot11_conventional_child_bytes(fields: Mapping[str, JSONObject], layer: str) -> bytes:
    if layer == "arp":
        return _arp_bytes(fields)
    if layer == "ipv4":
        return _ipv4_bytes(fields)
    if layer == "ipv6":
        return _ipv6_bytes(fields)
    raise ValueError(f"unsupported Dot11 child protocol: {layer}")


def _arp_bytes(fields: Mapping[str, JSONObject]) -> bytes:
    arp = _layer_fields(fields, "arp")
    hwlen = _int(arp.get("hardware_length"), 6)
    plen = _int(arp.get("protocol_length"), 4)
    return (
        _hardware_type_value(arp.get("hardware_type", "ethernet")).to_bytes(2, "big")
        + _ethertype_value(arp.get("protocol_type", "ipv4")).to_bytes(2, "big")
        + bytes([hwlen & 0xFF, plen & 0xFF])
        + _arp_opcode_value(arp.get("opcode", arp.get("op", "request"))).to_bytes(2, "big")
        + _bytes_exact(_arp_address_bytes(arp.get("sender_hardware_address", arp.get("hwsrc")), "hardware"), hwlen)
        + _bytes_exact(_arp_address_bytes(arp.get("sender_protocol_address", arp.get("sender_ip", arp.get("psrc"))), "protocol"), plen)
        + _bytes_exact(_arp_address_bytes(arp.get("target_hardware_address", arp.get("hwdst")), "hardware"), hwlen)
        + _bytes_exact(_arp_address_bytes(arp.get("target_protocol_address", arp.get("target_ip", arp.get("pdst"))), "protocol"), plen)
    )


def _arp_opcode_value(value: object) -> int:
    if not isinstance(value, str):
        return _int(value, 1)
    mapping = {"request": 1, "who-has": 1, "reply": 2, "is-at": 2}
    normalized = value.lower().replace("_", "-")
    if normalized in mapping:
        return mapping[normalized]
    return _int(value, 1)


def _arp_address_bytes(value: object, kind: str) -> bytes:
    if kind == "protocol" and isinstance(value, str) and "." in value:
        return bytes(int(part) & 0xFF for part in value.split("."))
    default = "00:00:5e:00:53:01" if kind == "hardware" else {"hex": "00000000"}
    return _bytes_optional(value if value is not None else default)


def _ipv4_bytes(fields: Mapping[str, JSONObject]) -> bytes:
    ipv4 = _layer_fields(fields, "ipv4")
    payload = b""
    ihl = 5
    version_ihl = (4 << 4) | ihl
    flags_fragment = _ipv4_flags_fragment(ipv4)
    total_length = 20 + len(payload)
    protocol = _protocol_value(ipv4.get("protocol", ipv4.get("proto", "unknown")), _IP_PROTOCOLS)
    header = bytearray(
        [
            version_ihl,
            _int(ipv4.get("ds_field", ipv4.get("tos")), 0) & 0xFF,
        ]
    )
    header.extend(total_length.to_bytes(2, "big"))
    header.extend(_int(ipv4.get("identification", ipv4.get("id")), 0).to_bytes(2, "big"))
    header.extend(flags_fragment.to_bytes(2, "big"))
    header.extend(bytes([_int(ipv4.get("ttl"), 64) & 0xFF, protocol & 0xFF]))
    header.extend(b"\x00\x00")
    header.extend(_ipv4_address_bytes(ipv4.get("src"), "192.0.2.1"))
    header.extend(_ipv4_address_bytes(ipv4.get("dst"), "198.51.100.1"))
    checksum = _internet_checksum(bytes(header))
    header[10:12] = checksum.to_bytes(2, "big")
    return bytes(header) + payload


def _ipv4_flags_fragment(fields: Mapping[str, object]) -> int:
    flags = fields.get("flags", "none")
    flag_bits = 0
    if isinstance(flags, str):
        normalized = flags.lower().replace("_", "-")
        if "df" in normalized:
            flag_bits |= 0x4000
        if "mf" in normalized:
            flag_bits |= 0x2000
    else:
        flag_bits = (_int(flags, 0) & 0x7) << 13
    return flag_bits | (_int(fields.get("fragment_offset", fields.get("frag")), 0) & 0x1FFF)


def _ipv4_address_bytes(value: object, default: str = "0.0.0.0") -> bytes:
    text = _text(value, default)
    return bytes(int(part) & 0xFF for part in text.split("."))


def _ipv6_bytes(fields: Mapping[str, JSONObject]) -> bytes:
    ipv6 = _layer_fields(fields, "ipv6")
    traffic_class = _int(ipv6.get("traffic_class", ipv6.get("tc")), 0) & 0xFF
    flow_label = _int(ipv6.get("flow_label", ipv6.get("fl")), 0) & 0xFFFFF
    first_word = (6 << 28) | (traffic_class << 20) | flow_label
    payload = b""
    next_header = _protocol_value(
        ipv6.get("next_header", ipv6.get("nh", "unknown")),
        _IPV6_NEXT_HEADERS,
    )
    return (
        first_word.to_bytes(4, "big")
        + len(payload).to_bytes(2, "big")
        + bytes([next_header & 0xFF, _int(ipv6.get("hop_limit", ipv6.get("hlim")), 64) & 0xFF])
        + _ipv6_address_bytes(ipv6.get("src"), "2001:db8::1")
        + _ipv6_address_bytes(ipv6.get("dst"), "2001:db8::2")
        + payload
    )


def _ipv6_address_bytes(value: object, default: str) -> bytes:
    import ipaddress

    return ipaddress.IPv6Address(_text(value, default)).packed


def _llc_snap_ethertype_for_stack(stack: Sequence[str]) -> str:
    try:
        index = list(stack).index("llc_snap")
    except ValueError:
        return "unknown"
    if index + 1 >= len(stack):
        return "unknown"
    next_layer = stack[index + 1]
    return "eapol" if next_layer == "eapol" else next_layer


def _eapol_bytes(fields: Mapping[str, JSONObject], stack: Sequence[str], index: int) -> bytes:
    eapol = _layer_fields(fields, "eapol")
    packet_type = _eapol_type(eapol.get("packet_type"))
    body = _eapol_key_bytes(eapol) if packet_type == 3 or "descriptor_type" in eapol else b""
    trailing = _payload_bytes(fields) if "payload" in stack[index + 1 :] else b""
    body_length = len(body) + len(trailing)
    explicit_length = _int(eapol.get("body_length"), 0)
    if explicit_length:
        body_length = explicit_length
    return bytes(
        [
            _int(eapol.get("version"), 2) & 0xFF,
            packet_type & 0xFF,
        ]
    ) + body_length.to_bytes(2, "big") + body


def _eapol_type(value: object) -> int:
    if not isinstance(value, str):
        return _int(value, 1)
    mapping = {
        "eap_packet": 0,
        "eap-packet": 0,
        "start": 1,
        "logoff": 2,
        "key": 3,
        "asf_alert": 4,
        "asf-alert": 4,
        "unknown": 255,
    }
    normalized = value.lower()
    if normalized in mapping:
        return mapping[normalized]
    return _int(value, 1)


def _eapol_key_bytes(fields: Mapping[str, object]) -> bytes:
    key_data = _bytes_optional(fields.get("key_data"))
    key_data_length = _int(fields.get("key_data_length"), len(key_data))
    if key_data and key_data_length == 0:
        key_data_length = len(key_data)
    return (
        bytes([_eapol_descriptor_type(fields.get("descriptor_type"))])
        + _int(fields.get("key_information"), 0).to_bytes(2, "big")
        + _int(fields.get("key_length"), 0).to_bytes(2, "big")
        + _int(fields.get("replay_counter"), 0).to_bytes(8, "big")
        + _bytes_exact(fields.get("key_nonce"), 32)
        + _bytes_exact(fields.get("key_iv"), 16)
        + _bytes_exact(fields.get("key_rsc"), 8)
        + _bytes_exact(fields.get("key_id"), 8)
        + _bytes_exact(fields.get("key_mic"), 16)
        + key_data_length.to_bytes(2, "big")
        + key_data
    )


def _eapol_descriptor_type(value: object) -> int:
    if not isinstance(value, str):
        return _int(value, 2)
    mapping = {"rc4_key": 1, "rc4-key": 1, "rsn_key": 2, "rsn-key": 2, "unknown": 254}
    normalized = value.lower()
    if normalized in mapping:
        return mapping[normalized]
    return _int(value, 2)


def _rsn_element_bytes(fields: Mapping[str, JSONObject]) -> bytes:
    rsn = _layer_fields(fields, "rsn")
    value = _rsn_information_value_bytes(rsn)
    element_id = _int(rsn.get("element_id"), 48) & 0xFF
    length = _int(rsn.get("length"), len(value))
    if length == 0:
        length = len(value)
    return bytes([element_id, length & 0xFF]) + value


def _rsn_information_value_bytes(fields: Mapping[str, object] | None = None) -> bytes:
    fields = {} if fields is None else fields
    output = bytearray()
    output.extend(_int(fields.get("version"), 1).to_bytes(2, "little"))
    output.extend(_rsn_suite_selector(fields.get("group_cipher_suite"), default_type=4))
    pairwise = _suite_list(fields.get("pairwise_cipher_suites"), default_type=4)
    output.extend(len(pairwise).to_bytes(2, "little"))
    for suite in pairwise:
        output.extend(suite)
    akms = _suite_list(fields.get("akm_suites"), default_type=2)
    output.extend(len(akms).to_bytes(2, "little"))
    for suite in akms:
        output.extend(suite)
    if "capabilities" in fields or "group_management_cipher_suite" in fields:
        output.extend(_int(fields.get("capabilities"), 0).to_bytes(2, "little"))
    pmkids = _bytes_optional(fields.get("pmkid_list"))
    if pmkids:
        if len(pmkids) % 16 != 0:
            raise ValueError("rsn pmkid_list length must be a multiple of 16")
        output.extend((len(pmkids) // 16).to_bytes(2, "little"))
        output.extend(pmkids)
    elif "group_management_cipher_suite" in fields:
        output.extend((0).to_bytes(2, "little"))
    if "group_management_cipher_suite" in fields:
        output.extend(_rsn_suite_selector(fields.get("group_management_cipher_suite"), default_type=6))
    output.extend(_bytes_optional(fields.get("trailing_bytes")))
    return bytes(output)


def _suite_list(value: object, *, default_type: int) -> list[bytes]:
    if value is None:
        return [_rsn_suite_selector(None, default_type=default_type)]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_rsn_suite_selector(item, default_type=default_type) for item in value]
    return [_rsn_suite_selector(value, default_type=default_type)]


def _rsn_suite_selector(value: object, *, default_type: int) -> bytes:
    if value is None:
        suite_type = default_type
    elif isinstance(value, Mapping) or isinstance(value, bytes):
        raw = _bytes_optional(value)
        if len(raw) != 4:
            raise ValueError("rsn suite selector must be exactly 4 bytes")
        return raw
    elif isinstance(value, int):
        suite_type = value
    elif isinstance(value, str):
        normalized = value.lower().replace("-", "_")
        suite_type = {
            "use_group": 0,
            "tkip": 2,
            "ccmp_128": 4,
            "aes_128_cmac": 6,
            "bip_cmac_128": 6,
            "psk": 2,
            "ieee8021x": 1,
            "sae": 8,
        }.get(normalized)
        if suite_type is None:
            return _bytes_optional(value)
    else:
        suite_type = default_type
    return b"\x00\x0f\xac" + bytes([suite_type & 0xFF])


def _bytes_exact(value: object, length: int) -> bytes:
    raw = _bytes_optional(value)
    if len(raw) > length:
        return raw[:length]
    return raw.ljust(length, b"\x00")


def _bytes_optional(value: object) -> bytes:
    if value is None:
        return b""
    return _bytes_field(value)


def _mac_bytes(value: object, default: str) -> bytes:
    return _bytes_exact(value if value is not None else default, 6)


def _oui_bytes(value: object) -> bytes:
    return _bytes_exact(value if value is not None else {"hex": "000000"}, 3)


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
    names = {
        "mf": 0b001,
        "more-fragments": 0b001,
        "df": 0b010,
        "dont-fragment": 0b010,
        "reserved": 0b100,
    }
    if isinstance(value, str):
        lowered = value.lower().replace("_", "-")
        if lowered in {"none", "0"}:
            return 0
        if lowered == "df-mf":
            return names["df"] | names["mf"]
        if lowered == "all":
            return names["reserved"] | names["df"] | names["mf"]
        if lowered in names:
            return names[lowered]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        flags = 0
        for item in value:
            flags |= _int(_ipv4_flags(item), 0)
        return flags
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
