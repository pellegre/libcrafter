"""Scapy raw packet materialization for oracle packet plans."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ...model import EncodedVector, JSONObject, PacketPlan
from ..registry import BackendCapabilities, BackendRegistration, get_backend
from . import dns_raw
from .bootstrap import import_scapy
from .encode_helpers import (
    _ETHERTYPES,
    _IP_PROTOCOLS,
    _IPV6_NEXT_HEADERS,
    _bool_int,
    _bytes_field,
    _ethertype_value,
    _hardware_type_value,
    _int,
    _ipv4_flags,
    _layer_fields,
    _option_bytes,
    _optional_field,
    _payload_bytes,
    _protocol_value,
    _required_field,
    _text,
    _validate_payload_length,
)
# Importing the protocols package runs its ``autodiscover`` so every per-protocol
# Scapy encoder/decoder module self-registers. ``STACK_ENCODER_REGISTRY`` is
# consulted before the legacy whole-stack branches and ``SCAPY_REGISTRY`` before the
# per-layer ``_build_layer`` if/elif. No protocol is migrated yet, so both registries
# are empty and every stack/layer falls through to the legacy code.
from .protocols import SCAPY_REGISTRY, STACK_ENCODER_REGISTRY

# The IPv6 extension-header builders live in the co-located ipv6 plugin module
# (``protocols/ipv6.py``) but, unlike the base ``ipv6`` layer, are not registered in
# ``SCAPY_REGISTRY`` because the ext-header names are sub-layers of the ``ipv6`` spec
# rather than top-level spec layers. They are re-imported here so the legacy per-layer
# ``_build_layer`` dispatch keeps routing ``ipv6_hop_by_hop`` /
# ``ipv6_destination_options`` / ``ipv6_fragment`` / ``ipv6_routing`` to them unchanged.
from .protocols.ipv6 import (
    _ipv6_destination_options,
    _ipv6_fragment,
    _ipv6_hop_by_hop,
    _ipv6_routing,
)


BACKEND_NAME = "scapy"

_BGP_MESSAGE_TYPES: dict[str, int] = {
    "open": 1,
    "update": 2,
    "notification": 3,
    "keepalive": 4,
    "route-refresh": 5,
    "route_refresh": 5,
}
_SCAPY_LAYER_BY_LAYER: dict[str, str] = {
    "ah": "AH",
    "ble_adv": "BTLE_ADV_IND",
    "ble_radio": "BTLE_PHDR",
    "bgp": "BGPHeader",
    "dhcp": "DHCP",
    "dns": "DNS",
    "dot11": "Dot11",
    "dot15d4": "Dot15d4",
    # Scapy has no native IEEE 802.15.4 TAP (DLT 283) pseudo-header dissector;
    # libcrafter's Dot15d4Radio carries it, so the radio descriptor is
    # materialized/normalized outside Scapy's native layer set (Raw passthrough)
    # the same way the BLE LL-with-PHDR pseudo-header is handled.
    "dot15d4_radio": "Raw",
    "eapol": "EAPOL",
    "esp": "ESP",
    "icmp": "ICMP",
    # IGMP contrib classes are not exposed through scapy.all consistently
    # across supported Scapy versions. The oracle materializer emits exact
    # IGMP bytes through Raw while preserving IPv4 protocol number 2.
    "igmp": "Raw",
    "igmp_extension": "Raw",
    "igmp_query": "Raw",
    "igmp_report": "Raw",
    "ikev2": "ISAKMP",
    "icmpv6": "ICMPv6EchoRequest",
    "ipv6_destination_options": "IPv6ExtHdrDestOpt",
    "ipv6_fragment": "IPv6ExtHdrFragment",
    "ipv6_hop_by_hop": "IPv6ExtHdrHopByHop",
    "ipv6_routing": "IPv6ExtHdrRouting",
    "ospf": "OSPF_Hdr",
    "radiotap": "RadioTap",
    "raw": "Raw",
    "rip": "RIP",
    # Scapy has no native RIPng dissector, so a RIPng plan is materialized as
    # manually-built header + RTE octets wrapped in a Scapy ``Raw`` layer; the
    # parser (wireshark/tshark) backend supplies the cross-validation decode.
    "ripng": "Raw",
    "rsn": "Dot11EltRSN",
}
_SCAPY_DECODER_BY_ROOT: dict[str, str] = {
    "link:bluetooth-le-ll-with-phdr": "BTLE_PHDR",
    "link:bluetooth_le_ll_with_phdr": "BTLE_PHDR",
    "link:ethernet": "Ether",
    "link:dot11": "Dot11",
    "link:ieee80211": "Dot11",
    "link:ieee802154": "Dot15d4FCS",
    # The TAP pseudo-header has no native Scapy dissector; the link-type bytes
    # are normalized as raw bytes (libcrafter owns the TAP descriptor decode).
    "link:ieee802154-tap": "Raw",
    "link:ieee802154_tap": "Raw",
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
    "link:bluetooth-le-ll-with-phdr": {"ble_radio"},
    "link:bluetooth_le_ll_with_phdr": {"ble_radio"},
    "link:dot11": {"dot11"},
    "link:ethernet": {"ethernet"},
    "link:ieee80211": {"dot11"},
    "link:ieee802154": {"dot15d4"},
    "link:ieee802154-tap": {"dot15d4_radio"},
    "link:ieee802154_tap": {"dot15d4_radio"},
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


def _is_materialized_layer(layer: str) -> bool:
    """Report whether ``layer`` can be encoded by the Scapy backend.

    A migrated layer is materialized when it has a registered
    :class:`~.protocols.base.ScapyProtocol`; an unmigrated layer stays in the
    legacy ``_SCAPY_MATERIALIZED_LAYERS`` set. Checking the registry first lets the
    two coexist during the migration.
    """

    return layer in _SCAPY_MATERIALIZED_LAYERS or SCAPY_REGISTRY.get(layer) is not None


def _scapy_supported_fields(layer: str) -> frozenset[str] | set[str] | None:
    """Return the encode-side field allowlist for ``layer``.

    A migrated layer declares it on its registered ``ScapyProtocol``; an
    unmigrated layer keeps it in the legacy ``_SUPPORTED_FIELDS_BY_LAYER`` table.
    """

    plugin = SCAPY_REGISTRY.get(layer)
    if plugin is not None:
        return plugin.supported_fields
    return _SUPPORTED_FIELDS_BY_LAYER.get(layer)
_SUPPORTED_FEATURES = {
    "ah_integrity",
    "bgp_communities",
    "bgp_keepalive",
    "bgp_mp_reach",
    "bgp_notification",
    "bgp_open",
    "bgp_route_refresh",
    "bgp_update",
    "ble_advertising",
    "ble-adv-pdu",
    "ble-pcap-link-types",
    "ble-radio-phdr",
    "dhcp_behavior",
    "dns_behavior",
    "dot11_basic",
    "dot11_data_llc",
    "dot11_pcap_link_types",
    "dot15d4-mac",
    "dot15d4-pcap-link-types",
    "dot15d4_mac",
    "dot15d4_pcap_link_types",
    "eapol_basic",
    "esp_aead",
    "esp_cbc",
    "icmpv4_errors",
    "icmpv4_live",
    "icmpv6_errors",
    "igmp_extensions",
    "igmp_header",
    "igmp_mrd",
    "igmp_v3_query",
    "igmp_v3_report",
    "ikev2_header",
    "ikev2_payloads",
    "ip_fragment_transforms",
    "ipv4_options",
    "ipv6_fragment_routing",
    "pcap_contracts",
    "pcap_link_types",
    "radiotap_basic",
    "rip_auth",
    "rip_entries",
    "rip_header",
    "ripng_rtes",
    "rsn_foundations",
    "tcp_header",
    "tcp_options",
    "udp_options",
    "zigbee-nwk-aps",
    "zigbee_nwk_aps",
}
_SUPPORTED_FIELDS_BY_LAYER: dict[str, set[str]] = {
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
    "ble_adv": {
        "ad",
        "ad_list",
        "adv_a",
        "adva",
        "channel_selection",
        "chsel",
        "length",
        "pdu_type",
        "rfu",
        "rx_add",
        "rxaddr",
        "tx_add",
        "txaddr",
    },
    "ble_radio": {
        "access_address",
        "access_address_offenses",
        "channel",
        "crc_init",
        "flags",
        "noise_power",
        "ref_access_address",
        "reference_access_address",
        "rf_channel",
        "signal_power",
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
    "dot15d4": {
        "ack_request",
        "dest_addr",
        "dest_addr_mode",
        "dest_extended",
        "dest_pan",
        "dest_short",
        "fcs",
        "frame_pending",
        "frame_type",
        "frame_version",
        "pan_id_compression",
        "payload",
        "payload_hex",
        "security_enabled",
        "seq",
        "sequence_number",
        "src_addr",
        "src_addr_mode",
        "src_extended",
        "src_pan",
        "src_short",
    },
    "dot15d4_radio": {
        "channel",
        "fcs_type",
        "fcs_valid",
        "lqi",
        "rssi",
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
    "igmp": {
        "checksum",
        "chksum",
        "code",
        "extensions",
        "extension_tlvs",
        "group",
        "group_address",
        "group_records",
        "gaddr",
        "max_response_code",
        "max_response_time_tenths",
        "mrd_advertisement_interval",
        "mrd_query_interval",
        "mrd_reserved",
        "mrd_robustness_variable",
        "number_of_group_records",
        "number_of_records",
        "number_of_sources",
        "payload",
        "qqic",
        "query_flags",
        "raw",
        "raw_body",
        "raw_flags_qrv",
        "raw_tail",
        "report_flags",
        "reserved_flags",
        "source_addresses",
        "tail",
        "type",
        "type_code",
        "v2_max_response_time_tenths",
    },
    "igmp_extension": {
        "extension_length",
        "extension_type",
        "extension_value",
        "length",
        "type",
        "value",
        "value_hex",
    },
    "igmp_query": {
        "flags_qrv",
        "number_of_sources",
        "qqic",
        "query_flags",
        "raw_flags_qrv",
        "source_addresses",
    },
    "igmp_report": {
        "group_records",
        "number_of_group_records",
        "number_of_records",
        "records",
        "report_flags",
        "reserved_flags",
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
    "ospf": {
        # Oracle-neutral OSPFv2 common-header fields from specs/layers/ospf.yaml.
        "version",
        "type",
        "packet_length",
        "length",
        "len",
        "router_id",
        "area_id",
        "checksum",
        "autype",
        "authentication",
        # Per-type OSPFv2 body fields (Hello / DD / LSR / LSU / LSAck). The
        # reference layer types these; unknown packet types or an explicit raw
        # body fall back to opaque OSPF bytes.
        "network_mask",
        "hello_interval",
        "options",
        "router_priority",
        "router_dead_interval",
        "designated_router",
        "backup_designated_router",
        "neighbors",
        "interface_mtu",
        "dd_flags",
        "dd_sequence_number",
        "lsa_headers",
        "requests",
        "lsas",
        "num_lsas",
        "body",
        "body_hex",
        "raw",
        "raw_body",
    },
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

    # Consult the whole-stack encoder plugins before any legacy special case. The
    # registry is empty until a raw-bytes family is migrated, so this resolves to
    # ``None`` and the legacy branches below run unchanged.
    stack_encoder = next(
        (encoder for encoder in STACK_ENCODER_REGISTRY if encoder.matches(stack)),
        None,
    )

    wifi_materialization = _is_dot11_phase15_stack(stack)
    ble_materialization = _is_ble_stack(stack)
    needs_scapy = stack_encoder is not None or (
        not wifi_materialization and not ble_materialization
    )
    scapy_all = None
    scapy_version = "not-required"
    raw = None
    if needs_scapy:
        scapy = import_scapy()
        scapy_all = scapy["all"]
        scapy_version = _string(scapy["version"], "unknown")
        raw = scapy_all.raw

    ipsec_sa_metadata = None
    ble_metadata = None
    if stack_encoder is not None:
        raw_bytes = stack_encoder.encode(plan, scapy_all)
        raw_bytes, udp_options_metadata = _materialize_udp_options(plan, root, raw_bytes)
    elif wifi_materialization:
        raw_bytes = _dot11_phase15_bytes(plan, stack, scapy_all)
        udp_options_metadata = None
    elif ble_materialization:
        raw_bytes, ble_metadata = _ble_bytes(plan, stack)
        udp_options_metadata = None
        scapy_version = _string(ble_metadata.get("scapy_version"), scapy_version)
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
    if ble_metadata is not None:
        metadata["ble_materialization"] = ble_metadata
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

    # Consult the per-layer Scapy encoder plugins before the legacy if/elif. The
    # registry is empty until a protocol is migrated, so this resolves to ``None``
    # and the legacy branches below build the layer unchanged.
    plugin = SCAPY_REGISTRY.get(layer)
    if plugin is not None:
        return plugin.build(plan, fields, stack, index, scapy_all)

    if layer == "raw":
        return scapy_all.Raw(load=_payload_bytes(fields))
    if layer == "bgp":
        return _bgp(fields, stack, index, scapy_all)
    if layer == "ospf":
        return _ospf(fields, stack, index, scapy_all)
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
    if layer == "igmp":
        return _igmp(fields, stack, index, scapy_all)
    if layer == "igmp_query":
        return scapy_all.Raw(load=_igmp_query_bytes(fields))
    if layer == "igmp_report":
        return scapy_all.Raw(load=_igmp_report_bytes(fields))
    if layer == "igmp_extension":
        return scapy_all.Raw(load=_igmp_extension_layer_bytes(_layer_fields_for_stack_index(fields, stack, index)))
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
    if layer == "dot15d4_radio":
        return _dot15d4_radio(fields, scapy_all)
    if layer == "dot15d4":
        return _dot15d4(fields, stack, index, scapy_all)
    if layer == "zigbee_nwk":
        return _zigbee_nwk(fields, stack, index, scapy_all)
    if layer == "zigbee_aps":
        return _zigbee_aps(fields, stack, index, scapy_all)

    raise ValueError(f"unsupported Scapy materialization layer: {layer}")


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


# Oracle-neutral OSPFv2 packet-type domain names (specs/layers/ospf.yaml) mapped
# to the RFC 2328 type codes the OSPF_Hdr type field carries.
_OSPF_PACKET_TYPES: dict[str, int] = {
    "hello": 1,
    "database_description": 2,
    "database-description": 2,
    "link_state_request": 3,
    "link-state-request": 3,
    "link_state_update": 4,
    "link-state-update": 4,
    "link_state_ack": 5,
    "link-state-ack": 5,
}
# Oracle-neutral OSPF AuType domain names mapped to the AuType codes.
_OSPF_AUTYPES: dict[str, int] = {
    "null": 0,
    "simple": 1,
    "simple_password": 1,
    "cryptographic": 2,
}


def _ospf(
    fields: Mapping[str, JSONObject],
    stack: Sequence[str],
    index: int,
    scapy_all: Any,
) -> Any:
    """Materialize an OSPFv2 packet for the ``[ipv4, ospf, payload]`` stack.

    The oracle-neutral common-header field names from ``specs/layers/ospf.yaml``
    map to the ``scapy.contrib.ospf`` ``OSPF_Hdr`` fields (version/type/len/src/
    area/chksum/authtype/authdata); the per-type body fields map to the matching
    ``OSPF_Hello``/``OSPF_DBDesc``/``OSPF_LSReq``/``OSPF_LSUpd``/``OSPF_LSAck``
    bodies. Unknown packet types or an explicit raw ``body`` fall back to opaque
    OSPF bytes after the common header so they round-trip without Scapy
    re-interpreting them.
    """

    scapy_ospf = import_scapy()["ospf"]
    ospf_fields = _layer_fields_for_stack_index(fields, stack, index)
    packet_type = _ospf_packet_type(_required_field(ospf_fields, "ospf", "type"))
    header_kwargs = _ospf_header_kwargs(ospf_fields, packet_type)
    header = scapy_ospf.OSPF_Hdr(type=packet_type, **header_kwargs)

    body = _ospf_raw_body(ospf_fields)
    if body is not None:
        return header / scapy_all.Raw(load=body)

    if packet_type == 1:
        return header / _ospf_hello(ospf_fields, scapy_ospf)
    if packet_type == 2:
        return header / _ospf_database_description(ospf_fields, scapy_ospf)
    if packet_type == 3:
        return header / _ospf_link_state_request(ospf_fields, scapy_ospf)
    if packet_type == 4:
        return header / _ospf_link_state_update(ospf_fields, scapy_ospf)
    if packet_type == 5:
        return header / _ospf_link_state_ack(ospf_fields, scapy_ospf)
    return header


def _ospf_header_kwargs(fields: Mapping[str, object], packet_type: int) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "version": _int(_optional_field(fields, "version"), 2),
    }
    router_id = _optional_field(fields, "router_id")
    if router_id is not None:
        kwargs["src"] = _text(router_id, "0.0.0.0")
    area_id = _optional_field(fields, "area_id")
    if area_id is not None:
        kwargs["area"] = _text(area_id, "0.0.0.0")
    if _optional_field(fields, "packet_length", "length", "len") is not None:
        kwargs["len"] = _int(_optional_field(fields, "packet_length", "length", "len"), 0)
    if _optional_field(fields, "checksum") is not None:
        kwargs["chksum"] = _int(_optional_field(fields, "checksum"), 0)
    if _optional_field(fields, "autype") is not None:
        kwargs["authtype"] = _ospf_autype(_optional_field(fields, "autype"))
    authentication = _optional_field(fields, "authentication")
    if authentication is not None:
        kwargs["authdata"] = int.from_bytes(_bytes_field(authentication, pad_to=8)[:8], "big")
    return kwargs


def _ospf_packet_type(value: object) -> int:
    if isinstance(value, str):
        normalized = value.lower().replace("-", "_")
        if normalized in _OSPF_PACKET_TYPES:
            return _OSPF_PACKET_TYPES[normalized]
        return int(normalized, 0)
    return _int(value, 0)


def _ospf_autype(value: object) -> int:
    if isinstance(value, str):
        normalized = value.lower().replace("-", "_")
        if normalized in _OSPF_AUTYPES:
            return _OSPF_AUTYPES[normalized]
        return int(normalized, 0)
    return _int(value, 0)


def _ospf_raw_body(fields: Mapping[str, object]) -> bytes | None:
    value = _optional_field(fields, "body", "body_hex", "raw_body", "raw")
    if value is None:
        return None
    return _bytes_field(value)


def _ospf_neighbors(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (str, bytes, bytearray)):
        return [_text(value, "0.0.0.0")]
    if isinstance(value, Sequence):
        return [_text(item, "0.0.0.0") for item in value]
    return []


def _ospf_hello(fields: Mapping[str, object], scapy_ospf: Any) -> Any:
    kwargs: dict[str, Any] = {
        "neighbors": _ospf_neighbors(_optional_field(fields, "neighbors")),
    }
    if _optional_field(fields, "network_mask") is not None:
        kwargs["mask"] = _text(_optional_field(fields, "network_mask"), "0.0.0.0")
    if _optional_field(fields, "hello_interval") is not None:
        kwargs["hellointerval"] = _int(_optional_field(fields, "hello_interval"), 0)
    if _optional_field(fields, "options") is not None:
        kwargs["options"] = _int(_optional_field(fields, "options"), 0)
    if _optional_field(fields, "router_priority") is not None:
        kwargs["prio"] = _int(_optional_field(fields, "router_priority"), 0)
    if _optional_field(fields, "router_dead_interval") is not None:
        kwargs["deadinterval"] = _int(_optional_field(fields, "router_dead_interval"), 0)
    if _optional_field(fields, "designated_router") is not None:
        kwargs["router"] = _text(_optional_field(fields, "designated_router"), "0.0.0.0")
    if _optional_field(fields, "backup_designated_router") is not None:
        kwargs["backup"] = _text(_optional_field(fields, "backup_designated_router"), "0.0.0.0")
    return scapy_ospf.OSPF_Hello(**kwargs)


def _ospf_database_description(fields: Mapping[str, object], scapy_ospf: Any) -> Any:
    kwargs: dict[str, Any] = {
        "lsaheaders": _ospf_lsa_headers(_optional_field(fields, "lsa_headers"), scapy_ospf),
    }
    if _optional_field(fields, "interface_mtu") is not None:
        kwargs["mtu"] = _int(_optional_field(fields, "interface_mtu"), 0)
    if _optional_field(fields, "options") is not None:
        kwargs["options"] = _int(_optional_field(fields, "options"), 0)
    if _optional_field(fields, "dd_flags") is not None:
        kwargs["dbdescr"] = _int(_optional_field(fields, "dd_flags"), 0)
    if _optional_field(fields, "dd_sequence_number") is not None:
        kwargs["ddseq"] = _int(_optional_field(fields, "dd_sequence_number"), 0)
    return scapy_ospf.OSPF_DBDesc(**kwargs)


def _ospf_link_state_request(fields: Mapping[str, object], scapy_ospf: Any) -> Any:
    requests = _optional_field(fields, "requests")
    items: list[Any] = []
    if isinstance(requests, Sequence) and not isinstance(requests, (str, bytes, bytearray)):
        for entry in requests:
            if not isinstance(entry, Mapping):
                continue
            items.append(
                scapy_ospf.OSPF_LSReq_Item(
                    type=_int(_optional_field(entry, "ls_type", "type"), 0),
                    id=_text(_optional_field(entry, "link_state_id", "id"), "0.0.0.0"),
                    adrouter=_text(
                        _optional_field(entry, "advertising_router", "adrouter"),
                        "0.0.0.0",
                    ),
                )
            )
    return scapy_ospf.OSPF_LSReq(requests=items)


def _ospf_link_state_update(fields: Mapping[str, object], scapy_ospf: Any) -> Any:
    kwargs: dict[str, Any] = {
        "lsalist": _ospf_lsa_list(_optional_field(fields, "lsas"), scapy_ospf),
    }
    if _optional_field(fields, "num_lsas") is not None:
        kwargs["lsacount"] = _int(_optional_field(fields, "num_lsas"), 0)
    return scapy_ospf.OSPF_LSUpd(**kwargs)


def _ospf_link_state_ack(fields: Mapping[str, object], scapy_ospf: Any) -> Any:
    return scapy_ospf.OSPF_LSAck(
        lsaheaders=_ospf_lsa_headers(_optional_field(fields, "lsa_headers"), scapy_ospf)
    )


def _ospf_lsa_headers(value: object, scapy_ospf: Any) -> list[Any]:
    headers: list[Any] = []
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for entry in value:
            if not isinstance(entry, Mapping):
                continue
            headers.append(_ospf_lsa_header(entry, scapy_ospf))
    return headers


def _ospf_lsa_header(entry: Mapping[str, object], scapy_ospf: Any) -> Any:
    kwargs: dict[str, Any] = {
        "age": _int(_optional_field(entry, "ls_age", "age"), 0),
        "options": _int(_optional_field(entry, "options"), 0),
        "type": _int(_optional_field(entry, "ls_type", "type"), 0),
        "id": _text(_optional_field(entry, "link_state_id", "id"), "0.0.0.0"),
        "adrouter": _text(
            _optional_field(entry, "advertising_router", "adrouter"),
            "0.0.0.0",
        ),
        "seq": _int(_optional_field(entry, "ls_sequence_number", "seq"), 0x80000001),
    }
    if _optional_field(entry, "ls_checksum", "chksum") is not None:
        kwargs["chksum"] = _int(_optional_field(entry, "ls_checksum", "chksum"), 0)
    if _optional_field(entry, "length", "len") is not None:
        kwargs["len"] = _int(_optional_field(entry, "length", "len"), 0)
    return scapy_ospf.OSPF_LSA_Hdr(**kwargs)


def _ospf_lsa_list(value: object, scapy_ospf: Any) -> list[Any]:
    lsas: list[Any] = []
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for entry in value:
            if not isinstance(entry, Mapping):
                continue
            header = _ospf_lsa_header(entry, scapy_ospf)
            body = _optional_field(entry, "body", "body_hex", "raw")
            if body is not None:
                lsas.append(header / import_scapy()["all"].Raw(load=_bytes_field(body)))
            else:
                lsas.append(header)
    return lsas


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


_IGMP_TYPE_CODES: dict[str, int] = {
    "reserved": 0x00,
    "unassigned": 0x09,
    "membership-query": 0x11,
    "membership_query": 0x11,
    "v1-membership-report": 0x12,
    "v1_membership_report": 0x12,
    "dvmrp": 0x13,
    "dvmrp-unsupported-assigned": 0x13,
    "dvmrp_unsupported_assigned": 0x13,
    "pim-v1": 0x14,
    "pim_v1": 0x14,
    "pim-v1-unsupported-assigned": 0x14,
    "pim_v1_unsupported_assigned": 0x14,
    "cisco-trace-unsupported-assigned": 0x15,
    "cisco_trace_unsupported_assigned": 0x15,
    "v2-membership-report": 0x16,
    "v2_membership_report": 0x16,
    "v2-leave-group": 0x17,
    "v2_leave_group": 0x17,
    "multicast-traceroute-response-unsupported-assigned": 0x1E,
    "multicast_traceroute_response_unsupported_assigned": 0x1E,
    "multicast-traceroute-unsupported-assigned": 0x1F,
    "multicast_traceroute_unsupported_assigned": 0x1F,
    "v3-membership-report": 0x22,
    "v3_membership_report": 0x22,
    "multicast-router-advertisement": 0x30,
    "multicast_router_advertisement": 0x30,
    "multicast-router-solicitation": 0x31,
    "multicast_router_solicitation": 0x31,
    "multicast-router-termination": 0x32,
    "multicast_router_termination": 0x32,
    "experimental": 0xF0,
}
_IGMP_RECORD_TYPES: dict[str, int] = {
    "reserved": 0,
    "mode-is-include": 1,
    "mode_is_include": 1,
    "mode-is-exclude": 2,
    "mode_is_exclude": 2,
    "change-to-include-mode": 3,
    "change_to_include_mode": 3,
    "change-to-exclude-mode": 4,
    "change_to_exclude_mode": 4,
    "allow-new-sources": 5,
    "allow_new_sources": 5,
    "block-old-sources": 6,
    "block_old_sources": 6,
    "unknown": 0xC8,
}
_IGMP_QUERY_FLAG_BITS: dict[str, int] = {
    "zero": 0,
    "none": 0,
    "extension": 0x80,
    "unassigned": 0x70,
    "suppress-router-side-processing": 0x08,
    "suppress_router_side_processing": 0x08,
    "qrv": 0x02,
}
_IGMP_REPORT_FLAG_BITS: dict[str, int] = {
    "zero": 0,
    "none": 0,
    "extension": 0x8000,
    "unassigned": 0x0001,
}
_IGMP_EXTENSION_TYPES: dict[str, int] = {
    "noop": 0,
    "no-op": 0,
    "unassigned": 1,
    "experimental": 0xFFFE,
}
_IGMP_MRD_SHORT_TYPES = frozenset({0x31, 0x32})
_IGMP_BODY_STACK_LAYERS = frozenset(
    {"igmp_query", "igmp_report", "igmp_extension", "payload"}
)


def _igmp(
    fields: Mapping[str, JSONObject],
    stack: list[str],
    index: int,
    scapy_all: Any,
) -> Any:
    igmp_fields = _layer_fields(fields, "igmp")
    body_is_in_following_layers = any(
        layer in _IGMP_BODY_STACK_LAYERS for layer in stack[index + 1 :]
    )
    body = (
        _igmp_following_body_bytes(fields, stack, index)
        if body_is_in_following_layers
        else _igmp_inferred_body_bytes(fields)
    )
    header = _igmp_header_bytes(igmp_fields, body)
    return scapy_all.Raw(load=header if body_is_in_following_layers else header + body)


def _igmp_header_bytes(igmp_fields: Mapping[str, object], body: bytes) -> bytes:
    type_code = _igmp_type(
        _optional_field(igmp_fields, "type", "type_code"),
        default=0x11,
    )
    code = _igmp_code(igmp_fields, type_code)
    header = bytearray([type_code & 0xFF, code & 0xFF, 0, 0])
    if _igmp_base_header_len(igmp_fields, type_code) == 8:
        header.extend(_igmp_group_address_bytes(igmp_fields, type_code))

    checksum = _igmp_checksum(igmp_fields)
    if checksum is None:
        checksum = _internet_checksum(bytes(header) + body)
    header[2:4] = (checksum & 0xFFFF).to_bytes(2, "big")
    return bytes(header)


def _igmp_base_header_len(igmp_fields: Mapping[str, object], type_code: int) -> int:
    if type_code not in _IGMP_MRD_SHORT_TYPES:
        return 8
    if any(name in igmp_fields for name in ("group_address", "group", "gaddr")):
        return 8
    if any(name in igmp_fields for name in ("mrd_query_interval", "mrd_robustness_variable")):
        return 8
    return 4


def _igmp_inferred_body_bytes(fields: Mapping[str, JSONObject]) -> bytes:
    igmp_fields = _layer_fields(fields, "igmp")
    type_code = _igmp_type(_optional_field(igmp_fields, "type", "type_code"), default=0x11)

    raw_body = _optional_field(igmp_fields, "raw_body", "raw")
    if raw_body is not None:
        return _bytes_field(raw_body)

    body = b""
    if _igmp_has_query_body(fields, igmp_fields, type_code):
        body += _igmp_query_bytes(fields)
    elif _igmp_has_report_body(fields, igmp_fields, type_code):
        body += _igmp_report_bytes(fields)

    body += _igmp_extensions_bytes(fields)
    body += _igmp_raw_tail_bytes(igmp_fields)
    return body


def _igmp_following_body_bytes(
    fields: Mapping[str, JSONObject],
    stack: Sequence[str],
    index: int,
) -> bytes:
    body = b""
    for child_index in range(index + 1, len(stack)):
        layer = stack[child_index]
        if layer == "igmp_query":
            body += _igmp_query_bytes(fields)
        elif layer == "igmp_report":
            body += _igmp_report_bytes(fields)
        elif layer == "igmp_extension":
            body += _igmp_extension_layer_bytes(
                _layer_fields_for_stack_index(fields, stack, child_index)
            )
        elif layer == "payload":
            body += _payload_bytes(fields)
    return body


def _igmp_has_query_body(
    fields: Mapping[str, JSONObject],
    igmp_fields: Mapping[str, object],
    type_code: int,
) -> bool:
    if type_code != 0x11:
        return False
    if _layer_fields(fields, "igmp_query"):
        return True
    return any(
        name in igmp_fields
        for name in (
            "flags_qrv",
            "number_of_sources",
            "qqic",
            "query_flags",
            "raw_flags_qrv",
            "source_addresses",
        )
    )


def _igmp_has_report_body(
    fields: Mapping[str, JSONObject],
    igmp_fields: Mapping[str, object],
    type_code: int,
) -> bool:
    if type_code == 0x22:
        return True
    if _layer_fields(fields, "igmp_report"):
        return True
    return any(
        name in igmp_fields
        for name in (
            "group_records",
            "number_of_group_records",
            "number_of_records",
            "report_flags",
            "reserved_flags",
        )
    )


def _igmp_query_bytes(fields: Mapping[str, JSONObject]) -> bytes:
    igmp_fields = _layer_fields(fields, "igmp")
    query_fields = {**igmp_fields, **_layer_fields(fields, "igmp_query")}
    sources = _igmp_ipv4_list(_optional_field(query_fields, "source_addresses"))
    count = _int(
        _optional_field(query_fields, "number_of_sources"),
        len(sources),
    )
    return (
        bytes(
            [
                _igmp_query_flags(query_fields) & 0xFF,
                _int(_optional_field(query_fields, "qqic"), 0) & 0xFF,
            ]
        )
        + (count & 0xFFFF).to_bytes(2, "big")
        + b"".join(_ipv4_address_bytes(source) for source in sources)
    )


def _igmp_report_bytes(fields: Mapping[str, JSONObject]) -> bytes:
    igmp_fields = _layer_fields(fields, "igmp")
    report_fields = {**igmp_fields, **_layer_fields(fields, "igmp_report")}
    records = _igmp_group_records(report_fields)
    count = _int(
        _optional_field(report_fields, "number_of_group_records", "number_of_records"),
        len(records),
    )
    body = bytearray()
    body.extend((_igmp_report_flags(report_fields) & 0xFFFF).to_bytes(2, "big"))
    body.extend((count & 0xFFFF).to_bytes(2, "big"))
    for record in records:
        body.extend(_igmp_group_record_bytes(record))
    return bytes(body)


def _igmp_group_records(report_fields: Mapping[str, object]) -> list[Mapping[str, object]]:
    value = _optional_field(report_fields, "group_records", "records")
    if value is None:
        return []
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError("IGMP group_records materialization requires a record list")
    records: list[Mapping[str, object]] = []
    for record in value:
        if not isinstance(record, Mapping):
            raise ValueError(f"IGMP group record must be an object, got {record!r}")
        records.append(record)
    return records


def _igmp_group_record_bytes(record: Mapping[str, object]) -> bytes:
    sources = _igmp_ipv4_list(
        _optional_field(record, "source_addresses", "record_source_addresses")
    )
    auxiliary = _igmp_bytes_value(_optional_field(record, "auxiliary_data"))
    aux_len = _int(
        _optional_field(record, "auxiliary_data_len", "aux_data_len"),
        (len(auxiliary) + 3) // 4,
    )
    wire_aux_len = aux_len * 4
    if wire_aux_len > len(auxiliary) and _optional_field(record, "auxiliary_data_len", "aux_data_len") is not None:
        raise ValueError(
            "IGMP group record auxiliary_data_len exceeds supplied auxiliary_data bytes"
        )
    auxiliary = (auxiliary + b"\x00" * wire_aux_len)[:wire_aux_len]
    count = _int(
        _optional_field(record, "number_of_sources", "record_number_of_sources"),
        len(sources),
    )
    raw = bytearray(
        [
            _igmp_record_type(_optional_field(record, "record_type", "type")) & 0xFF,
            aux_len & 0xFF,
        ]
    )
    raw.extend((count & 0xFFFF).to_bytes(2, "big"))
    raw.extend(
        _ipv4_address_bytes(
            _optional_field(record, "multicast_address", "group_address", "group"),
            "0.0.0.0",
        )
    )
    for source in sources:
        raw.extend(_ipv4_address_bytes(source))
    raw.extend(auxiliary)
    return bytes(raw)


def _igmp_extensions_bytes(fields: Mapping[str, JSONObject]) -> bytes:
    igmp_fields = _layer_fields(fields, "igmp")
    value = _optional_field(igmp_fields, "extension_tlvs", "extensions")
    if value is not None:
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
            raise ValueError("IGMP extension_tlvs materialization requires a TLV list")
        raw = b""
        for item in value:
            if not isinstance(item, Mapping):
                raise ValueError(f"IGMP extension TLV must be an object, got {item!r}")
            raw += _igmp_extension_layer_bytes(item)
        return raw

    extension_fields = _layer_fields(fields, "igmp_extension")
    if extension_fields:
        return _igmp_extension_layer_bytes(extension_fields)
    return b""


def _igmp_extension_layer_bytes(fields: Mapping[str, object]) -> bytes:
    value = _igmp_bytes_value(_optional_field(fields, "extension_value", "value", "value_hex"))
    length = _int(_optional_field(fields, "extension_length", "length"), len(value))
    if length > len(value):
        raise ValueError("IGMP extension_length exceeds supplied extension_value bytes")
    return (
        (_igmp_extension_type(_optional_field(fields, "extension_type", "type")) & 0xFFFF).to_bytes(2, "big")
        + (length & 0xFFFF).to_bytes(2, "big")
        + value[:length]
    )


def _igmp_group_address_bytes(igmp_fields: Mapping[str, object], type_code: int) -> bytes:
    group_address = _optional_field(igmp_fields, "group_address", "group", "gaddr")
    if group_address is not None:
        return _ipv4_address_bytes(group_address, "0.0.0.0")
    if type_code == 0x30:
        query_interval = _int(_optional_field(igmp_fields, "mrd_query_interval"), 0)
        robustness = _int(_optional_field(igmp_fields, "mrd_robustness_variable"), 0)
        return (query_interval & 0xFFFF).to_bytes(2, "big") + (
            robustness & 0xFFFF
        ).to_bytes(2, "big")
    return b"\x00\x00\x00\x00"


def _igmp_code(igmp_fields: Mapping[str, object], type_code: int) -> int:
    value = _optional_field(
        igmp_fields,
        "code",
        "max_response_code",
        "max_response_time_tenths",
        "v2_max_response_time_tenths",
        "mrd_advertisement_interval",
        "mrd_reserved",
    )
    if value is None:
        return 0
    if isinstance(value, str):
        normalized = value.lower().replace(" ", "_").replace("-", "_")
        mapping = {
            "v1_query_zero": 0,
            "zero": 0,
            "reserved_zero": 0,
            "mrd_reserved": 0,
            "v2_max_response_time": 100,
            "v3_max_response_code": 100,
            "mrd_advertisement_interval": 20,
        }
        if normalized in mapping:
            return mapping[normalized]
        return int(normalized, 0)
    return _int(value, 0)


def _igmp_checksum(igmp_fields: Mapping[str, object]) -> int | None:
    value = _optional_field(igmp_fields, "checksum", "chksum")
    if value is None:
        return None
    if isinstance(value, str):
        normalized = value.lower().replace("-", "_")
        if normalized in {"derived", "auto"}:
            return None
        if normalized in {"explicit", "explicit_invalid"}:
            return 0x1234
        if normalized == "boundary":
            return 0xFFFF
        return int(normalized, 0)
    return _int(value, 0)


def _igmp_type(value: object, *, default: int = 0x11) -> int:
    if value is None:
        return default
    if isinstance(value, str):
        normalized = value.lower().replace(" ", "-")
        if normalized in _IGMP_TYPE_CODES:
            return _IGMP_TYPE_CODES[normalized]
        normalized = normalized.replace("-", "_")
        if normalized in _IGMP_TYPE_CODES:
            return _IGMP_TYPE_CODES[normalized]
        return int(normalized, 0)
    return _int(value, default)


def _igmp_record_type(value: object) -> int:
    if value is None:
        return 1
    if isinstance(value, str):
        normalized = value.lower().replace(" ", "-")
        if normalized in _IGMP_RECORD_TYPES:
            return _IGMP_RECORD_TYPES[normalized]
        normalized = normalized.replace("-", "_")
        if normalized in _IGMP_RECORD_TYPES:
            return _IGMP_RECORD_TYPES[normalized]
        return int(normalized, 0)
    return _int(value, 1)


def _igmp_extension_type(value: object) -> int:
    if value is None:
        return 0
    if isinstance(value, str):
        normalized = value.lower().replace(" ", "-")
        if normalized in _IGMP_EXTENSION_TYPES:
            return _IGMP_EXTENSION_TYPES[normalized]
        normalized = normalized.replace("-", "_")
        if normalized in _IGMP_EXTENSION_TYPES:
            return _IGMP_EXTENSION_TYPES[normalized]
        return int(normalized, 0)
    return _int(value, 0)


def _igmp_query_flags(fields: Mapping[str, object]) -> int:
    raw = _optional_field(fields, "raw_flags_qrv", "flags_qrv")
    if raw is not None:
        return _int(raw, 0)
    flags = _igmp_flags_value(_optional_field(fields, "query_flags"), _IGMP_QUERY_FLAG_BITS)
    suppress = _optional_field(fields, "suppress_router_side_processing", "s")
    if suppress is not None:
        if _bool_int(suppress, 0):
            flags |= 0x08
        else:
            flags &= ~0x08
    qrv = _optional_field(fields, "qrv", "querier_robustness_variable")
    if qrv is not None:
        flags = (flags & ~0x07) | (_int(qrv, 0) & 0x07)
    return flags


def _igmp_report_flags(fields: Mapping[str, object]) -> int:
    raw = _optional_field(fields, "reserved_flags")
    if raw is not None:
        return _int(raw, 0)
    return _igmp_flags_value(_optional_field(fields, "report_flags"), _IGMP_REPORT_FLAG_BITS)


def _igmp_flags_value(value: object, mapping: Mapping[str, int]) -> int:
    if value is None:
        return 0
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    items = value if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)) else [value]
    flags = 0
    for item in items:
        if isinstance(item, int) and not isinstance(item, bool):
            flags |= item
            continue
        if isinstance(item, str):
            normalized = item.lower().replace(" ", "_").replace("-", "_")
            flags |= mapping.get(normalized, int(normalized, 0) if normalized.startswith("0") else 0)
    return flags


def _igmp_ipv4_list(value: object) -> list[object]:
    if value is None:
        return []
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError("IGMP IPv4 address list requires a list")
    addresses: list[object] = []
    for item in value:
        if isinstance(item, Mapping):
            addresses.append(_optional_field(item, "address", "ip", "value"))
        else:
            addresses.append(item)
    return addresses


def _igmp_raw_tail_bytes(igmp_fields: Mapping[str, object]) -> bytes:
    value = _optional_field(igmp_fields, "raw_tail", "tail", "payload")
    if value is None:
        return b""
    return _igmp_bytes_value(value)


def _igmp_bytes_value(value: object) -> bytes:
    if value is None:
        return b""
    return _bytes_field(value)


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


# --------------------------------------------------------------------------
# IEEE 802.15.4 / Zigbee materialization.
#
# Scapy 2.7 ships native Dot15d4 / Dot15d4FCS / Dot15d4Data MAC layers and
# native ZigbeeNWK / ZigbeeAppDataPayload layers (scapy.layers.dot15d4 /
# scapy.layers.zigbee, imported by bootstrap.import_scapy). The materializer
# maps the libcrafter-neutral plan fields onto the scapy constructors so the
# emitted bytes match libcrafter's wire encoding (the spec ``expected`` bytes
# were derived from the crate). The trailing CRC-16/CCITT FCS is produced by
# scapy's Dot15d4FCS makeFCS, which matches libcrafter's reflected FCS.
#
# The IEEE 802.15.4 TAP (DLT 283) pseudo-header has no native scapy dissector;
# the radio descriptor is materialized as a Raw passthrough (the same precedent
# as the BLE LL-with-PHDR pseudo-header). libcrafter's Dot15d4Radio owns the TAP
# decode, so when a dot15d4_radio layer carries no strict-byte descriptor fields
# the materializer emits no bytes and lets the following MAC frame stand alone.

# spec frame_type -> scapy fcf_frametype codepoint.
_DOT15D4_FRAME_TYPES: dict[str, int] = {
    "beacon": 0,
    "data": 1,
    "ack": 2,
    "acknowledgement": 2,
    "command": 3,
    "mac_command": 3,
}
# spec addressing mode -> scapy fcf_*addrmode codepoint.
_DOT15D4_ADDR_MODES: dict[str, int] = {
    "none": 0,
    "absent": 0,
    "short_16": 2,
    "short": 2,
    "extended_64": 3,
    "extended": 3,
    "long": 3,
}
# spec zigbee NWK frame_type -> scapy frametype codepoint.
_ZIGBEE_NWK_FRAME_TYPES: dict[str, int] = {
    "data": 0,
    "command": 1,
    "inter_pan": 3,
    "inter-pan": 3,
}
# spec zigbee APS frame_type -> scapy aps_frametype codepoint.
_ZIGBEE_APS_FRAME_TYPES: dict[str, int] = {
    "data": 0,
    "command": 1,
    "ack": 2,
    "acknowledgement": 2,
}
# spec zigbee APS delivery_mode -> scapy delivery_mode codepoint.
_ZIGBEE_APS_DELIVERY_MODES: dict[str, int] = {
    "unicast": 0,
    "indirect": 1,
    "broadcast": 2,
    "group": 3,
    "group_addressing": 3,
}


def _dot15d4_enum(value: object, table: Mapping[str, int], default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        key = value.lower().replace("-", "_")
        if key in table:
            return table[key]
        return int(value, 0)
    raise ValueError(f"unsupported IEEE 802.15.4/Zigbee enum value: {value!r}")


def _has_child_layer(stack: Sequence[str], index: int) -> bool:
    """Return True when a non-payload protocol layer follows ``index``.

    dot15d4/zigbee plans carry the upper protocol as a stacked layer (zigbee_nwk
    inside dot15d4, zigbee_aps inside zigbee_nwk). When such a child exists the
    builder must not append its own ``payload`` field, because the composed
    child layer is the real payload; only the terminal layer materializes its
    declared opaque payload bytes.
    """

    return any(layer != "payload" and layer != "raw" for layer in stack[index + 1 :])


def _layer_opaque_payload(
    fields: Mapping[str, JSONObject],
    stack: Sequence[str],
    index: int,
    layer_fields: Mapping[str, object],
) -> bytes:
    """Resolve the trailing opaque payload bytes for a dot15d4/zigbee layer.

    The bytes come from the layer's own ``payload``/``payload_hex`` field, or
    from a following ``payload`` stack entry, and are only emitted when no
    protocol child layer follows this one in the stack.
    """

    if _has_child_layer(stack, index):
        return b""
    payload_field = _optional_field(layer_fields, "payload", "payload_hex")
    if payload_field is not None:
        return _opaque_bytes(payload_field)
    # Fall back to a following payload/raw stack entry, if present.
    for following in stack[index + 1 :]:
        if following in ("payload", "raw"):
            return _payload_bytes(fields)
    return b""


def _opaque_bytes(value: object) -> bytes:
    if value is None:
        return b""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return bytes.fromhex(value)
    if isinstance(value, Mapping):
        return _bytes_field(value)
    raise ValueError(f"unsupported IEEE 802.15.4/Zigbee payload value: {value!r}")


def _dot15d4_radio(fields: Mapping[str, JSONObject], scapy_all: Any) -> Any:
    """Materialize the IEEE 802.15.4 TAP (DLT 283) pseudo-header.

    Scapy 2.7 has no native Dot15d4 TAP dissector. libcrafter's Dot15d4Radio
    owns the TAP descriptor decode, so the radio layer carries no strict-byte
    descriptor fields here and is emitted as an empty Raw passthrough (the BLE
    LL-with-PHDR precedent); the following MAC frame provides the wire bytes.
    """

    _ = _layer_fields(fields, "dot15d4_radio")
    return scapy_all.Raw(load=b"")


def _dot15d4(
    fields: Mapping[str, JSONObject],
    stack: list[str],
    index: int,
    scapy_all: Any,
) -> Any:
    """Build an IEEE 802.15.4 MAC frame via scapy Dot15d4FCS / Dot15d4Data.

    The Dot15d4FCS header carries the frame-control field, sequence number, and
    the trailing CRC-16/CCITT FCS; Dot15d4Data carries the addressing fields
    when a destination or source addressing mode is present. PAN-ID compression,
    the addressing modes, and the address widths are all encoded by scapy from
    the frame-control codepoints, matching libcrafter's wire layout.
    """

    mac = _layer_fields(fields, "dot15d4")
    frame_type = _dot15d4_enum(
        _optional_field(mac, "frame_type"), _DOT15D4_FRAME_TYPES, 1
    )
    dest_mode = _dot15d4_enum(
        _optional_field(mac, "dest_addr_mode"), _DOT15D4_ADDR_MODES, 0
    )
    src_mode = _dot15d4_enum(
        _optional_field(mac, "src_addr_mode"), _DOT15D4_ADDR_MODES, 0
    )
    # When the plan omits explicit addressing modes but supplies addresses,
    # infer the mode from the address presence so the frame is self-consistent.
    if _optional_field(mac, "dest_addr_mode") is None:
        if _optional_field(mac, "dest_extended") is not None:
            dest_mode = 3
        elif _optional_field(mac, "dest_short", "dest_addr") is not None:
            dest_mode = 2
    if _optional_field(mac, "src_addr_mode") is None:
        if _optional_field(mac, "src_extended") is not None:
            src_mode = 3
        elif _optional_field(mac, "src_short", "src_addr") is not None:
            src_mode = 2

    fcf_kwargs: dict[str, Any] = {
        "fcf_frametype": frame_type,
        "fcf_destaddrmode": dest_mode,
        "fcf_srcaddrmode": src_mode,
        "fcf_panidcompress": _bool_int(_optional_field(mac, "pan_id_compression"), 0),
        "seqnum": _int(_optional_field(mac, "seq", "sequence_number"), 0),
    }
    if _optional_field(mac, "security_enabled") is not None:
        fcf_kwargs["fcf_security"] = _bool_int(mac.get("security_enabled"), 0)
    if _optional_field(mac, "frame_pending") is not None:
        fcf_kwargs["fcf_pending"] = _bool_int(mac.get("frame_pending"), 0)
    if _optional_field(mac, "ack_request") is not None:
        fcf_kwargs["fcf_ackreq"] = _bool_int(mac.get("ack_request"), 0)
    if _optional_field(mac, "frame_version") is not None:
        fcf_kwargs["fcf_framever"] = _int(mac.get("frame_version"), 0)
    if _optional_field(mac, "fcs") is not None:
        fcf_kwargs["fcs"] = _int(mac.get("fcs"), 0)

    packet = scapy_all.Dot15d4FCS(**fcf_kwargs)

    if dest_mode != 0 or src_mode != 0:
        data_kwargs: dict[str, Any] = {}
        if dest_mode != 0:
            data_kwargs["dest_panid"] = _int(_optional_field(mac, "dest_pan"), 0xFFFF)
            data_kwargs["dest_addr"] = _int(
                _optional_field(mac, "dest_extended", "dest_short", "dest_addr"), 0
            )
        if src_mode != 0:
            if _optional_field(mac, "src_pan") is not None:
                data_kwargs["src_panid"] = _int(mac.get("src_pan"), 0xFFFF)
            data_kwargs["src_addr"] = _int(
                _optional_field(mac, "src_extended", "src_short", "src_addr"), 0
            )
        packet = packet / scapy_all.Dot15d4Data(**data_kwargs)

    trailer = _layer_opaque_payload(fields, stack, index, mac)
    if trailer:
        packet = packet / scapy_all.Raw(load=trailer)
    return packet


def _zigbee_nwk(
    fields: Mapping[str, JSONObject],
    stack: list[str],
    index: int,
    scapy_all: Any,
) -> Any:
    """Build a Zigbee NWK header via scapy ZigbeeNWK.

    Maps the libcrafter-neutral frame type, protocol version, 16-bit dest/src
    addresses, radius, and sequence number onto the scapy constructor.
    """

    nwk = _layer_fields(fields, "zigbee_nwk")
    kwargs: dict[str, Any] = {
        "frametype": _dot15d4_enum(
            _optional_field(nwk, "frame_type"), _ZIGBEE_NWK_FRAME_TYPES, 0
        ),
        "proto_version": _int(_optional_field(nwk, "protocol_version"), 2),
        "flags": 0,
        "discover_route": 0,
        "destination": _int(_optional_field(nwk, "dest"), 0),
        "source": _int(_optional_field(nwk, "src"), 0),
        "radius": _int(_optional_field(nwk, "radius"), 0),
        "seqnum": _int(_optional_field(nwk, "seq"), 0),
    }
    packet = scapy_all.ZigbeeNWK(**kwargs)
    trailer = _layer_opaque_payload(fields, stack, index, nwk)
    if trailer:
        packet = packet / scapy_all.Raw(load=trailer)
    return packet


def _zigbee_aps(
    fields: Mapping[str, JSONObject],
    stack: list[str],
    index: int,
    scapy_all: Any,
) -> Any:
    """Build a Zigbee APS header via scapy ZigbeeAppDataPayload.

    Maps the libcrafter-neutral frame type, delivery mode, destination/source
    endpoints, cluster id, profile id, and APS counter onto the scapy
    constructor. dst_endpoint / cluster / profile / src_endpoint are conditional
    scapy fields driven by the frame type and delivery mode; the data frame /
    unicast delivery used by the spec stack carries all four.
    """

    aps = _layer_fields(fields, "zigbee_aps")
    kwargs: dict[str, Any] = {
        "aps_frametype": _dot15d4_enum(
            _optional_field(aps, "frame_type"), _ZIGBEE_APS_FRAME_TYPES, 0
        ),
        "delivery_mode": _dot15d4_enum(
            _optional_field(aps, "delivery_mode"), _ZIGBEE_APS_DELIVERY_MODES, 0
        ),
        "frame_control": 0,
        "counter": _int(_optional_field(aps, "counter"), 0),
    }
    if _optional_field(aps, "dest_endpoint") is not None:
        kwargs["dst_endpoint"] = _int(aps.get("dest_endpoint"), 0)
    if _optional_field(aps, "cluster") is not None:
        kwargs["cluster"] = _int(aps.get("cluster"), 0)
    if _optional_field(aps, "profile") is not None:
        kwargs["profile"] = _int(aps.get("profile"), 0)
    if _optional_field(aps, "src_endpoint") is not None:
        kwargs["src_endpoint"] = _int(aps.get("src_endpoint"), 0)
    packet = scapy_all.ZigbeeAppDataPayload(**kwargs)
    trailer = _layer_opaque_payload(fields, stack, index, aps)
    if trailer:
        packet = packet / scapy_all.Raw(load=trailer)
    return packet


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
        "ble": "ble_adv",
        "ble-adv": "ble_adv",
        "ble-advertising": "ble_adv",
        "ble-radio": "ble_radio",
        "bluetooth-le-adv": "ble_adv",
        "bluetooth-le-radio": "ble_radio",
        "btle-adv": "ble_adv",
        "btle-radio": "ble_radio",
        "dot1q": "vlan",
        "dot15d4-radio": "dot15d4_radio",
        "dot15d4-tap": "dot15d4_radio",
        "ieee802154": "dot15d4",
        "ieee802154-radio": "dot15d4_radio",
        "ieee802154-tap": "dot15d4_radio",
        "ether": "ethernet",
        "zigbee-aps": "zigbee_aps",
        "zigbee-app-data-payload": "zigbee_aps",
        "zigbee-nwk": "zigbee_nwk",
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

    if "igmp" in stack and (
        plan.case.startswith("malformed-igmp-") or plan.metadata.get("malformed") is True
    ):
        raise ValueError(
            "IGMP structured-error cases are not materialized by the Scapy strict-byte path"
        )

    for index, layer in enumerate(stack):
        if not _is_materialized_layer(layer):
            raise ValueError(f"unsupported Scapy materialization layer: {layer}")
        fields = _layer_fields_for_stack_index(plan.fields, stack, index)
        _validate_layer_fields(layer, fields)
        if layer == "payload":
            if not fields:
                raise ValueError("payload materialization requires payload fields")
            _payload_bytes(plan.fields)


def _validate_layer_fields(layer: str, fields: Mapping[str, object]) -> None:
    supported = _scapy_supported_fields(layer)
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


_BLE_LAYERS = frozenset({"ble_radio", "ble_adv"})
_BLE_ADV_PDU_TYPES: dict[str, int] = {
    "adv_ind": 0,
    "adv_direct_ind": 1,
    "adv_nonconn_ind": 2,
    "scan_req": 3,
    "scan_rsp": 4,
    "connect_ind": 5,
    "adv_scan_ind": 6,
    "adv_ext_ind": 7,
}
_BLE_ADV_PDU_TYPE_NAMES = {value: key for key, value in _BLE_ADV_PDU_TYPES.items()}
_BLE_AD_TYPES: dict[str, int] = {
    "flags": 0x01,
    "shortened_local_name": 0x08,
    "shortened_name": 0x08,
    "complete_local_name": 0x09,
    "local_name": 0x09,
    "name": 0x09,
}
_BLE_PHDR_FLAG_BITS: dict[str, int] = {
    "dewhitened": 0x0001,
    "signal_power_valid": 0x0002,
    "noise_power_valid": 0x0004,
    "decrypted": 0x0008,
    "reference_access_address_valid": 0x0010,
    "ref_access_address_valid": 0x0010,
    "access_address_offenses_valid": 0x0020,
    "rf_channel_aliased": 0x0040,
    "crc_checked": 0x0400,
    "crc_valid": 0x0800,
    "mic_checked": 0x1000,
    "mic_valid": 0x2000,
}
_BLE_ADV_FLAG_BITS: dict[str, int] = {
    "limited_disc_mode": 0x01,
    "le_limited_discoverable_mode": 0x01,
    "general_disc_mode": 0x02,
    "le_general_discoverable_mode": 0x02,
    "br_edr_not_supported": 0x04,
    "simultaneous_le_br_edr_controller": 0x08,
    "simultaneous_le_br_edr_host": 0x10,
}

_DOT11_PHASE15_LAYERS = frozenset({"radiotap", "dot11", "llc_snap", "eapol", "rsn"})
_DOT11_CONVENTIONAL_CHILDREN = frozenset({"arp", "ipv4", "ipv6"})


def _is_ble_stack(stack: Sequence[str]) -> bool:
    return any(layer in _BLE_LAYERS for layer in stack)


def _ble_bytes(plan: PacketPlan, stack: list[str]) -> tuple[bytes, JSONObject]:
    if stack != ["ble_radio", "ble_adv"]:
        joined = ", ".join(stack)
        raise ValueError(f"unsupported BLE materialization stack: {joined}")

    radio = _layer_fields(plan.fields, "ble_radio")
    adv = _layer_fields(plan.fields, "ble_adv")
    pdu_type = _ble_adv_pdu_type(adv.get("pdu_type"))
    tx_add = _ble_address_type_bit(_optional_field(adv, "tx_add", "txaddr"), 0)
    rx_add = _ble_address_type_bit(_optional_field(adv, "rx_add", "rxaddr"), 0)
    channel_selection = 1 if bool(_optional_field(adv, "channel_selection", "chsel")) else 0
    rfu = _int(adv.get("rfu"), 0) & 0x01
    adv_a_wire = _ble_address_wire(_optional_field(adv, "adv_a", "adva"))
    adv_a = _ble_address_text(adv_a_wire)
    ad_items = _ble_ad_items(_optional_field(adv, "ad_list", "ad"))
    adv_data = b"".join(data for _code, data in ad_items)
    payload = adv_a_wire + adv_data
    length = _int(adv.get("length"), len(payload)) & 0xFF
    header0 = (
        (pdu_type & 0x0F)
        | ((rfu & 0x01) << 4)
        | ((channel_selection & 0x01) << 5)
        | ((tx_add & 0x01) << 6)
        | ((rx_add & 0x01) << 7)
    )
    pdu = bytes([header0, length]) + payload
    access_address = _ble_access_address(radio.get("access_address"))
    crc_init = _ble_crc_init(radio.get("crc_init"))
    fallback_ll_packet = (
        access_address.to_bytes(4, "little")
        + pdu
        + _ble_crc(pdu, init=crc_init)
    )
    native_ll_packet, native_metadata = _ble_native_adv_ll_packet_bytes(
        access_address=access_address,
        pdu_type=pdu_type,
        tx_add=tx_add,
        rx_add=rx_add,
        channel_selection=channel_selection,
        rfu=rfu,
        length=length,
        adv_a=adv_a,
        ad_items=ad_items,
    )

    materialization = "deterministic_wire_bytes"
    ll_packet = fallback_ll_packet
    if native_ll_packet == fallback_ll_packet:
        materialization = "scapy_btle_layers"
        ll_packet = native_ll_packet
    elif native_ll_packet is not None:
        native_metadata["fallback_reason"] = "native_scapy_btle_bytes_mismatch"

    pseudoheader = _ble_pseudoheader_bytes(radio, default_access_address=access_address)
    metadata: JSONObject = {
        "native_scapy_support": native_ll_packet is not None,
        "materialization": materialization,
        "scapy_version": _string(native_metadata.get("scapy_version"), "not-required"),
    }
    fallback_reason = native_metadata.get("fallback_reason")
    if isinstance(fallback_reason, str):
        metadata["fallback_reason"] = fallback_reason
    return pseudoheader + ll_packet, metadata


def _ble_native_adv_ll_packet_bytes(
    *,
    access_address: int,
    pdu_type: int,
    tx_add: int,
    rx_add: int,
    channel_selection: int,
    rfu: int,
    length: int,
    adv_a: str,
    ad_items: Sequence[tuple[int, bytes]],
) -> tuple[bytes | None, JSONObject]:
    metadata: JSONObject = {"scapy_version": "not-required"}
    if pdu_type != 0:
        metadata["fallback_reason"] = "native_scapy_supports_only_adv_ind"
        return None, metadata
    try:
        import scapy  # type: ignore[import-untyped]
        import scapy.all as scapy_all  # type: ignore[import-untyped]
        from scapy.layers.bluetooth import (  # type: ignore[import-untyped]
            EIR_CompleteLocalName,
            EIR_Flags,
            EIR_Hdr,
        )
        from scapy.layers.bluetooth4LE import (  # type: ignore[import-untyped]
            BTLE,
            BTLE_ADV,
            BTLE_ADV_IND,
        )
    except Exception as exc:
        metadata["fallback_reason"] = f"scapy_btle_layers_unavailable: {type(exc).__name__}"
        return None, metadata

    metadata["scapy_version"] = _string(getattr(scapy, "__version__", "unknown"), "unknown")
    eir_packets: list[Any] = []
    for code, encoded in ad_items:
        raw = encoded[2:] if len(encoded) >= 2 else b""
        if code == 0x01:
            eir_packets.append(EIR_Hdr(len=len(raw) + 1, type=code) / EIR_Flags(flags=raw[0] if raw else 0))
        elif code == 0x09:
            eir_packets.append(EIR_Hdr(len=len(raw) + 1, type=code) / EIR_CompleteLocalName(local_name=raw))
        else:
            metadata["fallback_reason"] = f"native_scapy_eir_type_unsupported: {code}"
            return None, metadata

    try:
        packet = (
            BTLE(access_addr=access_address)
            / BTLE_ADV(
                PDU_type=pdu_type,
                TxAdd=tx_add,
                RxAdd=rx_add,
                ChSel=channel_selection,
                RFU=rfu,
                Length=length,
            )
            / BTLE_ADV_IND(AdvA=adv_a, data=eir_packets)
        )
        return bytes(scapy_all.raw(packet)), metadata
    except Exception as exc:  # pragma: no cover - Scapy exception types vary.
        metadata["fallback_reason"] = f"native_scapy_btle_build_failed: {type(exc).__name__}"
        return None, metadata


def _ble_pseudoheader_bytes(
    radio: Mapping[str, object],
    *,
    default_access_address: int,
) -> bytes:
    flags = _ble_phdr_flags(radio)
    signal_power = _signed_byte(_optional_field(radio, "signal_power"), 0)
    noise_power = _signed_byte(_optional_field(radio, "noise_power"), 0)
    offenses = _int(radio.get("access_address_offenses"), 0) & 0xFF
    ref_access_address = _ble_access_address(
        _optional_field(radio, "ref_access_address", "reference_access_address"),
        default=default_access_address,
    )
    return (
        bytes([_int(radio.get("rf_channel", radio.get("channel")), 37) & 0xFF])
        + signal_power
        + noise_power
        + bytes([offenses])
        + ref_access_address.to_bytes(4, "little")
        + flags.to_bytes(2, "little")
    )


def _ble_phdr_flags(radio: Mapping[str, object]) -> int:
    raw_flags = radio.get("flags")
    if raw_flags is None:
        flags = (
            _BLE_PHDR_FLAG_BITS["dewhitened"]
            | _BLE_PHDR_FLAG_BITS["reference_access_address_valid"]
            | _BLE_PHDR_FLAG_BITS["crc_checked"]
            | _BLE_PHDR_FLAG_BITS["crc_valid"]
        )
    else:
        flags = _ble_flag_value(raw_flags, _BLE_PHDR_FLAG_BITS, default=0)
    if "signal_power" in radio:
        flags |= _BLE_PHDR_FLAG_BITS["signal_power_valid"]
    if "noise_power" in radio:
        flags |= _BLE_PHDR_FLAG_BITS["noise_power_valid"]
    if "access_address_offenses" in radio:
        flags |= _BLE_PHDR_FLAG_BITS["access_address_offenses_valid"]
    return flags & 0xFFFF


def _ble_ad_items(value: object) -> list[tuple[int, bytes]]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        value = [value]
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError("BLE advertising data requires an AD structure list")

    output: list[tuple[int, bytes]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise ValueError(f"BLE AD structure must be an object, got {item!r}")
        code = _ble_ad_type_code(_optional_field(item, "type_code", "ad_type", "type"))
        data = _ble_ad_data(code, item)
        if len(data) > 254:
            raise ValueError("BLE AD structure data exceeds 254 octets")
        output.append((code, bytes([len(data) + 1, code]) + data))
    return output


def _ble_ad_data(code: int, item: Mapping[str, object]) -> bytes:
    raw = _optional_field(item, "data_hex", "hex", "bytes")
    if raw is not None:
        return _bytes_optional(raw)
    if code == 0x01:
        return bytes([_ble_flag_value(_optional_field(item, "value", "flags"), _BLE_ADV_FLAG_BITS, default=0x06)])
    if code in {0x08, 0x09}:
        value = _optional_field(item, "value", "name", "local_name", "text")
        return _text(value, "").encode("utf-8")
    value = item.get("value")
    if value is None:
        return b""
    return _bytes_optional(value)


def _ble_ad_type_code(value: object) -> int:
    if isinstance(value, str):
        normalized = value.lower().replace("-", "_").replace(" ", "_")
        if normalized in _BLE_AD_TYPES:
            return _BLE_AD_TYPES[normalized]
        return int(normalized, 0)
    return _int(value, 0)


def _ble_adv_pdu_type(value: object) -> int:
    if isinstance(value, str):
        normalized = value.lower().replace("-", "_").replace(" ", "_")
        if normalized in _BLE_ADV_PDU_TYPES:
            return _BLE_ADV_PDU_TYPES[normalized]
        return int(normalized, 0)
    return _int(value, 0)


def _ble_address_type_bit(value: object, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, str):
        normalized = value.lower().replace("-", "_").replace(" ", "_")
        if normalized == "public":
            return 0
        if normalized == "random":
            return 1
    return 1 if bool(_int(value, default)) else 0


def _ble_access_address(value: object, *, default: int = 0x8E89BED6) -> int:
    return _int(value, default) & 0xFFFF_FFFF


def _ble_crc_init(value: object) -> int:
    return _int(value, 0x555555) & 0xFF_FFFF


def _ble_flag_value(value: object, mapping: Mapping[str, int], *, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        normalized = value.lower().replace("-", "_").replace(" ", "_")
        if normalized in mapping:
            return mapping[normalized]
        if "|" in normalized or "," in normalized:
            flags = 0
            for token in normalized.replace(",", "|").split("|"):
                token = token.strip()
                if token:
                    flags |= mapping.get(token, int(token, 0) if token[:1].isdigit() else 0)
            return flags
        return int(normalized, 0)
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        flags = 0
        for item in value:
            flags |= _ble_flag_value(item, mapping, default=0)
        return flags
    raise ValueError(f"expected BLE flag-compatible value, got {value!r}")


def _ble_address_wire(value: object) -> bytes:
    if value is None:
        value = "a1:a2:a3:a4:a5:a6"
    if isinstance(value, str) and ":" in value:
        parts = value.split(":")
        if len(parts) != 6:
            raise ValueError(f"BLE address requires six octets, got {value!r}")
        return bytes(int(part, 16) for part in reversed(parts))
    return _bytes_exact(value, 6)


def _ble_address_text(wire: bytes) -> str:
    return ":".join(f"{octet:02x}" for octet in reversed(wire[:6]))


def _signed_byte(value: object, default: int) -> bytes:
    number = _int(value, default)
    if not -128 <= number <= 127:
        raise ValueError(f"expected signed byte value, got {number}")
    return int(number).to_bytes(1, "little", signed=True)


def _ble_crc(pdu: bytes, *, init: int) -> bytes:
    state = (
        _ble_swap_bits(init & 0xFF)
        | (_ble_swap_bits((init >> 8) & 0xFF) << 8)
        | (_ble_swap_bits((init >> 16) & 0xFF) << 16)
    )
    lfsr_mask = 0x5A6000
    for byte in pdu:
        current = byte
        for _bit in range(8):
            next_bit = (state ^ current) & 0x01
            current >>= 1
            state >>= 1
            if next_bit:
                state |= 1 << 23
                state ^= lfsr_mask
    return state.to_bytes(4, "little")[:3]


def _ble_swap_bits(value: int) -> int:
    output = 0
    for bit in range(8):
        if value & (1 << bit):
            output |= 1 << (7 - bit)
    return output


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
    plugin = SCAPY_REGISTRY.get(layer)
    if plugin is not None and plugin.scapy_class is not None:
        return plugin.scapy_class
    return _SCAPY_LAYER_BY_LAYER.get(layer, layer)


def _string(value: object, default: str) -> str:
    if isinstance(value, str):
        return value
    return default
