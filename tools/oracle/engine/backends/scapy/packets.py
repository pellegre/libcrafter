"""Scapy raw packet materialization for oracle packet plans."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ...model import EncodedVector, JSONObject, PacketPlan
from ..registry import BackendCapabilities, BackendRegistration, get_backend
from .bootstrap import import_scapy
from .encode_helpers import (
    _ETHERTYPES,
    _IP_PROTOCOLS,
    _IPV6_NEXT_HEADERS,
    _bytes_exact,
    _bytes_field,
    _bytes_optional,
    _ethertype_value,
    _hardware_type_value,
    _int,
    _internet_checksum,
    _ipv4_address_bytes,
    _ipv4_flags,
    _ipv6_address_bytes,
    _layer_fields,
    _layer_fields_for_stack_index,
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
# The ``igmp`` layer is migrated to ``protocols/igmp.py`` and registered in
# ``SCAPY_REGISTRY``. Its ``igmp_query`` / ``igmp_report`` / ``igmp_extension``
# sub-layer bytes builders are co-located there but, like the IPv6 ext-header
# builders, are not registered (the sub-layer names are children of the ``igmp``
# spec layer, not top-level spec layers). They are re-imported here so the legacy
# per-layer ``_build_layer`` dispatch keeps wrapping them in a Scapy ``Raw``
# unchanged.
from .protocols.igmp import (
    _igmp_extension_layer_bytes,
    _igmp_query_bytes,
    _igmp_report_bytes,
)
# The ``dns`` layer is migrated to ``protocols/dns.py`` and registered in
# ``SCAPY_REGISTRY`` (its ``ScapyProtocol`` build adapter calls the moved ``_dns``
# materializer). The ``_dns`` builder and the ``_dns_record_entry`` record helper are
# re-imported here so the existing ``test_dns_backend.py`` references
# (``packets._dns`` / ``packets._dns_record_entry``) keep resolving after the move.
from .protocols.dns import _dns, _dns_record_entry


BACKEND_NAME = "scapy"

_SCAPY_LAYER_BY_LAYER: dict[str, str] = {
    "ah": "AH",
    "ble_adv": "BTLE_ADV_IND",
    "ble_radio": "BTLE_PHDR",
    "dhcp": "DHCP",
    "dot11": "Dot11",
    "dot15d4": "Dot15d4",
    # Scapy has no native IEEE 802.15.4 TAP (DLT 283) pseudo-header dissector;
    # libcrafter's Dot15d4Radio carries it, so the radio descriptor is
    # materialized/normalized outside Scapy's native layer set (Raw passthrough)
    # the same way the BLE LL-with-PHDR pseudo-header is handled.
    "dot15d4_radio": "Raw",
    "eapol": "EAPOL",
    "esp": "ESP",
    # IGMP contrib classes are not exposed through scapy.all consistently
    # across supported Scapy versions, so the oracle materializer emits exact
    # IGMP bytes through Raw while preserving IPv4 protocol number 2. The base
    # ``igmp`` layer is migrated to ``protocols/igmp.py`` (its ``ScapyProtocol``
    # declares ``scapy_class="Raw"``, which drives ``_scapy_layer_name`` and the
    # ``scapy_stack`` metadata); its ``igmp_query`` / ``igmp_report`` /
    # ``igmp_extension`` sub-layers are not top-level spec layers, so they keep
    # their legacy ``Raw`` mapping here.
    "igmp_extension": "Raw",
    "igmp_query": "Raw",
    "igmp_report": "Raw",
    "ikev2": "ISAKMP",
    "ipv6_destination_options": "IPv6ExtHdrDestOpt",
    "ipv6_fragment": "IPv6ExtHdrFragment",
    "ipv6_hop_by_hop": "IPv6ExtHdrHopByHop",
    "ipv6_routing": "IPv6ExtHdrRouting",
    "radiotap": "RadioTap",
    "raw": "Raw",
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
    # The base ``igmp`` field allowlist moved to ``protocols/igmp.py`` (its
    # ``ScapyProtocol.supported_fields``); ``_scapy_supported_fields`` resolves it
    # from the registry. The ``igmp_query`` / ``igmp_report`` / ``igmp_extension``
    # sub-layers are not top-level spec layers, so they keep their legacy entries
    # here for the per-layer ``_build_layer`` dispatch.
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
    if layer == "ipv6_hop_by_hop":
        return _ipv6_hop_by_hop(fields, stack, index, scapy_all)
    if layer == "ipv6_destination_options":
        return _ipv6_destination_options(fields, stack, index, scapy_all)
    if layer == "ipv6_fragment":
        return _ipv6_fragment(fields, stack, index, scapy_all)
    if layer == "ipv6_routing":
        return _ipv6_routing(fields, stack, index, scapy_all)
    if layer == "igmp_query":
        return scapy_all.Raw(load=_igmp_query_bytes(fields))
    if layer == "igmp_report":
        return scapy_all.Raw(load=_igmp_report_bytes(fields))
    if layer == "igmp_extension":
        return scapy_all.Raw(load=_igmp_extension_layer_bytes(_layer_fields_for_stack_index(fields, stack, index)))
    if layer == "dhcp":
        return _dhcp(fields, scapy_all)
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
# RIP (RFC 1058 / RFC 2453) materialization moved to ``protocols/rip.py`` and
# RIPng (RFC 2080) materialization moved to ``protocols/ripng.py``; both are
# registered in ``SCAPY_REGISTRY`` (so ``_build_layer`` routes ``rip`` / ``ripng``
# to their ``build``). ``ripng`` shares the ``_rip_command`` symbolic-command
# resolver, which the ripng plugin imports from the co-located ``rip`` plugin.

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
