"""Scapy packet decoding and backend-neutral normalization."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from ...model import DecodedModel, EncodedVector, JSONObject, JSONValue, PacketPlan
from ..registry import BackendCapabilities, BackendRegistration, get_backend
from .bootstrap import import_scapy
from .decode_helpers import (
    _bool_flag,
    _crc32c,
    _field_key,
    _internet_checksum,
    _json_value,
    _mac_text,
    _normalize_flags,
    _object,
    _text,
    _text_or_none,
)
# Importing the protocols package runs its ``autodiscover`` so every per-protocol
# Scapy encoder/decoder module self-registers; ``SCAPY_REGISTRY`` is consulted for a
# layer's ``normalize`` hook before the legacy branches below. No protocol is
# migrated yet, so the registry is empty and every layer falls through to the legacy
# normalization.
from .protocols import SCAPY_REGISTRY
# The IPv6 extension-header decode normalizers (and the synthetic option-region key
# the orchestrator below smuggles in) live in the co-located ipv6 plugin module. They
# are NOT registered as ``ScapyProtocol.normalize`` hooks because the ext-header names
# are sub-layers of the ``ipv6`` spec rather than top-level spec layers; the legacy
# ``_normalize_fields`` dispatch and the ``_packet_layers`` option-region capture below
# call them through these re-imports so behavior stays byte-identical.
from .protocols.ipv6 import (
    _IPV6_OPTION_REGION_KEY,
    _normalize_ipv6_fragment_fields,
    _normalize_ipv6_options_header_fields,
    _normalize_ipv6_routing_fields,
)


BACKEND_NAME = "scapy"

# Synthetic field key carrying the raw DHCP option TLV region (hex) captured
# from the live Scapy DHCP sub-layer. Consumed and removed during DHCP field
# normalization so it never leaks into the comparable model.
_DHCP_OPTION_REGION_KEY = "__option_region_hex__"

# DHCP option codes whose payload is a single message-type octet (option 53).
_DHCP_OPTION_MESSAGE_TYPE = 53
_DHCP_OPTION_PAD = 0
_DHCP_OPTION_END = 255

_LAYER_ALIASES: dict[str, str] = {
    "AH": "ah",
    "BTLE": "ble_radio",
    "BTLE_ADV": "ble_adv",
    "BTLE_ADV_IND": "ble_adv",
    "BOOTP": "dhcp",
    "DHCP": "dhcp",
    "DNS": "dns",
    "Dot11": "dot11",
    "Dot11EltRSN": "rsn",
    "Dot15d4": "dot15d4",
    "Dot15d4Data": "dot15d4",
    "Dot15d4FCS": "dot15d4",
    "ESP": "esp",
    "EAPOL": "eapol",
    "IGMP": "igmp",
    "IGMPv3": "igmp",
    "IGMPv3gr": "igmp_group_record",
    "IGMPv3mq": "igmp_query",
    "IGMPv3mr": "igmp_report",
    "ISAKMP": "ikev2",
    "ISAKMP_v1": "ikev2",
    "IPv6ExtHdrDestOpt": "ipv6_destination_options",
    "IPv6ExtHdrFragment": "ipv6_fragment",
    "IPv6ExtHdrHopByHop": "ipv6_hop_by_hop",
    "IPv6ExtHdrRouting": "ipv6_routing",
    "IPv6ExtHdrSegmentRouting": "ipv6_routing",
    "OSPF_Hdr": "ospf",
    "OSPF_Hello": "ospf",
    "OSPF_DBDesc": "ospf",
    "OSPF_LSReq": "ospf",
    "OSPF_LSUpd": "ospf",
    "OSPF_LSAck": "ospf",
    "RadioTap": "radiotap",
}
_FIELD_ALIASES: dict[str, str] = {
    "chksum": "checksum",
    "dataofs": "data_offset",
    "dport": "dst_port",
    "frag": "fragment_offset",
    "hlim": "hop_limit",
    "len": "length",
    "nh": "next_header",
    "proto": "protocol",
    "sport": "src_port",
    "urgptr": "urgent_pointer",
}
_LAYER_FIELD_ALIASES: dict[str, dict[str, str]] = {
    "ah": {
        "nh": "next_header",
        "payloadlen": "payload_len",
        "seq": "sequence",
    },
    "esp": {
        "seq": "sequence",
    },
    "ikev2": {
        "exch_type": "exchange_type",
        "id": "message_id",
        "init_cookie": "initiator_spi",
        "resp_cookie": "responder_spi",
    },
    "dhcp": {
        "ciaddr": "client_ip",
        "chaddr": "client_hardware_address",
        "giaddr": "relay_ip",
        "htype": "hardware_type",
        "hlen": "hardware_length",
        "siaddr": "server_ip",
        "xid": "transaction_id",
        "yiaddr": "your_ip",
    },
    "dns": {
        "id": "transaction_id",
        "qr": "is_response",
        "rcode": "response_code",
    },
    "ipv6_destination_options": {
        "len": "header_ext_len",
    },
    "ipv6_hop_by_hop": {
        "len": "header_ext_len",
    },
    "linux_sll": {
        "lladdrlen": "address_length",
        "lladdrtype": "address_type",
        "pkttype": "packet_type",
        "src": "source_address",
    },
    "ospf": {
        # OSPF_Hdr common-header fields mapped to the oracle-neutral names
        # declared in specs/layers/ospf.yaml.
        "len": "packet_length",
        "src": "router_id",
        "area": "area_id",
        "chksum": "checksum",
        "authtype": "autype",
        "authdata": "authentication",
        # OSPF_Hello / OSPF_DBDesc body fields.
        "mask": "network_mask",
        "hellointerval": "hello_interval",
        "prio": "router_priority",
        "deadinterval": "router_dead_interval",
        "router": "designated_router",
        "backup": "backup_designated_router",
        "mtu": "interface_mtu",
        "dbdescr": "dd_flags",
        "ddseq": "dd_sequence_number",
        "lsaheaders": "lsa_headers",
    },
}
_ETHERTYPES: dict[str, int] = {
    "arp": 0x0806,
    "experimental": 0x9000,
    "ipv4": 0x0800,
    "ipv6": 0x86DD,
    "vlan": 0x8100,
}
_PROTOCOLS: dict[str, int] = {
    "destination-options": 60,
    "destination_options": 60,
    "fragment": 44,
    "hop-by-hop": 0,
    "hop_by_hop": 0,
    "icmp": 1,
    "igmp": 2,
    "icmpv6": 58,
    "no-next": 59,
    "no_next": 59,
    "routing": 43,
    "tcp": 6,
    "udp": 17,
}
_ROOT_ALIASES: dict[str, str] = {
    "BTLE_PHDR": "link:bluetooth-le-ll-with-phdr",
    "CookedLinux": "link:linux-cooked",
    "Ether": "link:ethernet",
    "Dot11": "link:dot11",
    "Dot15d4": "link:ieee802154",
    "Dot15d4FCS": "link:ieee802154",
    "IP": "l3:ipv4",
    "IPv6": "l3:ipv6",
    "Loopback": "link:null-loopback",
    "RadioTap": "link:radiotap",
    "Raw": "link:raw",
    "link:bluetooth_le_ll_with_phdr": "link:bluetooth-le-ll-with-phdr",
    "l2:ipv4": "l3:ipv4",
    "link:ieee80211": "link:dot11",
    "link:ieee802154_tap": "link:ieee802154-tap",
    "link:linux-sll": "link:linux-cooked",
}

_BLE_WITH_PHDR_ROOTS = frozenset(
    {
        "BTLE_PHDR",
        "link:bluetooth-le-ll-with-phdr",
        "link:bluetooth_le_ll_with_phdr",
    }
)
_DOT11_ROOTS = frozenset({"Dot11", "link:dot11", "link:ieee80211"})
_RADIOTAP_ROOTS = frozenset({"RadioTap", "link:radiotap"})
_BLE_ADV_PDU_TYPE_NAMES: dict[int, str] = {
    0: "adv_ind",
    1: "adv_direct_ind",
    2: "adv_nonconn_ind",
    3: "scan_req",
    4: "scan_rsp",
    5: "connect_ind",
    6: "adv_scan_ind",
    7: "adv_ext_ind",
}
_BLE_AD_TYPE_NAMES: dict[int, str] = {
    0x01: "flags",
    0x08: "shortened_local_name",
    0x09: "complete_local_name",
}
_BLE_PHDR_FLAG_NAMES: tuple[tuple[int, str], ...] = (
    (0x0001, "dewhitened"),
    (0x0002, "signal_power_valid"),
    (0x0004, "noise_power_valid"),
    (0x0008, "decrypted"),
    (0x0010, "reference_access_address_valid"),
    (0x0020, "access_address_offenses_valid"),
    (0x0040, "rf_channel_aliased"),
    (0x0400, "crc_checked"),
    (0x0800, "crc_valid"),
    (0x1000, "mic_checked"),
    (0x2000, "mic_valid"),
)
_BLE_ADV_FLAG_NAMES: tuple[tuple[int, str], ...] = (
    (0x01, "le_limited_discoverable_mode"),
    (0x02, "le_general_discoverable_mode"),
    (0x04, "br_edr_not_supported"),
    (0x08, "simultaneous_le_br_edr_controller"),
    (0x10, "simultaneous_le_br_edr_host"),
)


def decode_root(
    root: str,
    raw: bytes,
    *,
    capabilities: BackendCapabilities | BackendRegistration | None = None,
) -> Any:
    """Decode raw bytes with a Scapy decoder selected by oracle root name."""

    _require_decode_capability(capabilities)
    scapy_all = import_scapy()["all"]
    if root in _BLE_WITH_PHDR_ROOTS:
        decoder = getattr(scapy_all, "BTLE", None)
        if decoder is None:
            raise ValueError("Scapy decoder is unavailable: BTLE")
        if len(raw) < 10:
            raise ValueError(f"BLE LL-with-phdr requires 10 pseudo-header bytes, got {len(raw)}")
        return decoder(raw[10:])

    decoders = {
        "CookedLinux": "CookedLinux",
        "Dot11": "Dot11",
        "Ether": "Ether",
        "IP": "IP",
        "IPv6": "IPv6",
        "Loopback": "Loopback",
        "RadioTap": "RadioTap",
        "Raw": "Raw",
        "link:dot11": "Dot11",
        "link:ethernet": "Ether",
        "link:ieee80211": "Dot11",
        # IEEE 802.15.4 with-FCS MAC frame (DLT 195): scapy's Dot15d4FCS dissects
        # the frame-control field, addressing, payload, and trailing FCS, then
        # dispatches the MAC payload to ZigbeeNWK/ZigbeeAppDataPayload via the
        # conf.dot15d4_protocol="zigbee" pin set in bootstrap.import_scapy.
        "link:ieee802154": "Dot15d4FCS",
        # IEEE 802.15.4 TAP (DLT 283): no native scapy dissector; the radio
        # pseudo-header is carried as Raw (libcrafter owns the TAP descriptor
        # decode), mirroring _SCAPY_DECODER_BY_ROOT in packets.py.
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
        "l3:raw": "Raw",
    }
    decoder_name = decoders.get(root)
    if decoder_name is None:
        raise ValueError(f"unsupported Scapy root decoder: {root!r}")
    decoder = getattr(scapy_all, decoder_name, None)
    if decoder is None:
        raise ValueError(f"Scapy decoder is unavailable: {decoder_name}")
    return decoder(raw)


def decode_bytes(
    raw: bytes,
    *,
    root: str,
    source_hex: str | None = None,
    feature_tags: Sequence[str] = (),
    capabilities: BackendCapabilities | BackendRegistration | None = None,
) -> DecodedModel:
    """Decode raw bytes and return the normalized Scapy model."""

    if root in _BLE_WITH_PHDR_ROOTS:
        return _decode_ble_bytes(
            raw,
            root=root,
            source_hex=source_hex or raw.hex(),
            feature_tags=feature_tags,
        )
    if root in _DOT11_ROOTS or root in _RADIOTAP_ROOTS:
        return _decode_dot11_bytes(
            raw,
            root=root,
            source_hex=source_hex or raw.hex(),
            feature_tags=feature_tags,
        )

    packet = decode_root(root, raw, capabilities=capabilities)
    return normalize_packet(
        packet,
        root=root,
        source_hex=source_hex or raw.hex(),
        feature_tags=feature_tags,
    )


def decode_vector(
    vector: EncodedVector,
    *,
    capabilities: BackendCapabilities | BackendRegistration | None = None,
) -> DecodedModel:
    """Decode one encoded vector through its root decoder metadata."""

    root = vector.root or vector.decoder
    if root is None:
        raise ValueError("encoded vector is missing root decoder metadata")
    return decode_bytes(
        vector.to_bytes(),
        root=root,
        source_hex=vector.raw_hex,
        feature_tags=vector.plan.feature_tags,
        capabilities=capabilities,
    )


def decode_vectors(
    vectors: Iterable[EncodedVector],
    *,
    capabilities: BackendCapabilities | BackendRegistration | None = None,
) -> list[DecodedModel]:
    """Decode vectors in order."""

    _require_decode_capability(capabilities)
    return [decode_vector(vector, capabilities=capabilities) for vector in vectors]


def normalize_packet(
    packet: Any,
    *,
    root: str | None = None,
    source_hex: str | None = None,
    feature_tags: Sequence[str] = (),
) -> DecodedModel:
    """Convert a Scapy packet object into an oracle DecodedModel."""

    layers = _packet_layers(packet)
    normalized_layers: list[str] = []
    normalized_fields: dict[str, JSONObject] = {}
    for occurrence, layer in enumerate(layers):
        native_layer = _text(layer["name"])
        normalized_layer = _normalize_layer_name(native_layer)
        if normalized_layer == "padding":
            continue
        layer_fields = _normalize_fields(
            normalized_layer,
            _object(layer["fields"], f"{layer['name']}.fields"),
        )
        if normalized_layer == "dhcp" and "dhcp" in normalized_fields:
            normalized_fields["dhcp"].update(layer_fields)
            continue
        if normalized_layer == "bgp" and _is_bgp_body_layer(native_layer):
            key = _last_layer_field_key(normalized_fields, "bgp")
            if key is not None:
                normalized_fields[key].update(layer_fields)
                continue
        if normalized_layer == "ospf" and _is_ospf_body_layer(native_layer):
            key = _last_layer_field_key(normalized_fields, "ospf")
            if key is not None:
                normalized_fields[key].update(layer_fields)
                continue
        key = _field_key(normalized_fields, normalized_layer)
        normalized_fields[key] = layer_fields
        normalized_layers.append(normalized_layer)

    _canonicalize_icmpv4(
        packet,
        normalized_layers,
        normalized_fields,
        root=root,
        source_hex=source_hex,
    )
    _canonicalize_igmp(packet, normalized_layers, normalized_fields)
    _canonicalize_rip(packet, normalized_layers, normalized_fields)
    _canonicalize_ripng(packet, normalized_layers, normalized_fields)
    _canonicalize_dot15d4_zigbee(normalized_layers, normalized_fields)
    if source_hex is not None:
        _canonicalize_bgp_from_wire(source_hex, normalized_fields)

    metadata: JSONObject = {
        "native": {
            "summary": _text(packet.summary()),
            "layers": layers,
        },
    }
    if source_hex is not None:
        _apply_udp_surplus_normalization(
            normalized_layers,
            normalized_fields,
            root=_normalize_root_name(root),
            source_hex=source_hex,
            metadata=metadata,
        )
    try:
        metadata["reencoded_hex"] = bytes(import_scapy()["all"].raw(packet)).hex()
    except Exception as exc:  # pragma: no cover - Scapy exception types vary.
        metadata["reencoded_error"] = _text(exc)

    # The comparison-visible ``dns`` layer fields stay header-only so that the
    # current libcrafter decode model (which exposes only header counts/flags)
    # keeps comparing cleanly. The full backend-neutral DNS message model -- the
    # questions, answers, authorities, additionals, names, types, classes, TTLs,
    # and per-record RDATA -- is normalized here and stored on the metadata so it
    # is inspectable for record-level cases and ready for later steps that widen
    # the comparable surface. Compressed and uncompressed names normalize to the
    # same trailing-dot presentation form, so a compressed-name input and a
    # libcrafter uncompressed re-encode agree on this normalized model even when
    # the wire bytes differ (see specs/features/dns-behavior.yaml).
    dns_message = _normalize_dns_message(packet)
    if dns_message is not None:
        metadata["dns_message"] = dns_message

    return DecodedModel(
        backend=BACKEND_NAME,
        layers=normalized_layers,
        fields=normalized_fields,
        root=_normalize_root_name(root),
        source_hex=source_hex,
        feature_tags=list(feature_tags),
        metadata=metadata,
    )


def validate_smoke_decode(vector: EncodedVector, decoded: DecodedModel) -> None:
    """Validate normalized stack and selected generated fields for smoke vectors."""

    plan = vector.plan
    expected_stack = _expected_stack(plan)
    if decoded.layers != expected_stack:
        raise ValueError(
            f"normalized stack mismatch for index={plan.index}: "
            f"expected={expected_stack!r} actual={decoded.layers!r}"
        )

    for layer_name, expected_fields in _expected_smoke_fields(plan).items():
        actual_fields = decoded.fields.get(layer_name)
        if actual_fields is None:
            raise ValueError(f"missing normalized layer fields: {layer_name}")
        for field_name, expected_value in expected_fields.items():
            actual_value = actual_fields.get(field_name)
            if actual_value != expected_value:
                raise ValueError(
                    f"normalized field mismatch for index={plan.index} "
                    f"{layer_name}.{field_name}: "
                    f"expected={expected_value!r} actual={actual_value!r}"
                )


def validate_smoke_decodes(vectors: Iterable[EncodedVector], decoded: Iterable[DecodedModel]) -> None:
    """Validate a sequence of smoke decoded models against their plans."""

    for vector, model in zip(vectors, decoded, strict=True):
        validate_smoke_decode(vector, model)


def _packet_layers(packet: Any) -> list[JSONObject]:
    layers: list[JSONObject] = []
    current = packet
    while current is not None and current.__class__.__name__ != "NoPayload":
        fields = {
            str(key): _json_value(value)
            for key, value in sorted(current.fields.items())
        }
        if current.__class__.__name__ == "DHCP":
            # Capture the raw option TLV region so normalization can record
            # backend-neutral {code, payload_hex} option details instead of the
            # Scapy-typed option list, which is not byte-comparable across
            # backends. The DHCP sub-layer's wire bytes are exactly the option
            # region (after the BOOTP fixed fields and magic cookie).
            option_bytes = _dhcp_option_region_bytes(current)
            if option_bytes is not None:
                fields[_DHCP_OPTION_REGION_KEY] = option_bytes.hex()
        if current.__class__.__name__ in {"IPv6ExtHdrHopByHop", "IPv6ExtHdrDestOpt"}:
            option_bytes = _ipv6_option_region_bytes(current)
            if option_bytes is not None:
                fields[_IPV6_OPTION_REGION_KEY] = option_bytes.hex()
        if current.__class__.__name__ in {"ISAKMP", "ISAKMP_v1"}:
            # Scapy's ISAKMP FlagsField uses the IKEv1 flag labels, so its string
            # repr renders the IKEv2 (RFC 7296) bits as "?". Capture the raw
            # integer so the normalizer can resolve the IKEv2 flag set.
            raw_flags = current.fields.get("flags")
            if raw_flags is not None:
                try:
                    fields["flags"] = int(raw_flags)
                except (TypeError, ValueError):  # pragma: no cover - defensive
                    pass
        layers.append(
            {
                "name": current.__class__.__name__,
                "fields": fields,
                "summary": _text(current.summary()),
            }
        )
        current = current.payload
    return layers


def _dhcp_option_region_bytes(dhcp_layer: Any) -> bytes | None:
    try:
        return bytes(import_scapy()["all"].raw(dhcp_layer))
    except Exception:  # pragma: no cover - Scapy serialization edge cases.
        return None


def _ipv6_option_region_bytes(layer: Any) -> bytes | None:
    header_ext_len = getattr(layer, "len", None)
    if not isinstance(header_ext_len, int):
        return None
    total_len = (header_ext_len + 1) * 8
    try:
        raw = bytes(import_scapy()["all"].raw(layer))
    except Exception:  # pragma: no cover - Scapy serialization edge cases.
        return None
    if len(raw) < total_len or total_len < 2:
        return None
    return raw[2:total_len]


def _registered_layer_aliases() -> dict[str, str]:
    """Native Scapy class name -> oracle layer name, contributed by plugins.

    Each migrated layer's :class:`~.protocols.base.ScapyProtocol` carries the
    decode-side ``layer_aliases`` it owns; collecting them lets
    :func:`_normalize_layer_name` resolve migrated layers from the registry while
    the legacy ``_LAYER_ALIASES`` table still covers unmigrated ones.
    """

    aliases: dict[str, str] = {}
    for plugin in SCAPY_REGISTRY.values():
        for native_name, layer_name in plugin.layer_aliases:
            aliases[native_name] = layer_name
    return aliases


def _normalize_layer_name(native_name: str) -> str:
    if native_name.startswith("ICMPv6"):
        return "icmpv6"
    registered = _registered_layer_aliases()
    if native_name in registered:
        return registered[native_name]
    return _LAYER_ALIASES.get(native_name, native_name.lower())


def _is_bgp_body_layer(native_name: str) -> bool:
    return native_name in {"BGPOpen", "BGPUpdate", "BGPNotification", "BGPRouteRefresh"}


def _is_ospf_body_layer(native_name: str) -> bool:
    return native_name in {
        "OSPF_Hello",
        "OSPF_DBDesc",
        "OSPF_LSReq",
        "OSPF_LSUpd",
        "OSPF_LSAck",
    }


def _last_layer_field_key(fields: Mapping[str, JSONObject], layer_name: str) -> str | None:
    if layer_name in fields:
        key = layer_name
    else:
        key = None
    index = 2
    while f"{layer_name}#{index}" in fields:
        key = f"{layer_name}#{index}"
        index += 1
    return key


def _normalize_root_name(root: str | None) -> str | None:
    if root is None:
        return None
    return _ROOT_ALIASES.get(root, root)


def _normalize_fields(layer_name: str, fields: JSONObject) -> JSONObject:
    # Consult the per-layer Scapy decoder plugin before the legacy branches. The
    # registry is empty until a protocol is migrated, so this resolves to ``None``
    # (or a plugin without a ``normalize`` hook) and the legacy code below runs
    # unchanged.
    plugin = SCAPY_REGISTRY.get(layer_name)
    if plugin is not None and plugin.normalize is not None:
        return plugin.normalize(fields)
    if layer_name == "dns":
        return _normalize_dns_fields(fields)
    if layer_name == "dhcp":
        return _normalize_dhcp_fields(fields)

    output: JSONObject = {}
    for native_name, value in fields.items():
        normalized_name = _normalize_field_name(layer_name, native_name)
        output[normalized_name] = _normalize_field_value(layer_name, normalized_name, value)
    if layer_name in {"ipv6_hop_by_hop", "ipv6_destination_options"}:
        _normalize_ipv6_options_header_fields(output)
    if layer_name == "ospf":
        _normalize_ospf_fields(output)
    if layer_name == "ipv6_fragment":
        _normalize_ipv6_fragment_fields(output)
    if layer_name == "ipv6_routing":
        _normalize_ipv6_routing_fields(output)
    if layer_name in {"esp", "ah", "ikev2"}:
        _normalize_ipsec_fields(layer_name, output)
    return output


def _normalize_ipsec_fields(layer_name: str, output: JSONObject) -> None:
    """Tidy decoded ESP/AH/IKEv2 fields into the comparable oracle shape.

    ESP carries the SPI, sequence, and the opaque encrypted body (``data``); AH
    carries the header fields plus the ICV, with the empty trailing ``padding``
    artifact dropped; IKEv2 (ISAKMP) carries the SPIs, next-payload, version,
    exchange type, flags, message id, and length. The ESP/AH SPI is reported as
    an unsigned integer to match the libcrafter decode model.
    """

    if layer_name == "ah":
        # Scapy appends an empty ``padding`` field on the AH header; it carries
        # no wire bytes (the ICV padding is folded into ``icv``), so drop it.
        padding = output.get("padding")
        if padding in (None, {"hex": "", "ascii": ""}, ""):
            output.pop("padding", None)
    if layer_name == "ikev2":
        flags = output.get("flags")
        if flags is not None:
            output["flags"] = _normalize_ikev2_flags(flags)


# IKEv2 (ISAKMP) flag bits (RFC 7296 §3.1) mapped to the stable domain names the
# generator emits, so a decoded flag set compares against the planned domain.
_IKEV2_FLAG_NAMES: dict[int, str] = {
    0x08: "initiator",
    0x10: "version",
    0x20: "response",
}


def _normalize_ikev2_flags(value: JSONValue) -> JSONValue:
    if isinstance(value, str):
        # Scapy renders the FlagsField as a textual token (e.g. "initiator").
        cleaned = value.strip()
        if not cleaned:
            return []
        tokens = [
            token.lower().replace("-", "_").replace("+", "_")
            for token in cleaned.replace("+", " ").split()
        ]
        return tokens
    if isinstance(value, int) and not isinstance(value, bool):
        return [name for bit, name in sorted(_IKEV2_FLAG_NAMES.items()) if value & bit]
    return value


# BGP message-type code -> name. The per-layer BGP normalizer moved to
# ``protocols/bgp.py`` (which keeps its own copy), but this table is still consulted
# by the whole-packet ``_canonicalize_bgp_from_wire`` pass below, which — like the
# other whole-packet canonicalizers (``_canonicalize_icmpv4``/``_canonicalize_igmp``)
# — rebuilds BGP from the assembled wire bytes and therefore stays in this module.
_BGP_MESSAGE_TYPE_NAMES: dict[int, str] = {
    1: "open",
    2: "update",
    3: "notification",
    4: "keepalive",
    5: "route_refresh",
}


_BGP_HEADER_LEN = 19
_BGP_MARKER_LEN = 16
_BGP_TYPE_OPEN = 1
_BGP_TYPE_UPDATE = 2
_BGP_TYPE_NOTIFICATION = 3
_BGP_TYPE_KEEPALIVE = 4
_BGP_TYPE_ROUTE_REFRESH = 5


def _canonicalize_bgp_from_wire(source_hex: str, fields: dict[str, JSONObject]) -> None:
    key = _last_layer_field_key(fields, "bgp")
    if key is None:
        return
    try:
        raw = bytes.fromhex(source_hex)
    except ValueError:
        return
    offset = _bgp_offset(raw)
    if offset is None or len(raw) < offset + _BGP_HEADER_LEN:
        return
    length = int.from_bytes(raw[offset + _BGP_MARKER_LEN : offset + _BGP_MARKER_LEN + 2], "big")
    if length < _BGP_HEADER_LEN or len(raw) < offset + length:
        return

    message_type = raw[offset + _BGP_MARKER_LEN + 2]
    body = raw[offset + _BGP_HEADER_LEN : offset + length]
    bgp = fields[key]
    bgp["marker"] = {"hex": raw[offset : offset + _BGP_MARKER_LEN].hex()}
    bgp["length"] = length
    bgp["type"] = message_type
    bgp["message_type"] = _BGP_MESSAGE_TYPE_NAMES.get(message_type, message_type)

    if message_type == _BGP_TYPE_OPEN and len(body) >= 10:
        bgp["version"] = body[0]
        bgp["asn"] = int.from_bytes(body[1:3], "big")
        bgp["hold_time"] = int.from_bytes(body[3:5], "big")
        bgp["bgp_identifier"] = ".".join(str(octet) for octet in body[5:9])
        bgp["opt_param_len"] = body[9]
        bgp["optional_parameters"] = {"hex": body[10:].hex()}
    elif message_type == _BGP_TYPE_UPDATE and len(body) >= 4:
        withdrawn_len = int.from_bytes(body[0:2], "big")
        withdrawn_end = min(2 + withdrawn_len, len(body))
        bgp["withdrawn_routes_len"] = withdrawn_len
        bgp["withdrawn_routes"] = {"hex": body[2:withdrawn_end].hex()}
        if len(body) >= withdrawn_end + 2:
            path_attr_len = int.from_bytes(body[withdrawn_end : withdrawn_end + 2], "big")
            attr_start = withdrawn_end + 2
            attr_end = min(attr_start + path_attr_len, len(body))
            bgp["path_attr_len"] = path_attr_len
            bgp["path_attributes"] = {"hex": body[attr_start:attr_end].hex()}
            bgp["nlri"] = {"hex": body[attr_end:].hex()}
    elif message_type == _BGP_TYPE_NOTIFICATION and len(body) >= 2:
        bgp["error_code"] = body[0]
        bgp["error_subcode"] = body[1]
        bgp["data"] = {"hex": body[2:].hex()}
    elif message_type == _BGP_TYPE_ROUTE_REFRESH and len(body) >= 4:
        bgp["afi"] = int.from_bytes(body[0:2], "big")
        bgp["subtype"] = body[2]
        bgp["safi"] = body[3]
        if len(body) > 4:
            bgp["orf_data"] = {"hex": body[4:].hex()}


# RIPng (RFC 2080) over UDP port 521. Scapy has no native RIPng dissector, so a
# RIPng message rides Scapy as an opaque ``Raw`` payload; the generic layer loop
# therefore emits ``ipv6 / udp / payload`` instead of the ``ripng`` layer that
# libcrafter decodes. This canonicalizer reconstructs the neutral ``ripng`` layer
# (matching the libcrafter ``Ripng``/``RipngRte`` decode field shape) directly
# from the wire bytes so the offline ``reference_to_libcrafter`` decode compares
# cleanly, mirroring how ``_canonicalize_bgp_from_wire`` rebuilds BGP from bytes.
# This is the documented backend-limitation fallback (parser decode from wire +
# libcrafter round-trip), not a silent skip; the IPv4 RIP path (``_canonicalize_
# rip``) is untouched because Scapy dissects RIP natively.
_RIPNG_UDP_PORT = 521
_RIPNG_RTE_LEN = 20
_RIPNG_NEXT_HOP_METRIC = 0xFF


def _canonicalize_ripng(
    packet: Any,
    layers: list[str],
    fields: dict[str, JSONObject],
) -> None:
    udp_layer = _scapy_layer(packet, "UDP")
    if udp_layer is None:
        return
    if (
        _rip_int(getattr(udp_layer, "dport", 0)) != _RIPNG_UDP_PORT
        and _rip_int(getattr(udp_layer, "sport", 0)) != _RIPNG_UDP_PORT
    ):
        return
    if not layers or layers[-1] != "payload":
        return

    raw_layer = _scapy_layer(packet, "Raw")
    body = _rip_bytes(getattr(raw_layer, "load", b"")) if raw_layer is not None else b""
    if len(body) < 4:
        return

    ripng_fields: JSONObject = {
        "command": body[0],
        "version": body[1],
        "reserved": int.from_bytes(body[2:4], "big"),
    }
    rtes: list[JSONObject] = []
    offset = 4
    while offset + _RIPNG_RTE_LEN <= len(body):
        rte = body[offset : offset + _RIPNG_RTE_LEN]
        metric = rte[19]
        rtes.append(
            {
                "prefix": ipaddress.IPv6Address(rte[0:16]).compressed,
                "route_tag": int.from_bytes(rte[16:18], "big"),
                "prefix_len": rte[18],
                "metric": metric,
                "next_hop": metric == _RIPNG_NEXT_HOP_METRIC,
            }
        )
        offset += _RIPNG_RTE_LEN
    ripng_fields["rtes"] = rtes

    # Rename the trailing payload layer to ripng so the decoded layer lists match
    # ([ipv6, udp, ripng]); drop the old payload field entry and attach the
    # reconstructed ripng fields under the recomputed key.
    payload_index = len(layers) - 1
    payload_key = _layer_key_at(layers, payload_index)
    fields.pop(payload_key, None)
    layers[payload_index] = "ripng"
    ripng_key = _layer_key_at(layers, payload_index)
    fields[ripng_key] = ripng_fields


# Scapy normalized dot15d4/zigbee layer names mapped onto the libcrafter
# adapter's decoded layer names. Scapy splits the IEEE 802.15.4 MAC header
# (Dot15d4FCS) and the addressing fields (Dot15d4Data) into two layers that both
# normalize to ``dot15d4``; libcrafter decodes the MAC frame as a single
# ``Dot15d4`` layer, so the leading run of ``dot15d4`` entries collapses to one.
_DOT15D4_ZIGBEE_LIBCRAFTER_NAMES: dict[str, str] = {
    "dot15d4": "Dot15d4",
    "dot15d4_radio": "Dot15d4Radio",
    "zigbee_nwk": "ZigbeeNwk",
    "zigbee_aps": "ZigbeeAps",
}


def _canonicalize_dot15d4_zigbee(
    layers: list[str],
    fields: dict[str, JSONObject],
) -> None:
    """Align the IEEE 802.15.4 / Zigbee decode model with the libcrafter adapter.

    Scapy dissects the MAC frame as Dot15d4FCS + Dot15d4Data (two ``dot15d4``
    entries) and exposes rich per-layer fields; the libcrafter oracle decode
    adapter reports a single ``Dot15d4`` layer plus ``ZigbeeNwk`` / ``ZigbeeAps``
    with header-only field models. Collapse the consecutive ``dot15d4`` run into
    one ``Dot15d4`` layer, rename the Zigbee sublayers to the libcrafter names,
    and present header-only (empty) comparison fields so the cross-backend
    decoded model matches without weakening the strict-byte (``source_hex``)
    comparison. The full scapy field detail stays inspectable on the decoded
    model metadata (``native``). Mirrors the DNS/RIP normalization precedent that
    shapes the scapy reference model to the current libcrafter decode model.
    """

    if not any(layer in _DOT15D4_ZIGBEE_LIBCRAFTER_NAMES for layer in layers):
        return

    new_layers: list[str] = []
    new_fields: dict[str, JSONObject] = {}
    previous_was_dot15d4 = False
    for index, layer in enumerate(layers):
        key = _layer_key_at(layers, index)
        if layer in ("dot15d4", "dot15d4_radio"):
            # Collapse the Dot15d4FCS + Dot15d4Data run into a single MAC layer.
            if layer == "dot15d4" and previous_was_dot15d4:
                continue
            mapped = _DOT15D4_ZIGBEE_LIBCRAFTER_NAMES[layer]
            new_layers.append(mapped)
            new_fields[_layer_key_at(new_layers, len(new_layers) - 1)] = {}
            previous_was_dot15d4 = layer == "dot15d4"
            continue
        previous_was_dot15d4 = False
        mapped = _DOT15D4_ZIGBEE_LIBCRAFTER_NAMES.get(layer, layer)
        new_layers.append(mapped)
        new_key = _layer_key_at(new_layers, len(new_layers) - 1)
        new_fields[new_key] = {} if mapped in _DOT15D4_ZIGBEE_LIBCRAFTER_NAMES.values() else fields.get(key, {})

    layers[:] = new_layers
    fields.clear()
    fields.update(new_fields)


def _bgp_offset(raw: bytes) -> int | None:
    if not raw:
        return None
    version = raw[0] >> 4
    if version == 4:
        if len(raw) < 20:
            return None
        ip_header_len = (raw[0] & 0x0F) * 4
        tcp_offset_index = ip_header_len + 12
        if len(raw) <= tcp_offset_index:
            return None
        tcp_header_len = (raw[tcp_offset_index] >> 4) * 4
        return ip_header_len + tcp_header_len
    if version == 6:
        tcp_offset_index = 40 + 12
        if len(raw) <= tcp_offset_index:
            return None
        tcp_header_len = (raw[tcp_offset_index] >> 4) * 4
        return 40 + tcp_header_len
    return None


def _normalize_dns_fields(fields: JSONObject) -> JSONObject:
    aliases = {
        "id": "transaction_id",
        "qr": "is_response",
        "rcode": "response_code",
        "aa": "authoritative",
        "tc": "truncated",
        "rd": "recursion_desired",
        "ra": "recursion_available",
        "ad": "authenticated_data",
        "cd": "checking_disabled",
        "qdcount": "question_count",
        "ancount": "answer_count",
        "nscount": "authority_count",
        "arcount": "additional_count",
    }
    output: JSONObject = {}
    for native_name, value in fields.items():
        if native_name in {"qd", "an", "ns", "ar"}:
            continue
        normalized_name = aliases.get(native_name, _normalize_field_name("dns", native_name))
        if normalized_name in {
            "authoritative",
            "truncated",
            "recursion_desired",
            "recursion_available",
            "authenticated_data",
            "checking_disabled",
            "is_response",
        }:
            output[normalized_name] = _bool_flag(value)
        else:
            output[normalized_name] = _normalize_field_value("dns", normalized_name, value)
    return output


# DNS record-type codes used to drive RDATA normalization. These are the wire
# codepoints implemented in the feature worktree; everything else normalizes as
# raw RDATA so unknown or intentionally deferred types never get misdecoded.
_DNS_TYPE_A = 1
_DNS_TYPE_NS = 2
_DNS_TYPE_CNAME = 5
_DNS_TYPE_SOA = 6
_DNS_TYPE_PTR = 12
_DNS_TYPE_MX = 15
_DNS_TYPE_TXT = 16
_DNS_TYPE_AAAA = 28
_DNS_TYPE_SRV = 33
_DNS_TYPE_OPT = 41
_DNS_TYPE_DS = 43
_DNS_TYPE_RRSIG = 46
_DNS_TYPE_NSEC = 47
_DNS_TYPE_DNSKEY = 48
_DNS_TYPE_NSEC3 = 50
_DNS_TYPE_SVCB = 64
_DNS_TYPE_HTTPS = 65
_DNS_NAME_TARGET_TYPES = frozenset({_DNS_TYPE_NS, _DNS_TYPE_CNAME, _DNS_TYPE_PTR})


def _normalize_dns_message(packet: Any) -> JSONObject | None:
    """Build the backend-neutral normalized DNS message from a Scapy packet.

    Returns ``None`` when the packet carries no DNS layer. The model mirrors the
    ``normalized_model`` contract in specs/features/dns-behavior.yaml: a header,
    the four sections (questions, answers, authorities, additionals), and typed
    or raw RDATA per record. Names use libcrafter's trailing-dot presentation
    form with RFC 1035 Section 5.1 ``\\DDD`` escapes, and raw RDATA is rendered
    as lowercase hex so both backends compare consistently.
    """

    dns = _find_dns_layer(packet)
    if dns is None:
        return None
    return {
        "header": _normalize_dns_header(dns),
        "questions": [
            _normalize_dns_question(question)
            for question in _dns_section_records(dns, "qd")
        ],
        "answers": [
            _normalize_dns_record(record) for record in _dns_section_records(dns, "an")
        ],
        "authorities": [
            _normalize_dns_record(record) for record in _dns_section_records(dns, "ns")
        ],
        "additionals": [
            _normalize_dns_record(record) for record in _dns_section_records(dns, "ar")
        ],
    }


def _find_dns_layer(packet: Any) -> Any:
    current = packet
    while current is not None and current.__class__.__name__ != "NoPayload":
        if current.__class__.__name__ == "DNS":
            return current
        current = getattr(current, "payload", None)
    return None


def _normalize_dns_header(dns: Any) -> JSONObject:
    flags_word = _dns_flags_word(dns)
    return {
        "transaction_id": _dns_int(getattr(dns, "id", 0)),
        "is_response": bool(_dns_int(getattr(dns, "qr", 0))),
        "opcode": _dns_int(getattr(dns, "opcode", 0)),
        "authoritative": bool(_dns_int(getattr(dns, "aa", 0))),
        "truncated": bool(_dns_int(getattr(dns, "tc", 0))),
        "recursion_desired": bool(_dns_int(getattr(dns, "rd", 0))),
        "recursion_available": bool(_dns_int(getattr(dns, "ra", 0))),
        "authentic_data": bool(_dns_int(getattr(dns, "ad", 0))),
        "checking_disabled": bool(_dns_int(getattr(dns, "cd", 0))),
        "reserved_z": (flags_word >> 6) & 0x01,
        "response_code": _dns_int(getattr(dns, "rcode", 0)),
        "question_count": _dns_int(getattr(dns, "qdcount", 0)),
        "answer_count": _dns_int(getattr(dns, "ancount", 0)),
        "authority_count": _dns_int(getattr(dns, "nscount", 0)),
        "additional_count": _dns_int(getattr(dns, "arcount", 0)),
    }


def _dns_flags_word(dns: Any) -> int:
    word = _dns_int(getattr(dns, "qr", 0)) << 15
    word |= (_dns_int(getattr(dns, "opcode", 0)) & 0x0F) << 11
    word |= _dns_int(getattr(dns, "aa", 0)) << 10
    word |= _dns_int(getattr(dns, "tc", 0)) << 9
    word |= _dns_int(getattr(dns, "rd", 0)) << 8
    word |= _dns_int(getattr(dns, "ra", 0)) << 7
    word |= _dns_int(getattr(dns, "z", 0)) << 6
    word |= _dns_int(getattr(dns, "ad", 0)) << 5
    word |= _dns_int(getattr(dns, "cd", 0)) << 4
    word |= _dns_int(getattr(dns, "rcode", 0)) & 0x0F
    return word


def _dns_section_records(dns: Any, attr: str) -> list[Any]:
    records = getattr(dns, attr, None)
    if records is None:
        return []
    if isinstance(records, (list, tuple)):
        return [record for record in records if record is not None]
    return [records]


def _normalize_dns_question(question: Any) -> JSONObject:
    return {
        "name": _normalize_dns_name(getattr(question, "qname", b"")),
        "record_type": _dns_int(getattr(question, "qtype", 0)),
        "record_class": _dns_int(getattr(question, "qclass", 0)),
    }


def _normalize_dns_record(record: Any) -> JSONObject:
    record_type = _dns_int(getattr(record, "type", 0))
    normalized: JSONObject = {
        "name": _normalize_dns_name(getattr(record, "rrname", b"")),
        "record_type": record_type,
        "record_class": _dns_int(getattr(record, "rclass", 0)),
        "ttl": _dns_int(getattr(record, "ttl", 0)),
        "rdata": _normalize_dns_rdata(record, record_type),
    }
    return normalized


def _normalize_dns_rdata(record: Any, record_type: int) -> JSONObject:
    if record_type in (_DNS_TYPE_A, _DNS_TYPE_AAAA):
        return {"address": _dns_text(getattr(record, "rdata", ""))}
    if record_type in _DNS_NAME_TARGET_TYPES:
        return {"target": _normalize_dns_name(getattr(record, "rdata", b""))}
    if record_type == _DNS_TYPE_MX:
        return {
            "preference": _dns_int(getattr(record, "preference", 0)),
            "exchange": _normalize_dns_name(getattr(record, "exchange", b"")),
        }
    if record_type == _DNS_TYPE_TXT:
        return {"strings": _normalize_dns_txt_strings(getattr(record, "rdata", []))}
    if record_type == _DNS_TYPE_SOA:
        return {
            "primary_name": _normalize_dns_name(getattr(record, "mname", b"")),
            "responsible_name": _normalize_dns_name(getattr(record, "rname", b"")),
            "serial": _dns_int(getattr(record, "serial", 0)),
            "refresh": _dns_int(getattr(record, "refresh", 0)),
            "retry": _dns_int(getattr(record, "retry", 0)),
            "expire": _dns_int(getattr(record, "expire", 0)),
            "minimum": _dns_int(getattr(record, "minimum", 0)),
        }
    if record_type == _DNS_TYPE_SRV:
        return {
            "priority": _dns_int(getattr(record, "priority", 0)),
            "weight": _dns_int(getattr(record, "weight", 0)),
            "port": _dns_int(getattr(record, "port", 0)),
            "target": _normalize_dns_name(getattr(record, "target", b"")),
        }
    if record_type == _DNS_TYPE_OPT:
        return _normalize_dns_opt(record)
    if record_type == _DNS_TYPE_DS:
        return {
            "key_tag": _dns_int(getattr(record, "keytag", 0)),
            "algorithm": _dns_int(getattr(record, "algorithm", 0)),
            "digest_type": _dns_int(getattr(record, "digesttype", 0)),
            "digest": _dns_hex(getattr(record, "digest", b"")),
        }
    if record_type == _DNS_TYPE_DNSKEY:
        return {
            "flags": _dns_int(getattr(record, "flags", 0)),
            "protocol": _dns_int(getattr(record, "protocol", 0)),
            "algorithm": _dns_int(getattr(record, "algorithm", 0)),
            "public_key": _dns_hex(getattr(record, "publickey", b"")),
        }
    if record_type == _DNS_TYPE_RRSIG:
        return {
            "type_covered": _dns_int(getattr(record, "typecovered", 0)),
            "algorithm": _dns_int(getattr(record, "algorithm", 0)),
            "labels": _dns_int(getattr(record, "labels", 0)),
            "original_ttl": _dns_int(getattr(record, "originalttl", 0)),
            "signature_expiration": _dns_int(getattr(record, "expiration", 0)),
            "signature_inception": _dns_int(getattr(record, "inception", 0)),
            "key_tag": _dns_int(getattr(record, "keytag", 0)),
            "signer_name": _normalize_dns_name(getattr(record, "signersname", b"")),
            "signature": _dns_hex(getattr(record, "signature", b"")),
        }
    if record_type == _DNS_TYPE_NSEC:
        return {
            "next_name": _normalize_dns_name(getattr(record, "nextname", b"")),
            "type_bitmaps": _dns_hex(getattr(record, "typebitmaps", b"")),
        }
    if record_type == _DNS_TYPE_NSEC3:
        return {
            "hash_algorithm": _dns_int(getattr(record, "hashalg", 0)),
            "flags": _dns_int(getattr(record, "flags", 0)),
            "iterations": _dns_int(getattr(record, "iterations", 0)),
            "salt": _dns_hex(getattr(record, "salt", b"")),
            "next_hashed_owner": _dns_hex(getattr(record, "nexthashedownername", b"")),
            "type_bitmaps": _dns_hex(getattr(record, "typebitmaps", b"")),
        }
    if record_type in (_DNS_TYPE_SVCB, _DNS_TYPE_HTTPS):
        return {
            "priority": _dns_int(getattr(record, "svc_priority", 0)),
            "target": _normalize_dns_name(getattr(record, "target_name", b"")),
            "params": _normalize_dns_svc_params(getattr(record, "svc_params", [])),
        }
    return {"record_type": record_type, "data": _dns_hex(getattr(record, "rdata", b""))}


def _normalize_dns_opt(record: Any) -> JSONObject:
    # The OPT pseudo-record stores EDNS state in ordinary record header fields:
    # CLASS carries the UDP payload size, the upper TTL byte carries the extended
    # RCODE, then VERSION, the DO flag, and the remaining Z bits.
    rclass = _dns_int(getattr(record, "rclass", 0))
    z_word = _dns_int(getattr(record, "z", 0))
    return {
        "udp_payload_size": rclass,
        "extended_rcode": _dns_int(getattr(record, "extrcode", 0)),
        "version": _dns_int(getattr(record, "version", 0)),
        "dnssec_ok": bool(z_word & 0x8000),
        "z_bits": z_word & 0x7FFF,
        "options": _normalize_dns_edns_options(getattr(record, "rdata", [])),
    }


def _normalize_dns_edns_options(value: Any) -> list[JSONObject]:
    options: list[JSONObject] = []
    for option in _dns_iter(value):
        options.append(
            {
                "option_code": _dns_int(getattr(option, "optcode", 0)),
                "option_data": _dns_hex(_dns_edns_option_data(option)),
            }
        )
    return options


def _dns_edns_option_data(option: Any) -> bytes:
    # Scapy dissects known EDNS options (COOKIE, ECS, ...) into typed subclasses
    # rather than a flat optdata blob. Re-serialize the option payload so the
    # normalized option_data is the raw wire bytes regardless of the subclass.
    raw_option = getattr(option, "optdata", None)
    if isinstance(raw_option, (bytes, bytearray)):
        return bytes(raw_option)
    try:
        encoded = bytes(option)
    except Exception:  # pragma: no cover - Scapy exception types vary.
        return b""
    # EDNS0TLV layout: 2-byte optcode, 2-byte optlen, then optlen bytes of data.
    if len(encoded) >= 4:
        return encoded[4:]
    return b""


def _normalize_dns_svc_params(value: Any) -> list[JSONObject]:
    params: list[JSONObject] = []
    for param in _dns_iter(value):
        params.append(
            {
                "key": _dns_int(getattr(param, "key", 0)),
                "value": _dns_hex(_dns_svc_param_value(param)),
            }
        )
    return params


def _dns_svc_param_value(param: Any) -> bytes:
    value = getattr(param, "value", b"")
    return _dns_concat_bytes(value)


def _normalize_dns_txt_strings(value: Any) -> list[JSONObject]:
    strings = value
    if isinstance(strings, (bytes, bytearray, str)):
        strings = [strings]
    output: list[JSONObject] = []
    for item in _dns_iter(strings):
        output.append({"hex": _dns_hex(item)})
    return output


def _normalize_dns_name(value: Any) -> JSONObject:
    raw = _dns_name_bytes(value)
    labels = _dns_name_labels(raw)
    presentation = _dns_labels_to_presentation(labels)
    return {
        "labels": [_dns_hex(label) for label in labels],
        "presentation": presentation,
        "is_root": presentation == ".",
    }


def _dns_name_bytes(value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8", "surrogateescape")
    if value is None:
        return b""
    return _text(value).encode("utf-8", "surrogateescape")


def _dns_name_labels(raw: bytes) -> list[bytes]:
    # Scapy presents a decoded name as the labels joined by ``.`` with a trailing
    # ``.``. Split on the dot separators to recover labels; an empty input or a
    # bare ``.`` is the root name (no labels).
    if not raw or raw == b".":
        return []
    trimmed = raw[:-1] if raw.endswith(b".") else raw
    if not trimmed:
        return []
    return trimmed.split(b".")


def _dns_labels_to_presentation(labels: Sequence[bytes]) -> str:
    if not labels:
        return "."
    out: list[str] = []
    for label in labels:
        for byte in label:
            if 0x20 < byte < 0x7F and byte not in (0x2E, 0x5C):
                out.append(chr(byte))
            else:
                out.append(f"\\{byte:03d}")
        out.append(".")
    return "".join(out)


def _dns_concat_bytes(value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, (list, tuple)):
        chunks = bytearray()
        for item in value:
            chunks.extend(_dns_concat_bytes(item))
        return bytes(chunks)
    if isinstance(value, str):
        return value.encode("utf-8", "surrogateescape")
    if value is None:
        return b""
    return _text(value).encode("utf-8", "surrogateescape")


def _dns_iter(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [item for item in value if item is not None]
    return [value]


def _dns_hex(value: Any) -> str:
    return _dns_concat_bytes(value).hex()


def _dns_text(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    if value is None:
        return ""
    return _text(value)


def _dns_int(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _normalize_dhcp_fields(fields: JSONObject) -> JSONObject:
    aliases = {
        "op": "opcode",
        "htype": "hardware_type",
        "hlen": "hardware_length",
        "xid": "transaction_id",
        "secs": "seconds",
        "ciaddr": "client_ip",
        "yiaddr": "your_ip",
        "siaddr": "server_ip",
        "giaddr": "relay_ip",
        "chaddr": "client_hardware_address",
    }
    option_region_hex = fields.get(_DHCP_OPTION_REGION_KEY)
    output: JSONObject = {}
    for native_name, value in fields.items():
        if native_name in {"sname", "file", _DHCP_OPTION_REGION_KEY}:
            continue
        if native_name == "options" and isinstance(value, list):
            output["option_count"] = len(value)
            continue
        normalized_name = aliases.get(native_name, _normalize_field_name("dhcp", native_name))
        output[normalized_name] = _normalize_field_value("dhcp", normalized_name, value)
    if "client_hardware_address" in output:
        output["client_hardware_address"] = _normalize_dhcp_chaddr(
            output["client_hardware_address"],
            output.get("hardware_length"),
        )
    options = output.get("options")
    if isinstance(options, Mapping) and options.get("hex") == "63825363":
        output["magic_cookie"] = 0x63825363
        output.pop("options", None)
    if isinstance(option_region_hex, str):
        _apply_dhcp_option_details(output, option_region_hex)
    return output


def _apply_dhcp_option_details(output: JSONObject, option_region_hex: str) -> None:
    """Record backend-neutral DHCP option details from the raw TLV region.

    Each option is normalized to a stable ``{code, payload_hex}`` pair carrying
    the raw option payload (no typed reinterpretation), which compares cleanly
    against the libcrafter decoded option view regardless of how either backend
    types the value. The message type (option 53) is also surfaced as an integer
    so option coverage records it directly rather than only as a count.
    """

    options = _decode_dhcp_option_tlvs(option_region_hex)
    if options is None:
        return
    output["options"] = options
    output["option_count"] = len(options)
    for option in options:
        if option["code"] == _DHCP_OPTION_MESSAGE_TYPE:
            payload = bytes.fromhex(option["payload_hex"])
            if len(payload) == 1:
                output["message_type"] = payload[0]
            break


def _decode_dhcp_option_tlvs(option_region_hex: str) -> list[JSONObject] | None:
    """Parse a DHCP option TLV region into ``{code, payload_hex}`` entries.

    Pad (0) and end (255) are single-octet options with empty payloads. A
    truncated or malformed region returns ``None`` so the raw typed option list
    handling is preserved instead of emitting partial option details.
    """

    try:
        raw = bytes.fromhex(option_region_hex)
    except ValueError:
        return None
    options: list[JSONObject] = []
    index = 0
    length = len(raw)
    while index < length:
        code = raw[index]
        index += 1
        if code == _DHCP_OPTION_PAD:
            options.append({"code": code, "payload_hex": ""})
            continue
        if code == _DHCP_OPTION_END:
            options.append({"code": code, "payload_hex": ""})
            break
        if index >= length:
            return None
        option_length = raw[index]
        index += 1
        if index + option_length > length:
            return None
        payload = raw[index : index + option_length]
        index += option_length
        options.append({"code": code, "payload_hex": payload.hex()})
    return options


def _normalize_field_name(layer_name: str, native_name: str) -> str:
    layer_aliases = _LAYER_FIELD_ALIASES.get(layer_name, {})
    return layer_aliases.get(native_name, _FIELD_ALIASES.get(native_name, native_name))


def _normalize_field_value(layer_name: str, field_name: str, value: JSONValue) -> JSONValue:
    if layer_name == "linux_sll" and field_name == "source_address":
        return _normalize_linux_sll_source_address(value)
    if field_name == "flags":
        if layer_name == "dhcp":
            return _normalize_dhcp_flags(value)
        return _normalize_flags(value)
    if field_name == "is_response" and isinstance(value, int):
        return bool(value)
    if field_name in {"more_fragments"} and isinstance(value, int):
        return bool(value)
    return value


def _normalize_dhcp_flags(value: JSONValue) -> JSONValue:
    if value == "B":
        return 0x8000
    if value in {"", "none", "0"}:
        return 0
    return _normalize_flags(value)


def _normalize_dhcp_chaddr(value: JSONValue, hardware_length: JSONValue) -> JSONValue:
    if not isinstance(value, Mapping):
        return value
    hex_value = value.get("hex")
    if not isinstance(hex_value, str):
        return value
    length = hardware_length if isinstance(hardware_length, int) else 6
    return {"hex": hex_value[: length * 2]}


# IGMP over IPv4 protocol number 2. Scapy does not expose all IGMP contrib
# classes through scapy.all consistently, so normalize the IPv4 payload bytes
# directly into the same backend-neutral layer names that libcrafter reports.
_IGMP_PROTOCOL = 2
_IGMP_TYPE_MEMBERSHIP_QUERY = 0x11
_IGMP_TYPE_V3_MEMBERSHIP_REPORT = 0x22
_IGMP_TYPE_MRD_ADVERTISEMENT = 0x30
_IGMP_MRD_SHORT_TYPES = frozenset({0x31, 0x32})
_IGMP_QUERY_EXTENSION_FLAG = 0x80
_IGMP_QUERY_SUPPRESS_FLAG = 0x08
_IGMP_REPORT_EXTENSION_FLAG = 0x8000

_IGMP_TYPE_LABELS: dict[int, str] = {
    0x00: "reserved",
    0x11: "membership_query",
    0x12: "v1_membership_report",
    0x13: "dvmrp_unsupported_assigned",
    0x14: "pim_v1_unsupported_assigned",
    0x15: "cisco_trace_unsupported_assigned",
    0x16: "v2_membership_report",
    0x17: "v2_leave_group",
    0x1E: "multicast_traceroute_response_unsupported_assigned",
    0x1F: "multicast_traceroute_unsupported_assigned",
    0x22: "v3_membership_report",
    0x30: "multicast_router_advertisement",
    0x31: "multicast_router_solicitation",
    0x32: "multicast_router_termination",
}
_IGMP_RECORD_TYPE_LABELS: dict[int, str] = {
    0: "reserved",
    1: "mode_is_include",
    2: "mode_is_exclude",
    3: "change_to_include_mode",
    4: "change_to_exclude_mode",
    5: "allow_new_sources",
    6: "block_old_sources",
}


def _canonicalize_igmp(
    packet: Any,
    layers: list[str],
    fields: dict[str, JSONObject],
) -> None:
    """Rebuild Scapy's opaque IPv4 protocol-2 payload as IGMP layers."""

    if "ipv4" not in layers:
        return
    igmp_raw = _igmp_payload_from_ipv4(packet)
    if igmp_raw is None or len(igmp_raw) < 4:
        return

    ipv4_index = layers.index("ipv4")
    for offset in range(ipv4_index + 1, len(layers)):
        fields.pop(_layer_key_at(layers, offset), None)
    del layers[ipv4_index + 1 :]

    type_code = igmp_raw[0]
    header_len = _igmp_header_len(type_code, len(igmp_raw))
    igmp_fields = _igmp_base_fields(igmp_raw, header_len)
    _append_normalized_layer(layers, fields, "igmp", igmp_fields)

    if len(igmp_raw) < header_len:
        return

    body = igmp_raw[header_len:]
    if type_code == _IGMP_TYPE_MEMBERSHIP_QUERY:
        _append_igmp_query_layers(layers, fields, body)
    elif type_code == _IGMP_TYPE_V3_MEMBERSHIP_REPORT:
        _append_igmp_report_layers(layers, fields, body)
    elif body:
        _append_normalized_layer(layers, fields, "payload", _payload_fields_from_bytes(body))


def _igmp_payload_from_ipv4(packet: Any) -> bytes | None:
    ip_layer = _scapy_layer(packet, "IP")
    if ip_layer is None or _igmp_int(getattr(ip_layer, "proto", None)) != _IGMP_PROTOCOL:
        return None
    try:
        ip_raw = bytes(import_scapy()["all"].raw(ip_layer))
    except Exception:  # pragma: no cover - Scapy exception types vary.
        return None
    if len(ip_raw) < 20:
        return None
    header_len = (ip_raw[0] & 0x0F) * 4
    if header_len < 20 or len(ip_raw) < header_len:
        return None
    total_len = int.from_bytes(ip_raw[2:4], "big")
    if total_len < header_len:
        return None
    if total_len == 0 or total_len > len(ip_raw):
        total_len = len(ip_raw)
    return ip_raw[header_len:total_len]


def _igmp_header_len(type_code: int, available: int) -> int:
    if type_code in _IGMP_MRD_SHORT_TYPES:
        return 4
    return 8 if available >= 8 else available


def _igmp_base_fields(raw: bytes, header_len: int) -> JSONObject:
    type_code = raw[0]
    fields: JSONObject = {
        "type": type_code,
        "type_label": _igmp_type_label(type_code),
        "code": raw[1],
        "code_label": _igmp_code_label(type_code, raw[1]),
        "checksum": int.from_bytes(raw[2:4], "big"),
        "checksum_status": "valid" if _internet_checksum(raw) == 0 else "invalid",
    }
    if header_len >= 8:
        if type_code == _IGMP_TYPE_MRD_ADVERTISEMENT:
            fields["mrd_query_interval"] = int.from_bytes(raw[4:6], "big")
            fields["mrd_robustness_variable"] = int.from_bytes(raw[6:8], "big")
        else:
            fields["group_address"] = _ipv4_text(raw[4:8])
    return fields


def _append_igmp_query_layers(
    layers: list[str],
    fields: dict[str, JSONObject],
    body: bytes,
) -> None:
    if not body:
        return
    if len(body) < 4:
        _append_normalized_layer(layers, fields, "payload", _payload_fields_from_bytes(body))
        return

    flags = body[0]
    source_count = int.from_bytes(body[2:4], "big")
    cursor = 4
    sources: list[str] = []
    for _ in range(source_count):
        if cursor + 4 > len(body):
            break
        sources.append(_ipv4_text(body[cursor : cursor + 4]))
        cursor += 4

    query_fields: JSONObject = {
        "query_flags": flags,
        "query_flag_labels": _igmp_query_flag_labels(flags),
        "suppress_router_side_processing": bool(flags & _IGMP_QUERY_SUPPRESS_FLAG),
        "querier_robustness_variable": flags & 0x07,
        "qqic": body[1],
        "number_of_sources": source_count,
        "source_addresses": sources,
    }
    _append_normalized_layer(layers, fields, "igmp_query", query_fields)

    tail = body[cursor:]
    if len(sources) != source_count:
        if tail:
            _append_normalized_layer(layers, fields, "payload", _payload_fields_from_bytes(tail))
        return
    if flags & _IGMP_QUERY_EXTENSION_FLAG:
        _append_igmp_extensions_or_payload(layers, fields, tail)
    elif tail:
        _append_normalized_layer(layers, fields, "payload", _payload_fields_from_bytes(tail))


def _append_igmp_report_layers(
    layers: list[str],
    fields: dict[str, JSONObject],
    body: bytes,
) -> None:
    if len(body) < 4:
        if body:
            _append_normalized_layer(layers, fields, "payload", _payload_fields_from_bytes(body))
        return

    report_flags = int.from_bytes(body[0:2], "big")
    record_count = int.from_bytes(body[2:4], "big")
    cursor = 4
    records: list[JSONObject] = []
    complete = True
    for _ in range(record_count):
        record, next_cursor = _decode_igmp_group_record(body, cursor)
        if record is None:
            complete = False
            break
        records.append(record)
        cursor = next_cursor

    report_fields: JSONObject = {
        "report_flags": report_flags,
        "report_flag_labels": _igmp_report_flag_labels(report_flags),
        "number_of_group_records": record_count,
        "group_records": records,
    }
    _append_normalized_layer(layers, fields, "igmp_report", report_fields)

    tail = body[cursor:]
    if not complete:
        if tail:
            _append_normalized_layer(layers, fields, "payload", _payload_fields_from_bytes(tail))
        return
    if report_flags & _IGMP_REPORT_EXTENSION_FLAG:
        _append_igmp_extensions_or_payload(layers, fields, tail)
    elif tail:
        _append_normalized_layer(layers, fields, "payload", _payload_fields_from_bytes(tail))


def _decode_igmp_group_record(body: bytes, offset: int) -> tuple[JSONObject | None, int]:
    if offset + 8 > len(body):
        return None, offset
    record_type = body[offset]
    aux_words = body[offset + 1]
    source_count = int.from_bytes(body[offset + 2 : offset + 4], "big")
    multicast_address = _ipv4_text(body[offset + 4 : offset + 8])
    cursor = offset + 8

    sources: list[str] = []
    for _ in range(source_count):
        if cursor + 4 > len(body):
            return None, offset
        sources.append(_ipv4_text(body[cursor : cursor + 4]))
        cursor += 4

    auxiliary_len = aux_words * 4
    if cursor + auxiliary_len > len(body):
        return None, offset
    auxiliary = body[cursor : cursor + auxiliary_len]
    cursor += auxiliary_len
    return (
        {
            "record_type": record_type,
            "record_type_label": _igmp_record_type_label(record_type),
            "auxiliary_data_len": aux_words,
            "number_of_sources": source_count,
            "multicast_address": multicast_address,
            "source_addresses": sources,
            "auxiliary_data": _igmp_bytes_fields(auxiliary),
        },
        cursor,
    )


def _append_igmp_extensions_or_payload(
    layers: list[str],
    fields: dict[str, JSONObject],
    tail: bytes,
) -> None:
    cursor = 0
    while cursor < len(tail):
        if cursor + 4 > len(tail):
            _append_normalized_layer(layers, fields, "payload", _payload_fields_from_bytes(tail[cursor:]))
            return
        extension_type = int.from_bytes(tail[cursor : cursor + 2], "big")
        extension_length = int.from_bytes(tail[cursor + 2 : cursor + 4], "big")
        value_start = cursor + 4
        value_end = value_start + extension_length
        if value_end > len(tail):
            _append_normalized_layer(layers, fields, "payload", _payload_fields_from_bytes(tail[cursor:]))
            return
        value = tail[value_start:value_end]
        _append_normalized_layer(
            layers,
            fields,
            "igmp_extension",
            {
                "extension_type": extension_type,
                "extension_type_label": _igmp_extension_type_label(extension_type),
                "extension_length": extension_length,
                "extension_value": _igmp_bytes_fields(value),
            },
        )
        cursor = value_end


def _igmp_type_label(type_code: int) -> str:
    if type_code in _IGMP_TYPE_LABELS:
        return _IGMP_TYPE_LABELS[type_code]
    if 0xF0 <= type_code <= 0xFF:
        return "experimental"
    return "unassigned"


def _igmp_code_label(type_code: int, code: int) -> str:
    if type_code == _IGMP_TYPE_MEMBERSHIP_QUERY:
        if code == 0:
            return "v1_query_zero"
        return "v2_or_v3_max_response_code"
    if type_code == _IGMP_TYPE_MRD_ADVERTISEMENT:
        return "mrd_advertisement_interval"
    if type_code in _IGMP_MRD_SHORT_TYPES:
        return "mrd_reserved" if code == 0 else "explicit_override"
    return "reserved_zero" if code == 0 else "explicit_override"


def _igmp_record_type_label(record_type: int) -> str:
    return _IGMP_RECORD_TYPE_LABELS.get(record_type, "unknown")


def _igmp_extension_type_label(extension_type: int) -> str:
    if extension_type == 0:
        return "noop"
    if extension_type in {0xFFFE, 0xFFFF}:
        return "experimental"
    return "unassigned"


def _igmp_query_flag_labels(flags: int) -> list[str]:
    labels: list[str] = []
    if flags & _IGMP_QUERY_EXTENSION_FLAG:
        labels.append("extension")
    if flags & 0x70:
        labels.append("unassigned")
    if flags & _IGMP_QUERY_SUPPRESS_FLAG:
        labels.append("suppress_router_side_processing")
    if flags & 0x07:
        labels.append("qrv")
    return labels


def _igmp_report_flag_labels(flags: int) -> list[str]:
    labels: list[str] = []
    if flags & _IGMP_REPORT_EXTENSION_FLAG:
        labels.append("extension")
    if flags & 0x7FFF:
        labels.append("unassigned")
    return labels


def _igmp_bytes_fields(value: bytes) -> JSONObject:
    return {
        "hex": value.hex(),
        "length": len(value),
    }


def _ipv4_text(raw: bytes) -> str:
    return ".".join(str(byte) for byte in raw)


def _igmp_int(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


# ICMPv4 query types (RFC 792/950) that carry a 16-bit identifier/sequence in
# the rest-of-header, plus the RFC 8335 extended echo types. These mirror
# libcrafter's is_query_v4 / is_extended_echo_v4 decode rules so the normalized
# Scapy model surfaces identifier/sequence on exactly the same types.
_ICMPV4_ID_SEQ_TYPES = frozenset({0, 8, 13, 14, 15, 16, 17, 18})
_ICMPV4_EXTENDED_ECHO_TYPES = frozenset({42, 43})
# ICMPv4 types that carry the RFC 4884 length byte (rest-of-header byte 1).
_ICMPV4_EXTENSION_LENGTH_TYPES = frozenset({3, 11, 12})


def _canonicalize_icmpv4(
    packet: Any,
    layers: list[str],
    fields: dict[str, JSONObject],
    *,
    root: str | None = None,
    source_hex: str | None = None,
) -> None:
    """Collapse Scapy's typed ICMPv4 decode into libcrafter's flat model.

    Scapy types the ICMPv4 rest-of-header (gateway, pointer, next-hop MTU,
    address mask, timestamps, router-discovery words) and sub-dissects ICMP
    error bodies into ``IPerror``/``Padding`` layers. libcrafter keeps a flat
    model: ``type``/``code``/``rest_of_header`` plus the query identifier and
    sequence, the RFC 4884 length byte for error types, and a single ``payload``
    layer for everything after the four-byte rest-of-header. This rebuilds the
    normalized ICMPv4 layer/fields directly from the raw ICMP bytes so both
    backends agree.
    """

    if "icmp" not in layers:
        return
    icmp_layer = _scapy_layer(packet, "ICMP")
    if icmp_layer is None:
        return
    icmp_raw = _icmpv4_wire_bytes_from_source(source_hex, root)
    if icmp_raw is None:
        try:
            icmp_raw = bytes(import_scapy()["all"].raw(icmp_layer))
        except Exception:  # pragma: no cover - Scapy exception types vary.
            return
    if len(icmp_raw) < 8:
        return

    icmp_type = icmp_raw[0]
    rest = icmp_raw[4:8]
    icmp_fields: JSONObject = {
        "type": icmp_type,
        "code": icmp_raw[1],
        "checksum": int.from_bytes(icmp_raw[2:4], "big"),
        "rest_of_header": rest.hex(),
    }
    if icmp_type in _ICMPV4_EXTENDED_ECHO_TYPES:
        icmp_fields["identifier"] = int.from_bytes(rest[0:2], "big")
        icmp_fields["sequence"] = rest[2]
    elif icmp_type in _ICMPV4_ID_SEQ_TYPES:
        icmp_fields["identifier"] = int.from_bytes(rest[0:2], "big")
        icmp_fields["sequence"] = int.from_bytes(rest[2:4], "big")
    if icmp_type in _ICMPV4_EXTENSION_LENGTH_TYPES:
        icmp_fields["length"] = rest[1]

    # Find the icmp position in the normalized layer list and drop everything
    # Scapy parsed after it; libcrafter keeps a single trailing payload.
    icmp_index = layers.index("icmp")
    icmp_key = _layer_key_at(layers, icmp_index)
    for offset in range(icmp_index + 1, len(layers)):
        fields.pop(_layer_key_at(layers, offset), None)
    del layers[icmp_index + 1 :]

    fields[icmp_key] = icmp_fields

    body = icmp_raw[8:]
    if body:
        payload_key = _field_key(fields, "payload")
        fields[payload_key] = _payload_fields_from_bytes(body)
        layers.append("payload")


def _icmpv4_wire_bytes_from_source(source_hex: str | None, root: str | None) -> bytes | None:
    if source_hex is None:
        return None
    try:
        raw = bytes.fromhex(source_hex)
    except ValueError:
        return None

    ipv4_offset = _ipv4_offset_from_source(raw, root)
    if ipv4_offset is None or len(raw) < ipv4_offset + 20:
        return None
    first = raw[ipv4_offset]
    if first >> 4 != 4:
        return None
    ihl = (first & 0x0F) * 4
    if ihl < 20 or len(raw) < ipv4_offset + ihl:
        return None
    if raw[ipv4_offset + 9] != _PROTOCOLS["icmp"]:
        return None

    total_length = int.from_bytes(raw[ipv4_offset + 2 : ipv4_offset + 4], "big")
    available = len(raw) - ipv4_offset
    if total_length < ihl:
        return None
    ipv4_end = ipv4_offset + min(total_length, available)
    icmp_offset = ipv4_offset + ihl
    if icmp_offset >= ipv4_end:
        return None
    return raw[icmp_offset:ipv4_end]


def _ipv4_offset_from_source(raw: bytes, root: str | None) -> int | None:
    canonical_root = _normalize_root_name(root) if root is not None else None
    if root in {"IP", "l2:ipv4", "l3:ipv4"} or canonical_root == "l3:ipv4":
        return 0
    if canonical_root == "link:ethernet":
        return _ethernet_ipv4_offset(raw)
    if canonical_root == "link:linux-cooked":
        if len(raw) >= 16 and int.from_bytes(raw[14:16], "big") == _ETHERTYPES["ipv4"]:
            return 16
        return None
    if canonical_root == "link:null-loopback":
        if len(raw) >= 5 and raw[4] >> 4 == 4:
            return 4
        return None
    if raw and raw[0] >> 4 == 4:
        return 0
    return None


def _ethernet_ipv4_offset(raw: bytes) -> int | None:
    if len(raw) < 14:
        return None
    ethertype = int.from_bytes(raw[12:14], "big")
    offset = 14
    while ethertype in {0x8100, 0x88A8, 0x9100}:
        if len(raw) < offset + 4:
            return None
        ethertype = int.from_bytes(raw[offset + 2 : offset + 4], "big")
        offset += 4
    if ethertype == _ETHERTYPES["ipv4"]:
        return offset
    return None


# RIP authentication entries use the reserved address-family identifier 0xFFFF
# (RFC 2453 §4.1). Everything else in a RIP message is a route entry.
_RIP_AFI_AUTH = 0xFFFF
# RFC 2453 §4.1 simple-password authentication type.
_RIP_AUTH_TYPE_SIMPLE = 2


def _canonicalize_rip(
    packet: Any,
    layers: list[str],
    fields: dict[str, JSONObject],
) -> None:
    """Collapse Scapy's typed RIP decode into libcrafter's single ``rip`` layer.

    Scapy dissects a RIP message into a ``RIP`` header layer followed by one
    ``RIPEntry``/``RIPAuth`` payload layer per 20-octet entry, so the generic
    layer loop emits ``rip`` plus standalone ``ripentry``/``ripauth`` layers.
    libcrafter exposes a single ``Rip`` layer whose route entries live under an
    ``entries`` list and whose AFI 0xFFFF authentication entry lives under
    ``auth``. This rebuilds the normalized ``rip`` layer directly from the Scapy
    sub-layers (using the spec field names ``command``/``version``/``reserved``
    and per-entry ``address_family``/``route_tag``/``address``/``subnet_mask``/
    ``next_hop``/``metric``) and drops the standalone entry layers so both
    backends compare cleanly.
    """

    if "rip" not in layers:
        return
    rip_layer = _scapy_layer(packet, "RIP")
    if rip_layer is None:
        return

    rip_fields: JSONObject = {
        "command": _rip_int(getattr(rip_layer, "cmd", 0)),
        "version": _rip_int(getattr(rip_layer, "version", 0)),
        "reserved": _rip_int(getattr(rip_layer, "null", 0)),
    }

    entries: list[JSONObject] = []
    auth: JSONObject | None = None
    current = getattr(rip_layer, "payload", None)
    while current is not None and current.__class__.__name__ != "NoPayload":
        class_name = current.__class__.__name__
        if class_name == "RIPEntry":
            entries.append(_normalize_rip_entry(current))
        elif class_name == "RIPAuth":
            auth = _normalize_rip_auth(current)
        else:
            break
        current = getattr(current, "payload", None)

    rip_fields["entries"] = entries
    if auth is not None:
        rip_fields["auth"] = auth

    rip_index = layers.index("rip")
    rip_key = _layer_key_at(layers, rip_index)

    # Drop the standalone ripentry/ripauth layers Scapy parsed after the RIP
    # header; libcrafter keeps a single rip layer carrying the same entries.
    for offset in range(rip_index + 1, len(layers)):
        if layers[offset] in {"ripentry", "ripauth"}:
            fields.pop(_layer_key_at(layers, offset), None)
        else:
            break
    trailing_start = rip_index + 1
    while trailing_start < len(layers) and layers[trailing_start] in {
        "ripentry",
        "ripauth",
    }:
        trailing_start += 1
    del layers[rip_index + 1 : trailing_start]

    fields[rip_key] = rip_fields


def _normalize_rip_entry(entry: Any) -> JSONObject:
    return {
        "address_family": _rip_int(getattr(entry, "AF", 0)),
        "route_tag": _rip_int(getattr(entry, "RouteTag", 0)),
        "address": _text(getattr(entry, "addr", "0.0.0.0")),
        "subnet_mask": _text(getattr(entry, "mask", "0.0.0.0")),
        "next_hop": _text(getattr(entry, "nextHop", "0.0.0.0")),
        "metric": _rip_int(getattr(entry, "metric", 0)),
    }


def _normalize_rip_auth(auth: Any) -> JSONObject:
    auth_type = _rip_int(getattr(auth, "authtype", 0))
    normalized: JSONObject = {
        "address_family": _RIP_AFI_AUTH,
        "auth_type": auth_type,
    }
    if auth_type == _RIP_AUTH_TYPE_SIMPLE:
        normalized["simple_password"] = {
            "hex": _rip_bytes(getattr(auth, "password", b"")).hex()
        }
    else:
        # Keyed message digest (RFC 2082 / RFC 4822): the AFI 0xFFFF leading
        # entry is a digest header carrying the digest offset, key id, auth-data
        # length, and sequence number.
        normalized["digest_offset"] = _rip_int(getattr(auth, "digestoffset", 0))
        normalized["key_id"] = _rip_int(getattr(auth, "keyid", 0))
        normalized["auth_data_len"] = _rip_int(getattr(auth, "authdatalen", 0))
        normalized["sequence"] = _rip_int(getattr(auth, "seqnum", 0))
    return normalized


def _rip_int(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _rip_bytes(value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if value is None:
        return b""
    if isinstance(value, str):
        return value.encode("utf-8", "surrogateescape")
    return _text(value).encode("utf-8", "surrogateescape")


def _scapy_layer(packet: Any, class_name: str) -> Any:
    current = packet
    while current is not None and current.__class__.__name__ != "NoPayload":
        if current.__class__.__name__ == class_name:
            return current
        current = current.payload
    return None


def _layer_key_at(layers: Sequence[str], index: int) -> str:
    """Recompute the normalized_fields key for the layer at ``index``.

    Mirrors ``_field_key``: the first occurrence of a layer name uses the bare
    name, later occurrences use ``name#N`` where N is the 1-based occurrence.
    """

    layer_name = layers[index]
    occurrence = sum(1 for position in range(index + 1) if layers[position] == layer_name)
    return layer_name if occurrence == 1 else f"{layer_name}#{occurrence}"


def _payload_fields_from_bytes(body: bytes) -> JSONObject:
    return {
        "hex": body.hex(),
        "length": len(body),
        "ascii": body.decode("utf-8", "replace"),
    }


def _decode_ble_bytes(
    raw: bytes,
    *,
    root: str,
    source_hex: str,
    feature_tags: Sequence[str],
) -> DecodedModel:
    canonical_root = _normalize_root_name(root)
    if canonical_root != "link:bluetooth-le-ll-with-phdr":
        raise ValueError(f"unsupported BLE byte-normalizer root: {root!r}")

    radio_fields, ll_packet = _parse_ble_pseudoheader(raw)
    adv_fields = _parse_ble_ll_packet(ll_packet)
    layers: list[str] = []
    fields: dict[str, JSONObject] = {}
    _append_normalized_layer(layers, fields, "ble_radio", radio_fields)
    _append_normalized_layer(layers, fields, "ble_adv", adv_fields)

    metadata: JSONObject = {
        "native": {
            "summary": f"{canonical_root} byte-normalized packet",
            "layers": [
                {"name": layer, "fields": fields[_layer_key_at(layers, index)], "summary": layer}
                for index, layer in enumerate(layers)
            ],
        },
        "normalization": "byte_level_ble",
        "reencoded_hex": source_hex,
    }

    return DecodedModel(
        backend=BACKEND_NAME,
        layers=layers,
        fields=fields,
        root=canonical_root,
        source_hex=source_hex,
        feature_tags=list(feature_tags),
        metadata=metadata,
    )


def _parse_ble_pseudoheader(raw: bytes) -> tuple[JSONObject, bytes]:
    if len(raw) < 10:
        raise ValueError(f"BLE LL-with-phdr requires 10 pseudo-header bytes, got {len(raw)}")
    flags = int.from_bytes(raw[8:10], "little")
    radio_fields: JSONObject = {
        "rf_channel": raw[0],
        "signal_power": int.from_bytes(raw[1:2], "little", signed=True),
        "noise_power": int.from_bytes(raw[2:3], "little", signed=True),
        "access_address_offenses": raw[3],
        "ref_access_address": int.from_bytes(raw[4:8], "little"),
        "flags": flags,
        "flag_tokens": _ble_flag_tokens(flags, _BLE_PHDR_FLAG_NAMES),
        "dewhitened": bool(flags & 0x0001),
        "signal_power_valid": bool(flags & 0x0002),
        "noise_power_valid": bool(flags & 0x0004),
        "reference_access_address_valid": bool(flags & 0x0010),
        "access_address_offenses_valid": bool(flags & 0x0020),
        "crc_checked": bool(flags & 0x0400),
        "crc_valid": bool(flags & 0x0800),
    }
    return radio_fields, raw[10:]


def _parse_ble_ll_packet(raw: bytes) -> JSONObject:
    if len(raw) < 9:
        raise ValueError(f"BLE link-layer packet requires at least 9 bytes, got {len(raw)}")
    access_address = int.from_bytes(raw[:4], "little")
    pdu_with_crc = raw[4:]
    pdu = pdu_with_crc[:-3]
    crc = pdu_with_crc[-3:]
    if len(pdu) < 2:
        raise ValueError(f"BLE PDU requires at least 2 header bytes, got {len(pdu)}")
    header0 = pdu[0]
    pdu_type = header0 & 0x0F
    length = pdu[1]
    available_payload = pdu[2:]
    if length > len(available_payload):
        raise ValueError(
            f"BLE advertising payload length {length} exceeds available bytes {len(available_payload)}"
        )
    payload = available_payload[:length]
    surplus = available_payload[length:]
    fields: JSONObject = {
        "access_address": access_address,
        "crc": crc.hex(),
        "pdu_type": _BLE_ADV_PDU_TYPE_NAMES.get(pdu_type, f"unknown:{pdu_type}"),
        "pdu_type_code": pdu_type,
        "length": length,
        "rx_add": "random" if header0 & 0x80 else "public",
        "tx_add": "random" if header0 & 0x40 else "public",
        "channel_selection": bool(header0 & 0x20),
        "rfu": (header0 >> 4) & 0x01,
    }
    if pdu_type == 0 and len(payload) >= 6:
        fields["adv_a"] = _ble_address_text(payload[:6])
        fields["ad_list"] = _parse_ble_ad_list(payload[6:])
    elif payload:
        fields["payload_hex"] = payload.hex()
    if surplus:
        fields["surplus_hex"] = surplus.hex()
    return fields


def _parse_ble_ad_list(raw: bytes) -> list[JSONObject]:
    output: list[JSONObject] = []
    offset = 0
    while offset < len(raw):
        length = raw[offset]
        offset += 1
        if length == 0:
            output.append({"type": "terminator", "type_code": 0, "length": 0, "data_hex": ""})
            break
        if offset + length > len(raw):
            raise ValueError(
                f"BLE AD structure length {length} exceeds available bytes {len(raw) - offset}"
            )
        type_code = raw[offset]
        data = raw[offset + 1 : offset + length]
        offset += length
        entry: JSONObject = {
            "type": _BLE_AD_TYPE_NAMES.get(type_code, f"unknown:{type_code}"),
            "type_code": type_code,
            "length": length,
            "data_hex": data.hex(),
        }
        if type_code == 0x01:
            value = data[0] if data else 0
            entry["value"] = value
            entry["flag_tokens"] = _ble_flag_tokens(value, _BLE_ADV_FLAG_NAMES)
        elif type_code in {0x08, 0x09}:
            entry["value"] = data.decode("utf-8", errors="replace")
        output.append(entry)
    return output


def _ble_flag_tokens(value: int, names: Sequence[tuple[int, str]]) -> list[str]:
    return [name for bit, name in names if value & bit]


def _ble_address_text(wire: bytes) -> str:
    return ":".join(f"{octet:02x}" for octet in reversed(wire[:6]))


def _decode_dot11_bytes(
    raw: bytes,
    *,
    root: str,
    source_hex: str,
    feature_tags: Sequence[str],
) -> DecodedModel:
    canonical_root = _normalize_root_name(root)
    layers: list[str] = []
    fields: dict[str, JSONObject] = {}
    offset = 0

    if canonical_root == "link:radiotap":
        radiotap_fields, offset = _parse_radiotap(raw)
        _append_normalized_layer(layers, fields, "radiotap", radiotap_fields)
    elif canonical_root != "link:dot11":
        raise ValueError(f"unsupported Dot11 byte-normalizer root: {root!r}")

    dot11_fields, dot11_tail, rsn_layers = _parse_dot11(raw[offset:])
    _append_normalized_layer(layers, fields, "dot11", dot11_fields)

    if dot11_fields.get("protected") is True:
        if dot11_tail:
            _append_normalized_layer(layers, fields, "payload", _payload_fields_from_bytes(dot11_tail))
    elif dot11_fields.get("frame_type") == 2:
        if dot11_fields.get("more_fragments") is True or dot11_fields.get("fragment_number", 0) != 0:
            if dot11_tail:
                _append_normalized_layer(layers, fields, "payload", _payload_fields_from_bytes(dot11_tail))
        else:
            _decode_llc_or_payload(layers, fields, dot11_tail)
    else:
        for rsn_fields in rsn_layers:
            _append_normalized_layer(layers, fields, "rsn", rsn_fields)
        if dot11_tail:
            _append_normalized_layer(layers, fields, "payload", _payload_fields_from_bytes(dot11_tail))

    metadata: JSONObject = {
        "native": {
            "summary": f"{canonical_root or root} byte-normalized packet",
            "layers": [
                {"name": layer, "fields": fields[_layer_key_at(layers, index)], "summary": layer}
                for index, layer in enumerate(layers)
            ],
        },
        "normalization": "byte_level_dot11",
        "reencoded_hex": source_hex,
    }

    return DecodedModel(
        backend=BACKEND_NAME,
        layers=layers,
        fields=fields,
        root=canonical_root,
        source_hex=source_hex,
        feature_tags=list(feature_tags),
        metadata=metadata,
    )


def _append_normalized_layer(
    layers: list[str],
    fields: dict[str, JSONObject],
    layer_name: str,
    layer_fields: JSONObject,
) -> None:
    key = _field_key(fields, layer_name)
    fields[key] = layer_fields
    layers.append(layer_name)


def _parse_radiotap(raw: bytes) -> tuple[JSONObject, int]:
    if len(raw) < 8:
        raise ValueError(f"radiotap header requires 8 bytes, got {len(raw)}")
    length = int.from_bytes(raw[2:4], "little")
    if length < 8:
        raise ValueError(f"radiotap length must be at least 8, got {length}")
    if length > len(raw):
        raise ValueError(f"radiotap length {length} exceeds available {len(raw)}")

    present_words: list[int] = []
    offset = 4
    while True:
        if offset + 4 > length:
            raise ValueError("radiotap extended present bitmap is truncated")
        word = int.from_bytes(raw[offset : offset + 4], "little")
        present_words.append(word)
        offset += 4
        if word & (1 << 31) == 0:
            break

    fields: JSONObject = {
        "version": raw[0],
        "pad": raw[1],
        "length": length,
        "present_words": present_words,
    }
    unknown_bits: list[int] = []
    cursor = offset
    for word_index, word in enumerate(present_words):
        for bit in range(31):
            if word & (1 << bit) == 0:
                continue
            field_bit = word_index * 32 + bit
            parsed = _parse_radiotap_field(raw, length, field_bit, cursor, fields)
            if parsed is None:
                unknown_bits.append(field_bit)
                continue
            cursor = parsed
    if unknown_bits:
        fields["unknown_present_bits"] = unknown_bits
    return fields, length


def _parse_radiotap_field(
    raw: bytes,
    header_length: int,
    bit: int,
    cursor: int,
    fields: JSONObject,
) -> int | None:
    specs = {
        0: (8, 8, "tsft", "u64"),
        1: (1, 1, "flags", "u8"),
        2: (1, 1, "rate", "u8"),
        3: (2, 4, "channel", "channel"),
        4: (2, 2, "fhss", "hex"),
        5: (1, 1, "dbm_antenna_signal", "i8"),
        6: (1, 1, "dbm_antenna_noise", "i8"),
        7: (2, 2, "lock_quality", "u16"),
        8: (2, 2, "tx_attenuation", "u16"),
        9: (2, 2, "db_tx_attenuation", "u16"),
        10: (1, 1, "dbm_tx_power", "i8"),
        11: (1, 1, "antenna", "u8"),
        14: (2, 2, "rx_flags", "u16"),
        15: (2, 2, "tx_flags", "u16"),
        17: (1, 1, "data_retries", "u8"),
    }
    spec = specs.get(bit)
    if spec is None:
        return None
    alignment, size, name, kind = spec
    cursor += _radiotap_padding(cursor, alignment)
    if cursor + size > header_length:
        raise ValueError(f"radiotap field bit {bit} exceeds declared header length")
    data = raw[cursor : cursor + size]
    if kind == "u8":
        fields[name] = data[0]
    elif kind == "i8":
        fields[name] = int.from_bytes(data, "little", signed=True)
    elif kind == "u16":
        fields[name] = int.from_bytes(data, "little")
    elif kind == "u64":
        fields[name] = int.from_bytes(data, "little")
    elif kind == "channel":
        fields["channel_frequency"] = int.from_bytes(data[:2], "little")
        fields["channel_flags"] = int.from_bytes(data[2:], "little")
    elif kind == "hex":
        fields[name] = {"hex": data.hex()}
    if bit == 1:
        fields["fcs_status"] = _radiotap_fcs_status(data[0])
    return cursor + size


def _radiotap_padding(offset: int, alignment: int) -> int:
    if alignment <= 1:
        return 0
    remainder = offset % alignment
    return 0 if remainder == 0 else alignment - remainder


def _parse_dot11(raw: bytes) -> tuple[JSONObject, bytes, list[JSONObject]]:
    if len(raw) < 10:
        raise ValueError(f"dot11 header requires at least 10 bytes, got {len(raw)}")
    frame_control = int.from_bytes(raw[0:2], "little")
    frame_type = (frame_control >> 2) & 0x03
    subtype = (frame_control >> 4) & 0x0F
    fields: JSONObject = {
        "frame_control": frame_control,
        "protocol_version": frame_control & 0x03,
        "frame_type": frame_type,
        "subtype": subtype,
        "to_ds": bool(frame_control & 0x0100),
        "from_ds": bool(frame_control & 0x0200),
        "more_fragments": bool(frame_control & 0x0400),
        "retry": bool(frame_control & 0x0800),
        "power_management": bool(frame_control & 0x1000),
        "more_data": bool(frame_control & 0x2000),
        "protected": bool(frame_control & 0x4000),
        "order": bool(frame_control & 0x8000),
        "duration_id": int.from_bytes(raw[2:4], "little"),
        "addr1": _mac_text(raw[4:10]),
    }
    offset = 10
    rsn_layers: list[JSONObject] = []

    if frame_type == 1:
        if subtype not in {12, 13}:
            if len(raw) < 16:
                raise ValueError(f"dot11 control header requires 16 bytes, got {len(raw)}")
            fields["addr2"] = _mac_text(raw[10:16])
            offset = 16
        return fields, raw[offset:], rsn_layers

    if len(raw) < 24:
        raise ValueError(f"dot11 three-address header requires 24 bytes, got {len(raw)}")
    fields["addr2"] = _mac_text(raw[10:16])
    fields["addr3"] = _mac_text(raw[16:22])
    sequence_control = int.from_bytes(raw[22:24], "little")
    fields["sequence_control"] = sequence_control
    fields["fragment_number"] = sequence_control & 0x0F
    fields["sequence_number"] = sequence_control >> 4
    offset = 24

    if frame_type == 2 and fields["to_ds"] and fields["from_ds"]:
        if len(raw) < offset + 6:
            raise ValueError(f"dot11 four-address header requires {offset + 6} bytes, got {len(raw)}")
        fields["addr4"] = _mac_text(raw[offset : offset + 6])
        offset += 6
    if frame_type == 2 and subtype & 0x08:
        if len(raw) < offset + 2:
            raise ValueError(f"dot11 QoS header requires {offset + 2} bytes, got {len(raw)}")
        fields["qos_control"] = int.from_bytes(raw[offset : offset + 2], "little")
        offset += 2
        if fields["order"]:
            if len(raw) < offset + 4:
                raise ValueError(f"dot11 HT control requires {offset + 4} bytes, got {len(raw)}")
            fields["ht_control"] = int.from_bytes(raw[offset : offset + 4], "little")
            offset += 4
    elif frame_type == 0 and fields["order"]:
        if len(raw) < offset + 4:
            raise ValueError(f"dot11 HT control requires {offset + 4} bytes, got {len(raw)}")
        fields["ht_control"] = int.from_bytes(raw[offset : offset + 4], "little")
        offset += 4

    if frame_type == 0:
        fixed_len = _dot11_management_fixed_len(subtype)
        if len(raw) < offset + fixed_len:
            raise ValueError(f"dot11 management fixed fields require {offset + fixed_len} bytes, got {len(raw)}")
        fixed = raw[offset : offset + fixed_len]
        if fixed:
            fields["management_fixed_fields"] = {"hex": fixed.hex()}
        offset += fixed_len
        if _dot11_management_has_tags(subtype):
            tags, rsn_layers = _parse_dot11_tags(raw[offset:])
            if tags:
                fields["tagged_parameters"] = tags
            offset = len(raw)
    elif fields["protected"]:
        fields["encrypted_body_len"] = len(raw) - offset

    return fields, raw[offset:], rsn_layers


def _decode_llc_or_payload(layers: list[str], fields: dict[str, JSONObject], raw: bytes) -> None:
    if not raw:
        return
    if len(raw) < 8:
        if _is_truncated_snap_prefix(raw):
            raise ValueError(f"llc_snap header requires 8 bytes, got {len(raw)}")
        _append_normalized_layer(layers, fields, "payload", _payload_fields_from_bytes(raw))
        return
    llc = {
        "dsap": raw[0],
        "ssap": raw[1],
        "control": raw[2],
        "oui": {"hex": raw[3:6].hex()},
        "ethertype": int.from_bytes(raw[6:8], "big"),
    }
    if raw[:3] != b"\xaa\xaa\x03":
        _append_normalized_layer(layers, fields, "payload", _payload_fields_from_bytes(raw))
        return
    _append_normalized_layer(layers, fields, "llc_snap", llc)
    payload = raw[8:]
    if raw[3:6] != b"\x00\x00\x00":
        if payload:
            _append_normalized_layer(layers, fields, "payload", _payload_fields_from_bytes(payload))
        return
    ethertype = llc["ethertype"]
    if ethertype == 0x0806 and payload:
        _append_normalized_layer(layers, fields, "arp", _parse_arp(payload))
    elif ethertype == 0x0800 and payload:
        _append_normalized_layer(layers, fields, "ipv4", _parse_ipv4(payload))
    elif ethertype == 0x86DD and payload:
        _append_normalized_layer(layers, fields, "ipv6", _parse_ipv6(payload))
    elif ethertype == 0x888E:
        _decode_eapol(layers, fields, payload)
    elif payload:
        _append_normalized_layer(layers, fields, "payload", _payload_fields_from_bytes(payload))


def _decode_eapol(layers: list[str], fields: dict[str, JSONObject], raw: bytes) -> None:
    if len(raw) < 4:
        raise ValueError(f"eapol header requires 4 bytes, got {len(raw)}")
    body_length = int.from_bytes(raw[2:4], "big")
    required = 4 + body_length
    if len(raw) < required:
        raise ValueError(f"eapol body requires {required} bytes, got {len(raw)}")
    packet_type = raw[1]
    _append_normalized_layer(
        layers,
        fields,
        "eapol",
        {"version": raw[0], "packet_type": packet_type, "body_length": body_length},
    )
    body = raw[4:required]
    surplus = raw[required:]
    if packet_type == 3 and body:
        key_fields, key_tail = _parse_eapol_key(body)
        if key_fields is None:
            _append_normalized_layer(layers, fields, "payload", _payload_fields_from_bytes(body))
        else:
            _append_normalized_layer(layers, fields, "eapol_key", key_fields)
            if key_tail:
                _append_normalized_layer(layers, fields, "payload", _payload_fields_from_bytes(key_tail))
    elif body:
        _append_normalized_layer(layers, fields, "payload", _payload_fields_from_bytes(body))
    if surplus:
        _append_normalized_layer(layers, fields, "payload", _payload_fields_from_bytes(surplus))


def _parse_eapol_key(raw: bytes) -> tuple[JSONObject | None, bytes]:
    if len(raw) < 95:
        raise ValueError(f"eapol key body requires 95 bytes, got {len(raw)}")
    if raw[0] not in {2}:
        return None, b""
    key_data_length = int.from_bytes(raw[93:95], "big")
    required = 95 + key_data_length
    if len(raw) < required:
        raise ValueError(f"eapol key data requires {required} bytes, got {len(raw)}")
    return (
        {
            "descriptor_type": raw[0],
            "key_information": int.from_bytes(raw[1:3], "big"),
            "key_length": int.from_bytes(raw[3:5], "big"),
            "replay_counter": int.from_bytes(raw[5:13], "big"),
            "key_nonce": {"hex": raw[13:45].hex()},
            "key_iv": {"hex": raw[45:61].hex()},
            "key_rsc": {"hex": raw[61:69].hex()},
            "key_id": {"hex": raw[69:77].hex()},
            "key_mic": {"hex": raw[77:93].hex()},
            "key_data_length": key_data_length,
            "key_data": {"hex": raw[95:required].hex()},
        },
        raw[required:],
    )


def _parse_arp(raw: bytes) -> JSONObject:
    if len(raw) < 8:
        raise ValueError(f"arp header requires 8 bytes, got {len(raw)}")
    hw_len = raw[4]
    proto_len = raw[5]
    required = 8 + (2 * hw_len) + (2 * proto_len)
    if len(raw) < required:
        raise ValueError(f"arp addresses require {required} bytes, got {len(raw)}")
    hardware_type = int.from_bytes(raw[0:2], "big")
    protocol_type = int.from_bytes(raw[2:4], "big")
    cursor = 8
    sender_hardware = raw[cursor : cursor + hw_len]
    cursor += hw_len
    sender_protocol = raw[cursor : cursor + proto_len]
    cursor += proto_len
    target_hardware = raw[cursor : cursor + hw_len]
    cursor += hw_len
    target_protocol = raw[cursor : cursor + proto_len]
    fields: JSONObject = {
        "hardware_type": hardware_type,
        "protocol_type": protocol_type,
        "hardware_length": hw_len,
        "protocol_length": proto_len,
        "opcode": int.from_bytes(raw[6:8], "big"),
    }
    if hardware_type == 1 and hw_len == 6:
        fields["sender_hardware_address"] = _mac_text(sender_hardware)
        fields["target_hardware_address"] = _mac_text(target_hardware)
    else:
        fields["sender_hardware_address"] = {"hex": sender_hardware.hex()}
        fields["target_hardware_address"] = {"hex": target_hardware.hex()}
    if protocol_type == 0x0800 and proto_len == 4:
        fields["sender_protocol_address"] = ".".join(str(byte) for byte in sender_protocol)
        fields["target_protocol_address"] = ".".join(str(byte) for byte in target_protocol)
    else:
        fields["sender_protocol_address"] = {"hex": sender_protocol.hex()}
        fields["target_protocol_address"] = {"hex": target_protocol.hex()}
    return fields


def _parse_ipv4(raw: bytes) -> JSONObject:
    if len(raw) < 20:
        raise ValueError(f"ipv4 header requires 20 bytes, got {len(raw)}")
    header_length = (raw[0] & 0x0F) * 4
    if header_length < 20 or len(raw) < header_length:
        raise ValueError(f"ipv4 header length {header_length} exceeds available {len(raw)}")
    flags_fragment = int.from_bytes(raw[6:8], "big")
    return {
        "version": raw[0] >> 4,
        "header_length": raw[0] & 0x0F,
        "tos": raw[1],
        "length": int.from_bytes(raw[2:4], "big"),
        "identification": int.from_bytes(raw[4:6], "big"),
        "flags": _ipv4_flags((flags_fragment >> 13) & 0x07),
        "fragment_offset": flags_fragment & 0x1FFF,
        "ttl": raw[8],
        "protocol": raw[9],
        "checksum": int.from_bytes(raw[10:12], "big"),
        "src": ".".join(str(byte) for byte in raw[12:16]),
        "dst": ".".join(str(byte) for byte in raw[16:20]),
        "options": raw[20:header_length].hex(),
    }


def _parse_ipv6(raw: bytes) -> JSONObject:
    if len(raw) < 40:
        raise ValueError(f"ipv6 header requires 40 bytes, got {len(raw)}")
    first = int.from_bytes(raw[0:4], "big")
    traffic_class = (first >> 20) & 0xFF
    return {
        "version": raw[0] >> 4,
        "traffic_class": traffic_class,
        "dscp": traffic_class >> 2,
        "ecn": traffic_class & 0x03,
        "flow_label": first & 0xFFFFF,
        "payload_length": int.from_bytes(raw[4:6], "big"),
        "next_header": raw[6],
        "hop_limit": raw[7],
        "src": str(ipaddress.IPv6Address(raw[8:24])),
        "dst": str(ipaddress.IPv6Address(raw[24:40])),
    }


def _parse_dot11_tags(raw: bytes) -> tuple[list[JSONObject], list[JSONObject]]:
    tags: list[JSONObject] = []
    rsn_layers: list[JSONObject] = []
    offset = 0
    while offset < len(raw):
        if offset + 2 > len(raw):
            raise ValueError("dot11 tagged parameter header is truncated")
        element_id = raw[offset]
        length = raw[offset + 1]
        start = offset + 2
        end = start + length
        if end > len(raw):
            raise ValueError(f"dot11 tagged parameter length {length} exceeds available bytes")
        value = raw[start:end]
        tags.append({"id": element_id, "length": length, "value": {"hex": value.hex()}})
        if element_id == 48:
            rsn_layers.append(_parse_rsn_information(element_id, length, value))
        offset = end
    return tags, rsn_layers


def _parse_rsn_information(element_id: int, length: int, value: bytes) -> JSONObject:
    if len(value) < 8:
        raise ValueError(f"rsn information requires at least 8 value bytes, got {len(value)}")
    offset = 0
    version = int.from_bytes(value[offset : offset + 2], "little")
    offset += 2
    group_cipher = _rsn_suite_selector(value[offset : offset + 4], kind="cipher")
    offset += 4
    if offset + 2 > len(value):
        raise ValueError("rsn pairwise cipher count is truncated")
    pairwise_count = int.from_bytes(value[offset : offset + 2], "little")
    offset += 2
    pairwise: list[JSONObject] = []
    for _ in range(pairwise_count):
        if offset + 4 > len(value):
            raise ValueError("rsn pairwise cipher selector is truncated")
        pairwise.append(_rsn_suite_selector(value[offset : offset + 4], kind="cipher"))
        offset += 4
    if offset + 2 > len(value):
        raise ValueError("rsn akm count is truncated")
    akm_count = int.from_bytes(value[offset : offset + 2], "little")
    offset += 2
    akms: list[JSONObject] = []
    for _ in range(akm_count):
        if offset + 4 > len(value):
            raise ValueError("rsn akm selector is truncated")
        akms.append(_rsn_suite_selector(value[offset : offset + 4], kind="akm"))
        offset += 4

    fields: JSONObject = {
        "element_id": element_id,
        "length": length,
        "version": version,
        "group_cipher_suite": group_cipher,
        "pairwise_cipher_suites": pairwise,
        "akm_suites": akms,
    }
    if offset + 2 <= len(value):
        fields["capabilities"] = int.from_bytes(value[offset : offset + 2], "little")
        offset += 2
    if offset + 2 <= len(value):
        pmkid_count = int.from_bytes(value[offset : offset + 2], "little")
        pmkid_start = offset + 2
        pmkid_end = pmkid_start + (pmkid_count * 16)
        if pmkid_end <= len(value):
            fields["pmkid_count_present"] = True
            fields["pmkid_list"] = [
                {"hex": value[index : index + 16].hex()}
                for index in range(pmkid_start, pmkid_end, 16)
            ]
            offset = pmkid_end
    if offset + 4 <= len(value):
        fields["group_management_cipher_suite"] = _rsn_suite_selector(
            value[offset : offset + 4],
            kind="cipher",
        )
        offset += 4
    if offset < len(value):
        fields["trailing_bytes"] = {"hex": value[offset:].hex()}
    return fields


def _rsn_suite_selector(raw: bytes, *, kind: str) -> JSONObject:
    selector = bytes(raw)
    label = _rsn_cipher_label(selector) if kind == "cipher" else _rsn_akm_label(selector)
    output: JSONObject = {
        "selector": selector.hex(),
        "oui": selector[:3].hex(),
        "suite_type": selector[3],
    }
    if label is not None:
        output["label"] = label
    return output


def _rsn_cipher_label(selector: bytes) -> str | None:
    if selector[:3] != b"\x00\x0f\xac":
        return None
    return {
        0: "use-group",
        2: "tkip",
        4: "ccmp-128",
        6: "aes-128-cmac",
        7: "no-group-addressed",
        8: "gcmp-128",
        9: "gcmp-256",
        10: "ccmp-256",
        11: "bip-gmac-128",
        12: "bip-gmac-256",
        13: "bip-cmac-256",
        18: "ccm-star",
    }.get(selector[3])


def _rsn_akm_label(selector: bytes) -> str | None:
    if selector[:3] != b"\x00\x0f\xac":
        return None
    return {
        1: "802.1x",
        2: "psk",
        3: "ft-802.1x",
        4: "ft-psk",
        5: "802.1x-sha256",
        6: "psk-sha256",
        7: "tdls",
        8: "sae",
        9: "ft-sae",
        10: "ap-peer-key",
        11: "802.1x-suite-b",
        12: "802.1x-suite-b-192",
        13: "ft-802.1x-sha384-cmp-256",
        14: "fils-sha256",
        15: "fils-sha384",
        16: "ft-fils-sha256",
        17: "ft-fils-sha384",
        18: "owe",
        19: "ft-psk-sha384",
        20: "psk-sha384",
        21: "pasn",
        22: "ft-802.1x-sha384",
        23: "802.1x-sha384",
        24: "sae-pmk384",
        25: "ft-sae-pmk384",
        26: "pasn-defined-key-wrap",
        29: "edpke",
    }.get(selector[3])


def _dot11_management_fixed_len(subtype: int) -> int:
    return {
        0: 4,
        1: 6,
        2: 10,
        3: 6,
        5: 12,
        8: 12,
        10: 2,
        11: 6,
        12: 2,
        13: 1,
        14: 1,
    }.get(subtype, 0)


def _dot11_management_has_tags(subtype: int) -> bool:
    return subtype in {0, 1, 2, 3, 4, 5, 8, 11}


def _is_truncated_snap_prefix(raw: bytes) -> bool:
    return b"\xaa\xaa\x03".startswith(raw) and bool(raw)


def _radiotap_fcs_status(flags: int) -> str:
    present = bool(flags & 0x10)
    failed = bool(flags & 0x40)
    if present and failed:
        return "present_failed"
    if present:
        return "present"
    if failed:
        return "failed"
    return "absent"


def _ipv4_flags(flags: int) -> str:
    names = []
    if flags & 0x01:
        names.append("mf")
    if flags & 0x02:
        names.append("df")
    if flags & 0x04:
        names.append("reserved")
    return "|".join(names) if names else "none"


def _normalize_linux_sll_source_address(value: JSONValue) -> JSONValue:
    if isinstance(value, Mapping):
        hex_value = value.get("hex")
        if isinstance(hex_value, str):
            return {"hex": hex_value}
    return value


# OSPF_Hdr type codes (RFC 2328) rendered by Scapy's ShortEnumField as
# descriptive strings; collapse them onto the oracle-neutral packet-type domain
# names from specs/layers/ospf.yaml so a decoded type compares against the plan.
_OSPF_TYPE_NAMES: dict[int, str] = {
    1: "hello",
    2: "database_description",
    3: "link_state_request",
    4: "link_state_update",
    5: "link_state_ack",
}
# OSPF AuType codes mapped to the oracle-neutral autype domain names.
_OSPF_AUTYPE_NAMES: dict[int, str] = {
    0: "null",
    1: "simple",
    2: "cryptographic",
}


def _normalize_ospf_fields(fields: JSONObject) -> None:
    """Normalize decoded OSPFv2 fields into the backend-neutral oracle shape.

    The common-header field names are already aliased (len->packet_length,
    src->router_id, area->area_id, chksum->checksum, authtype->autype,
    authdata->authentication). This reduces the remaining Scapy-typed values to
    comparable forms: the packet ``type`` and ``autype`` enum strings collapse to
    the oracle-neutral domain names, and the 64-bit authentication field is
    rendered as raw hex bytes so both backends compare byte-for-byte.
    """

    type_value = fields.get("type")
    if isinstance(type_value, int) and not isinstance(type_value, bool):
        fields["type"] = _OSPF_TYPE_NAMES.get(type_value, type_value)
    elif isinstance(type_value, str):
        fields["type"] = _ospf_enum_token(type_value)

    autype_value = fields.get("autype")
    if isinstance(autype_value, int) and not isinstance(autype_value, bool):
        fields["autype"] = _OSPF_AUTYPE_NAMES.get(autype_value, autype_value)
    elif isinstance(autype_value, str):
        fields["autype"] = _ospf_enum_token(autype_value)

    authentication = fields.get("authentication")
    if isinstance(authentication, int) and not isinstance(authentication, bool):
        fields["authentication"] = {"hex": authentication.to_bytes(8, "big").hex()}

    lsa_headers = fields.get("lsa_headers")
    if isinstance(lsa_headers, list):
        fields["lsa_header_count"] = len(lsa_headers)


def _ospf_enum_token(value: str) -> str:
    return value.strip().lower().replace(" ", "_").replace("-", "_")


def _apply_udp_surplus_normalization(
    layers: list[str],
    fields: dict[str, JSONObject],
    *,
    root: str | None,
    source_hex: str,
    metadata: JSONObject,
) -> None:
    try:
        raw = bytes.fromhex(source_hex)
        layout = _udp_layout(root, raw)
    except ValueError as exc:
        metadata.setdefault("udp_options", {"parse_error": str(exc)})
        return

    surplus = raw[layout["surplus_start"] : layout["ip_end"]]
    if not surplus:
        return

    user_payload = raw[layout["udp_payload_start"] : layout["udp_payload_end"]]
    _normalize_udp_user_payload(layers, fields, user_payload)

    option_metadata = _udp_surplus_metadata(raw, layout, user_payload, surplus)
    key = _field_key(fields, "UdpOptions")
    if key not in fields:
        _insert_layer_after(layers, "UdpOptions", after={"payload", "dns", "dhcp", "udp"})
        fields[key] = {}
    fields[key]["options"] = option_metadata

    metadata["udp"] = {
        "checksum_status": _udp_checksum_status(raw, layout),
        "checksum_status_source": "byte_level_pseudo_header_validation",
    }
    metadata["udp_options"] = {
        **option_metadata,
        "native_scapy_support": False,
        "normalization": "byte_level_udp_surplus_split",
    }


def _normalize_udp_user_payload(
    layers: list[str],
    fields: dict[str, JSONObject],
    user_payload: bytes,
) -> None:
    payload_keys = [key for key in fields if _base_layer_name(key) == "payload"]
    if not user_payload:
        for key in payload_keys:
            fields.pop(key, None)
        layers[:] = [layer for layer in layers if layer != "payload"]
        return

    payload_fields: JSONObject = {
        "hex": user_payload.hex(),
        "length": len(user_payload),
    }
    if payload_keys:
        fields[payload_keys[0]] = payload_fields
        for key in payload_keys[1:]:
            fields.pop(key, None)
        seen_payload = False
        updated_layers = []
        for layer in layers:
            if layer != "payload":
                updated_layers.append(layer)
                continue
            if not seen_payload:
                updated_layers.append(layer)
                seen_payload = True
        layers[:] = updated_layers
        return

    if _has_udp_typed_application_layer(layers):
        return

    _insert_layer_after(layers, "payload", after={"udp"})
    fields["payload"] = payload_fields


def _has_udp_typed_application_layer(layers: Sequence[str]) -> bool:
    return any(layer in {"dns", "dhcp"} for layer in layers)


def _base_layer_name(layer_name: str) -> str:
    return layer_name.split("#", 1)[0]


def _insert_layer_after(layers: list[str], layer: str, *, after: set[str]) -> None:
    if layer in layers:
        return
    for index in range(len(layers) - 1, -1, -1):
        if layers[index] in after:
            layers.insert(index + 1, layer)
            return
    layers.append(layer)


def _udp_surplus_metadata(
    raw: bytes,
    layout: Mapping[str, int],
    user_payload: bytes,
    surplus: bytes,
) -> JSONObject:
    l3_relative_surplus_start = layout["surplus_start"] - layout["l3_start"]
    alignment_len = l3_relative_surplus_start & 1
    alignment = surplus[:alignment_len]
    ocs_start = alignment_len
    option_checksum = None
    option_bytes = b""
    if len(surplus) >= ocs_start + 2:
        option_checksum = int.from_bytes(surplus[ocs_start : ocs_start + 2], "big")
        option_bytes = surplus[ocs_start + 2 :]

    items, status = _udp_option_items(option_bytes, user_payload)
    if any(byte != 0 for byte in alignment):
        status = "ignored"
    elif option_checksum is None:
        status = "malformed_envelope"
    elif not _udp_option_checksum_valid(
        surplus,
        alignment_len=alignment_len,
        option_checksum=option_checksum,
        udp_checksum=int.from_bytes(
            raw[layout["udp_start"] + 6 : layout["udp_start"] + 8],
            "big",
        ),
    ):
        status = "option_checksum_invalid"

    return {
        "status": status,
        "raw_surplus_hex": surplus.hex(),
        "raw_surplus_length": len(surplus),
        "alignment_hex": alignment.hex(),
        "option_checksum": option_checksum,
        "option_bytes_hex": option_bytes.hex(),
        "option_count": len(items),
        "items": items,
        "application_payload_hex": user_payload.hex(),
        "application_payload_length": len(user_payload),
        "udp_length": layout["udp_length"],
        "placement": "after_udp_length",
        "surplus_excluded_from_udp_checksum": True,
    }


def _udp_option_items(option_bytes: bytes, user_payload: bytes) -> tuple[list[JSONObject], str]:
    items: list[JSONObject] = []
    status = "valid"
    consecutive_nops = 0
    index = 0
    while index < len(option_bytes):
        kind = option_bytes[index]
        if kind == 0:
            items.append({"kind": kind, "name": "eol", "length": 1})
            if any(byte != 0 for byte in option_bytes[index + 1 :]):
                status = "nonzero_after_end_of_list"
            break
        if kind == 1:
            consecutive_nops += 1
            items.append({"kind": kind, "name": "nop", "length": 1})
            if consecutive_nops > 7 and status == "valid":
                status = "too_many_no_operations"
            index += 1
            continue

        consecutive_nops = 0
        if index + 1 >= len(option_bytes):
            items.append({"kind": kind, "name": _udp_option_name(kind), "length": None})
            return items, "malformed_envelope"
        length = option_bytes[index + 1]
        if length < 2 or index + length > len(option_bytes):
            items.append(
                {
                    "kind": kind,
                    "name": _udp_option_name(kind),
                    "length": length,
                    "data_hex": option_bytes[index + 2 :].hex(),
                }
            )
            return items, "malformed_envelope"

        data = option_bytes[index + 2 : index + length]
        item = _udp_option_item(kind, length, data)
        items.append(item)
        if status == "valid":
            status = _udp_option_status_for_item(kind, data, user_payload)
        if status == "unknown_unsafe":
            break
        index += length
    return items, status


def _udp_option_item(kind: int, length: int, data: bytes) -> JSONObject:
    item: JSONObject = {
        "kind": kind,
        "name": _udp_option_name(kind),
        "length": length,
        "data_hex": data.hex(),
    }
    if kind == 2 and len(data) == 4:
        item["checksum"] = int.from_bytes(data, "big")
    elif kind == 4 and len(data) == 2:
        item["max_datagram_size"] = int.from_bytes(data, "big")
    elif kind == 5 and len(data) == 3:
        item["max_reassembled_size"] = int.from_bytes(data[:2], "big")
        item["segment_count"] = data[2]
    elif kind in {6, 7} and len(data) == 4:
        item["token"] = int.from_bytes(data, "big")
    elif kind == 8 and len(data) == 8:
        item["tsval"] = int.from_bytes(data[:4], "big")
        item["tsecr"] = int.from_bytes(data[4:], "big")
    return item


def _udp_option_name(kind: int) -> str:
    names = {
        0: "eol",
        1: "nop",
        2: "apc",
        3: "frag",
        4: "mds",
        5: "mrds",
        6: "req",
        7: "res",
        8: "time",
        9: "auth",
        127: "exp",
        254: "uexp",
    }
    if kind in names:
        return names[kind]
    if 10 <= kind <= 126:
        return "unassigned_safe"
    if 128 <= kind <= 191:
        return "reserved_safe"
    if 194 <= kind <= 253:
        return "unassigned_unsafe"
    return "reserved_unsafe"


def _udp_option_status_for_item(kind: int, data: bytes, user_payload: bytes) -> str:
    if kind == 2 and len(data) == 4:
        return (
            "valid"
            if int.from_bytes(data, "big") == _crc32c(user_payload)
            else "additional_payload_checksum_invalid"
        )
    if kind == 3:
        return "unsupported_fragmentation"
    if 10 <= kind <= 126:
        return "unknown_safe"
    if 194 <= kind <= 253:
        return "unknown_unsafe"
    return "valid"


def _udp_option_checksum_valid(
    surplus: bytes,
    *,
    alignment_len: int,
    option_checksum: int,
    udp_checksum: int,
) -> bool:
    if option_checksum == 0:
        return udp_checksum == 0
    if len(surplus) > 0xFFFF:
        return False
    return _internet_checksum(len(surplus).to_bytes(2, "big") + surplus[alignment_len:]) == 0


def _udp_checksum_status(raw: bytes, layout: Mapping[str, int]) -> str:
    checksum = int.from_bytes(raw[layout["udp_start"] + 6 : layout["udp_start"] + 8], "big")
    if layout["ip_version"] == 4 and checksum == 0:
        return "ipv4_no_checksum"
    if layout["ip_version"] == 6 and checksum == 0:
        return "ipv6_zero_checksum_exception_required"
    return "valid" if _udp_checksum_valid(raw, layout) else "invalid"


def _udp_checksum_valid(raw: bytes, layout: Mapping[str, int]) -> bool:
    udp_start = layout["udp_start"]
    udp_length = layout["udp_length"]
    udp_segment = raw[udp_start : udp_start + udp_length]
    l3_start = layout["l3_start"]
    if layout["ip_version"] == 4:
        pseudo = (
            raw[l3_start + 12 : l3_start + 20]
            + b"\x00"
            + bytes([17])
            + udp_length.to_bytes(2, "big")
        )
    else:
        pseudo = (
            raw[l3_start + 8 : l3_start + 40]
            + udp_length.to_bytes(4, "big")
            + b"\x00\x00\x00"
            + bytes([17])
        )
    return _internet_checksum(pseudo + udp_segment) == 0


def _udp_layout(root: str | None, raw: bytes) -> dict[str, int]:
    l3_start = _l3_start_offset(root, raw)
    if l3_start >= len(raw):
        raise ValueError(f"packet is too short for root {root!r}")
    version = raw[l3_start] >> 4
    if version == 4:
        ihl = (raw[l3_start] & 0x0F) * 4
        if ihl < 20 or l3_start + ihl + 8 > len(raw):
            raise ValueError("IPv4 packet is too short to locate UDP header")
        if raw[l3_start + 9] != 17:
            raise ValueError("IPv4 packet does not carry UDP")
        ip_end = l3_start + int.from_bytes(raw[l3_start + 2 : l3_start + 4], "big")
        udp_start = l3_start + ihl
    elif version == 6:
        if l3_start + 48 > len(raw):
            raise ValueError("IPv6 packet is too short to locate UDP header")
        ip_end = l3_start + 40 + int.from_bytes(raw[l3_start + 4 : l3_start + 6], "big")
        udp_start = _ipv6_udp_start(raw, l3_start)
    else:
        raise ValueError(f"unsupported IP version for UDP surplus parsing: {version}")

    if udp_start + 8 > len(raw):
        raise ValueError("packet is too short for UDP header")
    udp_length = int.from_bytes(raw[udp_start + 4 : udp_start + 6], "big")
    if udp_length < 8:
        raise ValueError(f"UDP length is too short: {udp_length}")
    udp_payload_start = udp_start + 8
    udp_payload_end = udp_start + udp_length
    if udp_payload_end > ip_end or ip_end > len(raw):
        raise ValueError("UDP/IP lengths exceed available packet bytes")
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


def _l3_start_offset(root: str | None, raw: bytes) -> int:
    if root in {
        None,
        "l3:ipv4",
        "l3:ipv6",
        "l3:raw",
        "link:raw",
        "IP",
        "IPv6",
        "Raw",
    }:
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
    raise ValueError(f"unsupported UDP surplus root: {root!r}")


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
        raise ValueError(f"IPv6 packet does not carry UDP; next_header={next_header}")
    return cursor


def _require_decode_capability(
    capabilities: BackendCapabilities | BackendRegistration | None,
) -> None:
    resolved = _capability_contract(capabilities)
    if not resolved.decode:
        raise ValueError("unsupported backend capability: Scapy decoding requires decode")


def _capability_contract(
    capabilities: BackendCapabilities | BackendRegistration | None,
) -> BackendCapabilities:
    if capabilities is None:
        return get_backend(BACKEND_NAME).capabilities
    if isinstance(capabilities, BackendRegistration):
        return capabilities.capabilities
    return capabilities


def _expected_stack(plan: PacketPlan) -> list[str]:
    payload_fields = _plan_layer_fields(plan, "payload")
    payload_hex = _text_or_none(payload_fields.get("hex"))
    aliases = {
        "dot1q": "vlan",
        "ether": "ethernet",
        "ip": "ipv4",
        "linux_cooked": "linux_sll",
        "raw": "payload",
    }
    output = [aliases.get(layer.lower(), layer.lower()) for layer in plan.stack]
    if payload_hex == "":
        output = [layer for layer in output if layer != "payload"]
    if _plan_has_udp_surplus_options(plan):
        insert_after = _udp_options_expected_insert_after(output)
        try:
            output.insert(output.index(insert_after) + 1, "UdpOptions")
        except ValueError:
            output.append("UdpOptions")
    return output


def _udp_options_expected_insert_after(layers: Sequence[str]) -> str:
    for layer in ("payload", "dns", "dhcp", "udp"):
        if layer in layers:
            return layer
    return "udp"


def _expected_smoke_fields(plan: PacketPlan) -> dict[str, JSONObject]:
    expected: dict[str, JSONObject] = {}

    ethernet = _plan_layer_fields(plan, "ethernet")
    if ethernet:
        ethertype = ethernet.get("ethertype", ethernet.get("type"))
        fields: JSONObject = {}
        if "src" in ethernet:
            fields["src"] = ethernet["src"]
        if "dst" in ethernet:
            fields["dst"] = ethernet["dst"]
        if ethertype is not None:
            fields["ethertype"] = _ethertype_value(ethertype)
        expected["ethernet"] = fields

    ipv4 = _plan_layer_fields(plan, "ipv4")
    if ipv4:
        fields = {}
        for name in ("src", "dst", "ttl"):
            if name in ipv4:
                fields[name] = ipv4[name]
        protocol = ipv4.get("protocol", ipv4.get("proto"))
        if protocol is not None:
            fields["protocol"] = _protocol_value(protocol)
        expected["ipv4"] = fields

    ipv6 = _plan_layer_fields(plan, "ipv6")
    if ipv6:
        fields = {}
        for name in ("src", "dst"):
            if name in ipv6:
                fields[name] = ipv6[name]
        hop_limit = ipv6.get("hop_limit", ipv6.get("hlim"))
        if hop_limit is not None:
            fields["hop_limit"] = hop_limit
        next_header = ipv6.get("next_header", ipv6.get("nh"))
        if next_header is not None:
            fields["next_header"] = _protocol_value(next_header)
        expected["ipv6"] = fields

    udp = _plan_layer_fields(plan, "udp")
    if udp:
        fields = {}
        src_port = udp.get("src_port", udp.get("sport"))
        dst_port = udp.get("dst_port", udp.get("dport"))
        if src_port is not None:
            fields["src_port"] = src_port
        if dst_port is not None:
            fields["dst_port"] = dst_port
        expected["udp"] = fields

    payload = _plan_layer_fields(plan, "payload")
    payload_hex = _text_or_none(payload.get("hex"))
    if payload_hex:
        expected["payload"] = {
            "hex": payload_hex,
            "length": len(bytes.fromhex(payload_hex)),
        }

    return expected


def _plan_layer_fields(plan: PacketPlan, layer: str) -> JSONObject:
    value = plan.fields.get(layer)
    if value is None and layer == "payload":
        value = plan.fields.get("raw")
    if value is None and layer == "ipv4":
        value = plan.fields.get("ip")
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"{layer} plan fields must be an object")
    return dict(value)


def _plan_has_udp_surplus_options(plan: PacketPlan) -> bool:
    udp = _plan_layer_fields(plan, "udp")
    options = udp.get("options")
    return isinstance(options, Mapping) and options.get("format") == "udp_surplus_options"


def _ethertype_value(value: object) -> int:
    if isinstance(value, str):
        lowered = value.lower()
        if lowered in _ETHERTYPES:
            return _ETHERTYPES[lowered]
        return int(lowered, 0)
    if isinstance(value, int):
        return value
    raise ValueError(f"expected ethertype-compatible value: {value!r}")


def _protocol_value(value: object) -> int:
    if isinstance(value, str):
        lowered = value.lower()
        if lowered in _PROTOCOLS:
            return _PROTOCOLS[lowered]
        return int(lowered, 0)
    if isinstance(value, int):
        return value
    raise ValueError(f"expected protocol-compatible value: {value!r}")
