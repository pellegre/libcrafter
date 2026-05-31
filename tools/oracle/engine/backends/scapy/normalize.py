"""Scapy packet decoding and backend-neutral normalization."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from ...model import DecodedModel, EncodedVector, JSONObject, JSONValue, PacketPlan
from ..registry import BackendCapabilities, BackendRegistration, get_backend
from .bootstrap import import_scapy


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
    "ARP": "arp",
    "BOOTP": "dhcp",
    "CookedLinux": "linux_sll",
    "DHCP": "dhcp",
    "DNS": "dns",
    "Dot1Q": "vlan",
    "Ether": "ethernet",
    "ICMP": "icmp",
    "IP": "ipv4",
    "IPv6": "ipv6",
    "IPv6ExtHdrFragment": "ipv6_fragment",
    "IPv6ExtHdrRouting": "ipv6_routing",
    "IPv6ExtHdrSegmentRouting": "ipv6_routing",
    "Loopback": "null_loopback",
    "Raw": "payload",
    "TCP": "tcp",
    "UDP": "udp",
}
_FIELD_ALIASES: dict[str, str] = {
    "chksum": "checksum",
    "dataofs": "data_offset",
    "dport": "dst_port",
    "frag": "fragment_offset",
    "hlim": "hop_limit",
    "hwsrc": "sender_hardware_address",
    "hwdst": "target_hardware_address",
    "len": "length",
    "nh": "next_header",
    "op": "opcode",
    "pdst": "target_protocol_address",
    "proto": "protocol",
    "psrc": "sender_protocol_address",
    "ptype": "protocol_type",
    "sport": "src_port",
    "urgptr": "urgent_pointer",
}
_LAYER_FIELD_ALIASES: dict[str, dict[str, str]] = {
    "arp": {
        "hwlen": "hardware_length",
        "hwtype": "hardware_type",
        "plen": "protocol_length",
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
    "ethernet": {
        "type": "ethertype",
    },
    "icmp": {
        "id": "identifier",
        "seq": "sequence",
    },
    "icmpv6": {
        "cksum": "checksum",
        "id": "identifier",
        "seq": "sequence",
    },
    "ipv4": {
        "id": "identification",
        "ihl": "header_length",
    },
    "ipv6": {
        "fl": "flow_label",
        "plen": "payload_length",
        "tc": "traffic_class",
        "version": "version",
    },
    "linux_sll": {
        "lladdrlen": "address_length",
        "lladdrtype": "address_type",
        "pkttype": "packet_type",
        "src": "source_address",
    },
    "payload": {
        "load": "hex",
    },
    "tcp": {
        "ack": "acknowledgement",
        "seq": "sequence",
    },
    "vlan": {
        "dei": "drop_eligible",
        "prio": "priority",
        "type": "ethertype",
        "vlan": "vlan_id",
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
    "fragment": 44,
    "icmp": 1,
    "icmpv6": 58,
    "routing": 43,
    "tcp": 6,
    "udp": 17,
}
_ROOT_ALIASES: dict[str, str] = {
    "CookedLinux": "link:linux-cooked",
    "Ether": "link:ethernet",
    "IP": "l3:ipv4",
    "IPv6": "l3:ipv6",
    "Loopback": "link:null-loopback",
    "Raw": "link:raw",
    "link:linux-sll": "link:linux-cooked",
}


def decode_root(
    root: str,
    raw: bytes,
    *,
    capabilities: BackendCapabilities | BackendRegistration | None = None,
) -> Any:
    """Decode raw bytes with a Scapy decoder selected by oracle root name."""

    _require_decode_capability(capabilities)
    scapy_all = import_scapy()["all"]
    decoders = {
        "CookedLinux": "CookedLinux",
        "Ether": "Ether",
        "IP": "IP",
        "IPv6": "IPv6",
        "Loopback": "Loopback",
        "Raw": "Raw",
        "link:ethernet": "Ether",
        "link:linux-cooked": "CookedLinux",
        "link:linux-sll": "CookedLinux",
        "link:null-loopback": "Loopback",
        "link:raw": "Raw",
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
        normalized_layer = _normalize_layer_name(_text(layer["name"]))
        if normalized_layer == "padding":
            continue
        layer_fields = _normalize_fields(
            normalized_layer,
            _object(layer["fields"], f"{layer['name']}.fields"),
        )
        if normalized_layer == "dhcp" and "dhcp" in normalized_fields:
            normalized_fields["dhcp"].update(layer_fields)
            continue
        key = _field_key(normalized_fields, normalized_layer)
        normalized_fields[key] = layer_fields
        normalized_layers.append(normalized_layer)

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


def _normalize_layer_name(native_name: str) -> str:
    if native_name.startswith("ICMPv6"):
        return "icmpv6"
    return _LAYER_ALIASES.get(native_name, native_name.lower())


def _normalize_root_name(root: str | None) -> str | None:
    if root is None:
        return None
    return _ROOT_ALIASES.get(root, root)


def _normalize_fields(layer_name: str, fields: JSONObject) -> JSONObject:
    if layer_name == "payload":
        return _normalize_payload_fields(fields)
    if layer_name == "dns":
        return _normalize_dns_fields(fields)
    if layer_name == "dhcp":
        return _normalize_dhcp_fields(fields)

    output: JSONObject = {}
    for native_name, value in fields.items():
        normalized_name = _normalize_field_name(layer_name, native_name)
        output[normalized_name] = _normalize_field_value(layer_name, normalized_name, value)
    if layer_name == "arp":
        _normalize_arp_fields(output)
    if layer_name in {"icmp", "icmpv6"}:
        output.pop("unused", None)
        if output.get("data") == {"hex": "", "ascii": ""}:
            output.pop("data", None)
        _fill_icmp_rest_of_header(output)
        if layer_name == "icmpv6":
            _normalize_icmpv6_rest_of_header(output)
    if layer_name == "ipv6_fragment":
        _normalize_ipv6_fragment_fields(output)
    if layer_name == "ipv6_routing":
        _normalize_ipv6_routing_fields(output)
    return output


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


def _normalize_payload_fields(fields: JSONObject) -> JSONObject:
    load = fields.get("load")
    if isinstance(load, Mapping):
        hex_value = load.get("hex")
        ascii_value = load.get("ascii")
        if isinstance(hex_value, str):
            output: JSONObject = {
                "hex": hex_value,
                "length": len(bytes.fromhex(hex_value)),
            }
            if isinstance(ascii_value, str):
                output["ascii"] = ascii_value
            return output
    if isinstance(load, str):
        return {"hex": load, "length": len(bytes.fromhex(load))}
    return {}


def _normalize_field_name(layer_name: str, native_name: str) -> str:
    layer_aliases = _LAYER_FIELD_ALIASES.get(layer_name, {})
    return layer_aliases.get(native_name, _FIELD_ALIASES.get(native_name, native_name))


def _normalize_field_value(layer_name: str, field_name: str, value: JSONValue) -> JSONValue:
    if layer_name == "icmpv6" and field_name == "type" and isinstance(value, str):
        return _normalize_icmpv6_type(value)
    if layer_name == "icmp" and field_name == "type" and isinstance(value, str):
        return _normalize_icmpv4_type(value)
    if layer_name == "linux_sll" and field_name == "source_address":
        return _normalize_linux_sll_source_address(value)
    if field_name == "flags":
        if layer_name == "tcp":
            return _normalize_tcp_flags(value)
        if layer_name == "dhcp":
            return _normalize_dhcp_flags(value)
        return _normalize_flags(value)
    if field_name == "is_response" and isinstance(value, int):
        return bool(value)
    if field_name in {"more_fragments"} and isinstance(value, int):
        return bool(value)
    return value


def _normalize_flags(value: JSONValue) -> JSONValue:
    if isinstance(value, str):
        if not value:
            return "none"
        return value.lower().replace("+", "|").replace(" ", "_")
    return value


def _normalize_icmpv6_type(value: str) -> str:
    lowered = value.lower().replace(" ", "_").replace("-", "_")
    aliases = {
        "echo_reply": "echo_reply",
        "echo_request": "echo_request",
        "destination_unreachable": "destination_unreachable",
        "packet_too_big": "packet_too_big",
        "parameter_problem": "parameter_problem",
        "time_exceeded": "time_exceeded",
    }
    return aliases.get(lowered, lowered)


def _normalize_icmpv4_type(value: str) -> str:
    lowered = value.lower().replace(" ", "_").replace("-", "_")
    aliases = {
        "dest_unreach": "destination_unreachable",
        "destination_unreachable": "destination_unreachable",
        "echo_reply": "echo_reply",
        "echo_request": "echo_request",
        "parameter_problem": "parameter_problem",
        "redirect": "redirect",
        "time_exceeded": "time_exceeded",
    }
    return aliases.get(lowered, lowered)


def _normalize_tcp_flags(value: JSONValue) -> JSONValue:
    if not isinstance(value, str):
        return value
    if not value:
        return "none"
    names = {
        "F": "fin",
        "S": "syn",
        "R": "rst",
        "P": "psh",
        "A": "ack",
        "U": "urg",
        "E": "ece",
        "C": "cwr",
        "N": "ns",
    }
    if all(char in names for char in value):
        return "|".join(names[char] for char in value)
    return value.lower().replace("+", "|").replace(" ", "_")


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


def _bool_flag(value: JSONValue) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value not in {"", "0", "false", "False"}
    return bool(value)


def _fill_icmp_rest_of_header(fields: JSONObject) -> None:
    if "rest_of_header" in fields:
        return
    identifier = fields.get("identifier")
    sequence = fields.get("sequence")
    if isinstance(identifier, int) and isinstance(sequence, int):
        fields["rest_of_header"] = f"{identifier:04x}{sequence:04x}"


def _normalize_icmpv6_rest_of_header(fields: JSONObject) -> None:
    icmp_type = fields.get("type")
    if icmp_type in {2, "packet_too_big"} and isinstance(fields.get("mtu"), int):
        fields["rest_of_header"] = f"{fields.pop('mtu'):08x}"
    elif icmp_type in {4, "parameter_problem"} and isinstance(fields.get("ptr"), int):
        fields["rest_of_header"] = f"{fields.pop('ptr'):08x}"
    elif icmp_type in {1, 3, "destination_unreachable", "time_exceeded"}:
        fields.setdefault("rest_of_header", "00000000")

    if fields.get("ext") is None:
        fields.pop("ext", None)
    if fields.get("extpad") == {"hex": "", "ascii": ""}:
        fields.pop("extpad", None)


def _normalize_ipv6_fragment_fields(fields: JSONObject) -> None:
    aliases = {
        "id": "identification",
        "offset": "fragment_offset",
        "m": "more_fragments",
        "res1": "reserved",
        "res2": "res",
    }
    for old, new in aliases.items():
        if old in fields and new not in fields:
            fields[new] = fields.pop(old)
    if isinstance(fields.get("more_fragments"), int):
        fields["more_fragments"] = bool(fields["more_fragments"])


def _normalize_ipv6_routing_fields(fields: JSONObject) -> None:
    if "segleft" in fields and "segments_left" not in fields:
        fields["segments_left"] = fields.pop("segleft")
    if fields.get("reserved") == 0:
        fields["reserved"] = "00000000"
    if fields.get("addresses") == []:
        fields.pop("addresses", None)


_ARP_ADDRESS_FIELDS = (
    "sender_hardware_address",
    "sender_protocol_address",
    "target_hardware_address",
    "target_protocol_address",
)


def _normalize_arp_fields(fields: JSONObject) -> None:
    """Normalize ARP fields for backend-neutral comparison.

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

    for name in _ARP_ADDRESS_FIELDS:
        if name in fields:
            fields[name] = _normalize_arp_address(fields[name])


def _normalize_arp_address(value: JSONValue) -> JSONValue:
    if isinstance(value, Mapping):
        hex_value = value.get("hex")
        if isinstance(hex_value, str):
            return {"hex": hex_value}
    return value


def _normalize_linux_sll_source_address(value: JSONValue) -> JSONValue:
    if isinstance(value, Mapping):
        hex_value = value.get("hex")
        if isinstance(hex_value, str):
            return {"hex": hex_value}
    return value


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


def _field_key(existing: Mapping[str, JSONObject], layer_name: str) -> str:
    if layer_name not in existing:
        return layer_name
    index = 2
    while f"{layer_name}#{index}" in existing:
        index += 1
    return f"{layer_name}#{index}"


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


def _json_value(value: Any) -> JSONValue:
    if isinstance(value, bytes):
        return {"hex": value.hex(), "ascii": value.decode("utf-8", "replace")}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    return str(value)


def _object(value: JSONValue, name: str) -> JSONObject:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    return dict(value)


def _text(value: object) -> str:
    if isinstance(value, str):
        return value
    return str(value)


def _text_or_none(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return str(value)
