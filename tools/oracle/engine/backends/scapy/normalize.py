"""Scapy packet decoding and backend-neutral normalization."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from ...model import DecodedModel, EncodedVector, JSONObject, JSONValue, PacketPlan
from .bootstrap import import_scapy


BACKEND_NAME = "scapy"

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
    "icmp": 1,
    "icmpv6": 58,
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


def decode_root(root: str, raw: bytes) -> Any:
    """Decode raw bytes with a Scapy decoder selected by oracle root name."""

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
) -> DecodedModel:
    """Decode raw bytes and return the normalized Scapy model."""

    packet = decode_root(root, raw)
    return normalize_packet(
        packet,
        root=root,
        source_hex=source_hex or raw.hex(),
        feature_tags=feature_tags,
    )


def decode_vector(vector: EncodedVector) -> DecodedModel:
    """Decode one encoded vector through its root decoder metadata."""

    root = vector.root or vector.decoder
    if root is None:
        raise ValueError("encoded vector is missing root decoder metadata")
    return decode_bytes(
        vector.to_bytes(),
        root=root,
        source_hex=vector.raw_hex,
        feature_tags=vector.plan.feature_tags,
    )


def decode_vectors(vectors: Iterable[EncodedVector]) -> list[DecodedModel]:
    """Decode vectors in order."""

    return [decode_vector(vector) for vector in vectors]


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
    try:
        metadata["reencoded_hex"] = bytes(import_scapy()["all"].raw(packet)).hex()
    except Exception as exc:  # pragma: no cover - Scapy exception types vary.
        metadata["reencoded_error"] = _text(exc)

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
        layers.append(
            {
                "name": current.__class__.__name__,
                "fields": {
                    str(key): _json_value(value)
                    for key, value in sorted(current.fields.items())
                },
                "summary": _text(current.summary()),
            }
        )
        current = current.payload
    return layers


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
    if layer_name in {"icmp", "icmpv6"}:
        output.pop("unused", None)
        if output.get("data") == {"hex": "", "ascii": ""}:
            output.pop("data", None)
        _fill_icmp_rest_of_header(output)
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
    output: JSONObject = {}
    for native_name, value in fields.items():
        if native_name in {"sname", "file"}:
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
    return output


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


def _normalize_linux_sll_source_address(value: JSONValue) -> JSONValue:
    if isinstance(value, Mapping):
        hex_value = value.get("hex")
        if isinstance(hex_value, str):
            return {"hex": hex_value}
    return value


def _field_key(existing: Mapping[str, JSONObject], layer_name: str) -> str:
    if layer_name not in existing:
        return layer_name
    index = 2
    while f"{layer_name}#{index}" in existing:
        index += 1
    return f"{layer_name}#{index}"


def _expected_stack(plan: PacketPlan) -> list[str]:
    payload_fields = _plan_layer_fields(plan, "payload")
    payload_hex = _text_or_none(payload_fields.get("hex"))
    aliases = {
        "dot1q": "vlan",
        "ether": "ethernet",
        "ip": "ipv4",
        "raw": "payload",
    }
    output = [aliases.get(layer.lower(), layer.lower()) for layer in plan.stack]
    if payload_hex == "":
        output = [layer for layer in output if layer != "payload"]
    return output


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
