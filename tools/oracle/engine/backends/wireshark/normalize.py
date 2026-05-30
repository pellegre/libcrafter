"""Wireshark/tshark decoded-model normalization interface."""

from __future__ import annotations

import json
import shutil
import struct
import subprocess
import tempfile
from collections.abc import Iterable, Sequence
from pathlib import Path

from ...model import DecodedModel, EncodedVector, JSONObject
from ..registry import get_backend


BACKEND_NAME = "wireshark"
_TSHARK_TIMEOUT_SECONDS = 30
_DLT_BY_ROOT: dict[str, int] = {
    "Ether": 1,
    "IP": 101,
    "IPv6": 101,
    "Raw": 101,
    "link:ethernet": 1,
    "link:linux-cooked": 113,
    "link:linux-sll": 113,
    "link:null-loopback": 0,
    "link:raw": 101,
    "l3:ipv4": 101,
    "l3:ipv6": 101,
    "l3:raw": 101,
}
_ROOT_ALIASES: dict[str, str] = {
    "Ether": "link:ethernet",
    "IP": "l3:ipv4",
    "IPv6": "l3:ipv6",
    "Raw": "link:raw",
    "link:linux-sll": "link:linux-cooked",
}
_PROTOCOL_LAYER_ALIASES: dict[str, str | None] = {
    "arp": "arp",
    "bootp": "dhcp",
    "data": "payload",
    "dhcp": "dhcp",
    "eth": "ethernet",
    "ethertype": None,
    "fake-field-wrapper": None,
    "frame": None,
    "icmp": "icmp",
    "icmpv6": "icmpv6",
    "ip": "ipv4",
    "ipv6": "ipv6",
    "null": "null_loopback",
    "raw": None,
    "sll": "linux_sll",
    "tcp": "tcp",
    "udp": "udp",
    "vlan": "vlan",
}

# DHCP magic cookie (RFC 2132) prefacing the option region.
_DHCP_MAGIC_COOKIE = 0x63825363
# Option codes that need no length octet and carry no payload.
_DHCP_OPTION_PAD = 0
_DHCP_OPTION_END = 255
# DHCP message type option (RFC 2132).
_DHCP_OPTION_MESSAGE_TYPE = 53


class WiresharkNormalizationUnsupported(RuntimeError):
    """Raised when tshark cannot perform the requested parser operation."""


def availability_metadata() -> JSONObject:
    """Return current tshark availability metadata."""

    return get_backend(BACKEND_NAME).availability.to_dict()


def unsupported_decoded_model(
    *,
    root: str | None = None,
    source_hex: str | None = None,
    feature_tags: Sequence[str] = (),
) -> DecodedModel:
    """Return a structured unsupported model for parser-only report paths."""

    return DecodedModel(
        backend=BACKEND_NAME,
        layers=[],
        fields={},
        root=root,
        source_hex=source_hex,
        feature_tags=list(feature_tags),
        metadata={
            "unsupported": True,
            "reason": "tshark decoded-model normalization is unavailable",
            "availability": availability_metadata(),
        },
    )


def decode_bytes(
    raw: bytes,
    *,
    root: str,
    source_hex: str | None = None,
    feature_tags: Sequence[str] = (),
) -> DecodedModel:
    """Decode one packet by wrapping bytes in a temporary pcap for tshark."""

    if not raw:
        raise WiresharkNormalizationUnsupported("tshark cannot decode an empty packet")
    datalink = _datalink_for_root(root, raw)
    with tempfile.TemporaryDirectory(prefix="oracle-wireshark.") as temp_dir:
        pcap_path = Path(temp_dir) / "packet.pcap"
        _write_single_packet_pcap(pcap_path, raw, datalink=datalink)
        packets = _tshark_json_packets(pcap_path)
    if not packets:
        raise WiresharkNormalizationUnsupported("tshark emitted no decoded packets")
    return normalize_packet_json(
        packets[0],
        root=root,
        source_hex=source_hex or raw.hex(),
        feature_tags=feature_tags,
    )


def decode_vector(vector: EncodedVector) -> DecodedModel:
    """Decode one vector through the parser-only tshark interface."""

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
    """Decode vectors in order through the parser-only tshark interface."""

    return [decode_vector(vector) for vector in vectors]


def normalize_packet_json(
    packet: JSONObject,
    *,
    root: str | None,
    source_hex: str | None,
    feature_tags: Sequence[str] = (),
) -> DecodedModel:
    """Convert one tshark ``-T json`` packet object into an oracle model."""

    layers_object = _object(_object(packet.get("_source"), "_source").get("layers"), "layers")
    protocol_names = _protocol_names(layers_object)
    normalized_layers: list[str] = []
    fields: dict[str, JSONObject] = {}
    for protocol in protocol_names:
        layer_name = _PROTOCOL_LAYER_ALIASES.get(protocol)
        if layer_name is None:
            continue
        layer_fields = _normalize_protocol_fields(
            layer_name, layers_object, source_hex=source_hex
        )
        if not layer_fields and layer_name == "payload":
            continue
        key = _field_key(fields, layer_name)
        fields[key] = layer_fields
        normalized_layers.append(layer_name)

    return DecodedModel(
        backend=BACKEND_NAME,
        layers=normalized_layers,
        fields=fields,
        root=_normalize_root_name(root),
        source_hex=source_hex,
        feature_tags=list(feature_tags),
        metadata={
            "native": {
                "protocols": protocol_names,
                "layers": layers_object,
            },
            "reencoded_hex": source_hex,
            "tshark": {
                "argv": _tshark_argv("<pcap>"),
            },
        },
    )


def pcap_decoded_models(path: str | Path, *, root: str | None = None) -> list[DecodedModel]:
    """Decode all packets in a pcap through tshark JSON output."""

    return [
        normalize_packet_json(packet, root=root, source_hex=None)
        for packet in _tshark_json_packets(Path(path))
    ]


def _tshark_json_packets(path: Path) -> list[JSONObject]:
    tshark = shutil.which("tshark")
    if tshark is None:
        raise WiresharkNormalizationUnsupported("tshark not found on PATH")
    process = subprocess.run(
        _tshark_argv(str(path), executable=tshark),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=_TSHARK_TIMEOUT_SECONDS,
    )
    if process.returncode != 0:
        detail = process.stderr.strip() or process.stdout.strip()
        raise WiresharkNormalizationUnsupported(
            f"tshark decode failed with exit {process.returncode}: {detail}"
        )
    try:
        value = json.loads(process.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise WiresharkNormalizationUnsupported(f"tshark emitted invalid JSON: {exc}") from exc
    if not isinstance(value, list):
        raise WiresharkNormalizationUnsupported("tshark JSON root must be a list")
    packets: list[JSONObject] = []
    for item in value:
        packets.append(_object(item, "tshark packet"))
    return packets


def _tshark_argv(path: str, *, executable: str = "tshark") -> list[str]:
    return [
        executable,
        "-n",
        "-o",
        "tcp.relative_sequence_numbers:FALSE",
        "-o",
        "tcp.analyze_sequence_numbers:FALSE",
        "-r",
        path,
        "-T",
        "json",
    ]


def _write_single_packet_pcap(path: Path, raw: bytes, *, datalink: int) -> None:
    path.write_bytes(
        b"\xd4\xc3\xb2\xa1"
        + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, datalink)
        + struct.pack("<IIII", 0, 0, len(raw), len(raw))
        + raw
    )


def _datalink_for_root(root: str, raw: bytes) -> int:
    if root == "link:raw":
        if raw and raw[0] >> 4 in {4, 6}:
            return 101
        raise WiresharkNormalizationUnsupported("tshark raw-link decode requires IPv4 or IPv6 bytes")
    datalink = _DLT_BY_ROOT.get(root)
    if datalink is None:
        raise WiresharkNormalizationUnsupported(f"unsupported tshark root decoder: {root!r}")
    return datalink


def _protocol_names(layers: JSONObject) -> list[str]:
    frame = layers.get("frame")
    if isinstance(frame, dict):
        protocols = _string_field(frame, "frame.protocols")
        if protocols is not None:
            return [item for item in protocols.split(":") if item]
    return [key for key, value in layers.items() if isinstance(value, dict)]


def _normalize_protocol_fields(
    layer_name: str, layers: JSONObject, *, source_hex: str | None = None
) -> JSONObject:
    if layer_name == "ethernet":
        return _normalize_ethernet(_layer(layers, "eth"))
    if layer_name == "arp":
        return _normalize_arp(_layer(layers, "arp"))
    if layer_name == "ipv4":
        return _normalize_ipv4(_layer(layers, "ip"))
    if layer_name == "ipv6":
        return _normalize_ipv6(_layer(layers, "ipv6"))
    if layer_name == "udp":
        return _normalize_udp(_layer(layers, "udp"))
    if layer_name == "dhcp":
        return _normalize_dhcp(_dhcp_layer(layers), source_hex=source_hex)
    if layer_name == "tcp":
        return _normalize_tcp(_layer(layers, "tcp"))
    if layer_name == "icmp":
        return _normalize_icmp(_layer(layers, "icmp"))
    if layer_name == "icmpv6":
        return _normalize_icmp(_layer(layers, "icmpv6"))
    if layer_name == "payload":
        return _normalize_payload(_layer(layers, "data"))
    if layer_name == "vlan":
        return _normalize_vlan(_layer(layers, "vlan"))
    if layer_name == "linux_sll":
        return _normalize_linux_sll(_layer(layers, "sll"))
    if layer_name == "null_loopback":
        return _normalize_null_loopback(_layer(layers, "null"))
    return {}


def _normalize_ethernet(layer: JSONObject) -> JSONObject:
    output = _fields_from_aliases(
        layer,
        {
            "dst": ("eth.dst",),
            "src": ("eth.src",),
            "ethertype": ("eth.type",),
        },
    )
    _parse_int_fields(output, "ethertype")
    return output


def _normalize_arp(layer: JSONObject) -> JSONObject:
    output = _fields_from_aliases(
        layer,
        {
            "hardware_type": ("arp.hw.type", "arp.hardware.type"),
            "protocol_type": ("arp.proto.type",),
            "hardware_length": ("arp.hw.size", "arp.hardware.size"),
            "protocol_length": ("arp.proto.size",),
            "opcode": ("arp.opcode",),
            "sender_hardware_address": ("arp.src.hw_mac", "arp.src.hw"),
            "sender_protocol_address": ("arp.src.proto_ipv4", "arp.src.proto"),
            "target_hardware_address": ("arp.dst.hw_mac", "arp.dst.hw"),
            "target_protocol_address": ("arp.dst.proto_ipv4", "arp.dst.proto"),
        },
    )
    _parse_int_fields(
        output,
        "hardware_type",
        "protocol_type",
        "hardware_length",
        "protocol_length",
        "opcode",
    )
    return output


def _normalize_ipv4(layer: JSONObject) -> JSONObject:
    output = _fields_from_aliases(
        layer,
        {
            "version": ("ip.version",),
            "header_length": ("ip.hdr_len",),
            "tos": ("ip.dsfield", "ip.tos"),
            "length": ("ip.len",),
            "identification": ("ip.id",),
            "fragment_offset": ("ip.frag_offset",),
            "ttl": ("ip.ttl",),
            "protocol": ("ip.proto",),
            "checksum": ("ip.checksum",),
            "src": ("ip.src",),
            "dst": ("ip.dst",),
        },
    )
    _parse_int_fields(
        output,
        "version",
        "header_length",
        "tos",
        "length",
        "identification",
        "fragment_offset",
        "ttl",
        "protocol",
        "checksum",
    )
    header_length = output.get("header_length")
    if isinstance(header_length, int) and header_length >= 20 and header_length % 4 == 0:
        output["header_length"] = header_length // 4
    output["flags"] = _ipv4_flags(layer)
    return output


def _normalize_ipv6(layer: JSONObject) -> JSONObject:
    output = _fields_from_aliases(
        layer,
        {
            "version": ("ipv6.version",),
            "traffic_class": ("ipv6.tclass",),
            "flow_label": ("ipv6.flow",),
            "payload_length": ("ipv6.plen",),
            "next_header": ("ipv6.nxt",),
            "hop_limit": ("ipv6.hlim",),
            "src": ("ipv6.src",),
            "dst": ("ipv6.dst",),
        },
    )
    _parse_int_fields(
        output,
        "version",
        "traffic_class",
        "flow_label",
        "payload_length",
        "next_header",
        "hop_limit",
    )
    return output


def _normalize_udp(layer: JSONObject) -> JSONObject:
    output = _fields_from_aliases(
        layer,
        {
            "src_port": ("udp.srcport",),
            "dst_port": ("udp.dstport",),
            "length": ("udp.length",),
            "checksum": ("udp.checksum",),
        },
    )
    _parse_int_fields(output, "src_port", "dst_port", "length", "checksum")
    return output


def _normalize_dhcp(layer: JSONObject, *, source_hex: str | None = None) -> JSONObject:
    """Normalize a tshark BOOTP/DHCP layer to the shared oracle field names.

    The normalized names match the Scapy reference backend
    (``tools/oracle/engine/backends/scapy/normalize.py``) and the libcrafter
    decoder (``tools/oracle/adapters/src/bin/decode_vectors.rs``): ``opcode``,
    ``hardware_type``/``hardware_length``, ``hops``, ``transaction_id``,
    ``seconds``, integer ``flags``, the BOOTP IPv4 fields, ``magic_cookie``,
    ``client_hardware_address`` as ``{"hex": ...}``, plus backend-neutral
    ``options`` (``{code, payload_hex}`` TLVs), ``option_count`` and integer
    ``message_type``. Wireshark renamed the dissector prefix from ``bootp.`` to
    ``dhcp.`` around 3.0, so both prefixes are accepted.
    """

    output = _fields_from_aliases(
        layer,
        {
            "opcode": ("dhcp.type", "bootp.type"),
            "hardware_type": ("dhcp.hw.type", "bootp.hw.type"),
            "hardware_length": ("dhcp.hw.len", "bootp.hw.len"),
            "hops": ("dhcp.hops", "bootp.hops"),
            "transaction_id": ("dhcp.id", "bootp.id"),
            "seconds": ("dhcp.secs", "bootp.secs"),
            "client_ip": ("dhcp.ip.client", "bootp.ip.client"),
            "your_ip": ("dhcp.ip.your", "bootp.ip.your"),
            "server_ip": ("dhcp.ip.server", "bootp.ip.server"),
            "relay_ip": ("dhcp.ip.relay", "bootp.ip.relay"),
            "magic_cookie": ("dhcp.cookie", "bootp.cookie"),
        },
    )
    _parse_int_fields(
        output,
        "opcode",
        "hardware_type",
        "hardware_length",
        "hops",
        "transaction_id",
        "seconds",
    )
    magic = _parse_int(output.get("magic_cookie"))
    output["magic_cookie"] = magic if magic is not None else _DHCP_MAGIC_COOKIE

    chaddr = _string_field(layer, "dhcp.hw.mac_addr", "bootp.hw.mac_addr", "dhcp.hw.addr")
    if chaddr is not None:
        output["client_hardware_address"] = {"hex": _hex_bytes(chaddr)}

    output["flags"] = _dhcp_flags(layer)

    options = _dhcp_options_from_source(source_hex)
    if options is not None:
        output["options"] = options
        output["option_count"] = len(options)
        for option in options:
            if option["code"] == _DHCP_OPTION_MESSAGE_TYPE:
                payload = bytes.fromhex(option["payload_hex"])
                if len(payload) == 1:
                    output["message_type"] = payload[0]
                break
    else:
        message_type = _parse_int(
            _field(layer, "dhcp.option.dhcp", "bootp.option.dhcp")
        )
        if message_type is not None:
            output["message_type"] = message_type
    return output


def _dhcp_flags(layer: JSONObject) -> int:
    """Return DHCP flags as the shared integer view (broadcast bit 0x8000)."""

    value = _parse_int(_field(layer, "dhcp.flags", "bootp.flags"))
    if value is not None:
        return value
    if _truthy_field(layer, "dhcp.flags.bc") or _truthy_field(layer, "bootp.flags.bc"):
        return 0x8000
    return 0


def _dhcp_options_from_source(source_hex: str | None) -> list[JSONObject] | None:
    """Reconstruct backend-neutral DHCP option TLVs from the raw packet bytes.

    The option region begins right after the magic cookie. Parsing the raw bytes
    (rather than tshark's typed option views) keeps the ``{code, payload_hex}``
    list byte-identical to the Scapy and libcrafter decoders. A malformed or
    truncated region yields ``None`` so callers fall back to tshark's own
    message-type field.
    """

    if not source_hex:
        return None
    try:
        raw = bytes.fromhex(source_hex)
    except ValueError:
        return None
    cookie = _DHCP_MAGIC_COOKIE.to_bytes(4, "big")
    marker = raw.find(cookie)
    if marker < 0:
        return None
    return _decode_dhcp_option_tlvs(raw[marker + len(cookie) :])


def _decode_dhcp_option_tlvs(raw: bytes) -> list[JSONObject] | None:
    # Mirrors the Scapy reference parser
    # (tools/oracle/engine/backends/scapy/normalize.py::_decode_dhcp_option_tlvs):
    # pad/end are single-octet options with empty payloads and END does not stop
    # parsing, so the ``option_count`` stays byte-identical across backends. The
    # wire bytes are identical for the offline strict-byte path, so the region
    # after the magic cookie matches the Scapy DHCP sub-layer region exactly.
    options: list[JSONObject] = []
    index = 0
    length = len(raw)
    while index < length:
        code = raw[index]
        index += 1
        if code in {_DHCP_OPTION_PAD, _DHCP_OPTION_END}:
            options.append({"code": code, "payload_hex": ""})
            continue
        if index >= length:
            return None
        option_length = raw[index]
        index += 1
        if index + option_length > length:
            return None
        payload = raw[index : index + option_length]
        index += option_length
        options.append({"code": code, "payload_hex": payload.hex()})
    return options if options else None


def _dhcp_layer(layers: JSONObject) -> JSONObject:
    layer = layers.get("dhcp")
    if isinstance(layer, dict):
        return layer
    return _layer(layers, "bootp")


def _normalize_tcp(layer: JSONObject) -> JSONObject:
    output = _fields_from_aliases(
        layer,
        {
            "src_port": ("tcp.srcport",),
            "dst_port": ("tcp.dstport",),
            "sequence": ("tcp.seq_raw", "tcp.seq"),
            "acknowledgement": ("tcp.ack_raw", "tcp.ack"),
            "data_offset": ("tcp.hdr_len",),
            "window": ("tcp.window_size_value", "tcp.window_size"),
            "checksum": ("tcp.checksum",),
            "urgent_pointer": ("tcp.urgent_pointer",),
        },
    )
    _parse_int_fields(
        output,
        "src_port",
        "dst_port",
        "sequence",
        "acknowledgement",
        "data_offset",
        "window",
        "checksum",
        "urgent_pointer",
    )
    data_offset = output.get("data_offset")
    if isinstance(data_offset, int) and data_offset >= 20 and data_offset % 4 == 0:
        output["data_offset"] = data_offset // 4
    output["flags"] = _tcp_flags(layer)
    return output


def _normalize_icmp(layer: JSONObject) -> JSONObject:
    output = _fields_from_aliases(
        layer,
        {
            "type": ("icmp.type", "icmpv6.type"),
            "code": ("icmp.code", "icmpv6.code"),
            "checksum": ("icmp.checksum", "icmpv6.checksum"),
            "identifier": ("icmp.ident", "icmpv6.echo.identifier"),
            "sequence": ("icmp.seq", "icmpv6.echo.sequence_number"),
        },
    )
    _parse_int_fields(output, "type", "code", "checksum", "identifier", "sequence")
    identifier = output.get("identifier")
    sequence = output.get("sequence")
    if isinstance(identifier, int) and isinstance(sequence, int):
        output["rest_of_header"] = f"{identifier:04x}{sequence:04x}"
    return output


def _normalize_payload(layer: JSONObject) -> JSONObject:
    data = _string_field(layer, "data.data", "data.text")
    if data is None:
        return {}
    hex_value = _hex_bytes(data)
    return {
        "hex": hex_value,
        "length": len(bytes.fromhex(hex_value)),
    }


def _normalize_vlan(layer: JSONObject) -> JSONObject:
    output = _fields_from_aliases(
        layer,
        {
            "priority": ("vlan.priority",),
            "drop_eligible": ("vlan.dei",),
            "vlan_id": ("vlan.id",),
            "ethertype": ("vlan.etype", "vlan.type"),
        },
    )
    _parse_int_fields(output, "priority", "drop_eligible", "vlan_id", "ethertype")
    return output


def _normalize_linux_sll(layer: JSONObject) -> JSONObject:
    output = _fields_from_aliases(
        layer,
        {
            "packet_type": ("sll.pkttype", "sll.packet_type"),
            "address_type": ("sll.hatype", "sll.etype"),
            "address_length": ("sll.halen",),
            "source_address": ("sll.src.eth", "sll.src", "sll.addr"),
            "protocol": ("sll.ltype", "sll.protocol"),
        },
    )
    _parse_int_fields(output, "packet_type", "address_type", "address_length", "protocol")
    return output


def _normalize_null_loopback(layer: JSONObject) -> JSONObject:
    output = _fields_from_aliases(layer, {"type": ("null.type",)})
    _parse_int_fields(output, "type")
    return output


def _fields_from_aliases(layer: JSONObject, aliases: dict[str, tuple[str, ...]]) -> JSONObject:
    output: JSONObject = {}
    for target, field_names in aliases.items():
        value = _field(layer, *field_names)
        if value is not None:
            output[target] = value
    return output


def _parse_int_fields(output: JSONObject, *names: str) -> None:
    for name in names:
        value = output.get(name)
        parsed = _parse_int(value)
        if parsed is not None:
            output[name] = parsed


def _ipv4_flags(layer: JSONObject) -> str:
    if _truthy_field(layer, "ip.flags.df"):
        return "df"
    if _truthy_field(layer, "ip.flags.mf"):
        return "mf"
    value = _parse_int(_field(layer, "ip.flags"))
    if value == 0:
        return "none"
    if value is None:
        return "none"
    flags: list[str] = []
    if value & 0x2:
        flags.append("df")
    if value & 0x1:
        flags.append("mf")
    return "|".join(flags) if flags else "none"


def _tcp_flags(layer: JSONObject) -> str:
    names = [
        ("tcp.flags.fin", "fin"),
        ("tcp.flags.syn", "syn"),
        ("tcp.flags.reset", "rst"),
        ("tcp.flags.push", "psh"),
        ("tcp.flags.ack", "ack"),
        ("tcp.flags.urg", "urg"),
        ("tcp.flags.ece", "ece"),
        ("tcp.flags.cwr", "cwr"),
    ]
    enabled = [name for field, name in names if _truthy_field(layer, field)]
    if enabled:
        return "|".join(enabled)
    value = _parse_int(_field(layer, "tcp.flags"))
    if value is None or value == 0:
        return "none"
    raw_names = [
        (0x01, "fin"),
        (0x02, "syn"),
        (0x04, "rst"),
        (0x08, "psh"),
        (0x10, "ack"),
        (0x20, "urg"),
        (0x40, "ece"),
        (0x80, "cwr"),
    ]
    return "|".join(name for bit, name in raw_names if value & bit) or "none"


def _truthy_field(layer: JSONObject, name: str) -> bool:
    value = _field(layer, name)
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value not in {"", "0", "0x0", "False", "false"}
    return False


def _field(layer: JSONObject, *names: str) -> object | None:
    for name in names:
        value = layer.get(name)
        if value is None:
            continue
        return _scalar_value(value)
    return None


def _string_field(layer: JSONObject, *names: str) -> str | None:
    value = _field(layer, *names)
    if value is None:
        return None
    return str(value)


def _scalar_value(value: object) -> object:
    if isinstance(value, list):
        if not value:
            return None
        return _scalar_value(value[0])
    if isinstance(value, dict):
        show = value.get("show")
        if show is not None:
            return _scalar_value(show)
        value_value = value.get("value")
        if value_value is not None:
            return _scalar_value(value_value)
        return value
    return value


def _parse_int(value: object) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    if " " in candidate:
        candidate = candidate.split(" ", 1)[0]
    try:
        return int(candidate, 0)
    except ValueError:
        return None


def _hex_bytes(value: str) -> str:
    return "".join(char for char in value.lower() if char in "0123456789abcdef")


def _field_key(fields: dict[str, JSONObject], layer_name: str) -> str:
    if layer_name not in fields:
        return layer_name
    suffix = 2
    while f"{layer_name}#{suffix}" in fields:
        suffix += 1
    return f"{layer_name}#{suffix}"


def _normalize_root_name(root: str | None) -> str | None:
    if root is None:
        return None
    return _ROOT_ALIASES.get(root, root)


def _layer(layers: JSONObject, name: str) -> JSONObject:
    value = layers.get(name)
    return value if isinstance(value, dict) else {}


def _object(value: object, name: str) -> JSONObject:
    if not isinstance(value, dict):
        raise WiresharkNormalizationUnsupported(f"tshark {name} must be an object")
    return dict(value)
