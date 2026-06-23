"""Wireshark/tshark decoded-model normalization interface."""

from __future__ import annotations

import ipaddress
import json
import shutil
import struct
import subprocess
import tempfile
from collections.abc import Iterable, Sequence
from pathlib import Path

from ...model import DecodedModel, EncodedVector, JSONObject
from ..registry import get_backend
from .decode_helpers import (
    _field,
    _field_list,
    _fields_from_aliases,
    _layer,
    _layer_any,
    _normalize_root_name,
    _parse_int,
    _parse_int_fields,
    _string_field,
)


BACKEND_NAME = "wireshark"
_TSHARK_TIMEOUT_SECONDS = 30
_DLT_BY_ROOT: dict[str, int] = {
    "Dot11": 105,
    "Ether": 1,
    "IP": 101,
    "IPv6": 101,
    "RadioTap": 127,
    "Raw": 101,
    "link:ethernet": 1,
    "link:dot11": 105,
    "link:ieee80211": 105,
    "link:linux-cooked": 113,
    "link:linux-sll": 113,
    "link:null-loopback": 0,
    "link:radiotap": 127,
    "link:raw": 101,
    "l3:ipv4": 101,
    "l3:ipv6": 101,
    "l3:raw": 101,
}
_PROTOCOL_LAYER_ALIASES: dict[str, str | None] = {
    "arp": "arp",
    "bootp": "dhcp",
    "data": "payload",
    "dhcp": "dhcp",
    "eapol": "eapol",
    "eth": "ethernet",
    "ethertype": None,
    "fake-field-wrapper": None,
    "frame": None,
    "icmp": "icmp",
    "icmpv6": "icmpv6",
    "ip": "ipv4",
    "ipv6": "ipv6",
    "ipv6.dstopts": "ipv6_destination_options",
    "ipv6.fragment": "ipv6_fragment",
    "ipv6.fraghdr": "ipv6_fragment",
    "ipv6.hopopts": "ipv6_hop_by_hop",
    "ipv6.routing": "ipv6_routing",
    "llc": "llc_snap",
    "null": "null_loopback",
    "radiotap": "radiotap",
    "raw": None,
    "rip": "rip",
    "ripng": "ripng",
    "sll": "linux_sll",
    "wlan": "dot11",
    "wlan_radio": None,
    "wlan_mgt": None,
    "wlan_mgt.rsn": "rsn",
    "wlan_rsna_eapol": None,
    "tcp": "tcp",
    "udp": "udp",
    "vlan": "vlan",
}
_DOT11_ROOTS = frozenset({"Dot11", "link:dot11", "link:ieee80211"})
_RADIOTAP_ROOTS = frozenset({"RadioTap", "link:radiotap"})

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
    dot11_byte_model = _dot11_source_model(
        root=root,
        source_hex=source_hex,
        feature_tags=feature_tags,
        protocol_names=protocol_names,
        layers_object=layers_object,
    )
    if dot11_byte_model is not None:
        return dot11_byte_model

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
    if layer_name == "radiotap":
        return _normalize_radiotap(_layer(layers, "radiotap"))
    if layer_name == "dot11":
        return _normalize_dot11(_layer(layers, "wlan"))
    if layer_name == "llc_snap":
        return _normalize_llc_snap(_layer(layers, "llc"))
    if layer_name == "eapol":
        return _normalize_eapol(_layer(layers, "eapol"))
    if layer_name == "rsn":
        return _normalize_rsn(_layer_any(layers, "wlan_mgt.rsn", "wlan.rsn"))
    if layer_name == "arp":
        return _normalize_arp(_layer(layers, "arp"))
    if layer_name == "ipv4":
        return _normalize_ipv4(_layer(layers, "ip"))
    if layer_name == "ipv6":
        return _normalize_ipv6(_layer(layers, "ipv6"))
    if layer_name == "ipv6_hop_by_hop":
        return _normalize_ipv6_options_header(
            _layer_any(layers, "ipv6.hopopts", "ipv6_hopopts"),
            prefix="ipv6.hopopts",
        )
    if layer_name == "ipv6_destination_options":
        return _normalize_ipv6_options_header(
            _layer_any(layers, "ipv6.dstopts", "ipv6_dstopts"),
            prefix="ipv6.dstopts",
        )
    if layer_name == "ipv6_fragment":
        return _normalize_ipv6_fragment(
            _layer_any(layers, "ipv6.fragment", "ipv6.fraghdr", "ipv6_fragment")
        )
    if layer_name == "ipv6_routing":
        return _normalize_ipv6_routing(
            _layer_any(layers, "ipv6.routing", "ipv6_routing")
        )
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
    if layer_name == "ripng":
        return _normalize_ripng(_layer(layers, "ripng"))
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


def _dot11_source_model(
    *,
    root: str | None,
    source_hex: str | None,
    feature_tags: Sequence[str],
    protocol_names: Sequence[str],
    layers_object: JSONObject,
) -> DecodedModel | None:
    canonical_root = _normalize_root_name(root)
    if canonical_root not in {"link:dot11", "link:radiotap"}:
        return None
    if not source_hex:
        return None
    try:
        raw = bytes.fromhex(source_hex)
    except ValueError:
        return None

    from ..scapy.normalize import _decode_dot11_bytes

    model = _decode_dot11_bytes(
        raw,
        root=canonical_root,
        source_hex=source_hex,
        feature_tags=feature_tags,
    )
    metadata = dict(model.metadata)
    metadata["native"] = {
        "protocols": list(protocol_names),
        "layers": layers_object,
        "byte_model": model.metadata.get("native"),
    }
    metadata["normalization"] = "byte_level_dot11_after_tshark_parse"
    metadata["tshark"] = {
        "argv": _tshark_argv("<pcap>"),
    }
    return DecodedModel(
        backend=BACKEND_NAME,
        layers=list(model.layers),
        fields=dict(model.fields),
        root=model.root,
        source_hex=model.source_hex,
        feature_tags=list(model.feature_tags),
        metadata=metadata,
    )


def _normalize_radiotap(layer: JSONObject) -> JSONObject:
    output = _fields_from_aliases(
        layer,
        {
            "version": ("radiotap.version",),
            "pad": ("radiotap.pad",),
            "length": ("radiotap.length",),
            "flags": ("radiotap.flags",),
            "rate": ("radiotap.datarate", "radiotap.rate"),
            "channel_frequency": ("radiotap.channel.freq", "radiotap.channel.frequency"),
            "channel_flags": ("radiotap.channel.flags",),
            "dbm_antenna_signal": ("radiotap.dbm_antsignal", "radiotap.dbm_antenna_signal"),
            "antenna": ("radiotap.antenna",),
            "rx_flags": ("radiotap.rxflags", "radiotap.rx_flags"),
            "tx_flags": ("radiotap.txflags", "radiotap.tx_flags"),
        },
    )
    _parse_int_fields(
        output,
        "version",
        "pad",
        "length",
        "flags",
        "channel_frequency",
        "channel_flags",
        "dbm_antenna_signal",
        "antenna",
        "rx_flags",
        "tx_flags",
    )
    rate = _parse_radiotap_rate(output.get("rate"))
    if rate is not None:
        output["rate"] = rate
    else:
        output.pop("rate", None)

    present_words = [
        parsed
        for parsed in (
            _parse_int(item)
            for item in _field_list(
                layer,
                "radiotap.present.word",
                "radiotap.present",
            )
        )
        if parsed is not None
    ]
    if present_words:
        output["present_words"] = present_words

    flags = output.get("flags")
    if isinstance(flags, int):
        output["fcs_status"] = _radiotap_fcs_status(flags)
    elif _truthy_field(layer, "radiotap.flags.fcs"):
        output["fcs_status"] = (
            "present_failed"
            if _truthy_field(layer, "radiotap.flags.badfcs")
            else "present"
        )
    elif _truthy_field(layer, "radiotap.flags.badfcs"):
        output["fcs_status"] = "failed"
    return output


def _normalize_dot11(layer: JSONObject) -> JSONObject:
    output = _fields_from_aliases(
        layer,
        {
            "frame_control": ("wlan.fc", "wlan.fc.raw"),
            "protocol_version": ("wlan.fc.version",),
            "frame_type": ("wlan.fc.type",),
            "subtype": ("wlan.fc.subtype",),
            "duration_id": ("wlan.duration", "wlan.duration_id"),
            "sequence_control": ("wlan.seq_control", "wlan.seqctl"),
            "sequence_number": ("wlan.seq", "wlan.seq.seq"),
            "fragment_number": ("wlan.frag", "wlan.seq.frag"),
            "qos_control": ("wlan.qos", "wlan.qos.control"),
            "ht_control": ("wlan.ht.control", "wlan.ht_control"),
        },
    )
    _parse_int_fields(
        output,
        "frame_control",
        "protocol_version",
        "frame_type",
        "subtype",
        "duration_id",
        "sequence_control",
        "sequence_number",
        "fragment_number",
        "qos_control",
        "ht_control",
    )

    bool_fields = {
        "to_ds": ("wlan.fc.tods",),
        "from_ds": ("wlan.fc.fromds",),
        "more_fragments": ("wlan.fc.frag",),
        "retry": ("wlan.fc.retry",),
        "power_management": ("wlan.fc.pwrmgt",),
        "more_data": ("wlan.fc.moredata",),
        "protected": ("wlan.fc.protected", "wlan.fc.wep"),
        "order": ("wlan.fc.order",),
    }
    for target, aliases in bool_fields.items():
        value = _field(layer, *aliases)
        if value is not None:
            output[target] = _truthy_value(value)
    ds = _parse_int(_field(layer, "wlan.fc.ds"))
    if ds is not None:
        output.setdefault("to_ds", bool(ds & 0x01))
        output.setdefault("from_ds", bool(ds & 0x02))

    addresses = [str(item) for item in _field_list(layer, "wlan.addr")]
    for index, address in enumerate(addresses[:4], start=1):
        output.setdefault(f"addr{index}", address)
    _copy_string_field(output, "addr1", layer, "wlan.addr1", "wlan.ra", "wlan.da")
    _copy_string_field(output, "addr2", layer, "wlan.addr2", "wlan.ta", "wlan.sa")
    _copy_string_field(output, "addr3", layer, "wlan.addr3", "wlan.bssid")
    _copy_string_field(output, "addr4", layer, "wlan.addr4")

    sequence_number = output.get("sequence_number")
    fragment_number = output.get("fragment_number")
    if "sequence_control" not in output and isinstance(sequence_number, int):
        fragment = fragment_number if isinstance(fragment_number, int) else 0
        output["sequence_control"] = (sequence_number << 4) | (fragment & 0x0F)
    if "sequence_number" not in output and isinstance(output.get("sequence_control"), int):
        output["sequence_number"] = output["sequence_control"] >> 4
    if "fragment_number" not in output and isinstance(output.get("sequence_control"), int):
        output["fragment_number"] = output["sequence_control"] & 0x0F
    return output


def _normalize_llc_snap(layer: JSONObject) -> JSONObject:
    output = _fields_from_aliases(
        layer,
        {
            "dsap": ("llc.dsap",),
            "ssap": ("llc.ssap",),
            "control": ("llc.control",),
            "oui": ("llc.oui", "llc.snap.oui"),
            "ethertype": ("llc.type", "llc.etype", "llc.pid"),
        },
    )
    _parse_int_fields(output, "dsap", "ssap", "control", "ethertype")
    oui = output.get("oui")
    if isinstance(oui, str):
        output["oui"] = {"hex": _hex_bytes(oui)}
    return output


def _normalize_eapol(layer: JSONObject) -> JSONObject:
    output = _fields_from_aliases(
        layer,
        {
            "version": ("eapol.version",),
            "packet_type": ("eapol.type",),
            "body_length": ("eapol.len", "eapol.length"),
            "descriptor_type": ("eapol.keydes.type",),
            "key_information": ("eapol.keydes.key_info",),
            "key_length": ("eapol.keydes.key_len",),
            "replay_counter": ("eapol.keydes.replay_counter",),
            "key_nonce": ("eapol.keydes.nonce",),
            "key_iv": ("eapol.keydes.key_iv",),
            "key_rsc": ("eapol.keydes.key_rsc",),
            "key_id": ("eapol.keydes.key_id",),
            "key_mic": ("eapol.keydes.key_mic",),
            "key_data_length": ("eapol.keydes.keydes_data_len",),
            "key_data": ("eapol.keydes.data",),
        },
    )
    _parse_int_fields(
        output,
        "version",
        "packet_type",
        "body_length",
        "descriptor_type",
        "key_information",
        "key_length",
        "replay_counter",
        "key_data_length",
    )
    for name in ("key_nonce", "key_iv", "key_rsc", "key_id", "key_mic", "key_data"):
        value = output.get(name)
        if isinstance(value, str):
            output[name] = {"hex": _hex_bytes(value)}
    return output


def _normalize_rsn(layer: JSONObject) -> JSONObject:
    output = _fields_from_aliases(
        layer,
        {
            "element_id": ("wlan.rsn.tag", "wlan.rsn.element_id"),
            "length": ("wlan.rsn.length",),
            "version": ("wlan.rsn.version",),
            "capabilities": ("wlan.rsn.capabilities",),
        },
    )
    _parse_int_fields(output, "element_id", "length", "version", "capabilities")
    group = _rsn_suite_from_layer(
        layer,
        kind="cipher",
        value_names=("wlan.rsn.gcs", "wlan.rsn.group_cipher_suite"),
        oui_names=("wlan.rsn.gcs.oui",),
        type_names=("wlan.rsn.gcs.type",),
    )
    if group is not None:
        output["group_cipher_suite"] = group
    pairwise = _rsn_suite_list_from_layer(
        layer,
        kind="cipher",
        value_names=("wlan.rsn.pcs", "wlan.rsn.pcs.type"),
        oui_names=("wlan.rsn.pcs.oui",),
    )
    if pairwise:
        output["pairwise_cipher_suites"] = pairwise
    akms = _rsn_suite_list_from_layer(
        layer,
        kind="akm",
        value_names=("wlan.rsn.akms", "wlan.rsn.akms.type"),
        oui_names=("wlan.rsn.akms.oui",),
    )
    if akms:
        output["akm_suites"] = akms
    return output


_ARP_HARDWARE_ADDRESS_FIELDS = (
    "sender_hardware_address",
    "target_hardware_address",
)
_ARP_PROTOCOL_ADDRESS_FIELDS = (
    "sender_protocol_address",
    "target_protocol_address",
)


def _normalize_arp(layer: JSONObject) -> JSONObject:
    """Normalize a tshark ARP layer to the shared canonical field names.

    The normalized names and comparable forms match the Scapy reference backend
    (``tools/oracle/engine/backends/scapy/normalize.py``) and the libcrafter
    decoder (``tools/oracle/adapters/src/bin/decode_vectors.rs``). The fixed
    header (``hardware_type``, ``protocol_type``, ``hardware_length``,
    ``protocol_length``, ``opcode``) is kept numeric so known and unknown
    codepoints stay raw-preserving. The four variable sender/target address
    fields keep their colon-formatted MAC / dotted IPv4 string form for standard
    Ethernet/IPv4 ARP, and reduce to a bare ``{"hex": ...}`` value carrying the
    raw octets for nonstandard hardware/protocol lengths or unknown address
    families. tshark exposes typed ``*.hw_mac`` / ``*.proto_ipv4`` fields for the
    standard forms and the generic ``*.hw`` / ``*.proto`` fields otherwise.
    """

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
    for name in _ARP_HARDWARE_ADDRESS_FIELDS:
        if name in output:
            output[name] = _normalize_arp_address(output[name], kind="hardware")
    for name in _ARP_PROTOCOL_ADDRESS_FIELDS:
        if name in output:
            output[name] = _normalize_arp_address(output[name], kind="protocol")
    return output


def _normalize_arp_address(value: object, *, kind: str) -> object:
    """Reduce one tshark ARP address to the shared comparable form.

    Standard Ethernet hardware addresses (a colon-separated MAC) and standard
    IPv4 protocol addresses (a dotted quad) keep their string form, matching the
    Scapy reference backend and libcrafter's decoded view. Any other form — a
    nonstandard-width hardware/protocol address or an unknown address family,
    which tshark renders as a colon-separated hex string — is reduced to a bare
    ``{"hex": ...}`` value carrying the raw octets, so the comparison stays
    byte-identical across backends regardless of tshark's textual rendering.
    """

    if not isinstance(value, str):
        return value
    if kind == "hardware" and _is_standard_mac(value):
        return value
    if kind == "protocol" and _is_standard_ipv4(value):
        return value
    return {"hex": _hex_bytes(value)}


def _is_standard_mac(value: str) -> bool:
    parts = value.split(":")
    if len(parts) != 6:
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
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        if not 0 <= int(part) <= 255:
            return False
    return True


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
    traffic_class = output.get("traffic_class")
    if isinstance(traffic_class, int):
        output["dscp"] = traffic_class >> 2
        output["ecn"] = traffic_class & 0x03
    return output


def _normalize_ipv6_options_header(layer: JSONObject, *, prefix: str) -> JSONObject:
    output = _fields_from_aliases(
        layer,
        {
            "next_header": (f"{prefix}.nxt", f"{prefix}.next", f"{prefix}.next_header"),
            "header_ext_len": (f"{prefix}.len", f"{prefix}.length", f"{prefix}.hdr_ext_len"),
            "options_raw_hex": (
                f"{prefix}.options_raw",
                f"{prefix}.options",
                f"{prefix}.option_bytes",
            ),
        },
    )
    _parse_int_fields(output, "next_header", "header_ext_len")
    if "header_ext_len" in output:
        output["length"] = output["header_ext_len"]

    raw_options = output.get("options_raw_hex")
    if isinstance(raw_options, str):
        raw_options = _hex_bytes(raw_options)
        options = _decode_ipv6_option_tlvs(raw_options)
        if options is not None:
            output["options_raw_hex"] = raw_options
            output["options"] = options
            output["option_count"] = len(options)
    return output


def _normalize_ipv6_fragment(layer: JSONObject) -> JSONObject:
    output = _fields_from_aliases(
        layer,
        {
            "next_header": (
                "ipv6.fragment.nxt",
                "ipv6.fraghdr.nxt",
                "ipv6.fragment.next_header",
            ),
            "reserved": ("ipv6.fragment.reserved", "ipv6.fraghdr.reserved"),
            "fragment_offset": (
                "ipv6.fragment.offset",
                "ipv6.fraghdr.offset",
                "ipv6.fragment.frag_offset",
            ),
            "more_fragments": (
                "ipv6.fragment.more",
                "ipv6.fragment.more_fragments",
                "ipv6.fraghdr.more",
            ),
            "identification": ("ipv6.fragment.id", "ipv6.fraghdr.id"),
        },
    )
    _parse_int_fields(
        output,
        "next_header",
        "reserved",
        "fragment_offset",
        "more_fragments",
        "identification",
    )
    if isinstance(output.get("more_fragments"), int):
        output["more_fragments"] = bool(output["more_fragments"])
    offset = output.get("fragment_offset")
    if isinstance(offset, int):
        output["fragment_offset_bytes"] = offset * 8
    more_fragments = output.get("more_fragments")
    if isinstance(offset, int) and isinstance(more_fragments, bool):
        output["fragment_status"] = _ipv6_fragment_status(offset, more_fragments)
    return output


def _normalize_ipv6_routing(layer: JSONObject) -> JSONObject:
    output = _fields_from_aliases(
        layer,
        {
            "next_header": ("ipv6.routing.nxt", "ipv6.routing.next_header"),
            "header_ext_len": (
                "ipv6.routing.len",
                "ipv6.routing.length",
                "ipv6.routing.hdr_ext_len",
            ),
            "type": ("ipv6.routing.type", "ipv6.routing.routing_type"),
            "segments_left": (
                "ipv6.routing.seg_left",
                "ipv6.routing.segleft",
                "ipv6.routing.segments_left",
            ),
            "last_entry": ("ipv6.routing.last_entry", "ipv6.routing.lastentry"),
            "flags": ("ipv6.routing.flags",),
            "tag": ("ipv6.routing.tag",),
            "raw_trailing_data": (
                "ipv6.routing.raw_trailing_data",
                "ipv6.routing.tlv_data",
            ),
            "type_data": ("ipv6.routing.type_data",),
        },
    )
    _parse_int_fields(
        output,
        "next_header",
        "header_ext_len",
        "type",
        "segments_left",
        "last_entry",
        "flags",
        "tag",
    )
    if "header_ext_len" in output:
        output["length"] = output["header_ext_len"]
    routing_type = output.get("type")
    if isinstance(routing_type, int):
        output["classification"] = _ipv6_routing_classification(routing_type)
    addresses = _field_list(layer, "ipv6.routing.address", "ipv6.routing.addresses")
    if addresses:
        output["addresses"] = [str(item) for item in addresses]
        if routing_type == 4:
            output["segments"] = list(output["addresses"])
    raw_trailing = output.get("raw_trailing_data")
    if isinstance(raw_trailing, str):
        output["raw_trailing_data"] = _hex_bytes(raw_trailing)
    type_data = output.get("type_data")
    if isinstance(type_data, str):
        output["type_data"] = _hex_bytes(type_data)
    return output


def _decode_ipv6_option_tlvs(option_region_hex: str) -> list[JSONObject] | None:
    try:
        raw = bytes.fromhex(option_region_hex)
    except ValueError:
        return None
    options: list[JSONObject] = []
    index = 0
    while index < len(raw):
        option_type = raw[index]
        index += 1
        if option_type == 0:
            options.append(_ipv6_option_item(option_type, b"", encoded_len=1))
            continue
        if index >= len(raw):
            return None
        option_length = raw[index]
        index += 1
        if index + option_length > len(raw):
            return None
        data = raw[index : index + option_length]
        index += option_length
        options.append(_ipv6_option_item(option_type, data, encoded_len=option_length + 2))
    return options


def _ipv6_option_item(option_type: int, data: bytes, *, encoded_len: int) -> JSONObject:
    item: JSONObject = {
        "option_type": option_type,
        "kind": _ipv6_option_kind(option_type),
        "length": encoded_len,
        "data_hex": data.hex(),
        "action": option_type >> 6,
        "change_en_route": bool(option_type & 0x20),
    }
    if option_type == 5 and len(data) == 2:
        item["value"] = int.from_bytes(data, "big")
    elif option_type == 0xC2 and len(data) == 4:
        item["jumbo_payload_length"] = int.from_bytes(data, "big")
    elif option_type == 0xC9 and len(data) == 16:
        item["address"] = str(ipaddress.IPv6Address(data))
    return item


def _ipv6_option_kind(option_type: int) -> str:
    if option_type == 0:
        return "pad1"
    if option_type == 1:
        return "padn"
    if option_type == 5:
        return "router_alert"
    if option_type == 0xC2:
        return "jumbo_payload"
    if option_type == 0xC9:
        return "home_address"
    return "unknown"


def _ipv6_fragment_status(offset: int, more_fragments: bool) -> str:
    if offset == 0 and not more_fragments:
        return "atomic"
    if offset == 0:
        return "initial"
    return "non_initial"


def _ipv6_routing_classification(routing_type: int) -> str:
    if routing_type in {0, 1}:
        return "deprecated"
    if routing_type == 2:
        return "mobile"
    if routing_type == 4:
        return "segment_routing"
    if routing_type in {253, 254}:
        return "experimental"
    if routing_type == 255:
        return "reserved"
    return "unknown"


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


def _normalize_ripng(layer: JSONObject) -> JSONObject:
    """Normalize a tshark RIPng layer to the shared oracle field names.

    Scapy has no native RIPng dissector, so the parser (tshark) backend supplies
    the RIPng cross-validation decode. The normalized names mirror the libcrafter
    Ripng/RipngRte accessor names (``command``/``version``/``reserved`` plus an
    ``rtes`` list of ``prefix``/``route_tag``/``prefix_len``/``metric``) so the
    parser decode aligns with the libcrafter surface. Wireshark's RIPng dissector
    (``packet-ripng.c``) exposes ``ripng.cmd``/``ripng.version``/``ripng.ip``/
    ``ripng.route_tag``/``ripng.prefix_length``/``ripng.metric``; the alternate
    ``ripng.command`` prefix is accepted defensively.
    """

    output = _fields_from_aliases(
        layer,
        {
            "command": ("ripng.cmd", "ripng.command"),
            "version": ("ripng.version",),
            "reserved": ("ripng.reserved", "ripng.null"),
        },
    )
    _parse_int_fields(output, "command", "version", "reserved")

    prefixes = [str(item) for item in _field_list(layer, "ripng.ip", "ripng.prefix")]
    route_tags = [_parse_int(item) for item in _field_list(layer, "ripng.route_tag", "ripng.tag")]
    prefix_lens = [
        _parse_int(item)
        for item in _field_list(layer, "ripng.prefix_length", "ripng.prefix_len")
    ]
    metrics = [_parse_int(item) for item in _field_list(layer, "ripng.metric")]

    rtes: list[JSONObject] = []
    for index, prefix in enumerate(prefixes):
        rte: JSONObject = {"prefix": prefix}
        if index < len(route_tags) and route_tags[index] is not None:
            rte["route_tag"] = route_tags[index]
        if index < len(prefix_lens) and prefix_lens[index] is not None:
            rte["prefix_len"] = prefix_lens[index]
        if index < len(metrics) and metrics[index] is not None:
            rte["metric"] = metrics[index]
        rtes.append(rte)
    if rtes:
        output["rtes"] = rtes
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


def _truthy_value(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value not in {"", "0", "0x0", "False", "false"}
    return bool(value)


def _copy_string_field(
    output: JSONObject,
    target: str,
    layer: JSONObject,
    *names: str,
) -> None:
    value = _string_field(layer, *names)
    if value is not None:
        output[target] = value


def _parse_radiotap_rate(value: object) -> int | None:
    parsed = _parse_int(value)
    if parsed is not None:
        return parsed
    if not isinstance(value, str):
        return None
    candidate = value.strip().split(" ", 1)[0]
    try:
        return int(round(float(candidate) * 2))
    except ValueError:
        return None


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


def _rsn_suite_from_layer(
    layer: JSONObject,
    *,
    kind: str,
    value_names: tuple[str, ...],
    oui_names: tuple[str, ...],
    type_names: tuple[str, ...],
) -> JSONObject | None:
    value = _field(layer, *value_names)
    suite = _rsn_suite_from_value(value, kind=kind)
    if suite is not None:
        return suite
    oui = _string_field(layer, *oui_names)
    suite_type = _parse_int(_field(layer, *type_names))
    if oui is None or suite_type is None:
        return None
    return _rsn_suite_from_oui_type(oui, suite_type, kind=kind)


def _rsn_suite_list_from_layer(
    layer: JSONObject,
    *,
    kind: str,
    value_names: tuple[str, ...],
    oui_names: tuple[str, ...],
) -> list[JSONObject]:
    values = _field_list(layer, *value_names)
    suites = [
        suite
        for suite in (_rsn_suite_from_value(value, kind=kind) for value in values)
        if suite is not None
    ]
    if suites:
        return suites
    oui_values = [str(value) for value in _field_list(layer, *oui_names)]
    if not oui_values:
        oui_values = ["00:0f:ac"] * len(values)
    output: list[JSONObject] = []
    for index, value in enumerate(values):
        suite_type = _parse_int(value)
        if suite_type is None:
            continue
        oui = oui_values[index] if index < len(oui_values) else oui_values[0]
        suite = _rsn_suite_from_oui_type(oui, suite_type, kind=kind)
        if suite is not None:
            output.append(suite)
    return output


def _rsn_suite_from_oui_type(oui: str, suite_type: int, *, kind: str) -> JSONObject | None:
    try:
        oui_bytes = bytes.fromhex(_hex_bytes(oui))
    except ValueError:
        return None
    if len(oui_bytes) < 3:
        return None
    return _rsn_suite_selector(oui_bytes[:3] + bytes([suite_type & 0xFF]), kind=kind)


def _rsn_suite_from_value(value: object, *, kind: str) -> JSONObject | None:
    if value is None:
        return None
    parsed = _parse_int(value)
    if parsed is not None:
        return _rsn_suite_selector(b"\x00\x0f\xac" + bytes([parsed & 0xFF]), kind=kind)
    if not isinstance(value, str):
        return None
    raw_hex = _hex_bytes(value)
    if len(raw_hex) < 8:
        return None
    try:
        raw = bytes.fromhex(raw_hex[:8])
    except ValueError:
        return None
    return _rsn_suite_selector(raw, kind=kind)


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


def _hex_bytes(value: str) -> str:
    return "".join(char for char in value.lower() if char in "0123456789abcdef")


def _field_key(fields: dict[str, JSONObject], layer_name: str) -> str:
    if layer_name not in fields:
        return layer_name
    suffix = 2
    while f"{layer_name}#{suffix}" in fields:
        suffix += 1
    return f"{layer_name}#{suffix}"


def _object(value: object, name: str) -> JSONObject:
    if not isinstance(value, dict):
        raise WiresharkNormalizationUnsupported(f"tshark {name} must be an object")
    return dict(value)
