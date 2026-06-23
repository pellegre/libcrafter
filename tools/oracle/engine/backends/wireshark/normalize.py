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
from .decode_helpers import (
    _fields_from_aliases,
    _layer,
    _layer_any,
    _normalize_root_name,
    _parse_int_fields,
    _string_field,
)
# Importing the protocols package runs its ``autodiscover`` so every per-protocol
# Wireshark decoder module self-registers; ``WIRESHARK_REGISTRY`` is consulted for a
# layer's ``normalize`` hook before the legacy branches below. No protocol is migrated
# yet, so the registry is empty and every layer falls through to the legacy
# normalization.
from .protocols import WIRESHARK_REGISTRY
# The IPv6 extension-header decode normalizers live in the co-located ipv6 plugin
# module. They are NOT registered as ``WiresharkProtocol.normalize`` hooks because the
# ext-header names are sub-layers of the ``ipv6`` spec rather than top-level spec
# layers; the legacy ``_normalize_protocol_fields`` dispatch below calls them through
# these re-imports so behavior stays byte-identical.
from .protocols.ipv6 import (
    _normalize_ipv6_fragment,
    _normalize_ipv6_options_header,
    _normalize_ipv6_routing,
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
    # Consult the per-layer Wireshark decoder plugin before the legacy branches. The
    # registry is empty until a protocol is migrated, so this resolves to ``None`` and
    # the legacy code below runs unchanged.
    plugin = WIRESHARK_REGISTRY.get(layer_name)
    if plugin is not None:
        return plugin.normalize(layers, source_hex=source_hex)
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
    if layer_name == "linux_sll":
        return _normalize_linux_sll(_layer(layers, "sll"))
    return {}


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


# The ``dot11`` tshark normalizer (``_normalize_dot11`` and its ``_truthy_value`` /
# ``_copy_string_field`` helpers) moved to ``protocols/wifi.py`` and is registered
# in ``WIRESHARK_REGISTRY`` (so ``_normalize_protocol_fields`` routes the ``dot11``
# layer to the plugin's ``normalize``). The whole-packet byte-level Dot11 path
# (``_dot11_source_model`` above, which calls the scapy ``_decode_dot11_bytes``
# cluster) stays here per the whole-packet decode precedent.


# The ``eapol`` and ``rsn`` tshark normalizers (``_normalize_eapol`` /
# ``_normalize_rsn`` and the RSN suite-selector helper cluster) moved to
# ``protocols/wifi.py`` and are registered in ``WIRESHARK_REGISTRY`` (so
# ``_normalize_protocol_fields`` routes the ``eapol`` / ``rsn`` layers to the
# plugin's ``normalize``).


# The DHCP tshark normalizer ``_normalize_dhcp`` and its ``_dhcp_flags`` /
# ``_dhcp_options_from_source`` / ``_decode_dhcp_option_tlvs`` / ``_dhcp_layer``
# helpers and the DHCP option/cookie constants moved to ``protocols/dhcp.py`` and are
# registered in ``WIRESHARK_REGISTRY`` (so ``_normalize_protocol_fields`` routes the
# ``dhcp`` layer to the plugin's ``normalize``).


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


# The RSN suite-selector helper cluster (``_rsn_suite_from_layer`` /
# ``_rsn_suite_list_from_layer`` / ``_rsn_suite_from_oui_type`` /
# ``_rsn_suite_from_value`` / ``_rsn_suite_selector`` / ``_rsn_cipher_label`` /
# ``_rsn_akm_label``) moved to ``protocols/wifi.py`` with the ``_normalize_rsn``
# tshark normalizer it serves.


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
