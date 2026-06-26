"""Wireshark/tshark classic-pcap read helpers."""

from __future__ import annotations

import struct
from pathlib import Path

from ...model import DecodedModel, JSONObject
from .normalize import (
    BACKEND_NAME,
    WiresharkNormalizationUnsupported,
    normalize_packet_json,
    _tshark_json_packets,
)
from .protocols.quic import quic_fields_from_bytes


_LINK_TYPES: dict[int, str] = {
    0: "null_loopback",
    1: "ethernet",
    12: "raw",
    101: "raw",
    105: "ieee80211",
    108: "null_loopback",
    113: "linux_sll",
    127: "radiotap",
    228: "raw",
    229: "raw",
}
_ROOTS_BY_LINK_TYPE: dict[str, str] = {
    "ethernet": "link:ethernet",
    "ieee80211": "link:dot11",
    "linux_cooked": "link:linux-cooked",
    "linux_sll": "link:linux-sll",
    "null_loopback": "link:null-loopback",
    "radiotap": "link:radiotap",
    "raw": "link:raw",
}
_DATALINK_BY_LINK_TYPE: dict[str, int] = {
    "ethernet": 1,
    "ieee80211": 105,
    "linux_cooked": 113,
    "linux_sll": 113,
    "null_loopback": 0,
    "radiotap": 127,
    "raw": 101,
}


def read_pcap(path: str | Path) -> list[JSONObject]:
    """Read a classic pcap with tshark and normalize packet records."""

    input_path = Path(path)
    pcap_records = _read_classic_pcap_records(input_path)
    fallback_reason: str | None = None
    try:
        packets = _tshark_json_packets(input_path)
    except WiresharkNormalizationUnsupported as exc:
        fallback_reason = str(exc)
        packets = []
    records: list[JSONObject] = []
    for position, record in enumerate(pcap_records):
        raw_hex = _string(record["raw_hex"], "raw_hex")
        root = _string(record["root"], "root")
        if position < len(packets):
            decoded = normalize_packet_json(
                packets[position],
                root=root,
                source_hex=raw_hex,
            )
        elif fallback_reason is not None:
            decoded = _fallback_quic_decoded_model(
                raw_hex=raw_hex,
                root=root,
                reason=fallback_reason,
            )
        else:
            raise WiresharkNormalizationUnsupported(
                "tshark emitted fewer decoded packets than the pcap contains"
            )
        records.append(
            {
                "index": position,
                "raw_hex": raw_hex,
                "root": root,
                "link_type": record["link_type"],
                "timestamp": record["timestamp"],
                "layers": list(decoded.layers),
                "decoded": decoded.to_dict(),
            }
        )
    return records


def _fallback_quic_decoded_model(
    *,
    raw_hex: str,
    root: str,
    reason: str,
) -> DecodedModel:
    raw = bytes.fromhex(raw_hex)
    layers: list[str] = []
    fields: dict[str, JSONObject] = {}
    offset = 0

    if root == "link:ethernet":
        offset = _parse_ethernet(raw, layers, fields)

    udp_payload = _parse_l3_udp(raw, offset, layers, fields)
    if udp_payload is None:
        raise WiresharkNormalizationUnsupported(
            f"{reason}; no byte-level QUIC pcap fallback matched"
        )
    fields["quic"] = quic_fields_from_bytes(udp_payload)
    layers.append("quic")
    return DecodedModel(
        backend=BACKEND_NAME,
        layers=layers,
        fields=fields,
        root=root,
        source_hex=raw_hex,
        metadata={
            "fallback": {
                "reason": reason,
                "parser": "classic_pcap_quic_bytes_without_tshark",
            },
            "reencoded_hex": raw_hex,
        },
    )


def _parse_ethernet(
    raw: bytes,
    layers: list[str],
    fields: dict[str, JSONObject],
) -> int:
    if len(raw) < 14:
        raise WiresharkNormalizationUnsupported("ethernet pcap record is truncated")
    ethertype = int.from_bytes(raw[12:14], "big")
    layers.append("ethernet")
    fields["ethernet"] = {
        "dst": raw[0:6].hex(":"),
        "src": raw[6:12].hex(":"),
        "ethertype": ethertype,
    }
    if ethertype not in {0x0800, 0x86DD}:
        raise WiresharkNormalizationUnsupported(
            f"ethernet pcap record has unsupported ethertype: 0x{ethertype:04x}"
        )
    return 14


def _parse_l3_udp(
    raw: bytes,
    offset: int,
    layers: list[str],
    fields: dict[str, JSONObject],
) -> bytes | None:
    if offset >= len(raw):
        return None
    version = raw[offset] >> 4
    if version == 4:
        return _parse_ipv4_udp(raw, offset, layers, fields)
    if version == 6:
        return _parse_ipv6_udp(raw, offset, layers, fields)
    return None


def _parse_ipv4_udp(
    raw: bytes,
    offset: int,
    layers: list[str],
    fields: dict[str, JSONObject],
) -> bytes | None:
    if len(raw) < offset + 28:
        return None
    ihl = (raw[offset] & 0x0F) * 4
    if ihl < 20 or len(raw) < offset + ihl + 8 or raw[offset + 9] != 17:
        return None
    total_length = int.from_bytes(raw[offset + 2 : offset + 4], "big")
    end = offset + min(total_length, len(raw) - offset)
    udp_offset = offset + ihl
    layers.append("ipv4")
    fields["ipv4"] = {
        "protocol": 17,
        "src": ".".join(str(part) for part in raw[offset + 12 : offset + 16]),
        "dst": ".".join(str(part) for part in raw[offset + 16 : offset + 20]),
    }
    return _parse_udp_payload(raw, udp_offset, end, layers, fields)


def _parse_ipv6_udp(
    raw: bytes,
    offset: int,
    layers: list[str],
    fields: dict[str, JSONObject],
) -> bytes | None:
    if len(raw) < offset + 48 or raw[offset + 6] != 17:
        return None
    payload_length = int.from_bytes(raw[offset + 4 : offset + 6], "big")
    end = offset + 40 + payload_length
    if end > len(raw):
        return None
    udp_offset = offset + 40
    layers.append("ipv6")
    fields["ipv6"] = {
        "next_header": 17,
        "src": raw[offset + 8 : offset + 24].hex(),
        "dst": raw[offset + 24 : offset + 40].hex(),
    }
    return _parse_udp_payload(raw, udp_offset, end, layers, fields)


def _parse_udp_payload(
    raw: bytes,
    udp_offset: int,
    end: int,
    layers: list[str],
    fields: dict[str, JSONObject],
) -> bytes | None:
    if udp_offset + 8 > end:
        return None
    src_port = int.from_bytes(raw[udp_offset : udp_offset + 2], "big")
    dst_port = int.from_bytes(raw[udp_offset + 2 : udp_offset + 4], "big")
    udp_length = int.from_bytes(raw[udp_offset + 4 : udp_offset + 6], "big")
    if udp_length < 8 or udp_offset + udp_length > end:
        return None
    layers.append("udp")
    fields["udp"] = {
        "src_port": src_port,
        "dst_port": dst_port,
        "length": udp_length,
    }
    if src_port not in {443, 4433} and dst_port not in {443, 4433}:
        return None
    return raw[udp_offset + 8 : udp_offset + udp_length]


def _read_classic_pcap_records(path: Path) -> list[JSONObject]:
    data = path.read_bytes()
    if len(data) < 24:
        raise ValueError(f"pcap header is too short: {path}")

    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
        precision = "microseconds"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
        precision = "microseconds"
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian = "<"
        precision = "nanoseconds"
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian = ">"
        precision = "nanoseconds"
    else:
        raise ValueError(f"unsupported pcap magic: {magic.hex()}")

    _version_major, _version_minor, _thiszone, _sigfigs, _snaplen, datalink = struct.unpack(
        f"{endian}HHIIII",
        data[4:24],
    )
    link_type = _link_type_name(datalink)
    root = _root_for_link_type(link_type)
    records: list[JSONObject] = []
    offset = 24
    index = 0
    while offset < len(data):
        if offset + 16 > len(data):
            raise ValueError(f"pcap packet header is truncated at offset {offset}: {path}")
        seconds, fractional, captured_len, _original_len = struct.unpack(
            f"{endian}IIII",
            data[offset : offset + 16],
        )
        offset += 16
        if offset + captured_len > len(data):
            raise ValueError(f"pcap packet data is truncated at offset {offset}: {path}")
        raw = data[offset : offset + captured_len]
        offset += captured_len
        records.append(
            {
                "index": index,
                "raw_hex": raw.hex(),
                "root": root,
                "link_type": _link_type_object(link_type, datalink=datalink),
                "timestamp": _timestamp(seconds, fractional, precision),
            }
        )
        index += 1
    return records


def _timestamp(seconds: int, fractional: int, precision: str) -> JSONObject:
    return {
        "seconds": seconds,
        "fractional": fractional,
        "precision": precision,
        "nanos": fractional if precision == "nanoseconds" else fractional * 1_000,
    }


def _link_type_name(datalink: int) -> str:
    return _LINK_TYPES.get(datalink, f"unknown:{datalink}")


def _link_type_object(name: str, *, datalink: int | None = None) -> JSONObject:
    normalized = _canonical_link_type_name(name)
    if normalized.startswith("unknown:"):
        value = int(normalized.split(":", 1)[1])
        return {"name": normalized, "datalink": value}
    if normalized not in _DATALINK_BY_LINK_TYPE:
        raise ValueError(f"unsupported pcap link type: {name}")
    return {
        "name": normalized,
        "datalink": _DATALINK_BY_LINK_TYPE[normalized] if datalink is None else datalink,
    }


def _root_for_link_type(link_type: str) -> str:
    normalized = _canonical_link_type_name(link_type)
    root = _ROOTS_BY_LINK_TYPE.get(normalized)
    if root is None:
        raise ValueError(f"unsupported pcap link type: {link_type}")
    return root


def _canonical_link_type_name(name: str) -> str:
    normalized = name.replace("-", "_")
    if normalized == "linux_cooked":
        return "linux_sll"
    if normalized in {"dot11", "ieee80211", "ieee802_11"}:
        return "ieee80211"
    if normalized in {"radiotap", "ieee80211_radio", "ieee80211_radiotap"}:
        return "radiotap"
    return normalized


def _string(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value
