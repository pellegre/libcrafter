"""Wireshark/tshark classic-pcap read helpers."""

from __future__ import annotations

import struct
from pathlib import Path

from ...model import JSONObject
from .normalize import normalize_packet_json, _tshark_json_packets


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
    packets = _tshark_json_packets(input_path)
    records: list[JSONObject] = []
    for position, record in enumerate(pcap_records):
        packet = packets[position] if position < len(packets) else {}
        raw_hex = _string(record["raw_hex"], "raw_hex")
        root = _string(record["root"], "root")
        decoded = normalize_packet_json(
            packet,
            root=root,
            source_hex=raw_hex,
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
