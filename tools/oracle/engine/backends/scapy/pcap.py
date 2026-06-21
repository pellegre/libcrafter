"""Scapy classic-pcap helpers for oracle validation."""

from __future__ import annotations

import struct
from dataclasses import replace
from decimal import Decimal, ROUND_FLOOR
from pathlib import Path
from typing import Any

from ...model import EncodedVector, JSONObject
from ..registry import BackendCapabilities, BackendRegistration, get_backend
from .bootstrap import import_scapy
from .normalize import decode_bytes, normalize_packet


PCAP_TIMESTAMP_BASE_SECONDS = 1_700_000_000
PCAP_TIMESTAMP_PRECISION = "microseconds"
PCAP_TIMESTAMP_UNITS = 1_000_000

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
    256: "bluetooth_le_ll_with_phdr",
}
_ROOTS_BY_LINK_TYPE: dict[str, str] = {
    "bluetooth_le_ll_with_phdr": "link:bluetooth-le-ll-with-phdr",
    "ethernet": "link:ethernet",
    "ieee80211": "link:dot11",
    "linux_cooked": "link:linux-cooked",
    "linux_sll": "link:linux-sll",
    "null_loopback": "link:null-loopback",
    "radiotap": "link:radiotap",
    "raw": "link:raw",
}
_DATALINK_BY_LINK_TYPE: dict[str, int] = {
    "bluetooth_le_ll_with_phdr": 256,
    "ethernet": 1,
    "ieee80211": 105,
    "linux_cooked": 113,
    "linux_sll": 113,
    "null_loopback": 0,
    "radiotap": 127,
    "raw": 101,
}


def with_pcap_metadata(
    vectors: list[EncodedVector],
    *,
    link_type: str = "ethernet",
    capabilities: BackendCapabilities | BackendRegistration | None = None,
) -> list[EncodedVector]:
    """Attach deterministic pcap metadata consumed by both pcap writers."""

    _require_capability(capabilities, "pcap_write", "annotate Scapy pcap records")
    _root_for_link_type(link_type)
    output: list[EncodedVector] = []
    for position, vector in enumerate(vectors):
        record_link_type = _pcap_link_type_for_vector(vector, link_type)
        metadata = dict(vector.metadata)
        metadata["pcap_record"] = {
            "index": position,
            "link_type": _link_type_object(record_link_type),
            "timestamp": timestamp_for_record(vector.plan.seed, vector.plan.index),
        }
        output.append(replace(vector, metadata=metadata))
    return output


def timestamp_for_record(seed: int, index: int) -> JSONObject:
    """Return a deterministic timestamp object for one generated packet index."""

    fractional = (abs(seed) * 97 + index * 1009) % PCAP_TIMESTAMP_UNITS
    return {
        "seconds": PCAP_TIMESTAMP_BASE_SECONDS + index,
        "fractional": fractional,
        "precision": PCAP_TIMESTAMP_PRECISION,
        "nanos": fractional * 1_000,
    }


def write_pcap(
    path: str | Path,
    vectors: list[EncodedVector],
    *,
    capabilities: BackendCapabilities | BackendRegistration | None = None,
) -> list[JSONObject]:
    """Write vectors to a classic pcap with Scapy ``wrpcap``."""

    _require_capability(capabilities, "pcap_write", "write Scapy pcap")
    if not vectors:
        raise ValueError("pcap writer requires at least one vector")

    scapy_all = import_scapy()["all"]
    records: list[JSONObject] = []
    decoded_packets: list[tuple[Any, JSONObject]] = []
    for position, vector in enumerate(vectors):
        record = _vector_record(vector, position)
        root = vector.root or vector.decoder or record["root"]
        packet = _decode_packet_for_write(root, vector.to_bytes(), scapy_all)
        timestamp = _object(record["timestamp"], "timestamp")
        if not isinstance(packet, (bytes, bytearray)):
            packet.time = _decimal_timestamp(timestamp)
        records.append(record)
        decoded_packets.append((packet, timestamp))

    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    link_type = _single_pcap_link_type(records)
    writer = scapy_all.PcapWriter(
        str(output_path),
        linktype=_datalink_for_link_type(link_type),
        sync=True,
    )
    try:
        for packet, timestamp in decoded_packets:
            if isinstance(packet, (bytes, bytearray)):
                if not bool(getattr(writer, "header_present", False)):
                    writer.write_header(packet)
                writer.write_packet(
                    bytes(packet),
                    sec=int(timestamp["seconds"]),
                    usec=int(timestamp["fractional"]),
                )
            else:
                writer.write(packet)
    finally:
        writer.close()
    return records


def read_pcap(
    path: str | Path,
    *,
    capabilities: BackendCapabilities | BackendRegistration | None = None,
) -> list[JSONObject]:
    """Read a classic pcap with Scapy ``rdpcap`` and normalize packet records."""

    _require_capability(capabilities, "pcap_read", "read Scapy pcap")
    input_path = Path(path)
    header = read_pcap_header(input_path)
    link_type_object = _object(header["link_type"], "link_type")
    link_type = _string(link_type_object["name"], "link_type.name")
    root = _root_for_link_type(link_type)
    scapy_all = import_scapy()["all"]
    packets = list(scapy_all.rdpcap(str(input_path)))

    records: list[JSONObject] = []
    for position, packet in enumerate(packets):
        raw_hex = bytes(scapy_all.raw(packet)).hex()
        if root in {"link:bluetooth-le-ll-with-phdr", "link:dot11", "link:radiotap"}:
            decoded = decode_bytes(bytes.fromhex(raw_hex), root=root, source_hex=raw_hex)
        else:
            decoded = normalize_packet(packet, root=root, source_hex=raw_hex)
        records.append(
            {
                "index": position,
                "raw_hex": raw_hex,
                "root": root,
                "link_type": header["link_type"],
                "timestamp": _packet_timestamp(packet, _string(header["precision"], "precision")),
                "layers": list(decoded.layers),
                "decoded": decoded.to_dict(),
            }
        )
    return records


def read_pcap_header(path: str | Path) -> JSONObject:
    """Read the classic pcap global header for link type and timestamp precision."""

    data = Path(path).read_bytes()[:24]
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

    version_major, version_minor, _thiszone, _sigfigs, snaplen, datalink = struct.unpack(
        f"{endian}HHIIII",
        data[4:24],
    )
    link_name = _LINK_TYPES.get(datalink, f"unknown:{datalink}")
    return {
        "format": "pcap",
        "version_major": version_major,
        "version_minor": version_minor,
        "snaplen": snaplen,
        "datalink": datalink,
        "link_type": _link_type_object(link_name, datalink=datalink),
        "precision": precision,
    }


def expected_records(vectors: list[EncodedVector]) -> list[JSONObject]:
    """Return expected pcap records for annotated vectors."""

    return [_vector_record(vector, position) for position, vector in enumerate(vectors)]


def pcap_link_type_for_vectors(
    vectors: list[EncodedVector],
    *,
    requested: str = "ethernet",
) -> str:
    """Return the single classic-pcap link type supported by a vector batch."""

    link_types = {_pcap_link_type_for_vector(vector, requested) for vector in vectors}
    if len(link_types) != 1:
        supported = ", ".join(sorted(link_types))
        raise ValueError(f"classic pcap requires one link type; got {supported}")
    return next(iter(link_types))


def _pcap_link_type_for_vector(vector: EncodedVector, requested: str) -> str:
    root = vector.root or vector.decoder
    if root in {
        "BTLE_PHDR",
        "link:bluetooth-le-ll-with-phdr",
        "link:bluetooth_le_ll_with_phdr",
    }:
        return "bluetooth_le_ll_with_phdr"
    if root in {"IP", "IPv6", "Raw", "l3:ipv4", "l3:ipv6", "link:raw"}:
        return "raw"
    if root in {"Ether", "link:ethernet"}:
        return "ethernet"
    if root in {"CookedLinux", "link:linux-cooked", "link:linux-sll"}:
        return "linux_sll"
    if root in {"Loopback", "link:null-loopback"}:
        return "null_loopback"
    if root in {"Dot11", "link:dot11", "link:ieee80211"}:
        return "ieee80211"
    if root in {"RadioTap", "link:radiotap"}:
        return "radiotap"
    return _canonical_link_type_name(requested)


def _single_pcap_link_type(records: list[JSONObject]) -> str:
    link_types = {
        _string(_object(record["link_type"], "link_type")["name"], "link_type.name")
        for record in records
    }
    if len(link_types) != 1:
        supported = ", ".join(sorted(link_types))
        raise ValueError(f"classic pcap requires one link type; got {supported}")
    return next(iter(link_types))


def _datalink_for_link_type(link_type: str) -> int:
    return int(_link_type_object(link_type)["datalink"])


def _decode_packet_for_write(root: str | None, raw: bytes, scapy_all: Any) -> Any:
    if root in {
        "BTLE_PHDR",
        "link:bluetooth-le-ll-with-phdr",
        "link:bluetooth_le_ll_with_phdr",
    }:
        return raw
    decoder_name = {
        "Ether": "Ether",
        "link:ethernet": "Ether",
        "CookedLinux": "CookedLinux",
        "link:linux-cooked": "CookedLinux",
        "link:linux-sll": "CookedLinux",
        "Loopback": "Loopback",
        "link:null-loopback": "Loopback",
        "Dot11": "Dot11",
        "link:dot11": "Dot11",
        "link:ieee80211": "Dot11",
        "RadioTap": "RadioTap",
        "link:radiotap": "RadioTap",
        "Raw": "Raw",
        "link:raw": "Raw",
        "l3:ipv4": "IP",
        "IP": "IP",
        "l3:ipv6": "IPv6",
        "IPv6": "IPv6",
    }.get(root or "link:ethernet")
    if decoder_name is None:
        raise ValueError(f"unsupported pcap write root: {root!r}")
    decoder = getattr(scapy_all, decoder_name, None)
    if decoder is None:
        raise ValueError(f"Scapy decoder is unavailable: {decoder_name}")
    return decoder(raw)


def _vector_record(vector: EncodedVector, position: int) -> JSONObject:
    metadata = _object(vector.metadata, "vector.metadata")
    record = metadata.get("pcap_record")
    if isinstance(record, dict):
        link_type = _object(record.get("link_type", _link_type_object("ethernet")), "link_type")
        timestamp = _object(
            record.get("timestamp", timestamp_for_record(vector.plan.seed, vector.plan.index)),
            "timestamp",
        )
    else:
        link_type = _link_type_object("ethernet")
        timestamp = timestamp_for_record(vector.plan.seed, vector.plan.index)

    root = vector.root or vector.decoder or _root_for_link_type(_string(link_type["name"], "name"))
    return {
        "index": position,
        "plan_index": vector.plan.index,
        "raw_hex": vector.raw_hex,
        "root": root,
        "link_type": link_type,
        "timestamp": timestamp,
        "layers": list(vector.plan.stack),
    }


def _packet_timestamp(packet: Any, precision: str) -> JSONObject:
    units = 1_000_000_000 if precision == "nanoseconds" else 1_000_000
    raw_time = getattr(packet, "time", Decimal(0))
    value = Decimal(str(raw_time))
    seconds_decimal = value.to_integral_value(rounding=ROUND_FLOOR)
    seconds = int(seconds_decimal)
    fractional = int(((value - seconds_decimal) * units).to_integral_value())
    return {
        "seconds": seconds,
        "fractional": fractional,
        "precision": precision,
        "nanos": fractional if precision == "nanoseconds" else fractional * 1_000,
    }


def _decimal_timestamp(timestamp: JSONObject) -> Decimal:
    seconds = int(timestamp["seconds"])
    fractional = int(timestamp["fractional"])
    precision = _string(timestamp["precision"], "precision")
    units = Decimal(1_000_000_000 if precision == "nanoseconds" else 1_000_000)
    return Decimal(seconds) + (Decimal(fractional) / units)


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
    if normalized in {
        "bluetooth_le_ll_with_phdr",
        "btle_ll_with_phdr",
        "btle_with_phdr",
        "dlt_256",
        "linktype_bluetooth_le_ll_with_phdr",
    }:
        return "bluetooth_le_ll_with_phdr"
    if normalized == "linux_cooked":
        return "linux_sll"
    if normalized in {"dot11", "ieee80211", "ieee802_11"}:
        return "ieee80211"
    if normalized in {"radiotap", "ieee80211_radio", "ieee80211_radiotap"}:
        return "radiotap"
    return normalized


def _require_capability(
    capabilities: BackendCapabilities | BackendRegistration | None,
    capability: str,
    operation: str,
) -> None:
    resolved = _capability_contract(capabilities)
    if not bool(getattr(resolved, capability, False)):
        raise ValueError(
            f"unsupported backend capability: Scapy {operation} requires {capability}"
        )


def _capability_contract(
    capabilities: BackendCapabilities | BackendRegistration | None,
) -> BackendCapabilities:
    if capabilities is None:
        return get_backend("scapy").capabilities
    if isinstance(capabilities, BackendRegistration):
        return capabilities.capabilities
    return capabilities


def _object(value: object, name: str) -> JSONObject:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    return dict(value)


def _string(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value
