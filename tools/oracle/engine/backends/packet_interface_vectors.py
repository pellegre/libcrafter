"""Independent Scapy capture/packet interface references, without live I/O.

Regenerate to stdout with ``uv run --with scapy==2.6.1 python -m
tools.oracle.engine.backends.packet_interface_vectors``.
"""
from __future__ import annotations

import json
import struct
import zlib


def normalize(capture: bytes, link_type: int, original_len: int) -> dict:
    """Normalize fixture framing with explicit, independently checked evidence."""
    flags = None
    offset = 0
    if link_type == 127:
        if len(capture) < 8:
            raise ValueError("truncated radiotap")
        _, _, offset, present = struct.unpack_from("<BBHI", capture)
        if not 8 <= offset <= len(capture):
            raise ValueError("invalid radiotap length")
        # This corpus deliberately uses only the fixed Flags field.
        if present not in (0, 2):
            raise ValueError("reference radiotap fields unsupported")
        if present == 2:
            if offset < 9:
                raise ValueError("truncated radiotap flags")
            flags = capture[8]
    elif link_type != 105:
        raise ValueError("unsupported link type")
    frame = capture[offset:]
    if len(frame) < 24:
        raise ValueError("truncated MAC header")
    control = int.from_bytes(frame[:2], "little")
    header_len = 24 + (6 if control & 0x0300 == 0x0300 else 0)
    if control & 0x000C == 0x0008 and control & 0x0080:
        header_len += 2
        if control & 0x8000:
            header_len += 4
    fcs = {"state": "unknown" if flags is None else "absent", "bytes_hex": "", "valid": None}
    if flags is not None and flags & 0x10:
        missing = max(0, original_len - len(capture))
        trailer_len = max(0, 4 - missing)
        if len(frame) < header_len + trailer_len:
            raise ValueError("truncated MAC or FCS")
        trailer = frame[len(frame) - trailer_len:] if trailer_len else b""
        frame = frame[:len(frame) - trailer_len] if trailer_len else frame
        fcs = {"state": "truncated" if missing else "present", "bytes_hex": trailer.hex(), "valid": None}
    padding = b""
    if flags is not None and flags & 0x20:
        padded_len = (header_len + 3) & ~3
        if len(frame) < padded_len:
            raise ValueError("truncated MAC padding")
        padding = frame[header_len:padded_len]
        frame = frame[:header_len] + frame[padded_len:]
    if fcs["state"] == "present":
        fcs["valid"] = zlib.crc32(frame) == int.from_bytes(bytes.fromhex(fcs["bytes_hex"]), "little")
    return {"normalized_hex": frame.hex(), "padding_hex": padding.hex(), "fcs": fcs,
            "driver_failed_fcs": None if flags is None else bool(flags & 0x40),
            "hardware_decrypted": None}


def materialize() -> dict:
    from scapy.layers.dot11 import Dot11, Dot11QoS, RadioTap
    from scapy.packet import Raw

    mac = Dot11(type=2, subtype=0, addr1="02:00:5e:00:53:01",
                addr2="02:00:5e:00:53:02", addr3="02:00:5e:00:53:03", SC=48)
    payload = b"\x17\x23\x45\x67\x89"
    bare = bytes(mac / Raw(payload))
    qos = mac.copy()
    qos.subtype = 8
    qos_header = bytes(qos / Dot11QoS(TID=3))
    qos_frame = qos_header + payload
    cases = []

    def case(name, frame, flags=None, link=127, padding=False, corrupt=False, missing=0):
        wrapper = bytes(RadioTap() if flags is None else RadioTap(present="Flags", Flags=flags)) if link == 127 else b""
        body = frame
        if padding:
            body = qos_header + b"\xa5\x5a" + payload
        if flags is not None and flags & 0x10:
            body += struct.pack("<I", zlib.crc32(frame) ^ int(corrupt))
        capture = wrapper + body
        original_len = len(capture)
        if missing:
            capture = capture[:-missing]
        expected = normalize(capture, link, original_len)
        assert expected["normalized_hex"] == frame.hex()
        cases.append({"name": name, "link_type": link, "capture_hex": capture.hex(),
                      "captured_len": len(capture), "original_len": original_len,
                      "timestamp": {"seconds": 123, "micros": 456},
                      "expected": expected, "monitor_tx_hex": (bytes(RadioTap()) + frame).hex()})

    case("bare-unknown", bare, link=105)
    case("radiotap-unknown", bare)
    case("radiotap-absent", bare, flags=0)
    case("radiotap-valid", bare, flags=0x10)
    case("radiotap-invalid", bare, flags=0x50, corrupt=True)
    case("qos-padding-valid", qos_frame, flags=0x30, padding=True)
    for missing in (1, 2, 3, 4):
        case(f"radiotap-truncated-{missing}", bare, flags=0x10, missing=missing)
    return {"schema": "crafter.packet-interface.references/v1", "generator": "independent-dot11/v1", "cases": cases}


if __name__ == "__main__":
    print(json.dumps(materialize(), indent=2, sort_keys=True))
