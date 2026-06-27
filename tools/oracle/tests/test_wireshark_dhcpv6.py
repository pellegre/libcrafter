"""Parser-only Wireshark/tshark coverage for DHCPv6 packets."""

from __future__ import annotations

import argparse
import ipaddress
import shutil
import struct
import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path

from tools.oracle.engine.backends.wireshark import normalize as wireshark


def _raw_ipv6_udp(payload: bytes, *, src_port: int = 546, dst_port: int = 547) -> bytes:
    udp_length = 8 + len(payload)
    ipv6_header = (
        b"\x60\x00\x00\x00"
        + udp_length.to_bytes(2, "big")
        + bytes([17, 64])
        + ipaddress.IPv6Address("2001:db8::1").packed
        + ipaddress.IPv6Address("2001:db8::2").packed
    )
    udp_header = (
        src_port.to_bytes(2, "big")
        + dst_port.to_bytes(2, "big")
        + udp_length.to_bytes(2, "big")
        + b"\x00\x00"
    )
    return ipv6_header + udp_header + payload


def _option(code: int, payload: bytes) -> bytes:
    return code.to_bytes(2, "big") + len(payload).to_bytes(2, "big") + payload


def _solicit_payload() -> bytes:
    return (
        b"\x01\x01\x02\x03"
        + _option(1, bytes.fromhex("0001000100000000020000000001"))
        + _option(6, bytes.fromhex("00170018"))
        + _option(8, bytes.fromhex("000a"))
    )


def _relay_forward_payload() -> bytes:
    return (
        b"\x0c\x01"
        + ipaddress.IPv6Address("2001:db8:100::").packed
        + ipaddress.IPv6Address("fe80::1").packed
        + _option(18, b"test")
        + _option(9, b"\x01\x01\x02\x03")
    )


def _synthetic_packet(raw: bytes, *, message_type: str = "1") -> dict:
    return {
        "_source": {
            "layers": {
                "frame": {"frame.protocols": "raw:ipv6:udp:dhcpv6"},
                "ipv6": {
                    "ipv6.version": "6",
                    "ipv6.plen": str(len(raw) - 40),
                    "ipv6.nxt": "17",
                    "ipv6.hlim": "64",
                    "ipv6.src": "2001:db8::1",
                    "ipv6.dst": "2001:db8::2",
                },
                "udp": {
                    "udp.srcport": "546",
                    "udp.dstport": "547",
                    "udp.length": str(len(raw) - 40),
                    "udp.checksum": "0x0000",
                },
                "dhcpv6": {
                    "dhcpv6.msgtype": message_type,
                    "dhcpv6.trid": "0x010203",
                },
            }
        }
    }


def _option_codes(fields: Mapping[str, object]) -> list[int]:
    options = fields.get("options")
    assert isinstance(options, list)
    return [
        int(option["code"])
        for option in options
        if isinstance(option, Mapping) and "code" in option
    ]


class WiresharkDhcpv6NormalizationTest(unittest.TestCase):
    def test_normalizes_solicit_from_raw_ipv6_udp_bytes(self) -> None:
        raw = _raw_ipv6_udp(_solicit_payload())
        model = wireshark.normalize_packet_json(
            _synthetic_packet(raw),
            root="l3:ipv6",
            source_hex=raw.hex(),
        )

        self.assertEqual(model.root, "l3:ipv6")
        self.assertEqual(model.layers, ["ipv6", "udp", "dhcpv6"])
        dhcpv6 = model.fields.get("dhcpv6")
        self.assertIsInstance(dhcpv6, Mapping)
        self.assertEqual(dhcpv6.get("message_type"), 1)
        self.assertEqual(dhcpv6.get("transaction_id"), 0x010203)
        self.assertEqual(dhcpv6.get("option_count"), 3)
        self.assertEqual(_option_codes(dhcpv6), [1, 6, 8])

    def test_normalizes_relay_forward_fields_and_options(self) -> None:
        raw = _raw_ipv6_udp(_relay_forward_payload(), src_port=547, dst_port=547)
        model = wireshark.normalize_packet_json(
            _synthetic_packet(raw, message_type="12"),
            root="l3:ipv6",
            source_hex=raw.hex(),
        )

        dhcpv6 = model.fields.get("dhcpv6")
        self.assertIsInstance(dhcpv6, Mapping)
        self.assertEqual(dhcpv6.get("message_type"), 12)
        self.assertEqual(dhcpv6.get("hop_count"), 1)
        self.assertEqual(dhcpv6.get("link_address"), "2001:db8:100::")
        self.assertEqual(dhcpv6.get("peer_address"), "fe80::1")
        self.assertNotIn("transaction_id", dhcpv6)
        self.assertEqual(_option_codes(dhcpv6), [18, 9])

    def test_dhcpv6_layer_is_recognized_as_a_layer(self) -> None:
        self.assertEqual(wireshark._PROTOCOL_LAYER_ALIASES.get("dhcpv6"), "dhcpv6")

    def test_parser_only_default_pcap_direction_is_read_only(self) -> None:
        from tools.oracle.engine import cli

        args = argparse.Namespace(backend="wireshark", direction="roundtrip")
        effective = cli._pcap_effective_args(args)
        self.assertEqual(effective.direction, "libcrafter_to_reference")

    def test_pcap_layer_canonicalization_normalizes_dhcpv6(self) -> None:
        from tools.oracle.engine import cli

        self.assertEqual(cli._canonical_pcap_layers(["Dhcpv6"]), ["dhcpv6"])


class WiresharkDhcpv6PcapFallbackTest(unittest.TestCase):
    def test_pcap_read_fallback_decodes_dhcpv6_without_tshark(self) -> None:
        from tools.oracle.engine.backends.wireshark import pcap
        from tools.oracle.engine.backends.wireshark.normalize import (
            WiresharkNormalizationUnsupported,
        )

        raw = _raw_ipv6_udp(_solicit_payload())

        def unavailable(_path: Path):
            raise WiresharkNormalizationUnsupported("tshark not found on PATH")

        original = pcap._tshark_json_packets
        pcap._tshark_json_packets = unavailable
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                path = Path(temp_dir) / "dhcpv6-raw.pcap"
                path.write_bytes(
                    b"\xd4\xc3\xb2\xa1"
                    + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 101)
                    + struct.pack("<IIII", 1, 2, len(raw), len(raw))
                    + raw
                )
                records = pcap.read_pcap(path)
        finally:
            pcap._tshark_json_packets = original

        self.assertEqual(records[0]["layers"], ["ipv6", "udp", "dhcpv6"])
        decoded = records[0]["decoded"]
        dhcpv6 = decoded["fields"]["dhcpv6"]
        self.assertEqual(dhcpv6["message_type"], 1)
        self.assertEqual(dhcpv6["option_count"], 3)
        self.assertEqual(
            decoded["metadata"]["fallback"]["parser"],
            "classic_pcap_dhcpv6_bytes_without_tshark",
        )


@unittest.skipUnless(
    shutil.which("tshark"),
    "tshark not installed; skipping parser-only DHCPv6 raw decode",
)
class WiresharkDhcpv6RawDecodeTest(unittest.TestCase):
    def test_decode_bytes_raw_ipv6_dhcpv6_solicit(self) -> None:
        raw = _raw_ipv6_udp(_solicit_payload())
        model = wireshark.decode_bytes(raw, root="l3:ipv6")
        self.assertEqual(model.layers, ["ipv6", "udp", "dhcpv6"])
        dhcpv6 = model.fields.get("dhcpv6")
        self.assertIsInstance(dhcpv6, Mapping)
        self.assertEqual(dhcpv6.get("message_type"), 1)
        self.assertEqual(_option_codes(dhcpv6), [1, 6, 8])


if __name__ == "__main__":
    unittest.main()
