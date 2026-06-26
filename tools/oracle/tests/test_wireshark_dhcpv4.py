"""Parser-only Wireshark/tshark coverage for raw IPv4 DHCPv4 packets.

Wireshark is parser-only in this repo: it decodes DHCPv4 packets but never sends
or receives them. These tests pin two things:

* The pure-Python normalizer maps tshark's ``bootp``/``dhcp`` dissector fields
  onto the same normalized names the Scapy reference backend
  (``tools/oracle/engine/backends/scapy/normalize.py``) and the libcrafter
  decoder (``tools/oracle/adapters/src/bin/decode_vectors.rs``) emit, so the
  cross-backend offline comparison stays meaningful. This runs everywhere; it
  does not need a ``tshark`` executable.
* When ``tshark`` is installed, decoding a real raw IPv4 / UDP / DHCPv4 DISCOVER
  packet from an ``l3:ipv4`` root produces the ``ipv4 / udp / dhcpv4`` stack with
  those aligned fields. When ``tshark`` is absent this test skips explicitly
  (the spec requires a clear skip, never a protocol-correctness failure).
"""

from __future__ import annotations

import shutil
import unittest
from collections.abc import Mapping

from tools.oracle.engine.backends.wireshark import normalize as wireshark


# A complete raw IPv4 / UDP(68->67) / BOOTP / DHCPv4 DISCOVER packet using
# documentation address space (192.0.2.0/24) and a documentation MAC. Options:
# 53 (message-type=DISCOVER), 55 (parameter request list 1,3), 255 (end).
# Fixed BOOTP header + 192-byte sname/file region + magic cookie + options.
_RAW_IPV4_DHCP_DISCOVER_HEX = (
    "45000114000100004011f5d4c0000201c0000202004400430100000001"
    "010600112233440000000000000000000000000000000000000000020000000001"
    + "00" * 202
    + "6382536335010137020103ff"
)

# DHCPv4 magic cookie (RFC 2132) as the shared integer view both backends emit.
_DHCP_MAGIC_COOKIE = 0x63825363


def _synthetic_dhcpv4_packet(*, dhcp_prefix: str) -> dict:
    """Build a tshark ``-T json`` style packet object for the raw IPv4 DHCPv4 bytes.

    ``dhcp_prefix`` is ``"dhcp"`` (Wireshark >= 3.0) or ``"bootp"`` (older
    Wireshark); the normalizer must accept either dissector field prefix.
    """

    layer_key = dhcp_prefix
    return {
        "_source": {
            "layers": {
                "frame": {"frame.protocols": f"raw:ip:udp:{dhcp_prefix}"},
                "ip": {
                    "ip.version": "4",
                    "ip.hdr_len": "20",
                    "ip.src": "192.0.2.1",
                    "ip.dst": "192.0.2.2",
                    "ip.proto": "17",
                    "ip.ttl": "64",
                    "ip.len": "276",
                    "ip.id": "0x0001",
                    "ip.checksum": "0xf5d4",
                    "ip.flags": "0x00",
                },
                "udp": {
                    "udp.srcport": "68",
                    "udp.dstport": "67",
                    "udp.length": "256",
                    "udp.checksum": "0x0000",
                },
                layer_key: {
                    f"{dhcp_prefix}.type": "1",
                    f"{dhcp_prefix}.hw.type": "1",
                    f"{dhcp_prefix}.hw.len": "6",
                    f"{dhcp_prefix}.hops": "0",
                    f"{dhcp_prefix}.id": "0x11223344",
                    f"{dhcp_prefix}.secs": "0",
                    f"{dhcp_prefix}.flags": "0x0000",
                    f"{dhcp_prefix}.ip.client": "0.0.0.0",
                    f"{dhcp_prefix}.ip.your": "0.0.0.0",
                    f"{dhcp_prefix}.ip.server": "0.0.0.0",
                    f"{dhcp_prefix}.ip.relay": "0.0.0.0",
                    f"{dhcp_prefix}.hw.mac_addr": "02:00:00:00:00:01",
                    f"{dhcp_prefix}.cookie": "0x63825363",
                    f"{dhcp_prefix}.option.dhcp": "1",
                },
            }
        }
    }


def _assert_ipv4_dhcpv4_discover(testcase: unittest.TestCase, model) -> None:
    testcase.assertEqual(model.root, "l3:ipv4")
    testcase.assertIn("ipv4", model.layers)
    testcase.assertIn("udp", model.layers)
    testcase.assertIn("dhcpv4", model.layers)
    # Stack order: ipv4 then udp then dhcpv4.
    testcase.assertEqual(
        [layer for layer in model.layers if layer in {"ipv4", "udp", "dhcpv4"}],
        ["ipv4", "udp", "dhcpv4"],
    )

    udp = model.fields.get("udp")
    testcase.assertIsInstance(udp, Mapping)
    testcase.assertEqual(udp.get("src_port"), 68)
    testcase.assertEqual(udp.get("dst_port"), 67)

    dhcpv4 = model.fields.get("dhcpv4")
    testcase.assertIsInstance(dhcpv4, Mapping)
    # Field names align with the Scapy reference and libcrafter decoders.
    testcase.assertEqual(dhcpv4.get("opcode"), 1)
    testcase.assertEqual(dhcpv4.get("hardware_type"), 1)
    testcase.assertEqual(dhcpv4.get("hardware_length"), 6)
    testcase.assertEqual(dhcpv4.get("hops"), 0)
    testcase.assertEqual(dhcpv4.get("transaction_id"), 0x11223344)
    testcase.assertEqual(dhcpv4.get("seconds"), 0)
    testcase.assertEqual(dhcpv4.get("flags"), 0)
    testcase.assertEqual(dhcpv4.get("client_ip"), "0.0.0.0")
    testcase.assertEqual(dhcpv4.get("your_ip"), "0.0.0.0")
    testcase.assertEqual(dhcpv4.get("server_ip"), "0.0.0.0")
    testcase.assertEqual(dhcpv4.get("relay_ip"), "0.0.0.0")
    testcase.assertEqual(dhcpv4.get("magic_cookie"), _DHCP_MAGIC_COOKIE)
    testcase.assertEqual(
        dhcpv4.get("client_hardware_address"), {"hex": "020000000001"}
    )
    testcase.assertEqual(dhcpv4.get("message_type"), 1)
    # Backend-neutral option TLVs reconstructed from the raw region.
    testcase.assertEqual(dhcpv4.get("option_count"), 3)
    testcase.assertEqual(
        dhcpv4.get("options"),
        [
            {"code": 53, "payload_hex": "01"},
            {"code": 55, "payload_hex": "0103"},
            {"code": 255, "payload_hex": ""},
        ],
    )


class WiresharkDhcpv4NormalizationTest(unittest.TestCase):
    """Pure-Python normalizer coverage (no ``tshark`` executable required)."""

    def test_normalizes_raw_ipv4_dhcpv4_discover_dhcp_prefix(self) -> None:
        packet = _synthetic_dhcpv4_packet(dhcp_prefix="dhcp")
        model = wireshark.normalize_packet_json(
            packet, root="l3:ipv4", source_hex=_RAW_IPV4_DHCP_DISCOVER_HEX
        )
        _assert_ipv4_dhcpv4_discover(self, model)

    def test_normalizes_raw_ipv4_dhcpv4_discover_bootp_prefix(self) -> None:
        # Older Wireshark exposes the dissector under the ``bootp`` prefix; the
        # normalized field names must be identical.
        packet = _synthetic_dhcpv4_packet(dhcp_prefix="bootp")
        model = wireshark.normalize_packet_json(
            packet, root="l3:ipv4", source_hex=_RAW_IPV4_DHCP_DISCOVER_HEX
        )
        _assert_ipv4_dhcpv4_discover(self, model)

    def test_dhcpv4_layer_is_recognized_as_a_layer(self) -> None:
        # Regression guard: ``dhcp``/``bootp`` must be in the protocol->layer
        # alias map so DHCPv4 is normalized rather than silently dropped.
        self.assertEqual(
            wireshark._PROTOCOL_LAYER_ALIASES.get("dhcp"), "dhcpv4"
        )
        self.assertEqual(
            wireshark._PROTOCOL_LAYER_ALIASES.get("bootp"), "dhcpv4"
        )


@unittest.skipUnless(
    shutil.which("tshark"),
    "tshark not installed; skipping parser-only DHCPv4 raw decode",
)
class WiresharkDhcpv4RawDecodeTest(unittest.TestCase):
    """End-to-end parser-only decode of a raw IPv4 DHCPv4 packet via tshark."""

    def test_decode_bytes_raw_ipv4_dhcpv4_discover(self) -> None:
        raw = bytes.fromhex(_RAW_IPV4_DHCP_DISCOVER_HEX)
        model = wireshark.decode_bytes(raw, root="l3:ipv4")
        _assert_ipv4_dhcpv4_discover(self, model)


if __name__ == "__main__":
    unittest.main()
