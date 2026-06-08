"""Unit coverage for the Scapy live endpoint l2:ipv4 capture/send protocol."""

from __future__ import annotations

import unittest

from tools.oracle.engine.backends.scapy import live
from tools.oracle.engine.backends.scapy.bootstrap import import_scapy
from tools.oracle.engine.model import EncodedVector, PacketPlan


def _l2_ipv4_plan(*, index: int = 0) -> PacketPlan:
    return PacketPlan(
        stack=["ipv4", "icmp", "payload"],
        fields={
            "icmp": {
                "code": 0,
                "identifier": 6254,
                "sequence": 11943,
                "type": "echo-request",
            },
            "ipv4": {
                "dst": "198.51.100.200",
                "flags": "none",
                "identification": 14250,
                "protocol": "icmp",
                "src": "203.0.113.84",
                "ttl": 64,
            },
            "payload": {
                "hex": "b408ee7722d3e10cfe17acfd843b11e6",
                "length": 16,
            },
        },
        profile="smoke",
        seed=11,
        index=index,
        direction="reference_to_libcrafter",
        family="ipv4",
        feature_tags=["baseline", "ipv4", "icmp", "payload"],
        case="ipv4-icmp",
        strict_bytes=True,
        metadata={"root": "l2:ipv4", "root_decoder": "l2:ipv4"},
    )


def _l2_ipv4_vector(*, index: int = 0) -> EncodedVector:
    return EncodedVector.from_bytes(
        plan=_l2_ipv4_plan(index=index),
        backend="scapy",
        raw=b"",
        root="l2:ipv4",
        decoder="IP",
    )


class ScapyLiveCaptureRootTest(unittest.TestCase):
    """l2:ipv4 capture comparison must canonicalize to the IPv4 header."""

    def test_capture_compare_roots_table_maps_l2_ipv4_to_l3_ipv4(self) -> None:
        self.assertEqual(live.CAPTURE_COMPARE_ROOTS["l2:ipv4"], "l3:ipv4")

    def test_canonical_compare_root_canonicalizes_l2_ipv4(self) -> None:
        self.assertEqual(live._canonical_compare_root("l2:ipv4"), "l3:ipv4")

    def test_compare_root_for_vector_falls_back_to_canonical_vector_root(self) -> None:
        request = {"metadata": {"packets": []}}
        self.assertEqual(
            live._compare_root_for_vector(request, _l2_ipv4_vector()),
            "l3:ipv4",
        )

    def test_compare_root_for_vector_honors_request_compare_root(self) -> None:
        request = {
            "metadata": {
                "packets": [{"index": 0, "compare_root": "l2:ipv4"}],
            }
        }
        self.assertEqual(
            live._compare_root_for_vector(request, _l2_ipv4_vector()),
            "l3:ipv4",
        )


class ScapyLiveSendModeTest(unittest.TestCase):
    """l2:ipv4 stays IPv4-rooted; the link path engages only with peer MACs."""

    def test_l2_ipv4_default_send_mode_is_network_layer(self) -> None:
        self.assertEqual(live._send_mode_for_root("l2:ipv4"), "network-layer")

    def test_can_send_as_ethernet_requires_both_macs(self) -> None:
        self.assertFalse(live._can_send_as_ethernet({}))
        self.assertFalse(
            live._can_send_as_ethernet(
                {"local_addresses": {"mac": "02:00:00:00:00:01"}}
            )
        )
        self.assertTrue(
            live._can_send_as_ethernet(
                {
                    "local_addresses": {"mac": "02:00:00:00:00:01"},
                    "peer_addresses": {"mac": "02:00:00:00:00:02"},
                }
            )
        )

    def test_l2_ipv4_send_without_macs_stays_network_layer(self) -> None:
        scapy_all = import_scapy()["all"]
        packet = scapy_all.IP(src="203.0.113.84", dst="198.51.100.200")
        send_packet, send_root, send_mode = live._materialized_send_packet(
            scapy_all,
            packet,
            {},
            "l2:ipv4",
        )
        self.assertEqual(send_mode, "network-layer")
        self.assertEqual(send_root, "l2:ipv4")
        self.assertFalse(send_packet.haslayer(scapy_all.Ether))

    def test_l2_ipv4_send_with_macs_uses_link_layer(self) -> None:
        scapy_all = import_scapy()["all"]
        packet = scapy_all.IP(src="203.0.113.84", dst="198.51.100.200")
        request = {
            "local_addresses": {"mac": "02:00:00:00:00:01"},
            "peer_addresses": {"mac": "02:00:00:00:00:02"},
        }
        send_packet, send_root, send_mode = live._materialized_send_packet(
            scapy_all,
            packet,
            request,
            "l2:ipv4",
        )
        self.assertEqual(send_mode, "link-layer")
        self.assertEqual(send_root, "link:ethernet")
        self.assertTrue(send_packet.haslayer(scapy_all.Ether))
        ether = send_packet[scapy_all.Ether]
        self.assertEqual(ether.type, 0x0800)
        # The comparable model still starts at IPv4 after slicing the frame.
        self.assertTrue(send_packet.haslayer(scapy_all.IP))


class ScapyLiveCaptureSliceTest(unittest.TestCase):
    """A captured l2:ipv4 frame slices down to the IPv4 header for comparison."""

    def test_capture_slice_for_l2_ipv4_returns_ipv4_slice(self) -> None:
        scapy_all = import_scapy()["all"]
        frame = (
            scapy_all.Ether(
                src="02:00:00:00:00:01",
                dst="02:00:00:00:00:02",
                type=0x0800,
            )
            / scapy_all.IP(src="203.0.113.84", dst="198.51.100.200")
            / scapy_all.ICMP(type="echo-request")
        )
        capture_slice = live._capture_slice_for_root(scapy_all, frame, "l2:ipv4")
        self.assertEqual(capture_slice.compare_root, "l3:ipv4")
        self.assertEqual(type(capture_slice.packet).__name__, "IP")
        self.assertEqual(capture_slice.comparable_raw[0] >> 4, 4)
        # The full frame retains the Ethernet header; the comparable slice drops it.
        self.assertGreater(
            len(capture_slice.full_raw),
            len(capture_slice.comparable_raw),
        )

    def test_capture_slice_trims_ipv4_ethernet_padding(self) -> None:
        scapy_all = import_scapy()["all"]
        payload = bytes.fromhex(
            "9143b12f45fd0bdbbe5ac967cdb6e9ce55189546ac4f9768c3"
        )
        frame = (
            scapy_all.Ether(
                src="02:00:00:00:00:01",
                dst="02:00:00:00:00:02",
                type=0x0800,
            )
            / scapy_all.IP(
                src="10.78.0.10",
                dst="10.78.0.20",
                proto=253,
                flags="MF",
                frag=1,
                id=65535,
                tos=255,
                ttl=255,
                len=45,
            )
            / scapy_all.Raw(payload)
            / scapy_all.Padding(b"\x00")
        )

        capture_slice = live._capture_slice_for_root(scapy_all, frame, "l2:ipv4")

        self.assertEqual(capture_slice.compare_root, "l3:ipv4")
        self.assertEqual(len(capture_slice.full_raw), 60)
        self.assertEqual(len(capture_slice.comparable_raw), 45)
        self.assertEqual(capture_slice.comparable_raw[-len(payload) :], payload)
        self.assertEqual(bytes(scapy_all.raw(capture_slice.packet)), capture_slice.comparable_raw)


if __name__ == "__main__":
    unittest.main()
