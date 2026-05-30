"""Unit coverage for the Scapy backend l2:ipv4 root mapping and decode."""

from __future__ import annotations

import unittest

from tools.oracle.engine.backends.scapy import normalize, packets
from tools.oracle.engine.model import PacketPlan


L2_IPV4_PLAN = PacketPlan(
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
    index=0,
    direction="reference_to_libcrafter",
    family="ipv4",
    feature_tags=["baseline", "ipv4", "icmp", "payload"],
    case="ipv4-icmp",
    strict_bytes=True,
    metadata={
        "root": "l2:ipv4",
        "root_decoder": "l2:ipv4",
        "stack_name": "l2_ipv4_icmp_payload",
    },
)


class ScapyL2Ipv4RootMappingTest(unittest.TestCase):
    """The l2:ipv4 root must canonicalize to the IPv4 materialization path."""

    def test_l2_ipv4_decoder_is_ip(self) -> None:
        self.assertEqual(packets._SCAPY_DECODER_BY_ROOT["l2:ipv4"], "IP")
        self.assertEqual(packets._scapy_decoder("l2:ipv4"), "IP")

    def test_l2_ipv4_first_layer_is_ipv4(self) -> None:
        self.assertEqual(packets._ROOT_FIRST_LAYERS["l2:ipv4"], {"ipv4"})

    def test_l2_ipv4_matches_the_l3_ipv4_materialization_root(self) -> None:
        self.assertEqual(
            packets._SCAPY_DECODER_BY_ROOT["l2:ipv4"],
            packets._SCAPY_DECODER_BY_ROOT["l3:ipv4"],
        )
        self.assertEqual(
            packets._ROOT_FIRST_LAYERS["l2:ipv4"],
            packets._ROOT_FIRST_LAYERS["l3:ipv4"],
        )

    def test_plan_contract_accepts_l2_ipv4_rooted_ipv4_stack(self) -> None:
        stack = packets._canonical_stack(L2_IPV4_PLAN.stack)
        # Must not raise: an l2:ipv4 plan whose first layer is ipv4 is valid.
        packets._validate_plan_contract(L2_IPV4_PLAN, stack, "l2:ipv4")

    def test_plan_contract_rejects_l2_ipv4_with_non_ipv4_first_layer(self) -> None:
        with self.assertRaises(ValueError):
            packets._validate_plan_contract(
                L2_IPV4_PLAN,
                ["ethernet", "ipv4"],
                "l2:ipv4",
            )

    def test_normalize_root_alias_canonicalizes_l2_ipv4_to_l3_ipv4(self) -> None:
        self.assertEqual(normalize._normalize_root_name("l2:ipv4"), "l3:ipv4")


class ScapyL2Ipv4EncodeDecodeTest(unittest.TestCase):
    """An l2:ipv4 plan encodes and decodes as an IPv4 packet through Scapy."""

    def test_encode_l2_ipv4_plan_emits_ipv4_root_bytes(self) -> None:
        vector = packets.encode_packet_plan(L2_IPV4_PLAN)
        self.assertEqual(vector.root, "l2:ipv4")
        self.assertEqual(vector.decoder, "IP")
        self.assertEqual(vector.metadata["scapy_stack"][0], "IP")
        # IPv4 version nibble in the first byte of the emitted slice.
        self.assertEqual(vector.to_bytes()[0] >> 4, 4)

    def test_decode_l2_ipv4_bytes_starts_at_ipv4(self) -> None:
        vector = packets.encode_packet_plan(L2_IPV4_PLAN)
        decoded = normalize.decode_bytes(
            vector.to_bytes(),
            root="l2:ipv4",
            source_hex=vector.raw_hex,
            feature_tags=vector.plan.feature_tags,
        )
        self.assertEqual(decoded.root, "l3:ipv4")
        self.assertEqual(decoded.layers[0], "ipv4")
        self.assertIn("icmp", decoded.layers)

    def test_decode_root_l2_ipv4_returns_ip_packet(self) -> None:
        vector = packets.encode_packet_plan(L2_IPV4_PLAN)
        packet = normalize.decode_root("l2:ipv4", vector.to_bytes())
        self.assertEqual(type(packet).__name__, "IP")


if __name__ == "__main__":
    unittest.main()
