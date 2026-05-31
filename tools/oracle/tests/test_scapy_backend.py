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


def _icmp_live_plan(icmp_fields: dict, *, case: str, payload_hex: str = "0102030405") -> PacketPlan:
    """Build an l2:ipv4 ICMP live-matrix plan with the given icmp body fields."""

    fields: dict = {
        "icmp": dict(icmp_fields),
        "ipv4": {
            "dst": "198.51.100.10",
            "flags": "none",
            "identification": 4242,
            "protocol": "icmp",
            "src": "192.0.2.20",
            "ttl": 64,
        },
    }
    stack = ["ipv4", "icmp"]
    if payload_hex:
        fields["payload"] = {"hex": payload_hex, "length": len(payload_hex) // 2}
        stack.append("payload")
    return PacketPlan(
        stack=stack,
        fields=fields,
        profile="smoke",
        seed=22,
        index=0,
        direction="live_exchange",
        family="ipv4",
        feature_tags=["icmp", "icmpv4_live", "ipv4"],
        case=case,
        strict_bytes=True,
        metadata={
            "root": "l2:ipv4",
            "root_decoder": "l2:ipv4",
            "feature": "icmpv4_live",
            "stack_name": "l2_ipv4_icmp_payload",
        },
    )


class ScapyIcmpLiveMaterializationTest(unittest.TestCase):
    """Each supported ICMP live behavior encodes to bytes that decode back to a
    flat libcrafter-compatible normalized model."""

    def _decode(self, plan: PacketPlan):
        vector = packets.encode_packet_plan(plan)
        decoded = normalize.decode_bytes(
            vector.to_bytes(),
            root="l2:ipv4",
            source_hex=vector.raw_hex,
            feature_tags=vector.plan.feature_tags,
        )
        return vector, decoded

    def test_icmpv4_live_is_a_supported_feature(self) -> None:
        self.assertIn("icmpv4_live", packets._SUPPORTED_FEATURES)

    def test_echo_request_uses_id_seq_rest_of_header(self) -> None:
        plan = _icmp_live_plan(
            {"type": "echo_request", "code": 0, "identifier": 0x1234, "sequence": 0x5678},
            case="ipv4-icmp",
        )
        _, decoded = self._decode(plan)
        icmp = decoded.fields["icmp"]
        self.assertEqual(icmp["type"], 8)
        self.assertEqual(icmp["identifier"], 0x1234)
        self.assertEqual(icmp["sequence"], 0x5678)
        self.assertEqual(icmp["rest_of_header"], "12345678")

    def test_destination_unreachable_collapses_to_rest_of_header(self) -> None:
        plan = _icmp_live_plan(
            {"type": "destination_unreachable", "code": 3, "identifier": 1, "sequence": 2},
            case="icmpv4-destination-unreachable",
        )
        _, decoded = self._decode(plan)
        icmp = decoded.fields["icmp"]
        self.assertEqual(icmp["type"], 3)
        self.assertEqual(icmp["code"], 3)
        self.assertEqual(icmp["rest_of_header"], "00000000")
        self.assertIn("length", icmp)
        self.assertNotIn("nexthopmtu", icmp)
        self.assertNotIn("gw", icmp)

    def test_frag_needed_next_hop_mtu_in_rest_of_header(self) -> None:
        plan = _icmp_live_plan(
            {"type": "destination_unreachable", "code": 4, "next_hop_mtu": 1280},
            case="icmpv4-frag-needed-next-hop-mtu",
            payload_hex="",
        )
        _, decoded = self._decode(plan)
        icmp = decoded.fields["icmp"]
        # next-hop MTU lives in rest-of-header bytes 2-3 (0x0500 == 1280).
        self.assertEqual(icmp["rest_of_header"], "00000500")
        self.assertNotIn("nexthopmtu", icmp)

    def test_redirect_gateway_in_rest_of_header(self) -> None:
        plan = _icmp_live_plan(
            {"type": "redirect", "code": 0, "gateway": "192.0.2.1"},
            case="icmpv4-redirect",
            payload_hex="",
        )
        _, decoded = self._decode(plan)
        icmp = decoded.fields["icmp"]
        self.assertEqual(icmp["type"], 5)
        self.assertEqual(icmp["rest_of_header"], "c0000201")
        self.assertNotIn("gw", icmp)

    def test_parameter_problem_pointer_in_rest_of_header(self) -> None:
        plan = _icmp_live_plan(
            {"type": "parameter_problem", "code": 0, "pointer": 20},
            case="icmpv4-parameter-problem",
            payload_hex="",
        )
        _, decoded = self._decode(plan)
        icmp = decoded.fields["icmp"]
        self.assertEqual(icmp["type"], 12)
        self.assertEqual(icmp["rest_of_header"], "14000000")
        self.assertNotIn("ptr", icmp)

    def test_time_exceeded_collapses_to_rest_of_header(self) -> None:
        plan = _icmp_live_plan(
            {"type": "time_exceeded", "code": 0},
            case="icmpv4-time-exceeded",
            payload_hex="",
        )
        _, decoded = self._decode(plan)
        icmp = decoded.fields["icmp"]
        self.assertEqual(icmp["type"], 11)
        self.assertEqual(icmp["rest_of_header"], "00000000")
        self.assertNotIn("reserved", icmp)

    def test_source_quench_rest_of_header(self) -> None:
        plan = _icmp_live_plan(
            {"type": "source_quench", "code": 0, "rest_of_header": {"hex": "00000000"}},
            case="icmpv4-source-quench",
            payload_hex="",
        )
        _, decoded = self._decode(plan)
        icmp = decoded.fields["icmp"]
        self.assertEqual(icmp["type"], 4)
        self.assertEqual(icmp["rest_of_header"], "00000000")

    def test_timestamp_moves_timestamps_into_payload(self) -> None:
        plan = _icmp_live_plan(
            {
                "type": "timestamp",
                "code": 0,
                "identifier": 0x1111,
                "sequence": 0x2222,
                "originate_timestamp": 0x01020304,
                "receive_timestamp": 0x05060708,
                "transmit_timestamp": 0x090A0B0C,
            },
            case="icmpv4-timestamp",
            payload_hex="",
        )
        _, decoded = self._decode(plan)
        icmp = decoded.fields["icmp"]
        self.assertEqual(icmp["type"], 13)
        self.assertEqual(icmp["identifier"], 0x1111)
        self.assertEqual(icmp["rest_of_header"], "11112222")
        self.assertNotIn("ts_ori", icmp)
        # The 12 timestamp bytes follow the rest-of-header in the flat payload.
        self.assertEqual(
            decoded.fields["payload"]["hex"], "0102030405060708090a0b0c"
        )

    def test_address_mask_moves_mask_into_payload(self) -> None:
        plan = _icmp_live_plan(
            {
                "type": "address_mask_reply",
                "code": 0,
                "identifier": 7,
                "sequence": 9,
                "address_mask": "255.255.255.0",
            },
            case="icmpv4-address-mask",
            payload_hex="",
        )
        _, decoded = self._decode(plan)
        icmp = decoded.fields["icmp"]
        self.assertEqual(icmp["type"], 18)
        self.assertEqual(icmp["rest_of_header"], "00070009")
        self.assertNotIn("addr_mask", icmp)
        self.assertEqual(decoded.fields["payload"]["hex"], "ffffff00")

    def test_router_advertisement_addresses_in_payload(self) -> None:
        plan = _icmp_live_plan(
            {
                "type": "router_advertisement",
                "code": 0,
                "router_address_entry_size": 2,
                "router_lifetime": 1800,
                "router_addresses": [
                    {"address": "192.0.2.1", "preference": 0},
                    {"address": "192.0.2.2", "preference": 0},
                ],
            },
            case="icmpv4-router-advertisement",
            payload_hex="",
        )
        vector, decoded = self._decode(plan)
        icmp = decoded.fields["icmp"]
        self.assertEqual(icmp["type"], 9)
        # The address/preference list is deterministic raw bytes after the header.
        self.assertEqual(
            decoded.fields["payload"]["hex"],
            "c000020100000000c000020200000000",
        )

    def test_router_solicitation_rest_of_header(self) -> None:
        plan = _icmp_live_plan(
            {"type": "router_solicitation", "code": 0, "rest_of_header": {"hex": "00000000"}},
            case="icmpv4-router-solicitation",
            payload_hex="",
        )
        _, decoded = self._decode(plan)
        self.assertEqual(decoded.fields["icmp"]["type"], 10)
        self.assertEqual(decoded.fields["icmp"]["rest_of_header"], "00000000")

    def test_extension_bytes_become_flat_payload(self) -> None:
        quoted = (
            "45000028424200004011b464c000020ac00002149c40003500140000"
            "71756f7465642d7175657279"
        )
        extension = "2000000000080100000010ff"
        plan = _icmp_live_plan(
            {
                "type": "destination_unreachable",
                "code": 0,
                "embedded_header": {"hex": quoted},
                "extension_bytes": {"hex": extension},
            },
            case="icmpv4-extensions-mpls",
            payload_hex="",
        )
        _, decoded = self._decode(plan)
        self.assertEqual(decoded.layers, ["ipv4", "icmp", "payload"])
        # rest-of-header stays in the icmp header; the extension blob is the
        # flat payload both backends parse identically.
        self.assertEqual(decoded.fields["icmp"]["rest_of_header"], "00000000")
        self.assertEqual(decoded.fields["payload"]["hex"], quoted + extension)

    def test_extended_echo_request_numeric_type(self) -> None:
        plan = _icmp_live_plan(
            {
                "type": "extended_echo_request",
                "code": 0,
                "identifier": 0x0102,
                "sequence": 0x03,
                "rest_of_header": {"hex": "01020301"},
                "extension_bytes": {"hex": "20000000000800010102030405060708"},
            },
            case="icmpv4-extended-echo-request",
            payload_hex="",
        )
        _, decoded = self._decode(plan)
        icmp = decoded.fields["icmp"]
        self.assertEqual(icmp["type"], 42)
        self.assertEqual(icmp["identifier"], 0x0102)
        # RFC 8335 narrows the sequence to a single octet (byte 2).
        self.assertEqual(icmp["sequence"], 0x03)

    def test_legacy_type_rest_of_header(self) -> None:
        plan = _icmp_live_plan(
            {"type": "traceroute", "code": 0, "rest_of_header": {"hex": "00000000"}},
            case="crafter-icmpv4-legacy-types",
            payload_hex="",
        )
        _, decoded = self._decode(plan)
        self.assertEqual(decoded.fields["icmp"]["type"], 30)
        self.assertEqual(decoded.fields["icmp"]["rest_of_header"], "00000000")

    def test_domain_name_request_rest_of_header_materializes_raw(self) -> None:
        plan = _icmp_live_plan(
            {"type": "domain_name_request", "code": 0, "rest_of_header": {"hex": "00000000"}},
            case="crafter-icmpv4-legacy-types",
            payload_hex="01020304",
        )
        vector, decoded = self._decode(plan)
        raw = vector.to_bytes()
        self.assertEqual(raw[20], 37)
        self.assertNotEqual(raw[22:24], b"\x00\x00")
        self.assertEqual(decoded.fields["icmp"]["type"], 37)
        self.assertEqual(decoded.fields["icmp"]["rest_of_header"], "00000000")
        self.assertEqual(decoded.fields["payload"]["hex"], "01020304")


if __name__ == "__main__":
    unittest.main()
