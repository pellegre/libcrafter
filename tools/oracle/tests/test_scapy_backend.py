"""Unit coverage for the Scapy backend l2:ipv4 root mapping and decode."""

from __future__ import annotations

import unittest

from tools.oracle.engine.backends.scapy import normalize, packets
from tools.oracle.engine.generator import generate_plans
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

    def test_ipv4_flag_domains_materialize_to_wire_bits(self) -> None:
        cases = {
            "none": 0,
            "reserved": 0b100,
            "df": 0b010,
            "mf": 0b001,
            "df_mf": 0b011,
            "all": 0b111,
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(packets._ipv4_flags(value), expected)
        self.assertEqual(packets._ipv4_flags(["reserved", "mf"]), 0b101)


def _dot11_plan(
    *,
    stack: list[str],
    fields: dict,
    root: str,
    case: str = "dot11-unit",
) -> PacketPlan:
    return PacketPlan(
        stack=stack,
        fields=fields,
        profile="dot11-smoke",
        seed=1,
        index=0,
        direction="reference_to_libcrafter",
        family="dot11",
        feature_tags=["dot11"],
        case=case,
        strict_bytes=True,
        metadata={"root": root, "root_decoder": root, "stack_name": "dot11_unit"},
    )


class ScapyDot11MaterializationTest(unittest.TestCase):
    def test_radiotap_dot11_payload_exact_hex(self) -> None:
        plan = _dot11_plan(
            stack=["radiotap", "dot11", "payload"],
            root="link:radiotap",
            fields={
                "radiotap": {"version": 0, "pad": 0, "flags": "fcs_present", "rate": 2},
                "dot11": {
                    "frame_control": 0x0008,
                    "duration_id": 0,
                    "addr1": "00:00:5e:00:53:01",
                    "addr2": "00:00:5e:00:53:02",
                    "addr3": "00:00:5e:00:53:03",
                    "sequence_control": 0x1000,
                },
                "payload": {"hex": "010203", "length": 3},
            },
        )

        vector = packets.encode_packet_plan(plan)

        self.assertEqual(
            vector.raw_hex,
            "00000a000600000010020800000000005e00530100005e00530200005e0053030010010203",
        )
        self.assertEqual(vector.metadata["scapy_stack"], ["RadioTap", "Dot11", "Raw"])

    def test_dot11_llc_snap_eapol_start_exact_hex(self) -> None:
        plan = _dot11_plan(
            stack=["dot11", "llc_snap", "eapol"],
            root="link:dot11",
            fields={
                "dot11": {
                    "frame_control": 0x0008,
                    "duration_id": 0,
                    "addr1": "00:00:5e:00:53:01",
                    "addr2": "00:00:5e:00:53:02",
                    "addr3": "00:00:5e:00:53:03",
                    "sequence_control": 0x1000,
                },
                "llc_snap": {
                    "dsap": 0xAA,
                    "ssap": 0xAA,
                    "control": 0x03,
                    "oui": {"hex": "000000"},
                    "ethertype": "eapol",
                },
                "eapol": {"version": 2, "packet_type": "start", "body_length": 0},
            },
        )

        vector = packets.encode_packet_plan(plan)

        self.assertEqual(
            vector.raw_hex,
            "0800000000005e00530100005e00530200005e0053030010aaaa03000000888e02010000",
        )
        self.assertEqual(vector.decoder, "Dot11")

    def test_radiotap_dot11_rsn_exact_hex(self) -> None:
        plan = _dot11_plan(
            stack=["radiotap", "dot11", "rsn"],
            root="link:radiotap",
            fields={
                "radiotap": {"version": 0, "pad": 0},
                "dot11": {
                    "frame_control": 0x0080,
                    "duration_id": 0,
                    "addr1": "ff:ff:ff:ff:ff:ff",
                    "addr2": "00:00:5e:00:53:02",
                    "addr3": "00:00:5e:00:53:03",
                    "sequence_control": 0,
                    "management_fixed_fields": {"hex": "000000000000000064000100"},
                },
                "rsn": {
                    "element_id": 48,
                    "version": 1,
                    "group_cipher_suite": "ccmp_128",
                    "pairwise_cipher_suites": ["ccmp_128"],
                    "akm_suites": ["psk"],
                    "capabilities": 0,
                },
            },
        )

        vector = packets.encode_packet_plan(plan)

        self.assertEqual(
            vector.raw_hex,
            "000008000000000080000000ffffffffffff00005e00530200005e005303000000000000000000006400010030140100000fac040100000fac040100000fac020000",
        )

    def test_generated_dot11_smoke_plans_materialize_without_scapy_bootstrap(self) -> None:
        plans = generate_plans(seed=1, profile="dot11-smoke", count=3, backend="scapy")

        vectors = [packets.encode_packet_plan(plan) for plan in plans]

        self.assertEqual(len(vectors), 3)
        self.assertTrue(all(vector.metadata["scapy_version"] == "not-required" for vector in vectors))
        self.assertTrue(all(vector.raw_hex for vector in vectors))


class ScapyDot11NormalizationTest(unittest.TestCase):
    def test_radiotap_dot11_llc_snap_eapol_payload_normalizes_from_bytes(self) -> None:
        plan = _dot11_plan(
            stack=["radiotap", "dot11", "llc_snap", "eapol", "payload"],
            root="link:radiotap",
            fields={
                "radiotap": {"version": 0, "pad": 0, "flags": "fcs_present", "rate": 2},
                "dot11": {
                    "frame_control": 0x0008,
                    "duration_id": 0,
                    "addr1": "00:00:5e:00:53:01",
                    "addr2": "00:00:5e:00:53:02",
                    "addr3": "00:00:5e:00:53:03",
                    "sequence_control": 0x1000,
                },
                "llc_snap": {"dsap": 0xAA, "ssap": 0xAA, "control": 0x03, "ethertype": "eapol"},
                "eapol": {"version": 2, "packet_type": "start", "body_length": 0},
                "payload": {"hex": "01020304", "length": 4},
            },
        )

        vector = packets.encode_packet_plan(plan)
        decoded = normalize.decode_bytes(vector.to_bytes(), root=vector.root, source_hex=vector.raw_hex)

        self.assertEqual(decoded.layers, ["radiotap", "dot11", "llc_snap", "eapol", "payload"])
        self.assertEqual(decoded.fields["radiotap"]["fcs_status"], "present")
        self.assertEqual(decoded.fields["dot11"]["sequence_number"], 0x100)
        self.assertEqual(decoded.fields["llc_snap"]["ethertype"], 0x888E)
        self.assertEqual(decoded.fields["eapol"]["body_length"], 4)
        self.assertEqual(decoded.fields["payload"]["hex"], "01020304")

    def test_protected_dot11_data_body_stays_payload(self) -> None:
        raw = bytes.fromhex(
            "0840000000005e00530100005e00530200005e0053030010"
            "aaaa03000000080001020304"
        )

        decoded = normalize.decode_bytes(raw, root="link:dot11", source_hex=raw.hex())

        self.assertEqual(decoded.layers, ["dot11", "payload"])
        self.assertTrue(decoded.fields["dot11"]["protected"])
        self.assertEqual(decoded.fields["dot11"]["encrypted_body_len"], 12)
        self.assertEqual(decoded.fields["payload"]["hex"], "aaaa03000000080001020304")

    def test_rsn_tag_normalizes_as_rsn_layer(self) -> None:
        plan = _dot11_plan(
            stack=["radiotap", "dot11", "rsn"],
            root="link:radiotap",
            fields={
                "radiotap": {"version": 0, "pad": 0},
                "dot11": {
                    "frame_control": 0x0080,
                    "duration_id": 0,
                    "addr1": "ff:ff:ff:ff:ff:ff",
                    "addr2": "00:00:5e:00:53:02",
                    "addr3": "00:00:5e:00:53:03",
                    "sequence_control": 0,
                    "management_fixed_fields": {"hex": "000000000000000064000100"},
                },
                "rsn": {
                    "element_id": 48,
                    "version": 1,
                    "group_cipher_suite": "ccmp_128",
                    "pairwise_cipher_suites": ["ccmp_128"],
                    "akm_suites": ["psk"],
                    "capabilities": 0,
                },
            },
        )

        vector = packets.encode_packet_plan(plan)
        decoded = normalize.decode_bytes(vector.to_bytes(), root=vector.root, source_hex=vector.raw_hex)

        self.assertEqual(decoded.layers, ["radiotap", "dot11", "rsn"])
        self.assertEqual(decoded.fields["rsn"]["version"], 1)
        self.assertEqual(decoded.fields["rsn"]["group_cipher_suite"]["label"], "ccmp-128")
        self.assertEqual(decoded.fields["rsn"]["akm_suites"][0]["label"], "psk")


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
