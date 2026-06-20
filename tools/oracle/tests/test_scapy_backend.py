"""Unit coverage for the Scapy backend l2:ipv4 root mapping and decode."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.oracle.engine.backends.scapy import normalize, packets, pcap
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


class ScapyDot11PcapTest(unittest.TestCase):
    def test_bare_dot11_pcap_roundtrip_preserves_link_type_and_layers(self) -> None:
        plan = _dot11_plan(
            stack=["dot11", "payload"],
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
                "payload": {"hex": "01020304", "length": 4},
            },
            case="pcap-scapy-dot11",
        )

        vector = pcap.with_pcap_metadata([packets.encode_packet_plan(plan)], link_type="ieee80211")[0]

        self.assertEqual(vector.metadata["pcap_record"]["link_type"]["name"], "ieee80211")
        self.assertEqual(vector.metadata["pcap_record"]["link_type"]["datalink"], 105)
        self.assertEqual(pcap.pcap_link_type_for_vectors([vector]), "ieee80211")
        records = _write_and_read_scapy_pcap(vector)
        self.assertEqual(records[0]["link_type"]["name"], "ieee80211")
        self.assertEqual(records[0]["link_type"]["datalink"], 105)
        self.assertEqual(records[0]["layers"], ["dot11", "payload"])
        self.assertEqual(records[0]["raw_hex"], vector.raw_hex)

    def test_radiotap_pcap_roundtrip_preserves_link_type_and_layers(self) -> None:
        plan = _dot11_plan(
            stack=["radiotap", "dot11", "payload"],
            root="link:radiotap",
            fields={
                "radiotap": {"version": 0, "pad": 0, "rate": 2},
                "dot11": {
                    "frame_control": 0x0008,
                    "duration_id": 0,
                    "addr1": "00:00:5e:00:53:01",
                    "addr2": "00:00:5e:00:53:02",
                    "addr3": "00:00:5e:00:53:03",
                    "sequence_control": 0x1000,
                },
                "payload": {"hex": "01020304", "length": 4},
            },
            case="pcap-scapy-radiotap",
        )

        vector = pcap.with_pcap_metadata([packets.encode_packet_plan(plan)], link_type="radiotap")[0]

        self.assertEqual(vector.metadata["pcap_record"]["link_type"]["name"], "radiotap")
        self.assertEqual(vector.metadata["pcap_record"]["link_type"]["datalink"], 127)
        self.assertEqual(pcap.pcap_link_type_for_vectors([vector]), "radiotap")
        records = _write_and_read_scapy_pcap(vector)
        self.assertEqual(records[0]["link_type"]["name"], "radiotap")
        self.assertEqual(records[0]["link_type"]["datalink"], 127)
        self.assertEqual(records[0]["layers"], ["radiotap", "dot11", "payload"])
        self.assertEqual(records[0]["raw_hex"], vector.raw_hex)


def _write_and_read_scapy_pcap(vector):
    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "dot11.pcap"
        pcap.write_pcap(path, [vector])
        return pcap.read_pcap(path)


def _igmp_plan(
    igmp_fields: dict,
    *,
    case: str,
    feature: str,
    ipv4_fields: dict | None = None,
    malformed: bool = False,
) -> PacketPlan:
    fields: dict = {
        "ipv4": {
            "src": "192.0.2.10",
            "dst": "224.0.0.1",
            "ttl": 1,
            "protocol": "igmp",
            "identification": 0x1701,
            "flags": "none",
        },
        "igmp": dict(igmp_fields),
    }
    if ipv4_fields:
        fields["ipv4"].update(ipv4_fields)
    return PacketPlan(
        stack=["ipv4", "igmp"],
        fields=fields,
        profile="igmp-unit",
        seed=1,
        index=0,
        direction="reference_to_libcrafter",
        family="igmp",
        feature_tags=["igmp", feature],
        case=case,
        strict_bytes=True,
        metadata={
            "root": "l3:ipv4",
            "root_decoder": "l3:ipv4",
            "stack_name": "ipv4_igmp",
            "feature": feature,
            "malformed": malformed,
        },
    )


class ScapyIgmpMaterializationTest(unittest.TestCase):
    def test_igmp_features_protocol_and_layers_are_supported(self) -> None:
        self.assertEqual(packets._IP_PROTOCOLS["igmp"], 2)
        self.assertIn("igmp", packets._SCAPY_MATERIALIZED_LAYERS)
        self.assertIn("igmp_query", packets._SCAPY_MATERIALIZED_LAYERS)
        self.assertIn("igmp_report", packets._SCAPY_MATERIALIZED_LAYERS)
        self.assertIn("igmp_extension", packets._SCAPY_MATERIALIZED_LAYERS)
        for feature in {
            "igmp_header",
            "igmp_v3_query",
            "igmp_v3_report",
            "igmp_extensions",
            "igmp_mrd",
        }:
            self.assertIn(feature, packets._SUPPORTED_FEATURES)

    def test_igmp_membership_query_materializes_fixed_header_bytes(self) -> None:
        plan = _igmp_plan(
            {
                "type": "membership_query",
                "code": 0,
                "group_address": "0.0.0.0",
            },
            case="igmp-membership-query",
            feature="igmp_header",
        )

        vector = packets.encode_packet_plan(plan)
        raw = vector.to_bytes()

        self.assertEqual(raw[0] >> 4, 4)
        self.assertEqual(raw[9], 2)
        self.assertEqual(raw[20:].hex(), "1100eeff00000000")

    def test_igmp_v3_query_extension_materializes_strict_bytes(self) -> None:
        plan = _igmp_plan(
            {
                "type": "membership_query",
                "max_response_code": 100,
                "group_address": "233.252.0.61",
                "query_flags": ["extension", "suppress_router_side_processing", "qrv"],
                "qqic": 0x7D,
                "number_of_sources": 7,
                "source_addresses": ["198.51.100.10", "203.0.113.20"],
                "extension_tlvs": [
                    {
                        "extension_type": "noop",
                        "extension_value": {"hex": "aabbccdd"},
                    }
                ],
            },
            case="igmp-extension-query-noop",
            feature="igmp_extensions",
            ipv4_fields={"dst": "233.252.0.61", "identification": 0x1708},
        )

        vector = packets.encode_packet_plan(plan)

        self.assertEqual(
            vector.to_bytes()[20:].hex(),
            "11649bece9fc003d8a7d0007c633640acb00711400000004aabbccdd",
        )

    def test_igmp_v3_report_record_auxiliary_data_materializes_strict_bytes(self) -> None:
        plan = _igmp_plan(
            {
                "type": "v3_membership_report",
                "report_flags": "extension",
                "group_records": [
                    {
                        "record_type": "change_to_exclude_mode",
                        "auxiliary_data_len": 1,
                        "number_of_sources": 1,
                        "multicast_address": "233.252.0.76",
                        "source_addresses": ["198.51.100.74"],
                        "auxiliary_data": {"hex": "deadbeef"},
                    }
                ],
            },
            case="igmp-v3-report-auxiliary-data-record",
            feature="igmp_v3_report",
            ipv4_fields={"dst": "224.0.0.22", "identification": 0x170F},
        )

        vector = packets.encode_packet_plan(plan)

        self.assertEqual(
            vector.to_bytes()[20:].hex(),
            "2200a797000000008000000104010001e9fc004cc633644adeadbeef",
        )

    def test_igmp_mrd_and_unknown_raw_payloads_materialize(self) -> None:
        mrd = packets.encode_packet_plan(
            _igmp_plan(
                {
                    "type": "multicast_router_advertisement",
                    "mrd_advertisement_interval": 20,
                    "mrd_query_interval": 125,
                    "mrd_robustness_variable": 2,
                },
                case="igmp-mrd-advertisement",
                feature="igmp_mrd",
                ipv4_fields={"dst": "224.0.0.106", "identification": 0x1711},
            )
        )
        unknown = packets.encode_packet_plan(
            _igmp_plan(
                {
                    "type": "unassigned",
                    "code": 0,
                    "raw_tail": {"hex": "deadbeef"},
                },
                case="igmp-unknown-type-raw",
                feature="igmp_header",
                ipv4_fields={"dst": "233.252.0.1", "identification": 0x1712},
            )
        )

        self.assertEqual(mrd.to_bytes()[20:].hex(), "3014cf6c007d0002")
        self.assertEqual(unknown.to_bytes()[20:].hex(), "0900596200000000deadbeef")

    def test_igmp_structured_error_cases_are_not_strict_materialized(self) -> None:
        plan = _igmp_plan(
            {
                "type": "membership_query",
                "code": 0,
                "group_address": "0.0.0.0",
            },
            case="malformed-igmp-truncated-header",
            feature="igmp_header",
            malformed=True,
        )

        with self.assertRaisesRegex(ValueError, "structured-error"):
            packets.encode_packet_plan(plan)


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


# Pinned ESP/AH/IKEv2 crypto material mirroring the generator determinism seam
# (engine.generator._ipsec_pinned_crypto). Both backends seal/verify with these
# exact values so the ciphertext and ICV are byte-reproducible.
_IPSEC_PINNED_CRYPTO = {
    "pinned": True,
    "encryption_key": {"hex": "b0b0b0b0a1a1a1a1c2c2c2c2d3d3d3d3"},
    "salt": {"hex": "00010203"},
    "iv": {"hex": "0001020304050607"},
    "cbc_iv": {"hex": "101112131415161718191a1b1c1d1e1f"},
    "integrity_key": {
        "hex": "4a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60616263646566676869"
    },
}


def _ipsec_plan(
    *,
    stack: list[str],
    fields: dict,
    family: str,
    feature: str,
    feature_behavior: str,
    case: str,
) -> PacketPlan:
    return PacketPlan(
        stack=stack,
        fields=fields,
        profile=family,
        seed=1,
        index=0,
        direction="reference_to_libcrafter",
        family=family,
        feature_tags=["baseline", family],
        case=case,
        strict_bytes=True,
        metadata={
            "root": "l3:ipv4",
            "root_decoder": "l3:ipv4",
            "stack_name": "ipsec_unit",
            "feature": feature,
            "feature_behavior": feature_behavior,
        },
    )


class ScapyIpsecMaterializationTest(unittest.TestCase):
    """ESP/AH/IKEv2 plans materialize through Scapy and decode to the model."""

    def test_layer_and_protocol_maps_register_ipsec(self) -> None:
        self.assertEqual(packets._SCAPY_LAYER_BY_LAYER["esp"], "ESP")
        self.assertEqual(packets._SCAPY_LAYER_BY_LAYER["ah"], "AH")
        self.assertEqual(packets._SCAPY_LAYER_BY_LAYER["ikev2"], "ISAKMP")
        self.assertEqual(packets._IP_PROTOCOLS["esp"], 50)
        self.assertEqual(packets._IP_PROTOCOLS["ah"], 51)

    def test_esp_aead_transport_materializes_and_decodes(self) -> None:
        plan = _ipsec_plan(
            stack=["ipv4", "esp", "payload"],
            family="esp",
            feature="esp_aead",
            feature_behavior="aead-transport",
            case="esp-aead-transport",
            fields={
                "ipv4": {
                    "src": "192.0.2.1",
                    "dst": "198.51.100.1",
                    "ttl": 64,
                    "flags": "none",
                    "identification": 1,
                    "protocol": "esp",
                },
                "esp": {
                    "spi": 0x10001001,
                    "sequence": 1,
                    "next_header": "payload",
                    "crypto": _IPSEC_PINNED_CRYPTO,
                },
                "payload": {"hex": "deadbeef", "length": 4},
            },
        )
        vector = packets.encode_packet_plan(plan)
        raw = vector.to_bytes()
        # IP proto 50 (ESP) and the 8-octet AEAD explicit IV in the payload.
        self.assertEqual(raw[9], 50)
        self.assertEqual(raw[28:36].hex(), "0001020304050607")
        # Materialization is deterministic for the pinned key/salt/IV.
        self.assertEqual(packets.encode_packet_plan(plan).to_bytes(), raw)
        decoded = normalize.decode_bytes(raw, root="l3:ipv4", source_hex=vector.raw_hex)
        self.assertIn("esp", decoded.layers)
        self.assertEqual(decoded.fields["esp"]["spi"], 0x10001001)
        self.assertEqual(decoded.fields["esp"]["sequence"], 1)

    def test_esp_cbc_hmac_transport_uses_cbc_iv(self) -> None:
        plan = _ipsec_plan(
            stack=["ipv4", "esp", "payload"],
            family="esp",
            feature="esp_cbc",
            feature_behavior="cbc-hmac-transport",
            case="esp-cbc-hmac-transport",
            fields={
                "ipv4": {
                    "src": "192.0.2.1",
                    "dst": "198.51.100.1",
                    "ttl": 64,
                    "flags": "none",
                    "identification": 1,
                    "protocol": "esp",
                },
                "esp": {
                    "spi": 0x10001001,
                    "sequence": 1,
                    "next_header": "payload",
                    "crypto": _IPSEC_PINNED_CRYPTO,
                },
                "payload": {"hex": "deadbeef", "length": 4},
            },
        )
        vector = packets.encode_packet_plan(plan)
        raw = vector.to_bytes()
        self.assertEqual(raw[9], 50)
        # CBC uses the 16-octet explicit IV from the crypto block.
        self.assertEqual(raw[28:44].hex(), "101112131415161718191a1b1c1d1e1f")
        self.assertEqual(
            vector.metadata["ipsec_sa_materialization"]["crypt_algo"], "AES-CBC"
        )

    def test_esp_null_opaque_builds_raw_layer(self) -> None:
        plan = _ipsec_plan(
            stack=["ipv4", "esp", "payload"],
            family="esp",
            feature="esp_cbc",
            feature_behavior="null-opaque",
            case="esp-null-opaque",
            fields={
                "ipv4": {
                    "src": "192.0.2.1",
                    "dst": "198.51.100.1",
                    "ttl": 64,
                    "flags": "none",
                    "identification": 1,
                    "protocol": "esp",
                },
                "esp": {
                    "spi": 0x10001001,
                    "sequence": 1,
                    "next_header": "payload",
                    "crypto": _IPSEC_PINNED_CRYPTO,
                },
                "payload": {"hex": "cafebabe", "length": 4},
            },
        )
        self.assertFalse(packets._is_ipsec_sa_stack(plan, packets._canonical_stack(plan.stack)))
        vector = packets.encode_packet_plan(plan)
        raw = vector.to_bytes()
        self.assertEqual(raw[9], 50)
        # SPI || Seq, then the opaque body preserved verbatim.
        self.assertEqual(raw[20:28].hex(), "1000100100000001")
        self.assertEqual(raw[28:32].hex(), "cafebabe")

    def test_ah_hmac_transport_materializes_and_decodes(self) -> None:
        plan = _ipsec_plan(
            stack=["ipv4", "ah", "tcp", "payload"],
            family="ah",
            feature="ah_integrity",
            feature_behavior="hmac-transport",
            case="ah-hmac-transport",
            fields={
                "ipv4": {
                    "src": "192.0.2.1",
                    "dst": "198.51.100.1",
                    "ttl": 64,
                    "flags": "none",
                    "identification": 1,
                    "protocol": "ah",
                },
                "ah": {
                    "spi": 0x10001001,
                    "sequence": 1,
                    "next_header": "tcp",
                    "crypto": _IPSEC_PINNED_CRYPTO,
                },
                "tcp": {
                    "src_port": 1234,
                    "dst_port": 80,
                    "flags": "syn",
                    "sequence": 0,
                    "acknowledgement": 0,
                    "window": 8192,
                    "reserved": 0,
                },
                "payload": {"hex": "0011", "length": 2},
            },
        )
        vector = packets.encode_packet_plan(plan)
        raw = vector.to_bytes()
        self.assertEqual(raw[9], 51)  # IP proto 51 (AH).
        decoded = normalize.decode_bytes(raw, root="l3:ipv4", source_hex=vector.raw_hex)
        self.assertIn("ah", decoded.layers)
        self.assertEqual(decoded.fields["ah"]["spi"], 0x10001001)
        self.assertEqual(decoded.fields["ah"]["sequence"], 1)
        self.assertIn("icv", decoded.fields["ah"])
        self.assertNotIn("padding", decoded.fields["ah"])

    def test_ikev2_header_materializes_and_decodes(self) -> None:
        plan = _ipsec_plan(
            stack=["ipv4", "udp", "ikev2", "payload"],
            family="ikev2",
            feature="ikev2_header",
            feature_behavior="sa-init",
            case="ikev2-sa-init",
            fields={
                "ipv4": {
                    "src": "192.0.2.1",
                    "dst": "198.51.100.1",
                    "ttl": 64,
                    "flags": "none",
                    "identification": 1,
                    "protocol": "udp",
                },
                "udp": {"src_port": 500, "dst_port": 500},
                "ikev2": {
                    "initiator_spi": {"hex": "1122334455667788"},
                    "responder_spi": {"hex": "0000000000000000"},
                    "next_payload": "sa",
                    "version": 0x20,
                    "exchange_type": "ike_sa_init",
                    "flags": ["initiator"],
                    "message_id": 0,
                    "crypto": _IPSEC_PINNED_CRYPTO,
                },
                "payload": {"hex": "21202320", "length": 4},
            },
        )
        vector = packets.encode_packet_plan(plan)
        raw = vector.to_bytes()
        decoded = normalize.decode_bytes(raw, root="l3:ipv4", source_hex=vector.raw_hex)
        self.assertIn("ikev2", decoded.layers)
        ike = decoded.fields["ikev2"]
        self.assertEqual(ike["initiator_spi"]["hex"], "1122334455667788")
        self.assertEqual(ike["exchange_type"], 34)
        self.assertEqual(ike["flags"], ["initiator"])
        self.assertEqual(ike["message_id"], 0)

    def test_natt_udp_encapsulated_esp_inserts_udp(self) -> None:
        plan = _ipsec_plan(
            stack=["ipv4", "udp", "esp", "payload"],
            family="esp",
            feature="esp_aead",
            feature_behavior="aead-transport",
            case="crafter-esp-aead-transport",
            fields={
                "ipv4": {
                    "src": "192.0.2.1",
                    "dst": "198.51.100.1",
                    "ttl": 64,
                    "flags": "none",
                    "identification": 1,
                    "protocol": "udp",
                },
                "udp": {"src_port": 4500, "dst_port": 4500},
                "esp": {
                    "spi": 0x10001001,
                    "sequence": 1,
                    "next_header": "payload",
                    "crypto": _IPSEC_PINNED_CRYPTO,
                },
                "payload": {"hex": "deadbeef", "length": 4},
            },
        )
        vector = packets.encode_packet_plan(plan)
        raw = vector.to_bytes()
        # IP proto 17 (UDP) wraps the ESP per RFC 3948.
        self.assertEqual(raw[9], 17)
        self.assertTrue(vector.metadata["ipsec_sa_materialization"]["nat_traversal"])


def _scapy_rip_available() -> bool:
    """Return True only when Scapy and its native RIP layer import cleanly.

    The guard does a plain ``import`` rather than going through
    ``import_scapy()`` so a missing Scapy skips the test cleanly instead of
    triggering the backend's bootstrap/re-exec path.
    """

    try:
        import scapy  # type: ignore[import-untyped]  # noqa: F401
        from scapy.layers.rip import (  # type: ignore[import-untyped]  # noqa: F401
            RIP,
            RIPAuth,
            RIPEntry,
        )
    except Exception:  # pragma: no cover - environment dependent
        return False
    return True


_HAS_SCAPY_RIP = _scapy_rip_available()


class ScapyRipLayerMappingTest(unittest.TestCase):
    """The rip layer maps to Scapy's native RIP and declares its plan fields.

    These checks do not import Scapy, so they run even when the backend
    dependency is absent.
    """

    def test_rip_layer_maps_to_native_rip(self) -> None:
        self.assertEqual(packets._SCAPY_LAYER_BY_LAYER["rip"], "RIP")
        self.assertEqual(packets._scapy_layer_name("rip"), "RIP")

    def test_rip_supported_fields_cover_header_and_entries(self) -> None:
        supported = packets._SUPPORTED_FIELDS_BY_LAYER["rip"]
        self.assertIn("command", supported)
        self.assertIn("version", supported)
        self.assertIn("entries", supported)
        self.assertIn("auth", supported)

    def test_rip_command_resolves_named_and_numeric_commands(self) -> None:
        self.assertEqual(packets._rip_command("request"), 1)
        self.assertEqual(packets._rip_command("response"), 2)
        self.assertEqual(packets._rip_command(2), 2)
        self.assertEqual(packets._rip_command("0x02"), 2)


def _rip_plan(*, command: object, version: int, entries: list, auth=None) -> PacketPlan:
    rip_fields: dict = {"command": command, "version": version, "entries": entries}
    if auth is not None:
        rip_fields["auth"] = auth
    return PacketPlan(
        stack=["ipv4", "udp", "rip"],
        fields={
            "ipv4": {
                "src": "192.0.2.1",
                "dst": "224.0.0.9",
                "ttl": 1,
                "flags": "none",
                "identification": 1,
                "protocol": "udp",
            },
            "udp": {"src_port": 520, "dst_port": 520},
            "rip": rip_fields,
        },
        profile="smoke",
        seed=53,
        index=0,
        direction="reference_to_libcrafter",
        family="ipv4",
        feature_tags=["baseline", "ipv4", "udp", "rip"],
        case="rip-unit",
        strict_bytes=True,
        metadata={
            "root": "l3:ipv4",
            "root_decoder": "l3:ipv4",
            "stack_name": "ipv4_udp_rip",
        },
    )


# RIP rides on IPv4 (20 octets) + UDP (8 octets); the RIP message begins at
# offset 28 and its first octet is the command.
_RIP_MESSAGE_OFFSET = 28


@unittest.skipUnless(_HAS_SCAPY_RIP, "scapy RIP layer is not available")
class ScapyRipMaterializationTest(unittest.TestCase):
    """A RIP plan materializes to Scapy RIP/RIPEntry/RIPAuth bytes."""

    def test_v1_request_first_octet_is_command(self) -> None:
        plan = _rip_plan(
            command="request",
            version=1,
            entries=[{"address_family": 0, "address": "0.0.0.0", "metric": 16}],
        )
        vector = packets.encode_packet_plan(plan)
        raw = vector.to_bytes()
        self.assertEqual(vector.metadata["scapy_stack"][-1], "RIP")
        # First octet of the RIP message is the command (request == 1).
        self.assertEqual(raw[_RIP_MESSAGE_OFFSET], 1)
        # version octet follows the command.
        self.assertEqual(raw[_RIP_MESSAGE_OFFSET + 1], 1)

    def test_v2_response_route_entry_first_octet_is_command(self) -> None:
        plan = _rip_plan(
            command="response",
            version=2,
            entries=[
                {
                    "address_family": 2,
                    "route_tag": 7,
                    "address": "198.51.100.0",
                    "subnet_mask": "255.255.255.0",
                    "next_hop": "192.0.2.2",
                    "metric": 1,
                }
            ],
        )
        vector = packets.encode_packet_plan(plan)
        raw = vector.to_bytes()
        # First octet of the RIP message is the command (response == 2).
        self.assertEqual(raw[_RIP_MESSAGE_OFFSET], 2)
        self.assertEqual(raw[_RIP_MESSAGE_OFFSET + 1], 2)
        # A RIPv2 message with one route entry is 4 header + 20 entry octets.
        self.assertEqual(len(raw) - _RIP_MESSAGE_OFFSET, 24)

    def test_numeric_command_first_octet_matches(self) -> None:
        plan = _rip_plan(
            command=2,
            version=2,
            entries=[{"address_family": 2, "address": "198.51.100.1", "metric": 1}],
        )
        raw = packets.encode_packet_plan(plan).to_bytes()
        self.assertEqual(raw[_RIP_MESSAGE_OFFSET], 2)

    def test_simple_password_auth_entry_materializes(self) -> None:
        plan = _rip_plan(
            command="response",
            version=2,
            entries=[{"address_family": 2, "address": "198.51.100.1", "metric": 1}],
            auth={"type": 2, "simple_password": "rip-doc-secret"},
        )
        raw = packets.encode_packet_plan(plan).to_bytes()
        # Command octet is unchanged by the leading auth entry.
        self.assertEqual(raw[_RIP_MESSAGE_OFFSET], 2)
        # Header (4) + AFI 0xFFFF auth entry (20) + route entry (20).
        self.assertEqual(len(raw) - _RIP_MESSAGE_OFFSET, 44)
        # The auth entry's address-family identifier is 0xFFFF.
        self.assertEqual(
            raw[_RIP_MESSAGE_OFFSET + 4 : _RIP_MESSAGE_OFFSET + 6], b"\xff\xff"
        )


@unittest.skipUnless(_HAS_SCAPY_RIP, "scapy RIP layer is not available")
class ScapyRipNormalizeRoundTripTest(unittest.TestCase):
    """A materialized RIP plan decodes/normalizes back to its planned fields.

    The normalized ``rip`` layer collapses Scapy's typed RIP/RIPEntry/RIPAuth
    decode into the single libcrafter-shaped layer: ``command``/``version``/
    ``reserved`` plus an ``entries`` list and an optional ``auth`` sub-object.
    """

    def _decode(self, plan: PacketPlan):
        vector = packets.encode_packet_plan(plan)
        decoded = normalize.decode_bytes(
            vector.to_bytes(), root="l3:ipv4", source_hex=vector.raw_hex
        )
        self.assertIn("rip", decoded.layers)
        return decoded.fields["rip"]

    def test_v1_request_round_trips_command_version_and_entry_count(self) -> None:
        plan = _rip_plan(
            command="request",
            version=1,
            entries=[{"address_family": 0, "address": "0.0.0.0", "metric": 16}],
        )
        rip = self._decode(plan)
        self.assertEqual(rip["command"], 1)
        self.assertEqual(rip["version"], 1)
        self.assertEqual(len(rip["entries"]), 1)
        self.assertEqual(rip["entries"][0]["address_family"], 0)
        self.assertEqual(rip["entries"][0]["metric"], 16)
        # Standalone Scapy entry sub-layers are folded into the rip layer.
        self.assertNotIn("ripentry", plan.fields)

    def test_v2_response_round_trips_entry_fields(self) -> None:
        plan = _rip_plan(
            command="response",
            version=2,
            entries=[
                {
                    "address_family": 2,
                    "route_tag": 7,
                    "address": "198.51.100.0",
                    "subnet_mask": "255.255.255.0",
                    "next_hop": "192.0.2.2",
                    "metric": 1,
                },
                {
                    "address_family": 2,
                    "address": "203.0.113.0",
                    "subnet_mask": "255.255.255.0",
                    "metric": 2,
                },
            ],
        )
        rip = self._decode(plan)
        self.assertEqual(rip["command"], 2)
        self.assertEqual(rip["version"], 2)
        self.assertEqual(len(rip["entries"]), 2)
        first = rip["entries"][0]
        self.assertEqual(first["address_family"], 2)
        self.assertEqual(first["route_tag"], 7)
        self.assertEqual(first["address"], "198.51.100.0")
        self.assertEqual(first["subnet_mask"], "255.255.255.0")
        self.assertEqual(first["next_hop"], "192.0.2.2")
        self.assertEqual(first["metric"], 1)

    def test_simple_password_auth_round_trips_as_auth_sub_object(self) -> None:
        plan = _rip_plan(
            command="response",
            version=2,
            entries=[{"address_family": 2, "address": "198.51.100.1", "metric": 1}],
            auth={"type": 2, "simple_password": "rip-doc-secret"},
        )
        rip = self._decode(plan)
        self.assertEqual(rip["command"], 2)
        self.assertEqual(rip["version"], 2)
        # The AFI 0xFFFF auth entry is surfaced under "auth", not in "entries".
        self.assertEqual(len(rip["entries"]), 1)
        self.assertIn("auth", rip)
        self.assertEqual(rip["auth"]["address_family"], 0xFFFF)
        self.assertEqual(rip["auth"]["auth_type"], 2)
        self.assertIn("simple_password", rip["auth"])


def _scapy_available() -> bool:
    """Return True only when Scapy imports cleanly.

    The manual RIPng materializer wraps its hand-built header/RTE octets in a
    Scapy ``IPv6/UDP/Raw`` stack, so it needs Scapy itself but not a native
    RIPng layer (Scapy has none). The guard does a plain ``import`` rather than
    going through ``import_scapy()`` so a missing Scapy skips the test cleanly.
    """

    try:
        import scapy  # type: ignore[import-untyped]  # noqa: F401
    except Exception:  # pragma: no cover - environment dependent
        return False
    return True


_HAS_SCAPY = _scapy_available()


def _ripng_plan(*, command: object, version: int, rtes: list) -> PacketPlan:
    return PacketPlan(
        stack=["ipv6", "udp", "ripng"],
        fields={
            "ipv6": {
                "src": "2001:db8::1",
                "dst": "ff02::9",
                "hop_limit": 255,
                "next_header": "udp",
            },
            "udp": {"src_port": 521, "dst_port": 521},
            "ripng": {"command": command, "version": version, "rtes": rtes},
        },
        profile="smoke",
        seed=55,
        index=0,
        direction="reference_to_libcrafter",
        family="ipv6",
        feature_tags=["baseline", "ipv6", "udp", "ripng"],
        case="ripng-unit",
        strict_bytes=True,
        metadata={
            "root": "l3:ipv6",
            "root_decoder": "l3:ipv6",
            "stack_name": "ipv6_udp_ripng",
        },
    )


# RIPng rides on IPv6 (40 octets) + UDP (8 octets); the RIPng message begins at
# offset 48 and its first octet is the command.
_RIPNG_MESSAGE_OFFSET = 48


class RipngRteByteEncodingTest(unittest.TestCase):
    """The manual RIPng RTE encoder emits the RFC 2080 §2.1 20-octet layout.

    These checks build raw octets and do not import Scapy, so they run even
    when the backend dependency is absent.
    """

    def test_ripng_layer_maps_to_raw(self) -> None:
        self.assertEqual(packets._SCAPY_LAYER_BY_LAYER["ripng"], "Raw")
        self.assertEqual(packets._scapy_layer_name("ripng"), "Raw")

    def test_ripng_supported_fields_cover_header_and_rtes(self) -> None:
        supported = packets._SUPPORTED_FIELDS_BY_LAYER["ripng"]
        self.assertIn("command", supported)
        self.assertIn("version", supported)
        self.assertIn("rtes", supported)

    def test_route_rte_encodes_prefix_tag_prefix_len_and_metric(self) -> None:
        raw = packets._ripng_rte_bytes(
            {
                "prefix": "2001:db8::",
                "route_tag": 7,
                "prefix_len": 64,
                "metric": 1,
            }
        )
        self.assertEqual(len(raw), 20)
        # 16-octet prefix.
        self.assertEqual(raw[:16], bytes.fromhex("20010db8000000000000000000000000"))
        # 2-octet route tag, 1-octet prefix length, 1-octet metric.
        self.assertEqual(raw[16:18], b"\x00\x07")
        self.assertEqual(raw[18], 64)
        self.assertEqual(raw[19], 1)

    def test_next_hop_rte_defaults_metric_to_0xff(self) -> None:
        raw = packets._ripng_rte_bytes({"prefix": "2001:db8::99", "next_hop": True})
        self.assertEqual(len(raw), 20)
        # A next-hop RTE carries metric 0xFF with route tag and prefix length 0.
        self.assertEqual(raw[16:18], b"\x00\x00")
        self.assertEqual(raw[18], 0)
        self.assertEqual(raw[19], 0xFF)


@unittest.skipUnless(_HAS_SCAPY, "scapy is not available")
class ScapyRipngMaterializationTest(unittest.TestCase):
    """A RIPng plan materializes to manually-built header + RTE bytes.

    Scapy has no native RIPng dissector, so the RIPng header (command, version,
    reserved) and 20-octet RTEs are encoded directly and wrapped in a Scapy
    ``Raw`` layer carried on IPv6/UDP-521.
    """

    def test_response_first_octets_match_command_and_version(self) -> None:
        plan = _ripng_plan(
            command="response",
            version=1,
            rtes=[
                {
                    "prefix": "2001:db8::",
                    "route_tag": 0,
                    "prefix_len": 64,
                    "metric": 1,
                }
            ],
        )
        vector = packets.encode_packet_plan(plan)
        raw = vector.to_bytes()
        self.assertEqual(vector.metadata["scapy_stack"][-1], "Raw")
        # First octet of the RIPng message is the command (response == 2).
        self.assertEqual(raw[_RIPNG_MESSAGE_OFFSET], 2)
        # version octet follows the command (RIPng version 1).
        self.assertEqual(raw[_RIPNG_MESSAGE_OFFSET + 1], 1)
        # Header (4) + one route RTE (20) octets.
        self.assertEqual(len(raw) - _RIPNG_MESSAGE_OFFSET, 24)

    def test_numeric_command_first_octet_matches(self) -> None:
        plan = _ripng_plan(
            command=1,
            version=1,
            rtes=[{"prefix": "2001:db8::1", "prefix_len": 128, "metric": 16}],
        )
        raw = packets.encode_packet_plan(plan).to_bytes()
        # First octet of the RIPng message is the command (request == 1).
        self.assertEqual(raw[_RIPNG_MESSAGE_OFFSET], 1)
        self.assertEqual(raw[_RIPNG_MESSAGE_OFFSET + 1], 1)

    def test_next_hop_rte_metric_octet_is_0xff(self) -> None:
        plan = _ripng_plan(
            command="response",
            version=1,
            rtes=[
                {"prefix": "2001:db8::99", "next_hop": True},
                {"prefix": "2001:db8::", "prefix_len": 64, "metric": 1},
            ],
        )
        raw = packets.encode_packet_plan(plan).to_bytes()
        # Header (4) + next-hop RTE (20) + route RTE (20) octets.
        self.assertEqual(len(raw) - _RIPNG_MESSAGE_OFFSET, 44)
        # The next-hop RTE's metric octet (last octet of the first RTE) is 0xFF.
        next_hop_metric_index = _RIPNG_MESSAGE_OFFSET + 4 + 19
        self.assertEqual(raw[next_hop_metric_index], 0xFF)


if __name__ == "__main__":
    unittest.main()
